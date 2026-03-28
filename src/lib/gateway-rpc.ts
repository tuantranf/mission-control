/**
 * Server-side OpenClaw Gateway WebSocket RPC client.
 *
 * Implements the v3 protocol using control UI / token-only auth mode.
 * Reference: docs/openclaw_gateway_ws.md (Python implementation)
 * Reference: docs/ai/implementation/knowledge-mission-control-gateway-interaction.md
 *
 * Each call opens a fresh WebSocket, performs the connect handshake,
 * sends the method RPC, receives the response, and closes. No connection pooling.
 */

import WebSocket from 'ws';
import { randomUUID } from 'node:crypto';
import { config } from '@/lib/config';
import { getDetectedGatewayToken } from '@/lib/gateway-runtime';
import { buildGatewayWebSocketUrl } from '@/lib/gateway-url';
import { logger } from '@/lib/logger';

const PROTOCOL_VERSION = 3;
const CLIENT_ID = 'openclaw-control-ui';
const CLIENT_MODE = 'ui';
const CLIENT_VERSION = '1.0.0';
const GATEWAY_OPERATOR_SCOPES = [
  'operator.read',
  'operator.admin',
  'operator.approvals',
  'operator.pairing',
];

const DEFAULT_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GatewayRpcConfig {
  /** WebSocket URL (ws:// or wss://) */
  url: string;
  /** Auth token for query parameter and connect RPC auth.token field */
  token: string;
  /** Allow insecure TLS (self-signed certs) */
  allowInsecureTls?: boolean;
}

export class GatewayRpcError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    /** HTTP status code to propagate to the caller */
    public readonly statusCode: number,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'GatewayRpcError';
  }
}

interface GatewayFrame {
  type: 'event' | 'req' | 'res';
  id?: string;
  event?: string;
  method?: string;
  params?: unknown;
  payload?: unknown;
  ok?: boolean;
  error?: { message?: string; code?: string; [key: string]: unknown };
}

// ---------------------------------------------------------------------------
// URL building
// ---------------------------------------------------------------------------

function appendTokenToUrl(url: string, token: string): string {
  try {
    const parsed = new URL(url);
    if (token) parsed.searchParams.set('token', token);
    return parsed.toString();
  } catch {
    return url;
  }
}

function redactUrl(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.search = '';
    return parsed.toString();
  } catch {
    return url;
  }
}

/**
 * Build the HTTP(S) origin for the control UI WebSocket connection.
 * The gateway validates the Origin header in control UI mode.
 * Mirrors Python `_build_control_ui_origin` from docs/openclaw_gateway_ws.md.
 *
 * ws://host:port  → http://host:port
 * wss://host:port → https://host:port
 */
function buildControlUiOrigin(url: string): string | null {
  try {
    const parsed = new URL(url);
    let originScheme: string;
    if (parsed.protocol === 'ws:' || parsed.protocol === 'http:') {
      originScheme = 'http';
    } else if (parsed.protocol === 'wss:' || parsed.protocol === 'https:') {
      originScheme = 'https';
    } else {
      return null;
    }
    const host = parsed.port
      ? `${parsed.hostname}:${parsed.port}`
      : parsed.hostname;
    return `${originScheme}://${host}`;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Primary gateway config resolution
// ---------------------------------------------------------------------------

/** Resolve the primary gateway WebSocket URL and token from config/env. */
function resolvePrimaryGatewayConfig(): GatewayRpcConfig {
  const token = getDetectedGatewayToken();
  const url = buildGatewayWebSocketUrl({
    host: config.gatewayHost,
    port: config.gatewayPort,
  });
  return { url, token };
}

// ---------------------------------------------------------------------------
// WebSocket helpers
// ---------------------------------------------------------------------------

function openWebSocket(
  url: string,
  allowInsecureTls: boolean,
  origin?: string,
): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const wsOptions: WebSocket.ClientOptions = {
      rejectUnauthorized: !allowInsecureTls,
    };
    if (origin) {
      wsOptions.headers = { Origin: origin };
    }
    const ws = new WebSocket(url, wsOptions);

    const onOpen = () => {
      cleanup();
      resolve(ws);
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      ws.off('open', onOpen);
      ws.off('error', onError);
    };

    ws.once('open', onOpen);
    ws.once('error', onError);
  });
}

/**
 * Wait up to 2 seconds for a `connect.challenge` event.
 * Returns the nonce string if received, or null.
 * Matches Python `_recv_first_message_or_none` + challenge extraction.
 */
function maybeReceiveChallenge(ws: WebSocket): Promise<string | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      cleanup();
      resolve(null);
    }, 10_000);

    const onMessage = (data: WebSocket.RawData) => {
      cleanup();
      try {
        const frame = JSON.parse(data.toString()) as GatewayFrame;
        if (frame.type === 'event' && frame.event === 'connect.challenge') {
          const nonce =
            frame.payload &&
            typeof frame.payload === 'object' &&
            'nonce' in (frame.payload as object)
              ? String((frame.payload as { nonce: unknown }).nonce ?? '')
              : '';
          resolve(nonce.trim() || null);
        } else {
          // Unexpected first frame — log and continue without nonce
          logger.debug(
            { type: frame.type, event: frame.event },
            'gateway.rpc: unexpected first frame (expected connect.challenge)',
          );
          resolve(null);
        }
      } catch {
        resolve(null);
      }
    };

    const cleanup = () => {
      clearTimeout(timer);
      ws.off('message', onMessage);
    };

    ws.once('message', onMessage);
  });
}

/**
 * Send the connect RPC and wait for its response.
 * Uses control UI mode (token-only, no device identity).
 */
function performHandshake(
  ws: WebSocket,
  token: string,
  nonce: string | null,
): Promise<void> {
  const connectId = randomUUID();
  const params: Record<string, unknown> = {
    minProtocol: PROTOCOL_VERSION,
    maxProtocol: PROTOCOL_VERSION,
    role: 'operator',
    scopes: GATEWAY_OPERATOR_SCOPES,
    client: {
      id: CLIENT_ID,
      version: CLIENT_VERSION,
      platform: 'node',
      mode: CLIENT_MODE,
    },
  };
  if (token) {
    params.auth = { token };
  }
  // Control UI mode: no device field

  return awaitResponse(ws, connectId, {
    type: 'req',
    id: connectId,
    method: 'connect',
    params,
  }).then(() => undefined);
}

/**
 * Send an RPC request frame and wait for the matching `res` frame.
 * Matches Python `_send_request` + `_await_response`.
 */
function sendRpcRequest<T>(
  ws: WebSocket,
  method: string,
  params: unknown,
  requestId: string,
): Promise<T> {
  const frame = { type: 'req', id: requestId, method, params: params ?? {} };
  ws.send(JSON.stringify(frame));
  return awaitResponse<T>(ws, requestId);
}

/**
 * Send a frame then collect incoming frames until the one with matching `id` arrives.
 * If `frameToSend` is undefined, only waits (the frame was already sent).
 */
function awaitResponse<T>(
  ws: WebSocket,
  requestId: string,
  frameToSend?: object,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onMessage = (data: WebSocket.RawData) => {
      let frame: GatewayFrame;
      try {
        frame = JSON.parse(data.toString()) as GatewayFrame;
      } catch {
        return; // Ignore malformed frames
      }

      // Match by request ID
      if (frame.id !== requestId) return;

      cleanup();

      // Gateway error response
      if (frame.ok === false || frame.error) {
        const msg = (frame.error as any)?.message ?? 'Gateway RPC error';
        reject(new GatewayRpcError(msg, 'RPC_ERROR', 502, frame.error));
        return;
      }

      resolve(frame.payload as T);
    };

    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };

    const onClose = () => {
      cleanup();
      reject(
        new GatewayRpcError(
          'WebSocket closed before response',
          'GATEWAY_CLOSED',
          502,
        ),
      );
    };

    const cleanup = () => {
      ws.off('message', onMessage);
      ws.off('error', onError);
      ws.off('close', onClose);
    };

    ws.on('message', onMessage);
    ws.once('error', onError);
    ws.once('close', onClose);

    if (frameToSend) {
      ws.send(JSON.stringify(frameToSend));
    }
  });
}

// ---------------------------------------------------------------------------
// Core per-call client
// ---------------------------------------------------------------------------

async function executeCall<T>(
  method: string,
  params: unknown,
  cfg: GatewayRpcConfig,
  timeoutMs: number,
): Promise<T> {
  const fullUrl = appendTokenToUrl(cfg.url, cfg.token);
  const logUrl = redactUrl(cfg.url);
  const startedAt = Date.now();

  logger.debug({ method, url: logUrl }, 'gateway.rpc: connecting');

  let ws: WebSocket | undefined;

  const origin = buildControlUiOrigin(cfg.url);

  const doCall = async (): Promise<T> => {
    ws = await openWebSocket(
      fullUrl,
      cfg.allowInsecureTls ?? false,
      origin ?? undefined,
    );
    const nonce = await maybeReceiveChallenge(ws);
    await performHandshake(ws, cfg.token, nonce);
    const requestId = randomUUID();
    return sendRpcRequest<T>(ws, method, params, requestId);
  };

  let timeoutHandle: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timeoutHandle = setTimeout(
      () =>
        reject(
          new GatewayRpcError(
            `Gateway RPC timed out after ${timeoutMs}ms`,
            'GATEWAY_TIMEOUT',
            502,
          ),
        ),
      timeoutMs,
    );
  });

  try {
    const result = await Promise.race([doCall(), timeout]);
    logger.debug(
      { method, url: logUrl, durationMs: Date.now() - startedAt },
      'gateway.rpc: success',
    );
    return result;
  } catch (err) {
    const durationMs = Date.now() - startedAt;
    if (err instanceof GatewayRpcError) {
      logger.warn(
        { method, url: logUrl, code: err.code, durationMs },
        'gateway.rpc: error',
      );
      throw err;
    }
    // Wrap transport errors (ECONNREFUSED, ENOTFOUND, etc.)
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(
      { method, url: logUrl, err, durationMs },
      'gateway.rpc: transport error',
    );
    throw new GatewayRpcError(
      `Gateway unreachable: ${msg}`,
      'GATEWAY_UNREACHABLE',
      502,
      { originalError: msg },
    );
  } finally {
    clearTimeout(timeoutHandle!);
    if (ws && ws.readyState !== WebSocket.CLOSED) {
      ws.close();
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Send an RPC call to the OpenClaw Gateway over WebSocket.
 * Drop-in replacement for the CLI-based callOpenClawGateway().
 *
 * Resolves the primary gateway config (URL + token) from env/config unless
 * an explicit config override is provided via options.
 */
export async function callGatewayRpc<T = unknown>(
  method: string,
  params: unknown,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
  options?: { config?: GatewayRpcConfig },
): Promise<T> {
  const cfg = options?.config ?? resolvePrimaryGatewayConfig();

  if (!cfg.url) {
    throw new GatewayRpcError(
      'Gateway URL is not configured',
      'GATEWAY_NOT_CONFIGURED',
      422,
    );
  }

  return executeCall<T>(method, params, cfg, timeoutMs);
}

/**
 * Send a chat message to a gateway session via the `chat.send` RPC.
 */
export async function gatewaySessionSend(
  sessionKey: string,
  message: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
  options?: { config?: GatewayRpcConfig; deliver?: boolean },
): Promise<void> {
  await callGatewayRpc(
    'chat.send',
    {
      sessionKey,
      message,
      deliver: options?.deliver ?? false,
      idempotencyKey: randomUUID(),
    },
    timeoutMs,
    options,
  );
}

/**
 * Invoke a gateway agent.
 * Replaces: runOpenClaw(['gateway', 'call', 'agent', ...])
 *
 * When expectFinal is true, waits for the agent's final response (up to timeoutMs).
 * Replaces: runOpenClaw(['gateway', 'call', 'agent', '--expect-final', ...])
 */
export async function gatewayAgentInvoke(
  params: {
    message: string;
    agentId?: string;
    /** Required by gateway AgentParamsSchema (NonEmptyString). */
    idempotencyKey: string;
    deliver?: boolean;
    attachments?: unknown[];
    /** Optional system prompt hint passed to the agent (schema-valid field in AgentParamsSchema). */
    extraSystemPrompt?: string;
  },
  options?: {
    expectFinal?: boolean;
    timeoutMs?: number;
    config?: GatewayRpcConfig;
  },
): Promise<unknown> {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const cfg = options?.config ?? resolvePrimaryGatewayConfig();

  if (!cfg.url) {
    throw new GatewayRpcError(
      'Gateway URL is not configured',
      'GATEWAY_NOT_CONFIGURED',
      422,
    );
  }

  if (!options?.expectFinal) {
    return executeCall('agent', params, cfg, timeoutMs);
  }

  // expectFinal: agent returns an initial "accepted" response, then a final
  // response when the agent completes. Keep the connection open and wait for
  // the final frame (payload.status === 'completed' | 'error' | 'done').
  const fullUrl = appendTokenToUrl(cfg.url, cfg.token);
  const logUrl = redactUrl(cfg.url);
  const startedAt = Date.now();

  logger.debug(
    { method: 'agent', url: logUrl, expectFinal: true },
    'gateway.rpc: connecting',
  );

  const origin = buildControlUiOrigin(cfg.url);
  let ws: WebSocket | undefined;

  const doCallFinal = async (): Promise<unknown> => {
    ws = await openWebSocket(
      fullUrl,
      cfg.allowInsecureTls ?? false,
      origin ?? undefined,
    );
    const nonce = await maybeReceiveChallenge(ws);
    await performHandshake(ws, cfg.token, nonce);

    const requestId = randomUUID();
    const frame = {
      type: 'req',
      id: requestId,
      method: 'agent',
      params: params ?? {},
    };
    ws.send(JSON.stringify(frame));

    // Collect all responses with matching request ID until we get final status
    return new Promise<unknown>((resolve, reject) => {
      let lastPayload: unknown = undefined;

      const onMessage = (data: WebSocket.RawData) => {
        let f: GatewayFrame;
        try {
          f = JSON.parse(data.toString()) as GatewayFrame;
        } catch {
          return;
        }

        if (f.id !== requestId) return;

        if (f.ok === false || f.error) {
          cleanup();
          const msg = (f.error as any)?.message ?? 'Gateway agent error';
          reject(new GatewayRpcError(msg, 'RPC_ERROR', 502, f.error));
          return;
        }

        const payload = f.payload;
        lastPayload = payload;

        // Check for final status.
        // Gateway sends: "accepted" (keep waiting), "ok" (success), "error" (failure).
        const status =
          payload && typeof payload === 'object'
            ? String((payload as any).status ?? '')
            : '';
        if (
          status === 'ok' ||
          status === 'completed' ||
          status === 'done' ||
          status === 'error' ||
          status === 'failed'
        ) {
          cleanup();
          resolve(payload);
          return;
        }

        // "accepted" or other intermediate status — keep waiting for final frame
      };

      const onError = (err: Error) => {
        cleanup();
        // If we have a last payload, consider it partial success
        if (lastPayload !== undefined) {
          resolve(lastPayload);
        } else {
          reject(
            new GatewayRpcError(
              `WebSocket error: ${err.message}`,
              'GATEWAY_ERROR',
              502,
            ),
          );
        }
      };

      const onClose = () => {
        cleanup();
        if (lastPayload !== undefined) {
          resolve(lastPayload);
        } else {
          reject(
            new GatewayRpcError(
              'WebSocket closed before final agent response',
              'GATEWAY_CLOSED',
              502,
            ),
          );
        }
      };

      const cleanup = () => {
        ws!.off('message', onMessage);
        ws!.off('error', onError);
        ws!.off('close', onClose);
      };

      ws!.on('message', onMessage);
      ws!.once('error', onError);
      ws!.once('close', onClose);
    });
  };

  let timeoutHandle: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timeoutHandle = setTimeout(
      () =>
        reject(
          new GatewayRpcError(
            `Gateway agent call timed out after ${timeoutMs}ms`,
            'GATEWAY_TIMEOUT',
            502,
          ),
        ),
      timeoutMs,
    );
  });

  try {
    const result = await Promise.race([doCallFinal(), timeout]);
    logger.debug(
      { method: 'agent', url: logUrl, durationMs: Date.now() - startedAt },
      'gateway.rpc: agent final success',
    );
    return result;
  } catch (err) {
    const durationMs = Date.now() - startedAt;
    if (err instanceof GatewayRpcError) {
      logger.warn(
        { method: 'agent', url: logUrl, code: err.code, durationMs },
        'gateway.rpc: agent error',
      );
      throw err;
    }
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(
      { method: 'agent', url: logUrl, err, durationMs },
      'gateway.rpc: transport error',
    );
    throw new GatewayRpcError(
      `Gateway unreachable: ${msg}`,
      'GATEWAY_UNREACHABLE',
      502,
      { originalError: msg },
    );
  } finally {
    clearTimeout(timeoutHandle!);
    if (ws && ws.readyState !== WebSocket.CLOSED) {
      ws.close();
    }
  }
}
