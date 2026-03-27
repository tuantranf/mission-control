/**
 * Gateway RPC abstraction — delegates to the WebSocket client in gateway-rpc.ts.
 *
 * callOpenClawGateway() signature is preserved for existing callers.
 */

export { callGatewayRpc, gatewaySessionSend, gatewayAgentInvoke, GatewayRpcError } from './gateway-rpc'
export type { GatewayRpcConfig } from './gateway-rpc'

import { callGatewayRpc } from './gateway-rpc'

/**
 * Call a gateway RPC method by name.
 * Signature-compatible replacement for the previous CLI-based implementation.
 */
export async function callOpenClawGateway<T = unknown>(
  method: string,
  params: unknown,
  timeoutMs = 10000,
): Promise<T> {
  return callGatewayRpc<T>(method, params, timeoutMs)
}
