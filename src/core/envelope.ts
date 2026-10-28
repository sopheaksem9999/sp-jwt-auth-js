import { SpAuthError, errorCodeFrom } from './errors';

/**
 * Throws the specific error for a HTTP 200 whose body is `{ success: false }`
 * (the envelope some hosts answer with on a business failure). Returns for any
 * other body (non-object, array, `success` missing or not `false`).
 */
export function throwIfEnvelopeFailure(body: unknown, module?: string): void {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return;
  const b = body as Record<string, unknown>;
  if (b.success !== false) return;
  const meta = typeof b.meta === 'object' && b.meta !== null && !Array.isArray(b.meta) ? (b.meta as Record<string, unknown>) : null;
  const rid = meta !== null && typeof meta.request_id === 'string' && meta.request_id !== '' ? meta.request_id : null;
  throw new SpAuthError({
    status: 200,
    code: 'request_failed',
    message: typeof b.message === 'string' && b.message !== '' ? b.message : 'Request failed',
    errorCode: errorCodeFrom(b.error_code),
    requestId: rid,
    module,
  });
}
