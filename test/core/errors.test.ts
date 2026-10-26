import { describe, expect, it } from 'vitest';
import { SpAuthError, authErrorFromResponse } from '../../src/core/errors';

const json = (status: number, body: unknown, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

describe('authErrorFromResponse', () => {
  it('keeps status 401 for a plain Unauthenticated. body', async () => {
    const err = await authErrorFromResponse(json(401, { message: 'Unauthenticated.' }));
    expect(err).toBeInstanceOf(SpAuthError);
    expect(err).toBeInstanceOf(Error);
    expect(err.status).toBe(401);
    expect(err.code).toBe('unknown');
    expect(err.message).toBe('Unauthenticated.');
    expect(err.response).not.toBeNull();
  });

  it('maps 422 to invalid_code with fieldErrors', async () => {
    const err = await authErrorFromResponse(json(422, { message: 'Bad', errors: { code: ['Invalid code'] } }));
    expect(err.code).toBe('invalid_code');
    expect(err.fieldErrors).toEqual({ code: ['Invalid code'] });
  });

  it('maps 429 with Retry-After to rate_limited with retryAfter', async () => {
    const err = await authErrorFromResponse(json(429, { message: 'Slow' }, { 'Retry-After': '30' }));
    expect(err.code).toBe('rate_limited');
    expect(err.retryAfter).toBe(30);
  });

  it('accepts an HTTP-date Retry-After, clamped to >= 0', async () => {
    const past = new Date(Date.now() - 60_000).toUTCString();
    const err = await authErrorFromResponse(json(429, {}, { 'Retry-After': past }));
    expect(err.retryAfter).toBe(0);
    const future = new Date(Date.now() + 60_000).toUTCString();
    const e2 = await authErrorFromResponse(json(429, {}, { 'Retry-After': future }));
    expect(e2.retryAfter).toBeGreaterThan(50);
  });

  it('garbage or empty Retry-After yields null', async () => {
    expect((await authErrorFromResponse(json(429, {}, { 'Retry-After': 'soon' }))).retryAfter).toBeNull();
    expect((await authErrorFromResponse(json(429, {}))).retryAfter).toBeNull();
  });

  it('maps 502 to delivery_failed', async () => {
    expect((await authErrorFromResponse(json(502, {}))).code).toBe('delivery_failed');
  });

  it('maps 404 to module_disabled only with disabledOn404', async () => {
    const res = (): Response => new Response('', { status: 404 });
    expect((await authErrorFromResponse(res(), { disabledOn404: true, module: 'two-factor' })).code).toBe('module_disabled');
    expect((await authErrorFromResponse(res())).code).toBe('unknown');
    expect((await authErrorFromResponse(res(), { module: 'm' })).module).toBe('m');
  });

  it('uses RFC 6749 error and error_description', async () => {
    const err = await authErrorFromResponse(json(400, { error: 'invalid_client', error_description: 'Client auth failed' }));
    expect(err.code).toBe('invalid_client');
    expect(err.message).toBe('Client auth failed');
  });

  it('a body error on 401 sets the code', async () => {
    const err = await authErrorFromResponse(json(401, { error: 'invalid_grant' }));
    expect(err.code).toBe('invalid_grant');
    expect(err.status).toBe(401);
  });

  it('handles enveloped errors and request id from meta', async () => {
    const err = await authErrorFromResponse(
      json(422, { success: false, message: 'Nope', errors: { a: 'x' }, meta: { request_id: 'r1' } }, { 'X-Request-ID': 'h' }),
    );
    expect(err.requestId).toBe('r1');
    expect(err.fieldErrors).toEqual({ a: ['x'] });
  });

  it('falls back to X-Request-ID header and normalises array errors to {}', async () => {
    const err = await authErrorFromResponse(json(422, { message: 'x', errors: [] }, { 'X-Request-ID': 'h' }));
    expect(err.requestId).toBe('h');
    expect(err.fieldErrors).toEqual({});
  });

  it('empty body gives a non-empty message and null body', async () => {
    const err = await authErrorFromResponse(new Response('', { status: 500 }));
    expect(err.message).not.toBe('');
    expect(err.body).toBeNull();
  });

  it('HTML body gives a non-empty message and string body', async () => {
    const err = await authErrorFromResponse(new Response('<html>Bad</html>', { status: 503 }));
    expect(err.message).not.toBe('');
    expect(err.body).toBe('<html>Bad</html>');
  });

  it('an aborted body stream still yields an SpAuthError', async () => {
    const stream = new ReadableStream({
      start(c) {
        c.error(new Error('aborted'));
      },
    });
    const err = await authErrorFromResponse(new Response(stream, { status: 500 }));
    expect(err).toBeInstanceOf(SpAuthError);
    expect(err.message).not.toBe('');
    expect(err.body).toBeNull();
  });
});
