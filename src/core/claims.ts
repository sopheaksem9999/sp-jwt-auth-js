/** Decoded JWT claims (unverified), with `sub` as a string and `scopes` as a string array. */
export interface Claims {
  sub: string;
  exp: number;
  iat?: number;
  sid?: string;
  scopes: string[];
  company_id?: string | number;
  [k: string]: unknown;
}

function decodeSegment(seg: string): unknown {
  const b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

function toScopes(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === 'string') return v.split(/\s+/).filter((s) => s !== '');
  return [];
}

/** Decodes a JWT payload WITHOUT verifying it; returns `null` for anything that is not a three-part JWT with a JSON object payload. */
export function decodeClaims(jwt: string): Claims | null {
  if (typeof jwt !== 'string') return null;
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  let payload: unknown;
  try {
    const header = decodeSegment(parts[0] as string);
    if (typeof header !== 'object' || header === null || Array.isArray(header)) return null;
    payload = decodeSegment(parts[1] as string);
  } catch {
    return null;
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return null;
  const p = payload as Record<string, unknown>;
  return {
    ...p,
    sub: p.sub === undefined || p.sub === null ? '' : String(p.sub),
    exp: typeof p.exp === 'number' ? p.exp : 0,
    scopes: toScopes(p.scopes),
  };
}
