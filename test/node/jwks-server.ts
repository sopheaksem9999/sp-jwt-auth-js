// Node-only helper: serves a JWKS document from a local `node:http` server so verify tests hit a real HTTP endpoint.
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { exportJWK } from 'jose';
import type { JWK } from 'jose';

/** A running test JWKS endpoint. */
export interface JwksServer {
  /** Full URL of the JWKS document. */
  url: string;
  /** Replaces the published key set. */
  setKeys(keys: JWK[]): void;
  /** Makes every following request answer with this HTTP status (and no JWKS) until `setKeys` or `recover`. */
  failWith(status: number): void;
  /** Stops failing and serves the last key set again. */
  recover(): void;
  /** Number of JWKS requests served so far. */
  readonly requests: number;
  close(): Promise<void>;
}

/** Exports a public key as a JWK shaped like the Laravel `JwksFormatter` output (`kty`, `use`, `kid`, `alg`, `n`, `e`). */
export async function publicJwk(key: CryptoKey, kid: string, alg = 'RS256'): Promise<JWK> {
  const { kty, n, e } = await exportJWK(key);
  return { kty, use: 'sig', kid, alg, n, e };
}

/** Starts a JWKS server on an ephemeral localhost port. */
export async function startJwksServer(initial: JWK[] = []): Promise<JwksServer> {
  let keys = initial;
  let failStatus: number | null = null;
  let requests = 0;
  const server: Server = createServer((_req, res) => {
    requests++;
    if (failStatus !== null) {
      res.statusCode = failStatus;
      res.end('upstream failure');
      return;
    }
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ keys }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/.well-known/sp-jwt-auth/jwks.json`,
    setKeys(k) {
      keys = k;
      failStatus = null;
    },
    failWith(status) {
      failStatus = status;
    },
    recover() {
      failStatus = null;
    },
    get requests() {
      return requests;
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
}
