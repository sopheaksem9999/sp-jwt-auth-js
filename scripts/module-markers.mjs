// The one list of per-module markers, shared by check-dist.mjs (tsup dist graph) and check-bundle.mjs (esbuild
// browser bundles). A marker is a string literal that only that module's code emits (an endpoint name, a storage
// key, an error message), so finding it in the core proves module code leaked into the main entry.
//
// Adding a module (`src/<name>/` + a tsup entry + a package.json subpath):
//   1. add `<name>: [...]` here with 1+ literals from src/<name>/ that the core never contains (endpoint names a
//      module reads through `auth.endpoint(...)` are only markers when the core itself never names them);
//   2. run `pnpm check`. Both guards are non-vacuous: check-dist fails when a marker is missing from
//      dist/<name>.{js,cjs}, check-bundle fails when it is missing from the module's own browser bundle,
//      so a marker the bundler never emits (minified away, renamed) is caught instead of passing silently;
//   3. if the core legitimately needs one of the literals, pick another marker: never add an exception.
export const MODULE_MARKERS_BY_MODULE = {
  verify: ['cacheMaxAgeMs', 'maxStaleMs', 'JWKS response is not a key set'],
  otp: ['/resend-by-destination', 'Response did not describe a sent OTP'],
  mfa: ['secondFactorResend'],
  oauth: ['sp-jwt-auth:oauth:pending', 'oauthAuthorizationCode', 'Login callback has no authorization code'],
  sessions: ['sessionRevokeOthers', 'deviceRevoke', 'Response was not a list of sessions'],
  account: ['verifyEmail'],
  social: ['socialRedirect', 'socialCallback', 'Invalid provider'],
};

export const MODULE_MARKERS = Object.values(MODULE_MARKERS_BY_MODULE).flat();

// Node built-ins flagged in browser-facing dist files and bundles, with or without the `node:` prefix
// (a bare `fs` is as Node-only as `node:fs`). Hard-coded, so the guard does not depend on the Node version
// running it. Subpaths (`fs/promises`, `stream/web`) match through their first segment.
export const NODE_BUILTINS = [
  'assert',
  'buffer',
  'child_process',
  'crypto',
  'dns',
  'events',
  'fs',
  'http',
  'https',
  'module',
  'net',
  'os',
  'path',
  'perf_hooks',
  'readline',
  'stream',
  'timers',
  'tls',
  'url',
  'util',
  'vm',
  'worker_threads',
  'zlib',
];

const builtinAlt = NODE_BUILTINS.join('|');
// `from "x"`, `import "x"`, `import("x")`, `require("x")` where x is `node:<anything>` or a bare builtin
// (optionally with a `/sub` path). Quotes: ' " or `.
export const NODE_IMPORT_RE = new RegExp(
  String.raw`(?:\bfrom|\bimport|\brequire)\s*\(?\s*["'\x60](?:node:[^"'\x60]+|(?:${builtinAlt})(?:/[^"'\x60]*)?)["'\x60]`,
);

/** `true` for `node:x` and for a bare builtin specifier (`fs`, `fs/promises`). */
export function isNodeBuiltin(spec) {
  if (spec.startsWith('node:')) return true;
  return NODE_BUILTINS.includes(spec.split('/')[0]);
}
