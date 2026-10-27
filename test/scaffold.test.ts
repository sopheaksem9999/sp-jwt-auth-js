import { describe, expect, it } from 'vitest';
// JSON import (not node:fs) so this test also runs in the edge-runtime project.
import pkg from '../package.json';
import { VERSION } from '../src/index';

describe('scaffold', () => {
  it('exports a VERSION string', () => {
    expect(typeof VERSION).toBe('string');
  });

  it('package.json carries the binding constraints', () => {
    expect(pkg.name).toBe('@sokpheak/sp-jwt-auth');
    expect(pkg.engines.node).toBe('>=20');
    expect(pkg.sideEffects).toBe(false);
    expect(pkg.license).toBe('MIT');
  });

  it('jose is an optional peer and there are no runtime dependencies', () => {
    expect(pkg.peerDependenciesMeta.jose.optional).toBe(true);
    expect(Object.keys((pkg as { dependencies?: object }).dependencies ?? {})).toEqual([]);
  });
});
