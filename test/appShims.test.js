/**
 * The Android app replaces Node's crypto with a pure-JS SHA-256. Known-malware
 * hashes depend on it, so it must match Node exactly.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const shim = require('../app/mobile/shims/crypto');

describe('Android app SHA-256 shim', () => {
  it('matches Node crypto for empty, small, block-edge and large inputs', () => {
    const sizes = [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000, 100000, 1 << 20];
    for (const n of sizes) {
      const buf = crypto.randomBytes(n);
      const want = crypto.createHash('sha256').update(buf).digest('hex');
      assert.strictEqual(shim.createHash('sha256').update(buf).digest('hex'), want, `size ${n}`);
    }
    assert.strictEqual(shim.createHash('sha256').update('abc').digest('hex'),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});
