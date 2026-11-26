/**
 * Learned signatures: the feed must be signed, never rolled back, and its
 * malicious-package / hash rules must hit only the listed versions.
 * Runs with an isolated HOME and a throwaway key; never touches the real feed.
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const zlib = require('zlib');
const crypto = require('crypto');

const feedRules = require('../src/rules/feedRules');
const { detectMalware } = require('../src/rules/malware');

const keys = crypto.generateKeyPairSync('ed25519');
const otherKeys = crypto.generateKeyPairSync('ed25519');
const PUB = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const MALWARE_FILE = Buffer.from('pretend malware sample for the hash rule');

function makeFeed(sequence, extra = {}) {
  const feed = {
    schema: 1, sequence, generatedAt: new Date(sequence * 1000).toISOString(),
    packages: { npm: { 'evil-pkg': '*', chalk: ['5.6.1'] }, PyPI: { 'bad-lib': '*' } },
    hashes: { [crypto.createHash('sha256').update(MALWARE_FILE).digest('hex')]: 'Test sample' },
    markers: [{ id: 'm1', name: 'Test marker', pattern: 'STEAL_ALL_KEYS\\(', files: '\\.js$', verdict: 'SUSPECT' }],
    ...extra
  };
  const gz = zlib.gzipSync(JSON.stringify(feed));
  return { feed, gz, sig: crypto.sign(null, gz, keys.privateKey).toString('base64') };
}

describe('Signature feed: signing and updates', () => {
  let server; let url; let serve = {}; let home; const saved = {};
  before(async () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-sig-'));
    for (const k of ['HOME', 'USERPROFILE']) { saved[k] = process.env[k]; process.env[k] = home; }
    server = http.createServer((req, res) => {
      const body = req.url.endsWith('.sig') ? serve.sig : serve.gz;
      res.end(body);
    });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${server.address().port}/feed.json.gz`;
  });
  after(() => {
    server.close();
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    fs.rmSync(home, { recursive: true, force: true });
    feedRules.setFeed(null);
  });

  it('accepts only feeds signed with the built-in key', () => {
    const sigs = require('../src/signatures');
    const { gz, sig } = makeFeed(100);
    assert.strictEqual(sigs.parseFeed(gz, sig, PUB).sequence, 100);
    const tampered = Buffer.from(gz); tampered[tampered.length - 5] ^= 0xff;
    assert.throws(() => sigs.parseFeed(tampered, sig, PUB), /signature/);
    const forged = crypto.sign(null, gz, otherKeys.privateKey).toString('base64');
    assert.throws(() => sigs.parseFeed(gz, forged, PUB), /signature/);
    // The real built-in key never accepts a feed signed by someone else.
    assert.throws(() => sigs.parseFeed(gz, sig), /signature/);
  });

  it('installs a newer feed, refuses rollbacks and tampered downloads', async () => {
    const sigs = require('../src/signatures');
    serve = makeFeed(200);
    const first = await sigs.update({ url, publicKey: PUB });
    assert.strictEqual(first.updated, true);
    assert.ok(fs.existsSync(path.join(home, '.gitsafty', 'signatures', 'feed.json.gz')));

    serve = makeFeed(150); // older: rollback attempt
    const rollback = await sigs.update({ url, publicKey: PUB });
    assert.strictEqual(rollback.updated, false);
    assert.strictEqual(rollback.sequence, 200);

    const bad = makeFeed(300);
    serve = { gz: bad.gz, sig: crypto.sign(null, bad.gz, otherKeys.privateKey).toString('base64') };
    await assert.rejects(sigs.update({ url, publicKey: PUB }), /signature/);
    assert.strictEqual(sigs.status().sequence, 200, 'the bad download did not replace the installed feed');
  });
});

describe('Signature feed: detections', () => {
  before(() => feedRules.setFeed(makeFeed(1).feed));
  after(() => feedRules.setFeed(null));
  const hit = (file, text) => detectMalware(file, Buffer.from(text)).filter(f => f.id === 'malicious-package').map(f => f.line);

  it('flags malicious packages in package.json and every lock file format', () => {
    assert.deepStrictEqual(hit('app/package.json', JSON.stringify({ dependencies: { 'evil-pkg': '^1.0.0', react: '^18.0.0' } })), ['evil-pkg']);
    const lock = { lockfileVersion: 3, packages: { '': {}, 'node_modules/chalk': { version: '5.6.1' }, 'node_modules/a/node_modules/evil-pkg': { version: '0.0.1' } } };
    assert.deepStrictEqual(hit('package-lock.json', JSON.stringify(lock)).sort(), ['chalk', 'evil-pkg']);
    assert.deepStrictEqual(hit('yarn.lock', 'chalk@^5.0.0:\n  version "5.6.1"\n  resolved "x"\n\n"@scope/ok@^1":\n  version "1.0.0"\n'), ['chalk']);
    assert.deepStrictEqual(hit('pnpm-lock.yaml', 'packages:\n\n  chalk@5.6.1:\n    resolution: {}\n  react@18.2.0:\n    resolution: {}\n'), ['chalk']);
    assert.deepStrictEqual(hit('requirements.txt', 'requests==2.31.0\nBad_Lib>=1.0  # comment\n'), ['Bad_Lib']);
  });

  it('does not flag other versions of a hijacked package', () => {
    assert.deepStrictEqual(hit('package-lock.json', JSON.stringify({ packages: { 'node_modules/chalk': { version: '5.6.2' } } })), []);
    assert.deepStrictEqual(hit('package.json', JSON.stringify({ dependencies: { chalk: '^5.6.0' } })), [], 'a range is not a known-bad exact version');
    assert.deepStrictEqual(hit('package.json', JSON.stringify({ dependencies: { chalk: '5.6.1' } })), ['chalk'], 'exact pin of the bad version');
  });

  it('removes files whose hash is in the feed, and reports (never removes) marker matches', () => {
    const byHash = detectMalware('dist/x.bin', MALWARE_FILE);
    assert.ok(byHash.some(f => f.id === 'feed-hash' && f.verdict === 'CONFIRMED' && f.remedy.type === 'quarantine'));
    const byMarker = detectMalware('src/a.js', Buffer.from('x = STEAL_ALL_KEYS(process.env);'));
    const m = byMarker.find(f => f.id === 'feed-m1');
    assert.ok(m && m.verdict === 'SUSPECT' && m.remedy.type === 'manual');
    assert.ok(!detectMalware('README.md', Buffer.from('STEAL_ALL_KEYS(')).some(f => f.id === 'feed-m1'), 'marker limited to its files');
  });
});
