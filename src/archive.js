/**
 * Reads the files inside archives WITHOUT extracting anything to disk and
 * without running anything from them.
 *
 *   zip family (zip, jar, war, apk, aab, aar, ipa, xpi, vsix, nupkg, whl, crx,
 *   docx/xlsx/pptx ...): parsed here (stored + deflate, zip64)
 *   tar, tar.gz / tgz, gz: parsed here
 *   7z, rar, bz2, xz, and zip entries with other compression: read through the
 *   system `7z` / `tar` (bsdtar) one entry at a time to stdout, if available
 *
 * Archives are detected by their first bytes, not only by the file name, so a
 * renamed archive is still opened. Nested archives are opened too (limited depth).
 * Limits keep zip bombs harmless: per-entry size, total size and entry count.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { spawnSync } = require('child_process');

const LIMITS = {
  maxEntryBytes: 64 * 1024 * 1024, // one file inside an archive
  maxTotalBytes: 1024 * 1024 * 1024, // all files of one top-level archive
  maxEntries: 100000,
  maxDepth: 4,
  maxArchiveBytes: 1024 * 1024 * 1024 // archive file read into memory
};

const ZIP_EXT = /\.(zip|jar|war|ear|apk|aab|aar|ipa|xpi|vsix|nupkg|whl|egg|crx|docx|xlsx|pptx|odt|ods|odp|epub|appx|msix|jmod|kmz)$/i;
const ARCHIVE_EXT = /\.(zip|jar|war|ear|apk|aab|aar|ipa|xpi|vsix|nupkg|whl|egg|crx|appx|msix|jmod|kmz|tar|tgz|tbz2?|txz|gz|bz2|xz|7z|rar|cab|iso|cpio)$/i;

/** Archive type from the first bytes (and the name as a hint). */
function detectArchiveType(head, name = '') {
  if (!head || head.length < 4) return null;
  if (head[0] === 0x50 && head[1] === 0x4b && (head[2] === 3 || head[2] === 5 || head[2] === 7)) return 'zip';
  if (head.toString('latin1', 0, 4) === 'Cr24') return 'crx';
  if (head[0] === 0x1f && head[1] === 0x8b) return 'gzip';
  if (head.length >= 262 && head.toString('latin1', 257, 262) === 'ustar') return 'tar';
  if (head.toString('latin1', 0, 6) === '7z\xbc\xaf\x27\x1c') return '7z';
  if (head.toString('latin1', 0, 4) === 'Rar!') return 'rar';
  if (head.toString('latin1', 0, 3) === 'BZh') return 'bzip2';
  if (head.length >= 6 && head[0] === 0xfd && head.toString('latin1', 1, 6) === '7zXZ\0') return 'xz';
  if (head.toString('latin1', 0, 4) === 'MSCF') return 'cab';
  // Old tar without "ustar" magic: only trust the name.
  if (/\.tar$/i.test(name)) return 'tar';
  return null;
}

function isArchiveName(name) {
  return ARCHIVE_EXT.test(name);
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

function findEocd(buf) {
  const min = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) return i;
  }
  return -1;
}

/**
 * Lists zip entries.
 * @returns {Array<{name, method, compSize, size, offset, encrypted, dir}>}
 */
function zipEntries(buf) {
  const eocd = findEocd(buf);
  if (eocd < 0) throw new Error('not a valid zip (no end of central directory)');
  let count = buf.readUInt16LE(eocd + 10);
  let cdSize = buf.readUInt32LE(eocd + 12);
  let cdOffset = buf.readUInt32LE(eocd + 16);

  // zip64
  if (eocd >= 20 && buf.readUInt32LE(eocd - 20) === 0x07064b50) {
    const z64 = Number(buf.readBigUInt64LE(eocd - 20 + 8));
    if (z64 + 56 <= buf.length && buf.readUInt32LE(z64) === 0x06064b50) {
      count = Number(buf.readBigUInt64LE(z64 + 32));
      cdSize = Number(buf.readBigUInt64LE(z64 + 40));
      cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
    }
  }
  // Self-extracting / prefixed zips (e.g. crx): the central directory sits right before the EOCD.
  const shift = eocd - cdSize - cdOffset > 0 ? eocd - cdSize - cdOffset : 0;

  const entries = [];
  let p = cdOffset + shift;
  for (let i = 0; i < count && p + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    let compSize = buf.readUInt32LE(p + 20);
    let size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let offset = buf.readUInt32LE(p + 42);
    const name = buf.toString(flags & 0x800 ? 'utf8' : 'latin1', p + 46, p + 46 + nameLen);

    // zip64 extra field
    let e = p + 46 + nameLen;
    const extraEnd = e + extraLen;
    while (e + 4 <= extraEnd) {
      const id = buf.readUInt16LE(e);
      const len = buf.readUInt16LE(e + 2);
      if (id === 0x0001) {
        let q = e + 4;
        if (size === 0xffffffff) { size = Number(buf.readBigUInt64LE(q)); q += 8; }
        if (compSize === 0xffffffff) { compSize = Number(buf.readBigUInt64LE(q)); q += 8; }
        if (offset === 0xffffffff) { offset = Number(buf.readBigUInt64LE(q)); }
      }
      e += 4 + len;
    }

    entries.push({ name, method, compSize, size, offset: offset + shift, encrypted: !!(flags & 1), dir: name.endsWith('/') });
    p = extraEnd + commentLen;
  }
  return entries;
}

function zipEntryData(buf, entry, maxBytes) {
  const lh = entry.offset;
  if (lh + 30 > buf.length || buf.readUInt32LE(lh) !== 0x04034b50) throw new Error('broken local header');
  const start = lh + 30 + buf.readUInt16LE(lh + 26) + buf.readUInt16LE(lh + 28);
  const data = buf.subarray(start, start + entry.compSize);
  if (entry.method === 0) return data.subarray(0, maxBytes);
  if (entry.method === 8) return zlib.inflateRawSync(data, { maxOutputLength: maxBytes });
  const err = new Error(`compression method ${entry.method}`);
  err.code = 'UNSUPPORTED_METHOD';
  throw err;
}

// ---------------------------------------------------------------------------
// TAR
// ---------------------------------------------------------------------------

function tarNumber(buf, off, len) {
  if (buf[off] & 0x80) { // base-256
    let n = 0;
    for (let i = off + 1; i < off + len; i++) n = n * 256 + buf[i];
    return n;
  }
  const s = buf.toString('latin1', off, off + len).replace(/\0.*$/, '').trim();
  return s ? parseInt(s, 8) || 0 : 0;
}

function* tarEntries(buf) {
  let p = 0;
  let longName = null;
  let paxPath = null;
  while (p + 512 <= buf.length) {
    const h = buf.subarray(p, p + 512);
    if (h.every(b => b === 0)) break;
    let name = h.toString('utf8', 0, 100).replace(/\0.*$/s, '');
    const prefix = h.toString('latin1', 257, 262) === 'ustar' ? h.toString('utf8', 345, 500).replace(/\0.*$/s, '') : '';
    if (prefix) name = `${prefix}/${name}`;
    const size = tarNumber(h, 124, 12);
    const type = String.fromCharCode(h[156] || 48);
    const dataStart = p + 512;
    const data = buf.subarray(dataStart, Math.min(buf.length, dataStart + size));
    p = dataStart + Math.ceil(size / 512) * 512;

    if (type === 'L') { longName = data.toString('utf8').replace(/\0.*$/s, ''); continue; }
    if (type === 'x') {
      const m = data.toString('utf8').match(/\d+ path=([^\n]*)\n/);
      if (m) paxPath = m[1];
      continue;
    }
    if (type === 'g') continue;
    const finalName = paxPath || longName || name;
    longName = null;
    paxPath = null;
    if (type === '0' || type === '\0' || type === '7') yield { name: finalName, size, data };
  }
}

// ---------------------------------------------------------------------------
// External tools (7z, bsdtar) for formats Node can't read
// ---------------------------------------------------------------------------

let toolCache;
function externalTool() {
  if (toolCache !== undefined) return toolCache;
  const candidates = process.platform === 'win32'
    ? [['7z'], [path.join(process.env.ProgramFiles || 'C:\\Program Files', '7-Zip', '7z.exe')], ['tar']]
    : [['7zz'], ['7z'], ['bsdtar'], ['tar']];
  for (const [bin] of candidates) {
    const isTar = /tar(\.exe)?$/i.test(bin);
    const r = spawnSync(bin, isTar ? ['--version'] : ['i'], { encoding: 'utf8', timeout: 10000 });
    if (r.error) continue;
    if (isTar && !/bsdtar|libarchive/i.test(r.stdout || '')) continue; // GNU tar can't read zip/7z/rar
    toolCache = { bin, kind: isTar ? 'bsdtar' : '7z' };
    return toolCache;
  }
  toolCache = null;
  return null;
}

/** Writes an in-memory nested archive to a private temp file (only to read it, never executed). */
function withTempFile(buf, name, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-arc-'));
  const file = path.join(dir, `archive${path.extname(name) || ''}`);
  try {
    fs.writeFileSync(file, buf, { mode: 0o600 });
    return fn(file);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
  }
}

function externalList(tool, file) {
  if (tool.kind === '7z') {
    const r = spawnSync(tool.bin, ['l', '-slt', '-ba', '-p', '--', file], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: 120000 });
    if (r.status !== 0) return null;
    const out = [];
    for (const block of r.stdout.split(/\r?\n\r?\n/)) {
      const get = (k) => { const m = block.match(new RegExp(`^${k} = (.*)$`, 'm')); return m ? m[1].trim() : ''; };
      const name = get('Path');
      if (!name || get('Folder') === '+' || /D/.test(get('Attributes').split(' ')[0] || '')) continue;
      out.push({ name, size: Number(get('Size')) || 0, encrypted: get('Encrypted') === '+' });
    }
    return out;
  }
  const r = spawnSync(tool.bin, ['-tf', file], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: 120000 });
  if (r.status !== 0) return null;
  return r.stdout.split(/\r?\n/).filter(n => n && !n.endsWith('/')).map(name => ({ name, size: 0, encrypted: false }));
}

function externalRead(tool, file, name, maxBytes) {
  const args = tool.kind === '7z' ? ['e', '-so', '-p', '--', file, name] : ['-xOf', file, '--', name];
  const r = spawnSync(tool.bin, args, { maxBuffer: maxBytes, timeout: 120000 });
  if (r.error && r.error.code === 'ENOBUFS') return { tooLarge: true };
  if (r.status !== 0 || r.error) return { error: (r.stderr || '').toString().trim().split('\n')[0] || 'could not read' };
  return { data: r.stdout };
}

// ---------------------------------------------------------------------------
// Walker
// ---------------------------------------------------------------------------

/**
 * Calls onFile(innerPath, buffer, info) for every file inside an archive,
 * opening nested archives too.
 *
 * @param {Buffer} buf archive bytes
 * @param {string} name archive name (for type hints)
 * @param {(inner: string, data: Buffer) => void} onFile
 * @param {{ skipEntry?: (inner: string) => boolean }} [opts]
 * @returns {{ type, entries, scanned, problems: Array<{entry, reason}> }}
 */
function walkArchive(buf, name, onFile, opts = {}) {
  const stats = { type: null, entries: 0, scanned: 0, bytes: 0, problems: [], encrypted: [] };
  const skip = opts.skipEntry || (() => false);

  const visit = (data, label, prefix, depth) => {
    const type = detectArchiveType(data.subarray(0, 512), label);
    if (depth === 0) stats.type = type;
    if (!type) return false;
    if (depth >= LIMITS.maxDepth) {
      stats.problems.push({ entry: prefix || label, reason: 'archive nested too deep, not opened' });
      return true;
    }

    const emit = (inner, content) => {
      stats.entries++;
      const full = prefix ? `${prefix}!/${inner}` : inner;
      if (stats.entries > LIMITS.maxEntries) return;
      if (skip(inner)) return;
      if (content == null) return;
      stats.bytes += content.length;
      if (stats.bytes > LIMITS.maxTotalBytes) {
        if (!stats.totalLimitHit) stats.problems.push({ entry: label, reason: 'more than 1 GB unpacked, rest skipped' });
        stats.totalLimitHit = true;
        return;
      }
      if (detectArchiveType(content.subarray(0, 512), inner) && visit(content, inner, full, depth + 1)) {
        // Also give the nested archive itself to the caller (hashes, names).
      }
      stats.scanned++;
      onFile(full, content, { depth });
    };

    try {
      if (type === 'zip' || type === 'crx') {
        let tool = null;
        for (const e of zipEntries(data)) {
          if (e.dir) continue;
          if (e.encrypted) { stats.encrypted.push(prefix ? `${prefix}!/${e.name}` : e.name); stats.entries++; continue; }
          if (e.size > LIMITS.maxEntryBytes) { stats.problems.push({ entry: e.name, reason: 'file larger than 64 MB inside archive, skipped' }); continue; }
          try {
            emit(e.name, zipEntryData(data, e, LIMITS.maxEntryBytes));
          } catch (err) {
            if (err.code === 'UNSUPPORTED_METHOD' && (tool = tool || externalTool())) {
              const r = withTempFile(data, label, f => externalRead(tool, f, e.name, LIMITS.maxEntryBytes));
              if (r.data) emit(e.name, r.data);
              else stats.problems.push({ entry: e.name, reason: r.tooLarge ? 'too large' : r.error });
            } else {
              stats.problems.push({ entry: e.name, reason: err.code === 'ERR_BUFFER_TOO_LARGE' || /larger than|maxOutputLength/i.test(err.message) ? 'unpacks to more than 64 MB, skipped' : err.message });
            }
          }
        }
      } else if (type === 'tar') {
        for (const e of tarEntries(data)) {
          if (e.size > LIMITS.maxEntryBytes) { stats.problems.push({ entry: e.name, reason: 'file larger than 64 MB inside archive, skipped' }); continue; }
          emit(e.name, e.data);
        }
      } else if (type === 'gzip') {
        const out = zlib.gunzipSync(data, { maxOutputLength: LIMITS.maxEntryBytes * 4 });
        const inner = label.replace(/\.(tgz)$/i, '.tar').replace(/\.gz$/i, '') || 'content';
        if (detectArchiveType(out.subarray(0, 512), inner) === 'tar') visit(out, inner, prefix || '', depth + (prefix ? 1 : 0));
        else emit(path.basename(inner), out);
      } else {
        const tool = externalTool();
        if (!tool) {
          stats.problems.push({ entry: prefix || label, reason: `${type} archive: install 7-Zip (Windows) or p7zip to open it` });
          return true;
        }
        withTempFile(data, label, (f) => {
          const list = externalList(tool, f);
          if (!list) { stats.problems.push({ entry: prefix || label, reason: `${type} archive could not be opened (damaged or password protected)` }); return; }
          for (const e of list) {
            if (e.encrypted) { stats.encrypted.push(prefix ? `${prefix}!/${e.name}` : e.name); stats.entries++; continue; }
            if (e.size > LIMITS.maxEntryBytes) { stats.problems.push({ entry: e.name, reason: 'file larger than 64 MB inside archive, skipped' }); continue; }
            const r = externalRead(tool, f, e.name, LIMITS.maxEntryBytes);
            if (r.data) emit(e.name, r.data);
            else stats.problems.push({ entry: e.name, reason: r.tooLarge ? 'unpacks to more than 64 MB, skipped' : (r.error || 'could not read') });
          }
        });
      }
    } catch (err) {
      const tooBig = err.code === 'ERR_BUFFER_TOO_LARGE' || /larger than|maxOutputLength/i.test(err.message);
      stats.problems.push({ entry: prefix || label, reason: tooBig ? 'unpacks to more than 256 MB, skipped' : `could not open: ${err.message}` });
    }
    return true;
  };

  visit(buf, name, '', 0);
  return stats;
}

module.exports = {
  LIMITS,
  ZIP_EXT,
  detectArchiveType,
  isArchiveName,
  walkArchive,
  zipEntries,
  externalTool
};
