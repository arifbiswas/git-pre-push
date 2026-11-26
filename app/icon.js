/**
 * Draws the GitSafty app icon (blue rounded square, white shield with a check)
 * as a PNG of any size, without image tools. Used for desktop and Android.
 */
const zlib = require('zlib');

const SS = 4; // supersampling per axis
const BLUE = [31, 111, 235];

function inRoundRect(x, y) {
  const r = 0.22, m = 0.04;
  if (x < m || x > 1 - m || y < m || y > 1 - m) return false;
  const cx = Math.min(Math.max(x, m + r), 1 - m - r);
  const cy = Math.min(Math.max(y, m + r), 1 - m - r);
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}
function inShield(x, y) {
  const top = 0.2, mid = 0.5, bottom = 0.84, half = 0.27;
  if (y < top || y > bottom) return false;
  const hw = y <= mid ? half : half * Math.sqrt(Math.max(0, 1 - ((y - mid) / (bottom - mid)) ** 2));
  return Math.abs(x - 0.5) <= hw;
}
function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}
function inCheck(x, y) {
  const w = 0.042;
  return distToSegment(x, y, 0.37, 0.5, 0.46, 0.6) < w || distToSegment(x, y, 0.46, 0.6, 0.64, 0.39) < w;
}


const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (buf) => { let c = 0xffffffff; for (const x of buf) c = crcTable[(c ^ x) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

/** @param {number} N size in pixels @returns {Buffer} PNG */
function pngIcon(N) {
  const raw = Buffer.alloc(N * (N * 4 + 1));
  for (let py = 0; py < N; py++) {
    raw[py * (N * 4 + 1)] = 0;
    for (let px = 0; px < N; px++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const x = (px + (sx + 0.5) / SS) / N;
          const y = (py + (sy + 0.5) / SS) / N;
          if (!inRoundRect(x, y)) continue;
          const c = inShield(x, y) && !inCheck(x, y) ? [255, 255, 255] : BLUE;
          r += c[0]; g += c[1]; b += c[2]; a += 255;
        }
      }
      const n = SS * SS;
      const o = py * (N * 4 + 1) + 1 + px * 4;
      const cov = a / n;
      // colour is averaged over covered samples only (no dark fringe)
      const k = a ? 255 / a : 0;
      raw[o] = Math.round(r * k); raw[o + 1] = Math.round(g * k); raw[o + 2] = Math.round(b * k); raw[o + 3] = Math.round(cov);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(N, 0); ihdr.writeUInt32BE(N, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))
  ]);
}

module.exports = { pngIcon };
