// The two zlib calls the archive reader needs, on top of pako.
const pako = require('pako');
const { Buffer } = require('buffer');

function limit(out, opts) {
  if (opts && opts.maxOutputLength && out.length > opts.maxOutputLength) {
    const err = new Error('Cannot create a Buffer larger than maxOutputLength');
    err.code = 'ERR_BUFFER_TOO_LARGE';
    throw err;
  }
  return Buffer.from(out.buffer, out.byteOffset, out.length);
}

module.exports = {
  inflateRawSync: (buf, opts) => limit(pako.inflateRaw(buf), opts),
  gunzipSync: (buf, opts) => limit(pako.ungzip(buf), opts)
};
