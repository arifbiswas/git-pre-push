/**
 * Builds the signed signature feed (run daily by .github/workflows/signatures.yml).
 *
 *   SIGNATURES_PRIVATE_KEY="<Ed25519 private key PEM>" node tools/build-signatures.js <out-dir>
 *
 * Sources:
 *   - OSV / OpenSSF malicious packages (MAL-* entries) for npm and PyPI
 *   - signatures/rules.json in this repo: hashes and text markers added by the maintainers
 *
 * Output: feed.json.gz, feed.json.gz.sig (base64 Ed25519 signature of the .gz bytes), latest.json
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { zipEntries, zipEntryData } = require('../src/archive');

const ECOSYSTEMS = { npm: 'npm', PyPI: 'PyPI' };
const pypiName = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');

async function fetchZip(eco) {
  const url = `https://osv-vulnerabilities.storage.googleapis.com/${eco}/all.zip`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

/** "*" when every version is malicious, the list of malicious versions, or null when unclear (skipped). */
function affectedVersions(a) {
  const allVersions = (a.ranges || []).some(r =>
    (r.events || []).some(e => e.introduced === '0') && !(r.events || []).some(e => e.fixed || e.last_affected));
  if (allVersions) return '*';
  return Array.isArray(a.versions) && a.versions.length ? a.versions.map(String) : null;
}

function merge(list, name, versions) {
  const cur = list[name];
  if (cur === '*' || versions === '*') { list[name] = '*'; return; }
  list[name] = [...new Set([...(cur || []), ...versions])].sort();
}

async function maliciousPackages(eco) {
  const zip = await fetchZip(eco);
  const list = {};
  let entries = 0;
  for (const e of zipEntries(zip)) {
    if (!/^MAL-[\w-]+\.json$/.test(e.name)) continue;
    let doc;
    try { doc = JSON.parse(zipEntryData(zip, e, 8 * 1024 * 1024).toString('utf8')); } catch (_) { continue; }
    if (doc.withdrawn) continue;
    for (const a of doc.affected || []) {
      if (!a.package || a.package.ecosystem !== eco || !a.package.name) continue;
      const name = eco === 'PyPI' ? pypiName(a.package.name) : a.package.name;
      const versions = affectedVersions(a);
      if (!versions) continue; // no version information: never guess
      merge(list, name, versions);
      entries++;
    }
  }
  return { list, entries };
}

function readRules() {
  const p = path.join(__dirname, '..', 'signatures', 'rules.json');
  if (!fs.existsSync(p)) return { hashes: {}, markers: [] };
  const r = JSON.parse(fs.readFileSync(p, 'utf8'));
  for (const m of r.markers || []) new RegExp(m.pattern, m.flags || ''); // fail the build on a bad pattern
  return { hashes: r.hashes || {}, markers: r.markers || [] };
}

async function main() {
  const out = path.resolve(process.argv[2] || 'signatures-out');
  const pem = process.env.SIGNATURES_PRIVATE_KEY;
  if (!pem) throw new Error('SIGNATURES_PRIVATE_KEY is not set');
  const key = crypto.createPrivateKey(pem);

  const packages = {};
  const sources = {};
  for (const eco of Object.keys(ECOSYSTEMS)) {
    const { list, entries } = await maliciousPackages(eco);
    packages[eco] = list;
    sources[`osv-${eco}`] = { packages: Object.keys(list).length, entries };
    console.log(`${eco}: ${Object.keys(list).length} malicious packages`);
  }
  const rules = readRules();
  const now = new Date();
  const feed = {
    schema: 1,
    sequence: Math.floor(now.getTime() / 1000),
    generatedAt: now.toISOString(),
    sources,
    packages,
    hashes: rules.hashes,
    markers: rules.markers
  };

  const gz = zlib.gzipSync(JSON.stringify(feed), { level: 9 });
  const sig = crypto.sign(null, gz, key).toString('base64');
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'feed.json.gz'), gz);
  fs.writeFileSync(path.join(out, 'feed.json.gz.sig'), sig + '\n');
  fs.writeFileSync(path.join(out, 'latest.json'), JSON.stringify({ sequence: feed.sequence, generatedAt: feed.generatedAt, sources }, null, 2) + '\n');
  console.log(`feed.json.gz ${Math.round(gz.length / 1024)} KB, sequence ${feed.sequence}`);
}

main().catch((err) => { console.error(err); process.exit(1); });
