/**
 * Detections that come from the signed signature feed (updated daily, see
 * src/signatures.js), so GitSafty learns new malware without a new release:
 *
 *   - packages: known malicious npm / PyPI packages (OpenSSF / OSV) found in
 *     package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock,
 *     pnpm-lock.yaml and requirements*.txt (transitive dependencies too)
 *   - hashes:   SHA-256 of known malware files
 *   - markers:  extra text patterns published by the GitSafty maintainers
 *
 * Pure: the feed is handed in with setFeed() (Node: src/signatures.js,
 * Android app: mobile-api.js), so this also runs in the browser.
 */

let feed = null;
let loader = null;
let loaded = false;
let compiledMarkers = [];

function setFeed(f) {
  feed = f && typeof f === 'object' ? f : null;
  loaded = true;
  compiledMarkers = [];
  for (const m of (feed && Array.isArray(feed.markers) ? feed.markers : [])) {
    try {
      compiledMarkers.push({ ...m, re: new RegExp(m.pattern, (m.flags || '').replace(/[^imsu]/g, '')), files: m.files ? new RegExp(m.files, 'i') : null });
    } catch (_) { /* a bad pattern is skipped, never fatal */ }
  }
}

/** Lazy loader (Node: reads the cached, verified feed on first use). */
function setLoader(fn) {
  loader = fn;
  loaded = false;
}

function getFeed() {
  if (!loaded) {
    loaded = true;
    if (loader) {
      try { setFeed(loader()); } catch (_) { setFeed(null); }
    }
  }
  return feed;
}

// ---------------------------------------------------------------------------
// Dependency files -> [{ name, version|null, spec|null }]
// ---------------------------------------------------------------------------

function fromPackageJson(text) {
  let pkg;
  try { pkg = JSON.parse(text.replace(/^﻿/, '')); } catch (_) { return []; }
  const out = [];
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, spec] of Object.entries((pkg && pkg[field]) || {})) out.push({ name, version: null, spec: String(spec) });
  }
  return out;
}

function fromPackageLock(text) {
  let lock;
  try { lock = JSON.parse(text); } catch (_) { return []; }
  const out = [];
  for (const [key, v] of Object.entries(lock.packages || {})) {
    const m = key.match(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/);
    if (m && v && v.version) out.push({ name: v.name || m[1], version: v.version });
  }
  const walk = (deps) => {
    for (const [name, v] of Object.entries(deps || {})) {
      if (v && v.version) out.push({ name, version: v.version });
      if (v && v.dependencies) walk(v.dependencies);
    }
  };
  walk(lock.dependencies);
  return out;
}

function fromYarnLock(text) {
  const out = [];
  let names = [];
  for (const line of text.split(/\r?\n/)) {
    if (line && !/^\s/.test(line) && line.trim().endsWith(':') && !line.startsWith('#')) {
      names = line.slice(0, -1).split(/,\s*/).map(s => s.trim().replace(/^"|"$/g, ''))
        .map(s => s.replace(/@npm:/, '@'))
        .map(s => { const at = s.lastIndexOf('@'); return at > 0 ? s.slice(0, at) : s; });
      continue;
    }
    const v = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
    if (v && names.length) {
      for (const name of new Set(names)) out.push({ name, version: v[1] });
      names = [];
    }
  }
  return out;
}

function fromPnpmLock(text) {
  const out = [];
  const re = /^ {2,4}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s'"(]+)[@/](\d[^:('"\s]*)/gm;
  let m;
  while ((m = re.exec(text))) out.push({ name: m[1], version: m[2] });
  return out;
}

function fromRequirements(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==\s*([^\s;,]+))?/);
    if (m && !line.startsWith('-')) out.push({ name: m[1], version: m[3] || null, spec: m[2] ? null : '*' });
  }
  return out;
}

const pypiName = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');

function dependencyFile(filePath) {
  const base = filePath.split('/').pop().toLowerCase();
  if (base === 'package.json') return { eco: 'npm', parse: fromPackageJson };
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return { eco: 'npm', parse: fromPackageLock };
  if (base === 'yarn.lock') return { eco: 'npm', parse: fromYarnLock };
  if (base === 'pnpm-lock.yaml') return { eco: 'npm', parse: fromPnpmLock };
  if (/^requirements.*\.txt$/.test(base)) return { eco: 'PyPI', parse: fromRequirements };
  return null;
}

/** Is this dependency on the malicious list? entry is "*" (all versions) or a list of versions. */
function isMalicious(entry, dep) {
  if (!entry) return false;
  if (entry === '*') return true;
  if (!Array.isArray(entry)) return false;
  const exact = dep.version || (dep.spec && /^[=v]?\d[\w.+-]*$/.test(dep.spec) ? dep.spec.replace(/^[=v]/, '') : null);
  return !!exact && entry.includes(exact);
}

// ---------------------------------------------------------------------------

/**
 * @param {string} filePath normalized path
 * @param {Buffer} buffer
 * @param {string|null} text latin1 text, or null for binary files
 * @param {string} hash sha256 hex of buffer
 */
function detectFromFeed(filePath, buffer, text, hash) {
  const f = getFeed();
  if (!f) return [];
  const findings = [];
  const src = f.generatedAt ? ` (signature feed ${String(f.generatedAt).slice(0, 10)})` : '';

  const label = f.hashes && f.hashes[hash];
  if (label) {
    findings.push({
      filePath, verdict: 'CONFIRMED', severity: 'CRITICAL', id: 'feed-hash',
      name: 'Known malware file (signature feed)', description: `${label}${src}`,
      line: `sha256:${hash}`, remedy: { type: 'quarantine' }
    });
  }
  if (text == null) return findings;

  const dep = f.packages ? dependencyFile(filePath) : null;
  const list = dep && f.packages[dep.eco];
  if (list) {
    const seen = new Set();
    let utf8;
    try { utf8 = buffer.toString('utf8'); } catch (_) { utf8 = text; }
    for (const d of dep.parse(utf8)) {
      const key = dep.eco === 'PyPI' ? pypiName(d.name) : d.name;
      if (!isMalicious(list[key], d)) continue;
      const id = `${key}@${d.version || d.spec || ''}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        filePath, verdict: 'CONFIRMED', severity: 'CRITICAL', id: 'malicious-package',
        name: `Known malicious ${dep.eco} package: ${d.name}${d.version ? '@' + d.version : ''}`,
        description: `Listed as malware by OpenSSF / OSV${src}. Remove it (${dep.eco === 'npm' ? `npm uninstall ${d.name}` : `pip uninstall ${d.name}`}), delete node_modules / the virtualenv, and change every key on this computer.`,
        line: d.name,
        remedy: { type: 'manual' }
      });
    }
  }

  for (const m of compiledMarkers) {
    if (m.files && !m.files.test(filePath)) continue;
    const hit = m.re.exec(text);
    if (!hit) continue;
    findings.push({
      filePath, verdict: m.verdict === 'CONFIRMED' ? 'CONFIRMED' : 'SUSPECT', severity: m.severity || 'CRITICAL',
      id: `feed-${m.id || 'marker'}`, name: m.name || 'Malware pattern (signature feed)',
      description: `${m.description || 'Matches a pattern from the GitSafty signature feed.'}${src}`,
      line: String(hit[0]).slice(0, 120), remedy: { type: 'manual' }
    });
  }
  return findings;
}

module.exports = { setFeed, setLoader, getFeed, detectFromFeed, fromYarnLock, fromPnpmLock, fromPackageLock, fromRequirements };
