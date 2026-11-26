/**
 * Full Scan: scans EVERYTHING in a folder, not only git repositories.
 *
 *   gitsafty full-scan <folder> [--clean] [--json]
 *
 *   - every file in every sub-folder, git repository or not
 *   - inside archives (zip, jar, apk, ipa, vsix, tar, tar.gz, gz, 7z, rar, ...),
 *     also archives inside archives, read in memory (nothing is extracted)
 *   - git persistence tricks in every repository it passes (.git/hooks, config)
 *   - IDE auto-run tasks and disguised / executable file names
 *
 * Dependency folders (node_modules, composer vendor, Pods, virtualenvs, package
 * caches ...) are skipped: they are downloaded packages, not your code.
 *
 * Confirmed malware is removed only with --clean:
 *   loose file      -> repaired or removed (backup kept)
 *   inside archive  -> the whole archive is moved to quarantine (backup kept),
 *                      because an archive can't be safely rewritten
 * Backups go to ~/.gitsafty/quarantine/<time>/ (read-only), with report.json.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { sha256, CONFIRMED } = require('./rules/malware');
const { inspectContent } = require('./inspect');
const { gitPersistenceFindings } = require('./advancedScanner');
const { removeConfirmedMalware, notifyDesktop } = require('./malwareCleaner');
const { walkArchive, detectArchiveType } = require('./archive');
const { colors } = require('./reporter');

// Downloaded packages and caches: never scanned by Full Scan.
const DEPENDENCY_DIRS = new Set([
  'node_modules', 'bower_components', 'jspm_packages', '.pnpm-store', '.yarn', '.npm', '.bun',
  'vendor', // composer (PHP), bundler, go
  'Pods', 'Carthage', '.gradle', '.m2', '.ivy2', '.dart_tool', '.pub-cache', '.pub',
  '.venv', 'venv', 'site-packages', '__pycache__', '.tox', '.mypy_cache', '.pytest_cache',
  '.nuget', '.cargo', '.rustup', '.cache', 'DerivedData', '.expo', '.next', '.nuxt',
  '.turbo', '.parcel-cache', '.svelte-kit', '.angular', '.git',
  // GitSafty's own quarantine (backups of removed malware) and the trash
  '.gitsafty', 'gitsafty-quarantine', '.Trash', '$RECYCLE.BIN'
]);
// Package manager files: lock files and manifests of dependencies, not code that runs.
const PACKAGE_FILES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'npm-shrinkwrap.json',
  'composer.lock', 'Gemfile.lock', 'Podfile.lock', 'Cargo.lock', 'poetry.lock', 'Pipfile.lock',
  'pubspec.lock', 'go.sum', 'packages.lock.json', 'gradle.lockfile', 'mix.lock', 'flake.lock'
]);

const MAX_FILE = 32 * 1024 * 1024;
const MAX_ARCHIVE = 1024 * 1024 * 1024;

function home() {
  return process.env.HOME || process.env.USERPROFILE || os.homedir();
}

function isWin() {
  return process.platform === 'win32';
}

function skipEntry(inner) {
  const norm = inner.replace(/\\/g, '/');
  return PACKAGE_FILES.has(norm.split('/').pop()) || norm.split('/').slice(0, -1).some(s => DEPENDENCY_DIRS.has(s));
}

function readHead(full, n = 512) {
  let fd;
  try {
    fd = fs.openSync(full, 'r');
    const b = Buffer.alloc(n);
    const len = fs.readSync(fd, b, 0, n, 0);
    return b.subarray(0, len);
  } catch (_) {
    return null;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) {}
  }
}

/**
 * Scans a folder. Pure: nothing is changed.
 * @returns {object} result
 */
function fullScan(root, { onProgress } = {}) {
  const abs = path.resolve(root);
  const result = {
    root: abs,
    files: 0,
    archives: [],
    repos: [],
    skippedDirs: 0,
    tooLarge: [],
    unreadable: 0,
    findings: []
  };

  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { result.unreadable++; return; }
    if (entries.some(e => e.name === '.git')) {
      result.repos.push(dir);
      const rel = path.relative(abs, dir).replace(/\\/g, '/');
      for (const f of gitPersistenceFindings(dir)) {
        result.findings.push({ ...f, filePath: rel ? `${rel}/${f.filePath}` : f.filePath, repo: dir });
      }
    }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (DEPENDENCY_DIRS.has(e.name)) {
          if (e.name !== '.git' && e.name !== '.gitsafty' && e.name !== 'gitsafty-quarantine') result.skippedDirs++;
          continue;
        }
        walk(full);
      } else if (e.isFile()) {
        if (PACKAGE_FILES.has(e.name)) continue;
        scanFile(full);
      }
    }
  };

  const scanFile = (full) => {
    const rel = path.relative(result.root, full).replace(/\\/g, '/');
    let st;
    try { st = fs.statSync(full); } catch (_) { result.unreadable++; return; }
    if (!st.size) return;
    result.files++;
    if (onProgress && result.files % 200 === 0) onProgress(result);

    const head = readHead(full);
    if (!head) { result.unreadable++; return; }
    const type = detectArchiveType(head, full);
    const limit = type ? MAX_ARCHIVE : MAX_FILE;
    if (st.size > limit) { result.tooLarge.push(rel); return; }

    let buf;
    try { buf = fs.readFileSync(full); } catch (_) { result.unreadable++; return; }
    result.findings.push(...inspectContent(rel, rel, buf));

    if (!type) return;
    if (/\.(docx|xlsx|pptx|odt|ods|odp|epub)$/i.test(full) && st.size > 64 * 1024 * 1024) return;
    const before = result.findings.length;
    const stats = walkArchive(buf, path.basename(full), (inner, data) => {
      const innerName = inner.split('!/').pop();
      result.findings.push(...inspectContent(`${rel}!/${inner}`, innerName, data).map(f => ({ ...f, archive: rel })));
    }, { skipEntry });
    const own = result.findings.slice(before);
    result.archives.push({
      path: rel,
      type: stats.type,
      entries: stats.entries,
      scanned: stats.scanned,
      encrypted: stats.encrypted,
      problems: stats.problems,
      sha256: sha256(buf),
      malware: own.filter(f => f.verdict === CONFIRMED).length
    });
    // Password-protected archives with programs inside: a common way to sneak malware past scanners.
    const risky = stats.encrypted.filter(n => /\.(exe|scr|com|bat|cmd|ps1|vbs|js|jse|hta|msi|dll|lnk|jar|apk|sh|py)$/i.test(n));
    if (risky.length) {
      result.findings.push({
        category: 'archive', verdict: 'SUSPECT', severity: 'CRITICAL', archive: rel, filePath: rel,
        name: 'Password-protected archive with programs inside',
        description: `Could not be scanned (encrypted): ${risky.slice(0, 3).join(', ')}${risky.length > 3 ? ' …' : ''}. Malware is often sent like this. Do not open it unless you trust the sender.`
      });
    }
  };

  const st = fs.statSync(abs);
  if (st.isFile()) {
    // A single file: paths are shown (and removed) relative to its folder.
    result.root = path.dirname(abs);
    scanFile(abs);
  } else {
    walk(abs);
  }
  return result;
}

/** Copies a file to the quarantine folder (read-only) and deletes it. */
function quarantineWhole(full, rel, quarantineDir) {
  const target = path.join(quarantineDir, 'files', `${rel.replace(/\.\./g, '_')}.quarantined`);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(full, target);
  try { fs.chmodSync(target, 0o400); } catch (_) {}
  fs.unlinkSync(full);
  return target;
}

/**
 * Removes confirmed malware found by fullScan().
 * @returns {{ quarantineDir: string|null, results: Array<{file, action, ok, error?}> }}
 */
function removeFullScanMalware(result) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const quarantineDir = path.join(home(), '.gitsafty', 'quarantine', `full-scan-${stamp}`);
  const confirmed = result.findings.filter(f => f.verdict === CONFIRMED && f.category === 'malware');
  const results = [];

  // 1. Archives with malware inside: quarantine the whole archive.
  const archives = [...new Set(confirmed.filter(f => f.archive).map(f => f.archive))];
  for (const rel of archives) {
    const full = path.join(result.root, rel);
    try {
      const backup = quarantineWhole(full, rel, quarantineDir);
      results.push({ file: rel, action: 'archive-quarantined', ok: true, backup });
    } catch (err) {
      results.push({ file: rel, action: 'failed', ok: false, error: err.message });
    }
  }

  // 2. Loose files: same repair engine as clone/pull (strip, remove task/script, or remove file).
  const loose = [...new Set(confirmed.filter(f => !f.archive && !archives.includes(f.filePath)).map(f => f.filePath))];
  if (loose.length) {
    const r = removeConfirmedMalware(loose, result.root, { reason: 'full-scan', quarantineDir });
    results.push(...r.results);
  }

  if (results.length) {
    fs.mkdirSync(quarantineDir, { recursive: true });
    const reportPath = path.join(quarantineDir, 'full-scan-report.json');
    fs.writeFileSync(reportPath, JSON.stringify({ createdAt: new Date().toISOString(), root: result.root, results }, null, 2), { mode: 0o600 });
  }
  return { quarantineDir: results.length ? quarantineDir : null, results };
}

function annotate(result, clean) {
  const byFile = new Map();
  for (const r of (clean && clean.results) || []) byFile.set(r.file, r);
  for (const f of result.findings) {
    const res = f.verdict === CONFIRMED && f.category === 'malware' ? (byFile.get(f.archive) || byFile.get(f.filePath)) : null;
    if (res && res.ok && res.action === 'archive-quarantined') f.action = { removed: true, text: 'Removed: the whole archive was moved to quarantine (backup kept)' };
    else if (res && res.ok && res.action === 'quarantined') f.action = { removed: true, text: 'Removed: whole file was malware (backup kept)' };
    else if (res && res.ok && res.action === 'repaired') f.action = { removed: true, text: 'Removed: malware cut out, rest of the file kept' };
    else if (res && !res.ok) f.action = { removed: false, text: res.action === 'manual' ? 'Needs manual removal' : `Could not remove: ${res.error || 'unknown error'}` };
    else if (f.verdict === CONFIRMED) f.action = { removed: false, text: 'Not removed (report only; run with --clean)' };
    else if (f.fixCommand) f.action = { removed: false, text: `Not yours? Remove it: ${f.fixCommand}` };
    else f.action = { removed: false, text: 'Review it yourself (never removed automatically)' };
  }
}

function writeReport(result) {
  const dir = path.join(home(), '.gitsafty', 'reports');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `full-scan-${path.basename(result.root)}-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  fs.writeFileSync(file, JSON.stringify({ createdAt: new Date().toISOString(), ...result }, null, 2), { mode: 0o600 });
  return file;
}

function printFindings(result) {
  const groups = new Map();
  for (const f of result.findings) {
    const key = f.archive || f.filePath.split('/')[0];
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  for (const [key, list] of groups) {
    const malware = list.some(f => f.verdict === CONFIRMED);
    const allRemoved = list.every(f => f.action.removed);
    const color = malware && !allRemoved ? colors.red : allRemoved ? colors.green : colors.yellow;
    const isArchive = list.some(f => f.archive === key);
    console.log(`\n${color}${colors.bold}${isArchive ? '🗜️ ' : '📁'} ${key}${colors.reset}`);
    for (const f of list.slice(0, 30)) {
      const tag = f.verdict === CONFIRMED ? `${colors.red}${colors.bold}MALWARE${colors.reset}`
        : f.severity === 'CRITICAL' ? `${colors.red}${colors.bold}DANGER${colors.reset}` : `${colors.yellow}${(f.category || 'review').toUpperCase()}${colors.reset}`;
      console.log(`     ${tag}  ${f.name}`);
      console.log(`            ${colors.dim}${f.filePath}${f.lineNumber ? ':' + f.lineNumber : ''}${colors.reset}`);
      if (f.description && f.category === 'archive') console.log(`            ${colors.dim}${f.description}${colors.reset}`);
      const c = f.action.removed ? colors.green : (f.verdict === CONFIRMED ? colors.red : colors.dim);
      console.log(`            ${c}→ ${f.action.text}${colors.reset}`);
    }
    if (list.length > 30) console.log(`     ${colors.dim}… ${list.length - 30} more in the JSON report${colors.reset}`);
  }
}

/**
 * Runs Full Scan and prints the result.
 * @returns {number} exit code (1 when malware or critical findings remain)
 */
function runFullScan(target, { clean = false, json = false } = {}) {
  const abs = path.resolve(target || process.cwd());
  if (!fs.existsSync(abs)) {
    console.error(`${colors.red}✖ Not found: ${abs}${colors.reset}`);
    return 1;
  }
  const started = Date.now();
  const tty = !json && process.stdout.isTTY;
  if (!json) {
    console.log(`\n${colors.cyan}${colors.bold}🧪 Full Scan${colors.reset} ${colors.dim}${abs}${colors.reset}`);
    console.log(`${colors.dim}Every file and every archive (zip, jar, apk, tar, gz, 7z, rar …), git repository or not · skipping node_modules, vendor & package caches · ${clean ? 'auto-remove confirmed malware' : 'report only'}${colors.reset}\n`);
  }

  const result = fullScan(abs, {
    onProgress: tty ? (r) => process.stdout.write(`\r${colors.dim}  scanned ${r.files} files, ${r.archives.length} archives…${colors.reset}`) : null
  });
  if (tty) process.stdout.write('\r\x1b[K');

  const clean_ = clean && result.findings.some(f => f.verdict === CONFIRMED && f.category === 'malware') ? removeFullScanMalware(result) : null;
  annotate(result, clean_);
  result.clean = clean_;
  const reportPath = writeReport(result);

  if (json) {
    process.stdout.write(JSON.stringify({ reportPath, ...result }, null, 2) + '\n');
  } else {
    if (result.findings.length) {
      console.log(`${colors.bold}${colors.cyan}━━━━━━━━━━━━━━━━━━  What was found  ━━━━━━━━━━━━━━━━━━${colors.reset}`);
      printFindings(result);
    }
    const problemArchives = result.archives.filter(a => a.problems.length || a.encrypted.length);
    if (problemArchives.length) {
      console.log(`\n${colors.yellow}${colors.bold}Archives that could not be fully checked${colors.reset}`);
      for (const a of problemArchives.slice(0, 20)) {
        const why = [...(a.encrypted.length ? [`${a.encrypted.length} encrypted file(s)`] : []), ...a.problems.slice(0, 2).map(p => `${p.entry}: ${p.reason}`)];
        console.log(`  ${colors.yellow}⚠${colors.reset} ${a.path}  ${colors.dim}${why.join('; ')}${colors.reset}`);
      }
    }

    const confirmed = result.findings.filter(f => f.verdict === CONFIRMED);
    const removed = result.findings.filter(f => f.action.removed);
    const review = result.findings.filter(f => !f.action.removed && f.verdict !== CONFIRMED);
    const infectedArchives = result.archives.filter(a => a.malware);
    console.log(`\n${colors.bold}Summary${colors.reset} ${colors.dim}(${((Date.now() - started) / 1000).toFixed(1)}s)${colors.reset}`);
    console.log(`  Files scanned     : ${result.files}  (${result.repos.length} git repo(s) inside; non-git folders included)`);
    console.log(`  Archives opened   : ${result.archives.length}  (${result.archives.reduce((n, a) => n + a.scanned, 0)} files inside)`);
    console.log(`  ${confirmed.length ? colors.red : colors.green}Malware           : ${confirmed.length}${infectedArchives.length ? ` (${infectedArchives.length} archive(s))` : ''}${colors.reset}`);
    console.log(`  ${removed.length ? colors.green : colors.dim}Removed           : ${removed.length}${colors.reset}`);
    console.log(`  ${review.length ? colors.yellow : colors.green}To review         : ${review.length}${colors.reset}`);
    console.log(`  ${colors.dim}Skipped           : ${result.skippedDirs} dependency folder(s) (node_modules, vendor …)${result.tooLarge.length ? `, ${result.tooLarge.length} file(s) too large` : ''}${colors.reset}`);
    if (clean_ && clean_.quarantineDir) console.log(`  ${colors.dim}Backups           : ${clean_.quarantineDir}${colors.reset}`);
    console.log(`\n  ${colors.dim}Full report: ${reportPath}${colors.reset}`);
    const left = confirmed.filter(f => !f.action.removed);
    if (left.length && !clean) {
      console.log(`\n  ${colors.bold}Remove the confirmed malware:${colors.reset} ${colors.cyan}gitsafty full-scan "${abs}" --clean${colors.reset}`);
    }
    if (removed.length && result.repos.length) {
      console.log(`  ${colors.dim}Files inside git repositories changed in the working tree only: check git status there and commit the fix.${colors.reset}`);
    }
    console.log('');
    if (confirmed.length) notifyDesktop('GitSafty Full Scan', `${confirmed.length} malware finding(s) in ${path.basename(abs)}. Check the terminal.`);
  }

  const open = result.findings.filter(f => !f.action.removed && (f.verdict === CONFIRMED || f.severity === 'CRITICAL'));
  return open.length ? 1 : 0;
}

module.exports = {
  fullScan,
  runFullScan,
  annotate,
  removeFullScanMalware,
  DEPENDENCY_DIRS,
  PACKAGE_FILES
};
