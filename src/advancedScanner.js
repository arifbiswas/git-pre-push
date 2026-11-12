/**
 * Advanced Scanner: audits every project inside a folder in one run.
 *
 *   gitsafty scan-projects <folder> [--clean] [--deep] [--json]
 *
 * A "project" is every direct sub-folder (git repository or not), plus the
 * folder itself if it is a git repository. For each project:
 *   - malware engine (confirmed + suspect) on every file
 *   - dangerous / disguised file names
 *   - IDE auto-run backdoors (.vscode, .idea)
 *   - hard-coded secrets (masked in the report)
 *   - git persistence tricks that run code on normal git commands:
 *     unknown hooks in .git/hooks, core.fsmonitor, core.hooksPath,
 *     core.sshCommand, filter drivers, diff.external, "!" aliases
 * Files ignored by .gitignore and node_modules / build folders are skipped
 * unless --deep is given. Confirmed malware is only removed with --clean.
 * A JSON report is written to ~/.gitsafty/reports/.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { detectMalware, CONFIRMED } = require('./rules/malware');
const { checkFilename } = require('./rules/filenames');
const { inspectIdeConfig } = require('./rules/ideConfig');
const { scanSecrets } = require('./rules/secrets');
const { removeConfirmedMalware, printCleanResults, notifyDesktop } = require('./malwareCleaner');
const { colors } = require('./reporter');

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', '.nuxt', 'dist', 'build', 'out', 'coverage', 'Pods', '.gradle',
  '.dart_tool', '.expo', '.venv', 'venv', '__pycache__', '.idea-cache', 'DerivedData', '.turbo', '.cache', 'vendor', 'target',
  '.cxx', '.externalNativeBuild', '.svelte-kit', '.parcel-cache']);
// Standard build-tool wrappers that are scripts by design.
const KNOWN_GOOD_SCRIPTS = new Set(['gradlew.bat', 'mvnw.cmd', 'gradlew', 'mvnw']);

/** True when a path is inside a dependency / build folder (only the malware engine runs there). */
function inGeneratedDir(rel) {
  return rel.split('/').slice(0, -1).some(seg => SKIP_DIRS.has(seg));
}
const MAX_FILE = 8 * 1024 * 1024;
const MAX_TEXT_FOR_SECRETS = 1024 * 1024;
const SAMPLE_HOOK = /\.sample$/;

function git(args, cwd) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  return r.status === 0 ? r.stdout : null;
}

function isWin() {
  return process.platform === 'win32';
}

function isGitRepo(dir) {
  return fs.existsSync(path.join(dir, '.git'));
}

function listFilesGit(dir) {
  const out = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard'], dir);
  return out ? out.split('\0').filter(Boolean) : [];
}

/**
 * Lists a project's files. Git repositories (also nested ones inside a plain
 * folder) are listed with git so .gitignore is respected.
 * @returns {{ files: string[], tracked: Set<string> }} tracked = files git tracks
 */
function listProjectFiles(dir, deep) {
  const files = [];
  const tracked = new Set();

  const addRepo = (repoDir, prefix) => {
    const trackedOut = git(['ls-files', '-z'], repoDir);
    for (const f of (trackedOut || '').split('\0').filter(Boolean)) tracked.add(prefix + f);
    if (deep) return false;
    const all = listFilesGit(repoDir);
    if (!all.length) return false;
    for (const f of all) files.push(prefix + f);
    return true;
  };

  const walk = (rel) => {
    const abs = path.join(dir, rel);
    if (fs.existsSync(path.join(abs, '.git')) && addRepo(abs, rel ? `${rel}/` : '')) return;
    let entries;
    try { entries = fs.readdirSync(abs, { withFileTypes: true }); } catch (_) { return; }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (e.name === '.git' || (!deep && SKIP_DIRS.has(e.name))) continue;
        walk(r);
      } else if (e.isFile()) {
        files.push(r);
      }
    }
  };
  walk('');
  return { files, tracked };
}

function mask(text) {
  return String(text).replace(/([A-Za-z0-9_\-]{4})[A-Za-z0-9_\-+/=]{8,}/g, '$1••••••••');
}

// ---------------------------------------------------------------------------
// Git persistence checks
// ---------------------------------------------------------------------------

function gitPersistenceFindings(dir) {
  const findings = [];
  if (!isGitRepo(dir)) return findings;
  const gitDir = path.join(dir, '.git');

  // 1. Unknown executable hooks inside the repository
  const hooksDir = path.join(gitDir, 'hooks');
  let hooks = [];
  try { hooks = fs.readdirSync(hooksDir); } catch (_) {}
  for (const h of hooks) {
    if (SAMPLE_HOOK.test(h)) continue;
    const file = path.join(hooksDir, h);
    let content = '';
    try {
      if (!fs.statSync(file).isFile()) continue;
      content = fs.readFileSync(file, 'utf8');
    } catch (_) { continue; }
    if (content.includes('GIT-SAFTY SECURITY HOOK')) continue;
    if (/husky|lint-staged|pre-commit\.com|lefthook|simple-git-hooks|git-lfs|gitleaks|talisman/i.test(content)) continue;
    const malware = detectMalware(`.git/hooks/${h}`, Buffer.from(content));
    const dangerous = /(curl|wget|Invoke-WebRequest|iwr)\b[^\n|]*\|\s*(ba|z)?sh|base64\s+(-d|--decode)|node\s+-e|python[0-9]?\s+-c|powershell[^\n]*-e(nc)?\s|\/dev\/tcp\/|nc\s+-e/i.test(content);
    findings.push({
      category: 'git-backdoor',
      verdict: malware.some(f => f.verdict === CONFIRMED) ? CONFIRMED : 'SUSPECT',
      name: `Unknown git hook: .git/hooks/${h}`,
      description: dangerous
        ? 'Runs on normal git commands and downloads/decodes/executes code. Classic persistence trick.'
        : 'Runs automatically on git commands. Hooks are not part of the repository, so something on this PC put it there. Check it is yours.',
      filePath: `.git/hooks/${h}`,
      fixCommand: isWin() ? `Remove-Item "${file}"` : `rm "${file}"`,
      line: content.split('\n').find(l => l.trim() && !l.startsWith('#!')) || '',
      severity: dangerous ? 'CRITICAL' : 'WARNING'
    });
  }

  // 2. Config keys that execute commands
  const cfg = git(['config', '--local', '--list'], dir) || '';
  const risky = [
    [/^core\.fsmonitor=(?!true$|false$)(.+)/i, 'core.fsmonitor runs this command on every git status / git add'],
    [/^core\.hookspath=(.+)/i, 'core.hooksPath moves hooks to another folder (often used to hide malicious hooks)'],
    [/^core\.sshcommand=(.+)/i, 'core.sshCommand replaces ssh for every fetch/push'],
    [/^core\.(editor|pager|askpass)=(.+)/i, 'Runs this program during normal git commands'],
    [/^filter\.[^.]+\.(clean|smudge|process)=(.+)/i, 'Filter driver runs this command on checkout / add'],
    [/^diff\.external=(.+)/i, 'diff.external runs this program on every git diff'],
    [/^alias\.[^=]+=!(.+)/i, 'Alias that runs a shell command'],
    [/^credential\.[^=]*helper=(.+)/i, 'Repository-local credential helper (can capture your GitHub login)']
  ];
  for (const line of cfg.split('\n')) {
    for (const [re, why] of risky) {
      const m = line.match(re);
      if (!m) continue;
      if (/^core\.hookspath=\.husky/i.test(line) || /^filter\.lfs\./i.test(line)) continue;
      const value = m[m.length - 1];
      const dangerous = /(curl|wget|base64|\/dev\/tcp|node\s+-e|python[0-9]?\s+-c|powershell|nc\s+-e|\.woff2?|\.png|\.ttf)/i.test(value);
      findings.push({
        category: 'git-backdoor',
        verdict: 'SUSPECT',
        severity: dangerous ? 'CRITICAL' : 'WARNING',
        name: `Git config: ${line.split('=')[0]}`,
        description: why + '.',
        filePath: '.git/config',
        fixCommand: `git -C "${dir}" config --local --unset-all ${line.split('=')[0]}`,
        line: value
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Per-project scan
// ---------------------------------------------------------------------------

function scanProject(dir, { deep = false } = {}) {
  const started = Date.now();
  const { files, tracked } = listProjectFiles(dir, deep);
  const findings = [];
  // Project's own ignore list (.gitsafetyrc.json). It never turns off the malware engine.
  const { loadConfig } = require('./config');
  const ignore = (loadConfig(dir).ignoreFiles || []);
  const ignored = (rel) => ignore.some(p => (p.startsWith('*') ? rel.endsWith(p.slice(1)) : rel === p || rel.endsWith('/' + p)));

  for (const rel of files) {
    const full = path.join(dir, rel);
    let st;
    try { st = fs.lstatSync(full); } catch (_) { continue; }
    if (!st.isFile() || st.size === 0) continue;

    const generated = inGeneratedDir(rel);
    const skipRules = generated || ignored(rel);
    const base = rel.split('/').pop();
    const nameRule = skipRules || KNOWN_GOOD_SCRIPTS.has(base) ? null : checkFilename(rel);
    if (nameRule) {
      findings.push({ category: 'file', verdict: 'SUSPECT', severity: nameRule.severity, name: nameRule.rule, description: 'Dangerous, executable or disguised file name.', filePath: rel });
    }
    if (st.size > MAX_FILE) continue;

    let buf;
    try { buf = fs.readFileSync(full); } catch (_) { continue; }

    for (const f of detectMalware(rel, buf)) {
      findings.push({ category: 'malware', ...f });
    }

    if (skipRules) continue;
    const norm = rel.replace(/\\/g, '/');
    if (/(^|\/)\.vscode\/(tasks|settings)\.json$/.test(norm) || /(^|\/)\.idea\//.test(norm)) {
      for (const f of inspectIdeConfig(rel, buf.toString('utf8'))) {
        findings.push({ category: 'ide', verdict: 'SUSPECT', filePath: rel, ...f });
      }
    }

    if (buf.length <= MAX_TEXT_FOR_SECRETS && !buf.subarray(0, 8000).includes(0)) {
      const isEnv = /(^|\/)\.env(\.|$)/.test(norm);
      // .env files only matter when git tracks them (otherwise they are local config).
      if (isEnv && !tracked.has(rel)) continue;
      for (const f of scanSecrets(buf.toString('utf8'), rel)) {
        findings.push({ category: 'secret', verdict: 'SUSPECT', ...f, filePath: rel, line: mask(f.line || '') });
      }
    }
  }

  findings.push(...gitPersistenceFindings(dir));

  const count = (pred) => findings.filter(pred).length;
  return {
    project: path.basename(dir),
    path: dir,
    git: isGitRepo(dir),
    files: files.length,
    durationMs: Date.now() - started,
    findings,
    summary: {
      malware: count(f => f.verdict === CONFIRMED),
      backdoors: count(f => f.category === 'git-backdoor' || f.category === 'ide'),
      secrets: count(f => f.category === 'secret'),
      suspicious: count(f => f.verdict !== CONFIRMED && f.category !== 'secret' && f.category !== 'git-backdoor' && f.category !== 'ide')
    }
  };
}

function findProjects(root) {
  const projects = [];
  if (isGitRepo(root)) projects.push(root);
  let entries = [];
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch (_) {}
  for (const e of entries) {
    if (!e.isDirectory() || e.isSymbolicLink() || e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue;
    projects.push(path.join(root, e.name));
  }
  return projects;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

function statusOf(r) {
  const open = r.findings.filter(f => !(f.action && f.action.removed));
  if (r.summary.malware && open.every(f => f.verdict !== CONFIRMED) && r.findings.some(f => f.action)) {
    if (!open.length) return { icon: '✔', label: 'CLEANED', color: colors.green };
  } else if (r.summary.malware) {
    return { icon: '✖', label: 'MALWARE', color: colors.red };
  }
  r = { ...r, findings: open };
  if (r.findings.some(f => f.severity === 'CRITICAL' && f.category !== 'secret')) return { icon: '✖', label: 'DANGER', color: colors.red };
  if (r.findings.some(f => f.category === 'secret')) return { icon: '⚠', label: 'SECRETS', color: colors.yellow };
  if (r.findings.length) return { icon: '⚠', label: 'REVIEW', color: colors.yellow };
  return { icon: '✔', label: 'CLEAN', color: colors.green };
}

/** Marks every finding with what happened to it. */
function annotateActions(r, after) {
  const stillThere = after ? new Set(after.findings.map(f => `${f.category}|${f.name}|${f.filePath}`)) : null;
  const byFile = new Map();
  for (const res of (r.clean && r.clean.results) || []) byFile.set(res.file, res);
  for (const f of r.findings) {
    const res = f.verdict === CONFIRMED && f.category === 'malware' ? byFile.get(f.filePath) : null;
    if (res && res.ok && res.action === 'quarantined') f.action = { removed: true, text: 'Removed: whole file was malware (backup kept)' };
    else if (res && res.ok && res.action === 'repaired') f.action = { removed: true, text: 'Removed: malware cut out, rest of the file kept' };
    else if (res && !res.ok) f.action = { removed: false, text: res.action === 'manual' ? 'Needs manual removal' : `Could not remove: ${res.error || 'unknown error'}` };
    else if (f.verdict === CONFIRMED) f.action = { removed: false, text: 'Not removed (report only; run with --clean)' };
    else if (stillThere && !stillThere.has(`${f.category}|${f.name}|${f.filePath}`)) f.action = { removed: true, text: 'Resolved: gone after the malware was removed' };
    else if (f.fixCommand) f.action = { removed: false, text: `Not yours? Remove it: ${f.fixCommand}` };
    else if (f.category === 'secret') f.action = { removed: false, text: 'Rotate this secret and remove it from the code / git history' };
    else f.action = { removed: false, text: 'Review it yourself (never removed automatically)' };
  }
  r.removedFiles = [...new Set(r.findings.filter(f => f.action && f.action.removed).map(f => f.filePath))];
}

function printProjectDetails(r) {
  const order = { malware: 0, 'git-backdoor': 1, ide: 2, file: 3, secret: 4 };
  const sorted = [...r.findings].sort((a, b) =>
    (a.verdict === CONFIRMED ? -1 : 0) - (b.verdict === CONFIRMED ? -1 : 0) || (order[a.category] - order[b.category]));
  const removed = sorted.filter(f => f.action.removed);
  const open = sorted.filter(f => !f.action.removed);
  const s = statusOf(r);

  console.log(`\n${s.color}${colors.bold}📁 ${r.project}${colors.reset}  ${colors.dim}${r.path}${colors.reset}`);
  console.log(`   Found ${sorted.length} issue(s)${removed.length ? `, ${colors.green}${colors.bold}removed ${removed.length}${colors.reset} (${r.removedFiles.length} file(s))` : ''}${open.length ? `, ${open.length} need attention` : ''}`);

  const line = (f) => {
    const tag = f.verdict === CONFIRMED ? `${colors.red}${colors.bold}MALWARE${colors.reset}`
      : f.severity === 'CRITICAL' && f.category !== 'secret' ? `${colors.red}${colors.bold}DANGER${colors.reset}`
        : f.category === 'secret' ? `${colors.yellow}SECRET${colors.reset}` : `${colors.yellow}${f.category.toUpperCase()}${colors.reset}`;
    console.log(`     ${tag}  ${f.name}`);
    console.log(`            ${colors.dim}${f.filePath || ''}${f.lineNumber ? ':' + f.lineNumber : ''}${colors.reset}`);
    if (f.line && f.category !== 'malware') console.log(`            ${colors.dim}${String(f.line).slice(0, 100)}${colors.reset}`);
    const c = f.action.removed ? colors.green : (f.verdict === CONFIRMED ? colors.red : colors.dim);
    console.log(`            ${c}→ ${f.action.text}${colors.reset}`);
  };

  if (removed.length) {
    console.log(`   ${colors.green}${colors.bold}✔ Removed${colors.reset}`);
    removed.forEach(line);
  }
  if (open.length) {
    console.log(`   ${colors.yellow}${colors.bold}⚠ Still needs your attention${colors.reset}`);
    open.slice(0, 25).forEach(line);
    if (open.length > 25) console.log(`     ${colors.dim}… ${open.length - 25} more in the JSON report${colors.reset}`);
  }
  if (r.clean && r.clean.quarantineDir) {
    console.log(`   ${colors.dim}Backups of removed files: ${r.clean.quarantineDir}${colors.reset}`);
  }
}

function printResultsTable(results) {
  const nameW = Math.min(30, Math.max(7, ...results.map(r => r.project.length)));
  const pad = (v, w) => String(v).padEnd(w);
  console.log(`\n${colors.bold}Results per project${colors.reset}`);
  console.log(`  ${colors.dim}${pad('Project', nameW)}  ${pad('Status', 8)}  ${pad('Found', 6)}  ${pad('Removed', 8)}  To review${colors.reset}`);
  for (const r of results) {
    const s = statusOf(r);
    const removed = r.findings.filter(f => f.action && f.action.removed).length;
    const review = r.findings.length - removed;
    console.log(`  ${pad(r.project.slice(0, nameW), nameW)}  ${s.color}${pad(s.label, 8)}${colors.reset}  ${pad(r.findings.length, 6)}  ${removed ? colors.green : ''}${pad(removed, 8)}${colors.reset}  ${review ? colors.yellow + review + colors.reset : '0'}`);
  }
}

function writeReport(root, results) {
  const dir = path.join(process.env.HOME || process.env.USERPROFILE || os.homedir(), '.gitsafty', 'reports');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `scan-${path.basename(path.resolve(root))}-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  fs.writeFileSync(file, JSON.stringify({ root: path.resolve(root), createdAt: new Date().toISOString(), results }, null, 2), { mode: 0o600 });
  return file;
}

/**
 * Runs the Advanced Scanner.
 * @returns {number} exit code (1 if malware or critical findings)
 */
function runAdvancedScan(root, { clean = false, deep = false, json = false } = {}) {
  const abs = path.resolve(root);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) {
    console.error(`${colors.red}✖ Folder not found: ${abs}${colors.reset}`);
    return 1;
  }
  const projects = findProjects(abs);
  if (!json) {
    console.log(`\n${colors.cyan}${colors.bold}🔬 Advanced Scanner${colors.reset} ${colors.dim}${abs}${colors.reset}`);
    console.log(`${colors.dim}${projects.length} project(s) · ${deep ? 'deep (incl. node_modules & ignored files)' : 'skipping node_modules, build output and .gitignore\'d files'} · ${clean ? 'auto-remove confirmed malware' : 'report only'}${colors.reset}\n`);
  }

  const started = Date.now();
  const results = [];
  projects.forEach((dir, i) => {
    const r = scanProject(dir, { deep });
    results.push(r);
    if (!json) {
      const s = statusOf(r);
      const parts = [];
      if (r.summary.malware) parts.push(`${r.summary.malware} malware`);
      if (r.summary.backdoors) parts.push(`${r.summary.backdoors} backdoor/IDE`);
      if (r.summary.secrets) parts.push(`${r.summary.secrets} secret`);
      if (r.summary.suspicious) parts.push(`${r.summary.suspicious} suspicious`);
      const num = `[${String(i + 1).padStart(String(projects.length).length)}/${projects.length}]`;
      console.log(`${colors.dim}${num}${colors.reset} ${s.color}${s.icon} ${s.label.padEnd(7)}${colors.reset} ${r.project.padEnd(32)} ${colors.dim}${String(r.files).padStart(6)} files${colors.reset}  ${parts.join(', ')}`);
    }
  });

  // Optional removal of confirmed malware
  if (clean) {
    for (const r of results) {
      const files = [...new Set(r.findings.filter(f => f.verdict === CONFIRMED && f.category === 'malware').map(f => f.filePath))];
      if (!files.length) continue;
      r.clean = removeConfirmedMalware(files, r.path, { reason: 'advanced-scan' });
    }
  }

  // Re-scan cleaned projects so issues that disappeared with the malware are shown as resolved.
  results.forEach(r => annotateActions(r, r.clean ? scanProject(r.path, { deep }) : null));
  const reportPath = writeReport(abs, results);
  if (json) {
    process.stdout.write(JSON.stringify({ root: abs, reportPath, results }, null, 2) + '\n');
  } else {
    console.log(`\n${colors.bold}${colors.cyan}━━━━━━━━━━━━━━━━━━  Scan finished: details per project  ━━━━━━━━━━━━━━━━━━${colors.reset}`);
    for (const r of results.filter(x => x.findings.length)) printProjectDetails(r);
    printResultsTable(results);

    const total = (k) => results.reduce((n, r) => n + r.summary[k], 0);
    const infected = results.filter(r => r.summary.malware);
    const removedTotal = results.reduce((n, r) => n + r.removedFiles.length, 0);
    console.log(`\n${colors.bold}Summary${colors.reset} ${colors.dim}(${((Date.now() - started) / 1000).toFixed(1)}s)${colors.reset}`);
    console.log(`  Projects scanned : ${results.length}  (${results.reduce((n, r) => n + r.files, 0)} files)`);
    console.log(`  ${infected.length ? colors.red : colors.green}Malware          : ${total('malware')} in ${infected.length} project(s)${colors.reset}`);
    console.log(`  ${total('backdoors') ? colors.yellow : colors.green}Backdoors / IDE  : ${total('backdoors')}${colors.reset}`);
    console.log(`  ${total('secrets') ? colors.yellow : colors.green}Exposed secrets  : ${total('secrets')}${colors.reset}`);
    console.log(`  ${total('suspicious') ? colors.yellow : colors.green}Other suspicious : ${total('suspicious')}${colors.reset}`);
    console.log(`  ${removedTotal ? colors.green : colors.dim}Files cleaned    : ${removedTotal}${colors.reset}`);
    console.log(`  ${colors.green}Clean projects   : ${results.filter(r => !r.findings.length).length}${colors.reset}`);
    console.log(`\n  ${colors.dim}Full report: ${reportPath}${colors.reset}`);
    if (infected.length && !clean) {
      console.log(`\n  ${colors.bold}Remove the confirmed malware:${colors.reset} ${colors.cyan}gitsafty scan-projects "${abs}" --clean${colors.reset}`);
    }
    console.log('');
    if (infected.length) {
      notifyDesktop('GitSafty Advanced Scanner', `Malware in ${infected.length} of ${results.length} projects. Check the terminal.`);
    }
  }

  return results.some(r => r.summary.malware || r.findings.some(f => f.severity === 'CRITICAL' && f.category !== 'secret')) ? 1 : 0;
}

module.exports = {
  runAdvancedScan,
  scanProject,
  findProjects,
  gitPersistenceFindings
};
