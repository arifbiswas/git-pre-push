const fs = require('fs');
const {
  isGitRepo,
  parsePrePushInput,
  getChangedFiles,
  getDiffContent,
  getStagedFiles,
  getStagedDiff,
  getAllRepoFiles
} = require('./utils/git');
const { scanFilesAndDiff } = require('./scanner');
const {
  banner,
  printReport,
  printBlockMessage,
  colors
} = require('./reporter');
const { promptUser } = require('./utils/tty');
const { installHook, uninstallHook } = require('./installer');
const { execFileSync } = require('child_process');
const path = require('path');
const { detectMalware, CONFIRMED } = require('./rules/malware');
const {
  scanFilesOnDisk,
  removeConfirmedMalware,
  autoCleanEnabled,
  notifyDesktop,
  printMalwareFindings,
  printCleanResults
} = require('./malwareCleaner');
const { loadConfig } = require('./config');

const ZERO_OID = '0000000000000000000000000000000000000000';

function gitLines(args, cwd = process.cwd()) {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 })
      .split('\n').map(s => s.trim()).filter(Boolean);
  } catch (_) {
    return [];
  }
}

function gitNulList(args, cwd = process.cwd()) {
  try {
    return execFileSync('git', [...args, '-z'], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 })
      .split('\0').filter(Boolean);
  } catch (_) {
    return [];
  }
}

function readBlob(oid, file, cwd = process.cwd()) {
  try {
    return execFileSync('git', ['cat-file', 'blob', `${oid}:${file}`], { cwd, stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
  } catch (_) {
    return null;
  }
}

function malwareToThreats(findings) {
  return findings.map(f => ({
    name: f.verdict === CONFIRMED ? `MALWARE: ${f.name}` : `Suspicious: ${f.name}`,
    severity: f.verdict === CONFIRMED ? 'CRITICAL' : 'WARNING',
    description: f.description,
    filePath: f.lineNumber ? `${f.filePath}:${f.lineNumber}` : f.filePath,
    line: f.line
  }));
}

/**
 * Scans repo files on disk, reports, and removes CONFIRMED malware.
 * Shared by clone/checkout/pull hooks, manual scan and sweep.
 * @returns {{ findings: object[], clean: object|null }}
 */
function scanAndCleanRepo(files, cwd, { reason, clean = true, quietWhenClean = false } = {}) {
  const findings = scanFilesOnDisk(files, cwd);
  const confirmed = findings.filter(f => f.verdict === CONFIRMED);

  if (!findings.length) {
    if (!quietWhenClean) {
      console.log(`${colors.green}${colors.bold}✔ GitSafty:${colors.reset} ${files.length} file(s) scanned, no malware found.`);
    }
    return { findings, clean: null };
  }

  console.log(`\n${colors.bgRed}${colors.bold}  GITSAFTY MALWARE SCAN: ${path.basename(cwd)}  ${colors.reset}\n`);
  printMalwareFindings(findings);

  let cleanResult = null;
  if (confirmed.length) {
    const config = loadConfig(cwd);
    if (clean && autoCleanEnabled(config)) {
      cleanResult = removeConfirmedMalware(confirmed.map(f => f.filePath), cwd, { reason });
      console.log(`${colors.bold}Automatic removal (confirmed malware only):${colors.reset}`);
      printCleanResults(cleanResult);
      console.log('');
      const cleaned = cleanResult.results.filter(r => r.ok).length;
      notifyDesktop('GitSafty: malware removed',
        `${confirmed.length} malware finding(s) in ${path.basename(cwd)}. ${cleaned} file(s) cleaned. Check the terminal.`);
    } else {
      console.log(`${colors.yellow}Auto-clean is off. Run ${colors.bold}gitsafty clean${colors.reset}${colors.yellow} to remove it.${colors.reset}\n`);
      notifyDesktop('GitSafty: MALWARE FOUND', `${confirmed.length} malware finding(s) in ${path.basename(cwd)}. Do not open it in your IDE.`);
    }
  } else {
    console.log(`${colors.dim}Suspicious items are only reported, never removed. Review them yourself.${colors.reset}\n`);
  }

  return { findings, clean: cleanResult };
}

/**
 * post-checkout hook: runs after git clone, git checkout/switch.
 * Never fails the checkout; it reports and cleans.
 */
function runPostCheckout(prevHead, newHead, flag) {
  if (process.env.GITSAFTY_SKIP === '1') return 0;
  if (flag === '0') return 0; // file checkout, not a branch change
  const cwd = process.cwd();

  const isClone = !prevHead || prevHead === ZERO_OID;
  const files = isClone
    ? gitNulList(['ls-files'], cwd)
    : gitLines(['diff', '--name-only', '--diff-filter=ACMR', prevHead, newHead], cwd);

  if (isClone) {
    console.log(`${colors.cyan}${colors.bold}🛡️  GitSafty:${colors.reset} scanning freshly cloned repository for malware...`);
  }
  if (!files.length) return 0;
  scanAndCleanRepo(files, cwd, { reason: isClone ? 'clone' : 'checkout', quietWhenClean: !isClone });
  if (isClone) recordScan(cwd);
  return 0;
}

const LAST_SCAN_FILE = 'gitsafty-last-scan.json';
// Only to avoid scanning twice in ONE pull (hook + shell function run seconds apart).
const RECENT_SCAN_MS = 5 * 1000;

function gitDirOf(cwd) {
  const d = gitLines(['rev-parse', '--git-dir'], cwd)[0];
  return d ? path.resolve(cwd, d) : null;
}

function headOf(cwd) {
  return gitLines(['rev-parse', 'HEAD'], cwd)[0] || '';
}

function recordScan(cwd) {
  const dir = gitDirOf(cwd);
  if (!dir) return;
  try { fs.writeFileSync(path.join(dir, LAST_SCAN_FILE), JSON.stringify({ head: headOf(cwd), at: Date.now() })); } catch (_) {}
}

function scannedRecently(cwd) {
  const dir = gitDirOf(cwd);
  if (!dir) return false;
  try {
    const last = JSON.parse(fs.readFileSync(path.join(dir, LAST_SCAN_FILE), 'utf8'));
    return last.head === headOf(cwd) && Date.now() - last.at < RECENT_SCAN_MS;
  } catch (_) {
    return false;
  }
}

/** Scans every tracked file, like after a clone, and always prints the result. */
function scanWholeRepo(cwd, reason, label) {
  const files = gitNulList(['ls-files'], cwd);
  console.log(`${colors.cyan}${colors.bold}🛡️  GitSafty:${colors.reset} scanning repository after ${label}...`);
  if (files.length) scanAndCleanRepo(files, cwd, { reason, quietWhenClean: false });
  recordScan(cwd);
  return 0;
}

/** post-merge hook: runs after git pull (merge / fast-forward) and git merge. */
function runPostMerge() {
  if (process.env.GITSAFTY_SKIP === '1') return 0;
  return scanWholeRepo(process.cwd(), 'pull', 'git pull');
}

/** post-rewrite hook: `git pull --rebase` (and git rebase) never run post-merge. */
function runPostRewrite(kind) {
  if (process.env.GITSAFTY_SKIP === '1' || kind !== 'rebase') return 0;
  return scanWholeRepo(process.cwd(), 'pull', 'git pull --rebase');
}

/**
 * Called by the optional shell `git` wrapper after every `git pull`, also when
 * git says "Already up to date" (git runs no hook at all in that case).
 * Skips when a hook already scanned this exact commit a moment ago.
 */
function runScanPull() {
  if (process.env.GITSAFTY_SKIP === '1') return 0;
  const cwd = process.cwd();
  if (!gitDirOf(cwd) || scannedRecently(cwd)) return 0;
  return scanWholeRepo(cwd, 'pull', 'git pull');
}

function findGitRepos(root, maxDepth = 6) {
  const repos = [];
  const skip = new Set(['node_modules', '.Trash', 'Library', '.cache', '.npm', '.pnpm-store', 'Pods', 'build', 'dist', '.next']);
  const walk = (dir, depth) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    if (entries.some(e => e.name === '.git')) {
      repos.push(dir);
    }
    if (depth >= maxDepth) return;
    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink() || e.name === '.git' || skip.has(e.name)) continue;
      walk(path.join(dir, e.name), depth + 1);
    }
  };
  walk(path.resolve(root), 0);
  return repos;
}

/** Scans every git repository under a folder (whole device sweep). */
function runSweep(root, { clean = true } = {}) {
  banner();
  console.log(`${colors.cyan}Looking for git repositories under ${path.resolve(root)} ...${colors.reset}`);
  const repos = findGitRepos(root);
  console.log(`${colors.dim}Found ${repos.length} repositories.${colors.reset}\n`);

  const infected = [];
  for (const repo of repos) {
    const files = gitNulList(['ls-files', '--cached', '--others', '--exclude-standard'], repo);
    const { findings, clean: res } = scanAndCleanRepo(files, repo, { reason: 'sweep', clean, quietWhenClean: true });
    if (findings.length) infected.push({ repo, findings, res });
  }

  const confirmedRepos = infected.filter(i => i.findings.some(f => f.verdict === CONFIRMED));
  console.log(`\n${colors.bold}Sweep summary:${colors.reset} ${repos.length} repos scanned, ` +
    `${colors.red}${confirmedRepos.length} with malware${colors.reset}, ` +
    `${colors.yellow}${infected.length - confirmedRepos.length} with suspicious items only${colors.reset}.`);
  for (const i of confirmedRepos) console.log(`  ${colors.red}✖${colors.reset} ${i.repo}`);
  if (confirmedRepos.length && clean) {
    console.log(`\n${colors.yellow}Cleaned files are changed in the working tree only. Review with ${colors.bold}git status${colors.reset}${colors.yellow}, then commit and push the fix.${colors.reset}`);
  }
  console.log('');
  return confirmedRepos.length ? 1 : 0;
}

/**
 * Handles pre-push hook execution
 * Reads refs from stdin, scans diffs and blocks malicious pushes
 */
async function runPrePush() {
  banner();

  // Read stdin passed by git pre-push hook (only if piped, not TTY)
  let stdinData = '';
  if (!process.stdin.isTTY) {
    try {
      stdinData = fs.readFileSync(0, 'utf8');
    } catch (_) {
      stdinData = '';
    }
  }

  const pushes = parsePrePushInput(stdinData);

  let allFiles = [];
  let combinedDiff = '';

  if (pushes.length === 0) {
    // If hook triggered without stdin or for current HEAD commit
    const headDiffRange = 'HEAD~1..HEAD';
    allFiles = getChangedFiles(headDiffRange);
    combinedDiff = getDiffContent(headDiffRange);
  } else {
    for (const push of pushes) {
      const files = getChangedFiles(push.diffRange);
      const diff = getDiffContent(push.diffRange);
      allFiles.push(...files);
      combinedDiff += '\n' + diff;
    }
  }

  const scanResult = scanFilesAndDiff(allFiles, combinedDiff);

  // Deep scan: full content of every pushed file at the pushed commit.
  const malwareFindings = [];
  const refs = pushes.length ? pushes.map(p => ({ oid: p.localOid, range: p.diffRange })) : [{ oid: 'HEAD', range: 'HEAD~1..HEAD' }];
  const seen = new Set();
  for (const ref of refs) {
    for (const file of getChangedFiles(ref.range)) {
      const key = `${ref.oid}:${file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const blob = readBlob(ref.oid, file);
      if (blob) malwareFindings.push(...detectMalware(file, blob));
    }
  }
  if (malwareFindings.length) {
    scanResult.threats.unshift(...malwareToThreats(malwareFindings));
    scanResult.hasCritical = scanResult.threats.some(t => t.severity === 'CRITICAL');
    scanResult.hasWarning = scanResult.threats.some(t => t.severity === 'WARNING');
  }

  printReport(scanResult);

  const confirmedMalware = malwareFindings.filter(f => f.verdict === CONFIRMED);
  if (confirmedMalware.length && autoCleanEnabled(loadConfig(process.cwd()))) {
    const files = Array.from(new Set(confirmedMalware.map(f => f.filePath)));
    const onDisk = scanFilesOnDisk(files).filter(f => f.verdict === CONFIRMED);
    if (onDisk.length) {
      const res = removeConfirmedMalware(onDisk.map(f => f.filePath), process.cwd(), { reason: 'pre-push' });
      console.log(`${colors.bold}Malware removed from your working tree:${colors.reset}`);
      printCleanResults(res);
    }
    console.log(`\n${colors.yellow}${colors.bold}Next:${colors.reset} review ${colors.bold}git status${colors.reset}, commit the cleaned files, then push again.`);
    notifyDesktop('GitSafty: push blocked', `Malware found in ${files.length} pushed file(s). It was removed from your working tree.`);
  }

  if (scanResult.hasCritical) {
    printBlockMessage();
    process.exit(1);
  }

  if (scanResult.hasWarning) {
    const proceed = await promptUser(`${colors.yellow}${colors.bold}⚠️ Security warnings detected above. Proceed with git push? (y/N): ${colors.reset}`);
    if (!proceed) {
      console.log(`\n${colors.red}[ABORTED] Push canceled by user.${colors.reset}\n`);
      process.exit(1);
    }
  }

  process.exit(0);
}

/**
 * Handles manual scan (npx git-safty scan)
 */
function runManualScan() {
  banner();

  if (!isGitRepo()) {
    console.error(`${colors.red}Error: Current directory is not a git repository.${colors.reset}`);
    process.exit(1);
  }

  console.log(`${colors.cyan}Inspecting repository working directory & staged changes...${colors.reset}`);

  // Staged files & diff
  const stagedFiles = getStagedFiles();
  const stagedDiff = getStagedDiff();

  // All tracked & untracked repository files
  const allRepoFiles = getAllRepoFiles();
  const filesToScan = Array.from(new Set([...stagedFiles, ...allRepoFiles]));

  const scanResult = scanFilesAndDiff(filesToScan, stagedDiff);
  printReport(scanResult);

  console.log(`${colors.cyan}Deep malware scan of file contents...${colors.reset}`);
  const { findings } = scanAndCleanRepo(filesToScan, process.cwd(), {
    reason: 'manual-scan',
    clean: !process.argv.includes('--no-clean')
  });
  if (findings.some(f => f.verdict === CONFIRMED)) scanResult.hasCritical = true;

  if (scanResult.hasCritical) {
    console.log(`${colors.red}${colors.bold}Fix or remove the detected threats before committing or pushing.${colors.reset}\n`);
    process.exit(1);
  }

  process.exit(0);
}

module.exports = {
  runPrePush,
  runManualScan,
  runPostCheckout,
  runPostMerge,
  runPostRewrite,
  runScanPull,
  runSweep,
  scanAndCleanRepo,
  installHook,
  uninstallHook,
  scanFilesAndDiff
};
