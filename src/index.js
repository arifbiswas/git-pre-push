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
  printReport(scanResult);

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

  if (scanResult.hasCritical) {
    console.log(`${colors.red}${colors.bold}Fix or remove the detected threats before committing or pushing.${colors.reset}\n`);
    process.exit(1);
  }

  process.exit(0);
}

module.exports = {
  runPrePush,
  runManualScan,
  installHook,
  uninstallHook,
  scanFilesAndDiff
};
