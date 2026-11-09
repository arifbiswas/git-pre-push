const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

/**
 * Runs a git command and returns stdout as trimmed string
 * @param {string} command 
 * @param {string} [cwd] 
 * @returns {string}
 */
function runGit(command, cwd = process.cwd()) {
  try {
    return execSync(`git ${command}`, {
      cwd,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: 50 * 1024 * 1024 // 50MB
    }).trim();
  } catch (err) {
    return '';
  }
}

/**
 * Checks if directory is a git repository
 * @param {string} [cwd] 
 * @returns {boolean}
 */
function isGitRepo(cwd = process.cwd()) {
  const result = runGit('rev-parse --is-inside-work-tree', cwd);
  return result === 'true';
}

/**
 * Gets path to git hooks directory
 * @param {string} [cwd] 
 * @returns {string | null}
 */
function getHooksDir(cwd = process.cwd()) {
  if (!isGitRepo(cwd)) return null;

  // Check git core.hooksPath if configured
  const customHooksPath = runGit('config core.hooksPath', cwd);
  if (customHooksPath) {
    return path.resolve(cwd, customHooksPath);
  }

  const gitDir = runGit('rev-parse --git-dir', cwd);
  if (!gitDir) return null;

  return path.resolve(cwd, gitDir, 'hooks');
}

/**
 * Parses pre-push stdin lines (local_ref local_oid remote_ref remote_oid)
 * @param {string} stdinText 
 * @returns {Array<{ localRef: string, localOid: string, remoteRef: string, remoteOid: string, diffRange: string }>}
 */
function parsePrePushInput(stdinText) {
  const ZERO_OID = '0000000000000000000000000000000000000000';
  const pushes = [];

  const lines = stdinText.split('\n');
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    const parts = line.split(/\s+/);
    if (parts.length < 4) continue;

    const [localRef, localOid, remoteRef, remoteOid] = parts;

    // Branch/tag deletion: nothing to scan
    if (localOid === ZERO_OID) continue;

    let diffRange;
    if (remoteOid === ZERO_OID) {
      // New remote branch: check commit or commits not in origin/main / HEAD
      diffRange = localOid;
    } else {
      diffRange = `${remoteOid}..${localOid}`;
    }

    pushes.push({
      localRef,
      localOid,
      remoteRef,
      remoteOid,
      diffRange
    });
  }

  return pushes;
}

/**
 * Gets files changed in diff range
 * @param {string} diffRange 
 * @param {string} [cwd] 
 * @returns {string[]}
 */
function getChangedFiles(diffRange, cwd = process.cwd()) {
  // Use git diff-tree or git log to extract changed filenames
  const output = runGit(`diff-tree --no-commit-id --name-only -r ${diffRange}`, cwd);
  if (!output) {
    // Fallback to git log
    const logOutput = runGit(`log ${diffRange} --name-only --oneline`, cwd);
    if (!logOutput) return [];
    const files = new Set();
    for (const line of logOutput.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || /^[0-9a-f]{7,}/i.test(trimmed)) continue;
      files.add(trimmed);
    }
    return Array.from(files);
  }

  return output.split('\n').map(f => f.trim()).filter(Boolean);
}

/**
 * Gets git diff for commit range
 * @param {string} diffRange 
 * @param {string} [cwd] 
 * @returns {string}
 */
function getDiffContent(diffRange, cwd = process.cwd()) {
  return runGit(`diff ${diffRange}`, cwd);
}

/**
 * Gets staged files (for pre-commit or manual scan)
 * @param {string} [cwd] 
 * @returns {string[]}
 */
function getStagedFiles(cwd = process.cwd()) {
  const output = runGit('diff --cached --name-only', cwd);
  if (!output) return [];
  return output.split('\n').map(f => f.trim()).filter(Boolean);
}

/**
 * Gets staged diff
 * @param {string} [cwd] 
 * @returns {string}
 */
function getStagedDiff(cwd = process.cwd()) {
  return runGit('diff --cached', cwd);
}

/**
 * Gets all files in repository
 * @param {string} [cwd] 
 * @returns {string[]}
 */
function getAllRepoFiles(cwd = process.cwd()) {
  const output = runGit('ls-files --cached --others --exclude-standard', cwd);
  if (!output) return [];
  return output.split('\n').map(f => f.trim()).filter(Boolean);
}

module.exports = {
  runGit,
  isGitRepo,
  getHooksDir,
  parsePrePushInput,
  getChangedFiles,
  getDiffContent,
  getStagedFiles,
  getStagedDiff,
  getAllRepoFiles
};
