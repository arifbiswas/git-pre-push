const fs = require('fs');
const path = require('path');
const { runGit, getAllRepoFiles } = require('./utils/git');
const { checkFilename } = require('./rules/filenames');
const { colors } = require('./reporter');

/**
 * Automatically finds and cleans injected malware and trojan scripts from the repository
 * @param {string} [cwd] 
 * @returns {{ quarantined: string[], uncommitted: string[] }}
 */
function cleanInfectedFiles(cwd = process.cwd()) {
  const allFiles = getAllRepoFiles(cwd);
  const quarantined = [];
  const uncommitted = [];

  const quarantineDir = path.join(cwd, '.git', 'git-safty-quarantine');

  for (const file of allFiles) {
    const threat = checkFilename(file);
    if (threat && threat.severity === 'CRITICAL') {
      const fullPath = path.resolve(cwd, file);

      // Unstage from git index if staged
      runGit(`reset HEAD "${file}"`, cwd);
      uncommitted.push(file);

      // Quarantine or delete file
      if (fs.existsSync(fullPath)) {
        if (!fs.existsSync(quarantineDir)) {
          fs.mkdirSync(quarantineDir, { recursive: true });
        }
        const targetQuarantinePath = path.join(quarantineDir, `${Date.now()}_${path.basename(file)}`);
        try {
          fs.renameSync(fullPath, targetQuarantinePath);
          quarantined.push(file);
        } catch (err) {
          // If rename fails, try unlink
          try {
            fs.unlinkSync(fullPath);
            quarantined.push(file);
          } catch (_) {}
        }
      }
    }
  }

  return {
    quarantined,
    uncommitted
  };
}

module.exports = {
  cleanInfectedFiles
};

