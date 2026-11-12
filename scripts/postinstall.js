/**
 * Automatically executed on npm postinstall
 */

const { installHook, refreshInstalledHooks } = require('../src/installer');
const { isGitRepo } = require('../src/utils/git');

function main() {
  // In CI or production install without git, exit gracefully
  if (process.env.CI || process.env.CONTINUOUS_INTEGRATION) {
    return;
  }

  // Upgrade an existing global install so it also scans clones and pulls.
  // Only for a global install (npm i -g), so a project dependency never
  // points the device-wide hooks at its own node_modules.
  const isGlobalInstall = process.env.npm_config_global === 'true';
  const refreshed = isGlobalInstall ? refreshInstalledHooks() : null;
  if (refreshed) {
    console.log(`[git-safty] 🛡️ Global hooks updated (push + clone + pull malware scan) in ${refreshed}`);
  }

  // When installed as a dependency, process.env.INIT_CWD points to the parent project
  const targetDir = process.env.INIT_CWD || process.cwd();

  if (isGitRepo(targetDir)) {
    const result = installHook(targetDir);
    if (result.success) {
      console.log(`[git-safty] 🛡️ Pre-push security hook installed in ${targetDir}`);
    }
  }
}

main();

