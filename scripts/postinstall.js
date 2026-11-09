/**
 * Automatically executed on npm postinstall
 */

const { installHook } = require('../src/installer');
const { isGitRepo } = require('../src/utils/git');

function main() {
  // In CI or production install without git, exit gracefully
  if (process.env.CI || process.env.CONTINUOUS_INTEGRATION) {
    return;
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
