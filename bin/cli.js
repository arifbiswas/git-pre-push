#!/usr/bin/env node

const { runPrePush, runManualScan, installHook, uninstallHook } = require('../src/index');
const { cleanInfectedFiles } = require('../src/cleaner');
const { setupGitHubAction } = require('../src/action');
const { banner, colors } = require('../src/reporter');

const args = process.argv.slice(2);
const command = args[0] ? args[0].toLowerCase() : 'help';
const isGlobalFlag = args.includes('--global') || args.includes('-g');

async function main() {
  switch (command) {
    case 'scan-push':
      await runPrePush();
      break;

    case 'scan':
    case 'check':
      runManualScan();
      break;

    case 'clean':
    case 'fix': {
      banner();
      console.log(`${colors.cyan}Scanning workspace for injected malware scripts to quarantine...${colors.reset}`);
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

    case 'action':
    case 'ci': {
      banner();
      const res = setupGitHubAction();
      if (res.success) {
        console.log(`\n${colors.green}${colors.bold}✔ ${res.message}${colors.reset}`);
        console.log(`${colors.cyan}Now, even if a compromised PC pushes with --no-verify, GitHub Actions CI will block the build/PR!${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}\n`);
        process.exit(1);
      }
      break;
    }

    case 'init':
    case 'install': {
      banner();
      const result = installHook(process.cwd(), isGlobalFlag);
      if (result.success) {
        console.log(`\n${colors.green}${colors.bold}✔ ${result.message}${colors.reset}\n`);
        console.log(`${colors.cyan}Your git environment is now protected!${colors.reset}`);
        console.log(`${colors.dim}Every 'git push' will automatically scan outgoing commits for malware & secret leaks.${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${result.message}${colors.reset}\n`);
        process.exit(1);
      }
      break;
    }

    case 'uninstall':
    case 'remove': {
      banner();
      const result = uninstallHook();
      if (result.success) {
        console.log(`\n${colors.yellow}${colors.bold}✔ ${result.message}${colors.reset}\n`);
      } else {
        console.error(`\n${colors.red}${colors.bold}✖ ${result.message}${colors.reset}\n`);
        process.exit(1);
      }
      break;
    }

    case 'help':
    case '--help':
    case '-h':
    default:
      banner();
      console.log(`
${colors.bold}Usage:${colors.reset}
  npx git-safty <command>

${colors.bold}Commands:${colors.reset}
  ${colors.green}init${colors.reset}       Install the pre-push guard hook into .git/hooks/pre-push
  ${colors.green}scan${colors.reset}       Scan current repository, staged files & working tree
  ${colors.green}scan-push${colors.reset}  Triggered automatically by git during 'git push'
  ${colors.green}uninstall${colors.reset}  Remove git-safty hook from .git/hooks

${colors.bold}How it works:${colors.reset}
  1. Run ${colors.cyan}npx git-safty init${colors.reset} in any git repository.
  2. Whenever you run ${colors.cyan}git push${colors.reset}, GitSafty automatically intercepts and scans:
     - Outgoing modified files for blacklisted & trojan scripts (temp_auto_push.bat, .vbs, .ps1, .exe, etc.)
     - Outgoing diff content for obfuscated payloads (base64 eval, powershell cradles, curl | bash, lolbins)
     - IDE settings (.vscode/tasks.json, .vscode/settings.json, JetBrains configs)
     - Leaked API keys, private keys, and .env files
  3. If malware or critical secrets are detected, ${colors.red}${colors.bold}the push is rejected immediately${colors.reset}!

${colors.bold}Zero Dependencies:${colors.reset} 100% pure Node.js built-ins.
      `);
      break;
  }
}

main().catch((err) => {
  console.error(`[git-safty error]:`, err);
  process.exit(1);
});

