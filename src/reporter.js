/**
 * Terminal UI and report formatter (Zero-dependency ANSI colors)
 */

const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m'
};

const symbols = {
  pass: '✔',
  fail: '✖',
  warn: '⚠',
  info: 'ℹ',
  shield: '🛡️ '
};

function banner() {
  console.log(`\n${colors.cyan}${colors.bold}================================================================${colors.reset}`);
  console.log(`${colors.cyan}${colors.bold}       ${symbols.shield} GitSafty: Pre-Push Malware & Secret Guard        ${colors.reset}`);
  console.log(`${colors.cyan}${colors.bold}================================================================${colors.reset}`);
}

/**
 * Prints scan summary
 * @param {{ totalFiles: number, threats: Array<any>, durationMs: number }} result 
 */
function printReport(result) {
  const { totalFiles, threats, durationMs } = result;

  console.log(`\n${colors.dim}Scanned ${totalFiles} file(s) in ${durationMs}ms${colors.reset}`);

  if (threats.length === 0) {
    console.log(`\n${colors.bgGreen}${colors.bold}  PASSED  ${colors.reset} ${colors.green}${colors.bold}No malware, suspicious files, or leaked secrets found.${colors.reset}\n`);
    return;
  }

  const criticalThreats = threats.filter(t => t.severity === 'CRITICAL');
  const warnings = threats.filter(t => t.severity === 'WARNING');

  console.log(`\n${colors.bgRed}${colors.bold}  SECURITY THREATS DETECTED  ${colors.reset}\n`);

  for (const threat of threats) {
    const isCrit = threat.severity === 'CRITICAL';
    const tag = isCrit 
      ? `${colors.bgRed}${colors.white}${colors.bold} CRITICAL ${colors.reset}`
      : `${colors.bgYellow}${colors.white}${colors.bold} WARNING  ${colors.reset}`;
    
    console.log(`${tag} ${colors.bold}${threat.name || threat.rule}${colors.reset}`);
    if (threat.filePath) {
      console.log(`   ${colors.dim}File:${colors.reset}   ${colors.yellow}${threat.filePath}${colors.reset}`);
    }
    if (threat.description) {
      console.log(`   ${colors.dim}Reason:${colors.reset} ${threat.description}`);
    }
    if (threat.line) {
      console.log(`   ${colors.dim}Code:${colors.reset}   ${colors.red}${threat.line}${colors.reset}`);
    }
    console.log('');
  }

  console.log(`${colors.bold}Summary:${colors.reset} ${colors.red}${criticalThreats.length} Critical${colors.reset}, ${colors.yellow}${warnings.length} Warnings${colors.reset}`);
}

function printBlockMessage() {
  console.log(`\n${colors.bgRed}${colors.bold}  PUSH BLOCKED BY GITSAFTY  ${colors.reset}`);
  console.log(`${colors.red}Malware signatures or critical secrets were found in your outgoing commits.${colors.reset}`);
  console.log(`${colors.red}These files or changes will NOT be allowed to reach GitHub.${colors.reset}`);
  console.log(`${colors.dim}Please remove the malicious scripts/keys and unstage/recommit before pushing.${colors.reset}\n`);
}

module.exports = {
  colors,
  symbols,
  banner,
  printReport,
  printBlockMessage
};

