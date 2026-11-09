/**
 * Filename and extension blacklist rules
 */

const SUSPICIOUS_EXACT_NAMES = [
  'temp_auto_push.bat',
  'temp_interactive_push.bat',
  'config.bat',
  'autorun.bat',
  'hidden_push.sh',
  'auto_push.bat',
  'git_push.bat',
  'run_hidden.vbs',
  'payload.ps1',
  'injector.bat'
];

const BLOCKED_EXTENSIONS = [
  /\.(exe|scr|pif|cpl|hta|vbs|wsf)$/i,
  /\.(msi|dll|bin|iso|dmg)$/i,
  /\.(bat|cmd|ps1)$/i
];

const SUSPICIOUS_PATH_PATTERNS = [
  // Double extension deception like document.pdf.exe
  /\.[a-z0-9]+\.(exe|bat|cmd|vbs|ps1|scr)$/i,
  // Executables or scripts hidden inside dot directories or node_modules directly staged
  /\/\.(cache|tmp|temp)\/.*(\.bat|\.ps1|\.sh|\.exe)$/i,
  // Tampering with .git inside staged files
  /^\.git\/hooks\//i
];

/**
 * Checks a file path against filename rules
 * @param {string} filePath 
 * @returns {{ matched: boolean, rule: string, severity: 'CRITICAL' | 'WARNING' } | null}
 */
function checkFilename(filePath) {
  const normalized = filePath.replace(/\\/g, '/');
  const basename = normalized.split('/').pop() || '';

  // 1. Exact match check
  for (const suspiciousName of SUSPICIOUS_EXACT_NAMES) {
    if (basename.toLowerCase() === suspiciousName.toLowerCase()) {
      return {
        matched: true,
        rule: `Known malicious or unauthorized script filename: "${basename}"`,
        severity: 'CRITICAL'
      };
    }
  }

  // 2. Dangerous executable extension check
  for (const regex of BLOCKED_EXTENSIONS) {
    if (regex.test(basename)) {
      // Allow scripts only if in specific recognized script folders if user whitelist, otherwise warn/block
      const isCritical = /\.(exe|scr|pif|cpl|hta|vbs|msi|dll|bin)$/i.test(basename);
      return {
        matched: true,
        rule: `Executable or script extension detected: "${basename}"`,
        severity: isCritical ? 'CRITICAL' : 'WARNING'
      };
    }
  }

  // 3. Pattern / double extension check
  for (const regex of SUSPICIOUS_PATH_PATTERNS) {
    if (regex.test(normalized)) {
      return {
        matched: true,
        rule: `Suspicious or disguised path pattern: "${normalized}"`,
        severity: 'CRITICAL'
      };
    }
  }

  return null;
}

module.exports = {
  checkFilename,
  SUSPICIOUS_EXACT_NAMES,
  BLOCKED_EXTENSIONS
};
