/**
 * Secret & Credential Leakage Rules
 */

const SECRET_PATTERNS = [
  {
    name: 'Private Key',
    regex: /-----BEGIN\s+(RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE KEY-----/,
    severity: 'CRITICAL',
    description: 'Cryptographic private key detected.'
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})/,
    severity: 'CRITICAL',
    description: 'GitHub Personal Access Token detected.'
  },
  {
    name: 'AWS Access Key ID',
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    severity: 'CRITICAL',
    description: 'AWS Access Key ID detected.'
  },
  {
    name: 'Slack Token',
    regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/,
    severity: 'CRITICAL',
    description: 'Slack API token detected.'
  },
  {
    name: 'Google API Key',
    regex: /\b(AIza[0-9A-Za-z\\-_]{35})\b/,
    severity: 'WARNING',
    description: 'Google Cloud / Firebase API key detected.'
  },
  {
    name: 'Generic High Entropy Secret / Token Assignment',
    regex: /(api_key|apikey|secret_key|client_secret|auth_token)\s*[:=]\s*['"][A-Za-z0-9_\-]{24,}['"]/i,
    severity: 'WARNING',
    description: 'Hardcoded secret or API credential assignment.'
  }
];

/**
 * Checks if a file path is a committed .env file with secrets
 * @param {string} filePath 
 * @returns {boolean}
 */
function isCommittedEnvFile(filePath) {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  const basename = normalized.split('/').pop() || '';

  // Allow examples, templates and test mocks
  if (basename.includes('.example') || basename.includes('.sample') || basename.includes('.template')) {
    return false;
  }

  return basename === '.env' || basename.startsWith('.env.local') || basename.startsWith('.env.production');
}

/**
 * Scans content for leaked secrets
 * @param {string} content 
 * @param {string} filePath 
 * @returns {Array<{ name: string, severity: 'CRITICAL' | 'WARNING', description: string, line: string, lineNumber?: number }>}
 */
function scanSecrets(content = '', filePath = '') {
  const findings = [];

  // Check if .env file itself is being committed
  if (filePath && isCommittedEnvFile(filePath)) {
    findings.push({
      name: 'Committed Environment File (.env)',
      severity: 'CRITICAL',
      description: 'Production or local .env file should never be committed into git.',
      line: `File: ${filePath}`,
      filePath
    });
  }

  if (!content) return findings;

  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (content.startsWith('diff --git') && !line.startsWith('+')) {
      continue;
    }
    if (line.startsWith('+++')) continue;

    const cleanLine = line.startsWith('+') ? line.slice(1).trim() : line.trim();
    if (!cleanLine) continue;

    // Skip example or dummy placeholder values
    if (/your[-_]api[-_]key|example|dummy|placeholder|<your-|test_token/i.test(cleanLine)) {
      continue;
    }

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(cleanLine)) {
        findings.push({
          name: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          line: cleanLine.slice(0, 80) + '...',
          lineNumber: i + 1,
          filePath
        });
      }
    }
  }

  return findings;
}

module.exports = {
  SECRET_PATTERNS,
  isCommittedEnvFile,
  scanSecrets
};
