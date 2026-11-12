const fs = require('fs');
const path = require('path');

const DEFAULT_CONFIG = {
  // Filenames or glob patterns to exclude from malware checks
  ignoreFiles: [],
  // Rule names to disable if desired
  ignoreRules: [],
  // Custom blacklist patterns
  customSuspiciousFiles: [],
  customPayloads: [],
  // Strict mode: Treat warnings as errors
  strict: false,
  // Automatically remove CONFIRMED malware (backups kept in .git/gitsafty-quarantine)
  autoClean: true
};

/**
 * Loads configuration from .gitsafetyrc.json or git-safty.config.json
 * @param {string} [cwd] 
 * @returns {typeof DEFAULT_CONFIG}
 */
function loadConfig(cwd = process.cwd()) {
  const possiblePaths = [
    path.join(cwd, '.gitsafetyrc.json'),
    path.join(cwd, '.gitsafetyrc'),
    path.join(cwd, 'git-safty.config.json')
  ];

  for (const configPath of possiblePaths) {
    if (fs.existsSync(configPath)) {
      try {
        const raw = fs.readFileSync(configPath, 'utf8');
        const parsed = JSON.parse(raw);
        return {
          ...DEFAULT_CONFIG,
          ...parsed
        };
      } catch (err) {
        console.warn(`[git-safty] Warning: Could not parse config file at ${configPath}: ${err.message}`);
      }
    }
  }

  return DEFAULT_CONFIG;
}

module.exports = {
  loadConfig,
  DEFAULT_CONFIG
};

