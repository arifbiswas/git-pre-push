const fs = require('fs');
const path = require('path');
const { checkFilename } = require('./rules/filenames');
const { scanPayloads } = require('./rules/payloads');
const { scanSecrets } = require('./rules/secrets');
const { inspectIdeConfig } = require('./rules/ideConfig');

/**
 * Scans a list of files and diff content
 * @param {string[]} files 
 * @param {string} diffContent 
 * @param {string} [cwd]
 * @returns {{ totalFiles: number, threats: Array<any>, durationMs: number, hasCritical: boolean, hasWarning: boolean }}
 */
function scanFilesAndDiff(files, diffContent = '', cwd = process.cwd()) {
  const startTime = Date.now();
  const threats = [];
  const uniqueFiles = Array.from(new Set(files.filter(Boolean)));

  // 1. Check all filenames
  for (const file of uniqueFiles) {
    const fileRule = checkFilename(file);
    if (fileRule) {
      threats.push({
        name: fileRule.rule,
        severity: fileRule.severity,
        description: 'Unauthorized, dangerous or suspicious file detected.',
        filePath: file
      });
    }

    // 2. Inspect IDE configuration files if present
    const normalized = file.replace(/\\/g, '/');
    if (
      normalized.includes('.vscode/tasks.json') ||
      normalized.includes('.vscode/settings.json') ||
      normalized.includes('.idea/')
    ) {
      try {
        const fullPath = path.resolve(cwd, file);
        if (fs.existsSync(fullPath)) {
          const content = fs.readFileSync(fullPath, 'utf8');
          const ideThreats = inspectIdeConfig(file, content);
          threats.push(...ideThreats);
        }
      } catch (_) {}
    }

    // 3. Check for .env secret committing
    if (normalized.endsWith('.env') || normalized.includes('.env.local') || normalized.includes('.env.production')) {
      const envThreats = scanSecrets('', file);
      threats.push(...envThreats);
    }
  }

  // 4. Scan commit diff content for payloads
  if (diffContent) {
    const payloadThreats = scanPayloads(diffContent);
    threats.push(...payloadThreats);

    const secretThreats = scanSecrets(diffContent);
    threats.push(...secretThreats);
  }

  const durationMs = Date.now() - startTime;
  const hasCritical = threats.some(t => t.severity === 'CRITICAL');
  const hasWarning = threats.some(t => t.severity === 'WARNING');

  return {
    totalFiles: uniqueFiles.length,
    threats,
    durationMs,
    hasCritical,
    hasWarning
  };
}

module.exports = {
  scanFilesAndDiff
};

