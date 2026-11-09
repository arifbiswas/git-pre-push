const fs = require('fs');
const path = require('path');
const { checkFilename } = require('./rules/filenames');
const { scanPayloads } = require('./rules/payloads');
const { scanSecrets } = require('./rules/secrets');
const { inspectIdeConfig } = require('./rules/ideConfig');
const { loadConfig } = require('./config');

/**
 * Scans a list of files and diff content
 * @param {string[]} files 
 * @param {string} diffContent 
 * @param {string} [cwd]
 * @returns {{ totalFiles: number, threats: Array<any>, durationMs: number, hasCritical: boolean, hasWarning: boolean }}
 */
function scanFilesAndDiff(files, diffContent = '', cwd = process.cwd()) {
  const startTime = Date.now();
  const config = loadConfig(cwd);
  const rawThreats = [];
  const uniqueFiles = Array.from(new Set(files.filter(Boolean)));

  // Filter out ignored files based on config
  const filesToScan = uniqueFiles.filter(file => {
    const normalized = file.replace(/\\/g, '/');
    return !config.ignoreFiles.some(ignored => {
      if (ignored.startsWith('*')) {
        return normalized.endsWith(ignored.slice(1));
      }
      return normalized === ignored || normalized.endsWith('/' + ignored);
    });
  });

  // 1. Check all filenames
  for (const file of filesToScan) {
    const fileRule = checkFilename(file);
    if (fileRule) {
      rawThreats.push({
        name: fileRule.rule,
        severity: fileRule.severity,
        description: 'Unauthorized, dangerous or suspicious file detected.',
        filePath: file
      });
    }

    // Check custom suspicious files from config
    for (const customPattern of config.customSuspiciousFiles) {
      if (new RegExp(customPattern, 'i').test(file)) {
        rawThreats.push({
          name: `Custom Suspicious File Pattern: "${file}"`,
          severity: 'CRITICAL',
          description: 'Matches user-configured suspicious file blacklist.',
          filePath: file
        });
      }
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
          rawThreats.push(...ideThreats);
        }
      } catch (_) {}
    }

    // 3. Check for .env secret committing
    if (normalized.endsWith('.env') || normalized.includes('.env.local') || normalized.includes('.env.production')) {
      const envThreats = scanSecrets('', file);
      rawThreats.push(...envThreats);
    }
  }

  // 4. Scan commit diff content for payloads
  if (diffContent) {
    const payloadThreats = scanPayloads(diffContent);
    rawThreats.push(...payloadThreats);

    const secretThreats = scanSecrets(diffContent);
    rawThreats.push(...secretThreats);

    // Custom payloads from config
    for (const customPayload of config.customPayloads) {
      const regex = new RegExp(customPayload, 'i');
      if (regex.test(diffContent)) {
        rawThreats.push({
          name: `Custom Blacklisted Payload Pattern`,
          severity: 'CRITICAL',
          description: `Matches user-defined payload pattern: ${customPayload}`,
          line: customPayload
        });
      }
    }
  }

  // Filter out any ignored rules
  const threats = rawThreats.filter(t => {
    return !config.ignoreRules.includes(t.name);
  }).map(t => {
    if (config.strict && t.severity === 'WARNING') {
      return { ...t, severity: 'CRITICAL' };
    }
    return t;
  });

  const durationMs = Date.now() - startTime;
  const hasCritical = threats.some(t => t.severity === 'CRITICAL');
  const hasWarning = threats.some(t => t.severity === 'WARNING');

  return {
    totalFiles: filesToScan.length,
    threats,
    durationMs,
    hasCritical,
    hasWarning
  };
}

module.exports = {
  scanFilesAndDiff
};

