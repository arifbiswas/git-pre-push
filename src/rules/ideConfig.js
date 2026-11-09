/**
 * IDE Configuration inspection (.vscode/tasks.json, .vscode/settings.json, .idea/workspace.xml)
 */

/**
 * Inspects IDE config files for malware injection hooks
 * @param {string} filePath 
 * @param {string} content 
 * @returns {Array<{ name: string, severity: 'CRITICAL' | 'WARNING', description: string, line: string }>}
 */
function inspectIdeConfig(filePath, content) {
  const findings = [];
  if (!content) return findings;

  const normalized = filePath.replace(/\\/g, '/');

  // 1. VS Code tasks.json check
  if (normalized.endsWith('.vscode/tasks.json')) {
    // Check for auto-run tasks triggered on folder open
    if (/folderOpen/i.test(content)) {
      findings.push({
        name: 'Auto-Run Task on Folder Open (.vscode/tasks.json)',
        severity: 'CRITICAL',
        description: 'Auto-executing task triggered immediately upon opening the project in VS Code.',
        line: 'runOptions: { runOn: "folderOpen" }'
      });
    }

    // Check for suspicious shell commands in tasks
    if (/(\.bat|\.ps1|\.vbs|curl|powershell|cmd\.exe|wget|certutil)/i.test(content)) {
      findings.push({
        name: 'Suspicious Command in VS Code Task',
        severity: 'CRITICAL',
        description: 'Shell task executes suspicious external script or utility.',
        line: filePath
      });
    }
  }

  // 2. VS Code settings.json check
  if (normalized.endsWith('.vscode/settings.json')) {
    // Malicious terminal overrides
    if (/terminal\.integrated\.env\./i.test(content) || /terminal\.integrated\.profiles\./i.test(content)) {
      findings.push({
        name: 'VS Code Terminal Environment Override',
        severity: 'WARNING',
        description: 'Project settings override developer terminal environment or profiles.',
        line: filePath
      });
    }

    // Executable path overrides like git.path or node path hijacking
    if (/(git\.path|terminal\.integrated\.shell\.|terminal\.integrated\.automationProfile)/i.test(content)) {
      findings.push({
        name: 'VS Code Shell/Binary Path Redirection',
        severity: 'CRITICAL',
        description: 'Project overrides local binary execution path (potential binary hijack).',
        line: filePath
      });
    }
  }

  // 3. JetBrains .idea/workspace.xml or tasks
  if (normalized.includes('.idea/') && (normalized.endsWith('workspace.xml') || normalized.endsWith('tasks.xml'))) {
    if (/(powershell|cmd\.exe|bash\s+-c|curl|certutil|\.bat|\.ps1)/i.test(content)) {
      findings.push({
        name: 'Suspicious External Tool in JetBrains Config',
        severity: 'WARNING',
        description: 'JetBrains IDE configuration includes external shell command or script trigger.',
        line: filePath
      });
    }
  }

  return findings;
}

module.exports = {
  inspectIdeConfig
};

