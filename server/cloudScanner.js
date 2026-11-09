const { checkFilename } = require('../src/rules/filenames');
const { scanPayloads } = require('../src/rules/payloads');
const { scanSecrets } = require('../src/rules/secrets');
const { inspectIdeConfig } = require('../src/rules/ideConfig');

/**
 * Scans a remote GitHub repository tree and optionally auto-remediates
 * @param {import('./githubApi').GitHubApi} api 
 * @param {string} owner 
 * @param {string} repo 
 * @param {string} [branch='main'] 
 * @param {{ autoRemediate?: boolean }} [options] 
 */
async function scanRemoteRepository(api, owner, repo, branch = 'main', options = {}) {
  const startTime = Date.now();
  const autoRemediate = options.autoRemediate ?? false;

  const threats = [];
  const remediated = [];

  // 1. Fetch recursive tree
  const treeData = await api.getTree(owner, repo, branch);
  const items = (treeData.tree || []).filter(item => item.type === 'blob');

  // Stage 1: Path & Filename Matching
  const inspectContentQueue = [];

  for (const item of items) {
    const filePath = item.path;
    const fileRule = checkFilename(filePath);

    if (fileRule) {
      threats.push({
        path: filePath,
        sha: item.sha,
        name: fileRule.rule,
        severity: fileRule.severity,
        stage: 'PATH_MATCH'
      });
    }

    // Identify files that need Stage 2 Content Inspection
    const lower = filePath.toLowerCase();
    const needsContentInspection =
      lower.includes('.vscode/tasks.json') ||
      lower.includes('.vscode/settings.json') ||
      lower.includes('.idea/') ||
      lower.endsWith('.env') ||
      lower.endsWith('.bat') ||
      lower.endsWith('.ps1') ||
      lower.endsWith('.sh') ||
      lower.endsWith('.vbs');

    if (needsContentInspection) {
      inspectContentQueue.push(item);
    }
  }

  // Stage 2: Deep Content Inspection
  for (const item of inspectContentQueue) {
    try {
      const content = await api.getBlob(owner, repo, item.sha);
      const filePath = item.path;

      // IDE configs
      if (filePath.includes('.vscode/') || filePath.includes('.idea/')) {
        const ideThreats = inspectIdeConfig(filePath, content);
        for (const it of ideThreats) {
          threats.push({
            path: filePath,
            sha: item.sha,
            name: it.name,
            severity: it.severity,
            description: it.description,
            stage: 'IDE_INSPECTION'
          });
        }
      }

      // Payload signatures
      const payloadThreats = scanPayloads(content, filePath);
      for (const pt of payloadThreats) {
        threats.push({
          path: filePath,
          sha: item.sha,
          name: pt.name,
          severity: pt.severity,
          description: pt.description,
          line: pt.line,
          stage: 'CONTENT_INSPECTION'
        });
      }

      // Secret checks
      const secretThreats = scanSecrets(content, filePath);
      for (const st of secretThreats) {
        threats.push({
          path: filePath,
          sha: item.sha,
          name: st.name,
          severity: st.severity,
          description: st.description,
          stage: 'SECRET_INSPECTION'
        });
      }
    } catch (_) {}
  }

  // Stage 3: Auto-Remediation (Isolate and Delete Infected Files)
  if (autoRemediate && threats.length > 0) {
    const criticalThreats = threats.filter(t => t.severity === 'CRITICAL');
    const processedPaths = new Set();

    for (const threat of criticalThreats) {
      if (processedPaths.has(threat.path)) continue;
      processedPaths.add(threat.path);

      try {
        await api.deleteFile(
          owner,
          repo,
          threat.path,
          threat.sha,
          branch,
          `fix(security): remove compromised file detected by GitGuard Cloud [${threat.path}]`
        );
        remediated.push({
          path: threat.path,
          sha: threat.sha,
          action: 'DELETED',
          timestamp: new Date().toISOString()
        });
      } catch (err) {
        remediated.push({
          path: threat.path,
          sha: threat.sha,
          action: 'FAILED_TO_DELETE',
          error: err.message,
          timestamp: new Date().toISOString()
        });
      }
    }
  }

  const durationMs = Date.now() - startTime;

  return {
    owner,
    repo,
    branch,
    totalFilesScanned: items.length,
    threatsFound: threats,
    remediatedFiles: remediated,
    durationMs,
    scannedAt: new Date().toISOString()
  };
}

module.exports = {
  scanRemoteRepository
};

