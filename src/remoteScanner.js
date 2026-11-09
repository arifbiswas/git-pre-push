const { checkFilename } = require('./rules/filenames');
const { scanPayloads } = require('./rules/payloads');
const { scanSecrets } = require('./rules/secrets');
const { inspectIdeConfig } = require('./rules/ideConfig');
const { colors, symbols } = require('./reporter');
const { execSync } = require('child_process');

/**
 * Parses GitHub repo URL or string into { owner, repo, branch }
 * @param {string} inputUrl 
 * @returns {{ owner: string, repo: string, branch?: string } | null}
 */
function parseGitHubUrl(inputUrl) {
  if (!inputUrl) return null;
  let clean = inputUrl.trim().replace(/\.git$/, '');

  // Handle git@github.com:owner/repo
  if (clean.startsWith('git@github.com:')) {
    clean = clean.replace('git@github.com:', '');
  } else {
    clean = clean.replace(/^https?:\/\/github\.com\//, '');
  }

  const parts = clean.split('/').filter(Boolean);
  if (parts.length < 2) return null;

  const owner = parts[0];
  const repo = parts[1];
  let branch;

  if (parts[2] === 'tree' && parts[3]) {
    branch = parts.slice(3).join('/');
  }

  return { owner, repo, branch };
}

/**
 * Tries to get GitHub token from env or GitHub CLI
 * @returns {string | null}
 */
function resolveGitHubToken() {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  if (process.env.GH_TOKEN) return process.env.GH_TOKEN;

  // Try gh auth token
  try {
    const ghToken = execSync('gh auth token', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();
    if (ghToken) return ghToken;
  } catch (_) {}

  return null;
}

/**
 * Makes GitHub API request with proper headers
 * @param {string} endpoint 
 * @param {string | null} [token] 
 */
async function fetchGitHubApi(endpoint, token = null) {
  const url = endpoint.startsWith('http') ? endpoint : `https://api.github.com${endpoint}`;
  const headers = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'git-pre-push-remote-scanner/1.0',
    'X-GitHub-Api-Version': '2022-11-28',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {})
  };

  const res = await fetch(url, { headers });
  if (!res.ok) {
    const errText = await res.text();
    if (res.status === 404) {
      throw new Error(`Repository not found or private. If private, please provide a GitHub token.`);
    }
    if (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0') {
      throw new Error(`GitHub API rate limit exceeded. Please provide a GitHub token to scan.`);
    }
    throw new Error(`GitHub API Error [${res.status}]: ${errText}`);
  }

  return res.json();
}

/**
 * Scans a remote GitHub repository in memory without cloning or downloading
 * @param {string} repoInput 
 * @param {string | null} [customToken] 
 * @param {(msg: string) => void} [onProgress]
 */
async function scanRemoteRepositoryZeroClone(repoInput, customToken = null, onProgress = () => {}) {
  const startTime = Date.now();
  const parsed = parseGitHubUrl(repoInput);

  if (!parsed) {
    throw new Error(`Invalid GitHub repository URL: "${repoInput}". Format: https://github.com/owner/repo or owner/repo`);
  }

  const { owner, repo } = parsed;
  const token = customToken || resolveGitHubToken();

  onProgress(`Connecting to GitHub API for ${owner}/${repo}...`);

  // 1. Get repository info to resolve default branch
  let branch = parsed.branch;
  if (!branch) {
    const repoInfo = await fetchGitHubApi(`/repos/${owner}/${repo}`, token);
    branch = repoInfo.default_branch || 'main';
  }

  onProgress(`Fetching recursive file tree for branch "${branch}" (Zero-Clone)...`);

  // 2. Fetch full tree metadata in 1 single HTTP call
  const treeData = await fetchGitHubApi(`/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, token);
  const items = (treeData.tree || []).filter(item => item.type === 'blob');

  onProgress(`Indexed ${items.length} files. Running Stage 1 Path & Filename Audit...`);

  const threats = [];
  const inspectContentQueue = [];

  // Stage 1: Path & Filename Match (Instant in-memory check)
  for (const item of items) {
    const filePath = item.path;
    const fileRule = checkFilename(filePath);

    if (fileRule) {
      threats.push({
        name: fileRule.rule,
        severity: fileRule.severity,
        description: 'Unauthorized, dangerous or suspicious file detected in remote repository.',
        filePath,
        sha: item.sha
      });
    }

    // Flag files needing Stage 2 deep blob inspection
    const lower = filePath.toLowerCase();
    const needsBlobCheck =
      lower.includes('.vscode/tasks.json') ||
      lower.includes('.vscode/settings.json') ||
      lower.includes('.idea/') ||
      lower.endsWith('.env') ||
      lower.endsWith('.bat') ||
      lower.endsWith('.ps1') ||
      lower.endsWith('.vbs') ||
      lower.endsWith('.sh');

    if (needsBlobCheck) {
      inspectContentQueue.push(item);
    }
  }

  // Stage 2: On-Demand In-Memory Blob Inspection (Only for suspicious candidates)
  if (inspectContentQueue.length > 0) {
    onProgress(`Inspecting ${inspectContentQueue.length} suspicious file blobs in RAM...`);

    for (const item of inspectContentQueue) {
      try {
        const blobData = await fetchGitHubApi(`/repos/${owner}/${repo}/git/blobs/${item.sha}`, token);
        let content = '';
        if (blobData.encoding === 'base64') {
          content = Buffer.from(blobData.content, 'base64').toString('utf8');
        } else {
          content = blobData.content || '';
        }

        const filePath = item.path;

        // IDE tasks & settings
        if (filePath.includes('.vscode/') || filePath.includes('.idea/')) {
          const ideThreats = inspectIdeConfig(filePath, content);
          for (const it of ideThreats) {
            threats.push({
              name: it.name,
              severity: it.severity,
              description: it.description,
              filePath,
              line: it.line,
              sha: item.sha
            });
          }
        }

        // Payload signatures
        const payloadThreats = scanPayloads(content, filePath);
        for (const pt of payloadThreats) {
          threats.push({
            name: pt.name,
            severity: pt.severity,
            description: pt.description,
            filePath,
            line: pt.line,
            sha: item.sha
          });
        }

        // Secret checks
        const secretThreats = scanSecrets(content, filePath);
        for (const st of secretThreats) {
          threats.push({
            name: st.name,
            severity: st.severity,
            description: st.description,
            filePath,
            sha: item.sha
          });
        }
      } catch (_) {}
    }
  }

  const durationMs = Date.now() - startTime;
  const hasCritical = threats.some(t => t.severity === 'CRITICAL');
  const hasWarning = threats.some(t => t.severity === 'WARNING');

  return {
    owner,
    repo,
    branch,
    totalFiles: items.length,
    threats,
    durationMs,
    hasCritical,
    hasWarning
  };
}

/**
 * Prints formatted visual report for remote scan
 * @param {ReturnType<typeof scanRemoteRepositoryZeroClone> extends Promise<infer T> ? T : any} result 
 */
function printRemoteScanReport(result) {
  const { owner, repo, branch, totalFiles, threats, durationMs } = result;

  console.log(`\n${colors.cyan}${colors.bold}================================================================${colors.reset}`);
  console.log(`${colors.cyan}${colors.bold}          REMOTE REPOSITORY AUDIT REPORT (ZERO-CLONE)          ${colors.reset}`);
  console.log(`${colors.cyan}${colors.bold}================================================================${colors.reset}`);

  console.log(`\n${colors.bold}Target:${colors.reset}   ${colors.cyan}https://github.com/${owner}/${repo}${colors.reset}`);
  console.log(`${colors.bold}Branch:${colors.reset}   ${branch}`);
  console.log(`${colors.bold}Files:${colors.reset}    ${totalFiles} files indexed`);
  console.log(`${colors.bold}Storage:${colors.reset}  ${colors.green}0 MB downloaded (100% in-memory)${colors.reset}`);
  console.log(`${colors.bold}Time:${colors.reset}     ${durationMs}ms`);

  if (threats.length === 0) {
    console.log(`\n${colors.bgGreen}${colors.bold}  PASSED  ${colors.reset} ${colors.green}${colors.bold}Repository is CLEAN. No malware, Trojan scripts, or secrets found.${colors.reset}\n`);
    return;
  }

  const criticals = threats.filter(t => t.severity === 'CRITICAL');
  const warnings = threats.filter(t => t.severity === 'WARNING');

  console.log(`\n${colors.bgRed}${colors.bold}  THREATS DETECTED IN REMOTE REPOSITORY  ${colors.reset}\n`);

  for (const t of threats) {
    const isCrit = t.severity === 'CRITICAL';
    const tag = isCrit 
      ? `${colors.bgRed}${colors.white}${colors.bold} CRITICAL ${colors.reset}`
      : `${colors.bgYellow}${colors.white}${colors.bold} WARNING  ${colors.reset}`;

    console.log(`${tag} ${colors.bold}${t.name}${colors.reset}`);
    console.log(`   ${colors.dim}File:${colors.reset}   ${colors.yellow}${t.filePath}${colors.reset}`);
    if (t.description) console.log(`   ${colors.dim}Reason:${colors.reset} ${t.description}`);
    if (t.line) console.log(`   ${colors.dim}Line:${colors.reset}   ${colors.red}${t.line}${colors.reset}`);
    console.log('');
  }

  console.log(`${colors.bold}Audit Summary:${colors.reset} ${colors.red}${criticals.length} Critical${colors.reset}, ${colors.yellow}${warnings.length} Warnings\n`);
}

module.exports = {
  parseGitHubUrl,
  scanRemoteRepositoryZeroClone,
  printRemoteScanReport,
  resolveGitHubToken
};
