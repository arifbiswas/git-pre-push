/**
 * Deep scan of a GitHub repository without cloning it.
 *
 * Reads the file list with the GitHub API (2 requests), then downloads the
 * files that can carry malware from raw.githubusercontent.com (not counted
 * against the API rate limit) and runs the same engine as local scans,
 * including inside archives. Nothing is written to disk.
 *
 * Uses only fetch + Buffer, so it runs in Node.js 18+ and in the browser /
 * Android app.
 */

const { inspectContent } = require('./inspect');
const { walkArchive, detectArchiveType, isArchiveName } = require('./archive');

const SKIP_DIR = /(^|\/)(node_modules|vendor|bower_components|Pods|\.yarn|dist|build|\.next|coverage|\.gradle|\.dart_tool)\//;
const LOCK_FILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Podfile\.lock|Cargo\.lock|go\.sum|pubspec\.lock)$/;
// Files that can run code, or that malware disguises itself as.
const CODE_EXT = /\.(m?js|cjs|jsx|tsx?|json|sh|bash|zsh|bat|cmd|ps1|psm1|vbs|py|php|rb|pl|html?|ya?ml|xml|gradle|kts|plist|desktop|service)$/i;
const ASSET_EXT = /\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|bmp|webp|svg|mp3|mp4|wav|pdf)$/i;
const SPECIAL = /(^|\/)(\.vscode\/[^/]+\.json|\.idea\/[^/]+\.xml|Makefile|Dockerfile|\.npmrc|\.env[^/]*)$/;

const LIMITS = { maxFiles: 3000, maxFileBytes: 2 * 1024 * 1024, maxArchiveBytes: 25 * 1024 * 1024, concurrency: 8 };

function parseGitHubUrl(input) {
  if (!input) return null;
  let clean = String(input).trim().replace(/\.git$/, '').replace(/\/+$/, '');
  clean = clean.replace(/^git@github\.com:/, '').replace(/^https?:\/\/(www\.)?github\.com\//, '');
  const parts = clean.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  return { owner: parts[0], repo: parts[1], branch: parts[2] === 'tree' && parts[3] ? parts.slice(3).join('/') : undefined };
}

async function api(path, token) {
  const res = await fetch(`https://api.github.com${path}`, {
    headers: { Accept: 'application/vnd.github+json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }
  });
  if (res.ok) return res.json();
  if (res.status === 404) throw new Error('Repository not found. If it is private, add a GitHub token.');
  if (res.status === 403 || res.status === 429) throw new Error('GitHub limit reached (60 requests per hour without a token). Add a GitHub token or try again later.');
  throw new Error(`GitHub error ${res.status}`);
}

function wanted(item) {
  const p = item.path;
  if (SKIP_DIR.test(p) || LOCK_FILE.test(p)) return null;
  if (isArchiveName(p)) return item.size <= LIMITS.maxArchiveBytes ? 'archive' : null;
  if (item.size > LIMITS.maxFileBytes) return null;
  if (CODE_EXT.test(p) || ASSET_EXT.test(p) || SPECIAL.test(p)) return 'file';
  return null;
}

/**
 * @param {string} url GitHub URL or owner/repo
 * @param {{ token?: string, onProgress?: (done: number, total: number) => void }} [opts]
 */
async function scanGitHubRepo(url, { token, onProgress } = {}) {
  const started = Date.now();
  const parsed = parseGitHubUrl(url);
  if (!parsed) throw new Error('Enter a GitHub link like https://github.com/owner/repo');
  const { owner, repo } = parsed;
  let branch = parsed.branch;
  if (!branch) branch = (await api(`/repos/${owner}/${repo}`, token)).default_branch || 'main';
  const tree = await api(`/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`, token);
  const blobs = (tree.tree || []).filter(i => i.type === 'blob');

  const findings = [];
  // Every file name is checked, even files that are not downloaded.
  for (const b of blobs) {
    findings.push(...inspectContent(b.path, b.path, Buffer.alloc(0)).filter(f => f.category === 'file'));
  }

  const queue = blobs.map(b => ({ ...b, kind: wanted(b) })).filter(b => b.kind);
  const skipped = Math.max(0, queue.length - LIMITS.maxFiles);
  const todo = queue.slice(0, LIMITS.maxFiles);
  let done = 0;
  let failed = 0;
  let archiveFiles = 0;

  const raw = (p) => `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch).replace(/%2F/g, '/')}/${p.split('/').map(encodeURIComponent).join('/')}`;
  const worker = async () => {
    while (todo.length) {
      const item = todo.shift();
      try {
        const res = await fetch(raw(item.path), token ? { headers: { Authorization: `Bearer ${token}` } } : undefined);
        if (!res.ok) throw new Error(String(res.status));
        const buf = Buffer.from(await res.arrayBuffer());
        findings.push(...inspectContent(item.path, item.path, buf).filter(f => f.category !== 'file'));
        if (detectArchiveType(buf.subarray(0, 512), item.path)) {
          const stats = walkArchive(buf, item.path, (inner, data) => {
            archiveFiles++;
            findings.push(...inspectContent(`${item.path}!/${inner}`, inner.split('!/').pop(), data).map(f => ({ ...f, archive: item.path })));
          });
          if (stats.encrypted.length) {
            findings.push({ category: 'archive', verdict: 'SUSPECT', severity: 'WARNING', name: 'Password-protected archive', description: `${stats.encrypted.length} file(s) inside could not be checked.`, filePath: item.path });
          }
        }
      } catch (_) {
        failed++;
      }
      done++;
      if (onProgress) onProgress(done, done + todo.length);
    }
  };
  await Promise.all(Array.from({ length: LIMITS.concurrency }, worker));

  return {
    owner, repo, branch,
    totalFiles: blobs.length,
    scannedFiles: done - failed,
    archiveFiles,
    failed,
    skipped,
    truncated: !!tree.truncated,
    durationMs: Date.now() - started,
    findings
  };
}

module.exports = { scanGitHubRepo, parseGitHubUrl, LIMITS };
