/**
 * window.gitsafty for the Android app (and any browser): the GitSafty engine
 * runs inside the app, nothing is uploaded. Phones have no git hooks, so only
 * file scans and GitHub repo scans are offered.
 */
const { inspectContent } = require('../../src/inspect');
const { walkArchive, detectArchiveType } = require('../../src/archive');
const { scanGitHubRepo } = require('../../src/remoteDeepScan');
const { fromFullScan, fromGitHub } = require('../engine/normalize');
const { version } = require('../../package.json');

const DEPENDENCY = /(^|\/)(node_modules|vendor|bower_components|Pods|\.yarn|\.gradle)\//;
const MAX_FILE = 256 * 1024 * 1024;

function pickFiles() {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.style.display = 'none';
    input.addEventListener('change', () => { resolve(Array.from(input.files || [])); input.remove(); });
    input.addEventListener('cancel', () => { resolve([]); input.remove(); });
    document.body.appendChild(input);
    input.click();
  });
}

/** One picked file, scanned like Full Scan does on desktop. */
async function scanFile(file) {
  const result = { files: 1, archives: [], repos: [], skippedDirs: 0, findings: [] };
  if (file.size > MAX_FILE) {
    result.findings.push({ category: 'archive', verdict: 'SUSPECT', severity: 'WARNING', name: 'File too large to check on a phone', filePath: file.name });
    return result;
  }
  const buf = Buffer.from(await file.arrayBuffer());
  result.findings.push(...inspectContent(file.name, file.name, buf));
  if (detectArchiveType(buf.subarray(0, 512), file.name)) {
    const stats = walkArchive(buf, file.name, (inner, data) => {
      result.findings.push(...inspectContent(`${file.name}!/${inner}`, inner.split('!/').pop(), data).map(f => ({ ...f, archive: file.name })));
    }, { skipEntry: (inner) => DEPENDENCY.test(inner) });
    result.archives.push({ path: file.name, problems: stats.problems, encrypted: stats.encrypted, scanned: stats.scanned });
    const risky = stats.encrypted.filter(n => /\.(exe|scr|com|bat|cmd|ps1|vbs|js|jse|hta|msi|dll|lnk|jar|apk|sh|py)$/i.test(n));
    if (risky.length) {
      result.findings.push({ category: 'archive', verdict: 'SUSPECT', severity: 'CRITICAL', archive: file.name, filePath: file.name, name: 'Password-protected archive with programs inside', description: 'Could not be checked. Malware is often sent like this.' });
    }
  }
  return result;
}

const wait = () => new Promise(r => setTimeout(r, 0));

window.gitsafty = {
  info: async () => ({ platform: 'android', version }),
  pickFiles,
  pickFolder: async () => null,
  async scan(mode, files, onProgress) {
    if (mode !== 'files') throw new Error('Only file scans are available on a phone.');
    const results = [];
    for (let i = 0; i < files.length; i++) {
      if (onProgress) onProgress(i, files.length, `Checking ${files[i].name}`);
      await wait(); // let the progress bar paint
      results.push(await scanFile(files[i]));
    }
    const out = fromFullScan(results, `${files.length} file(s)`);
    out.canRemove = false;
    out.removeNote = 'Delete these files from your phone with the Files app, and do not open them.';
    return out;
  },
  async scanGitHub(url, token, onProgress) {
    return fromGitHub(await scanGitHubRepo(url, { token: token || undefined, onProgress }));
  },
  removeMalware: async () => { throw new Error('Delete the file with the Files app.'); }
};
