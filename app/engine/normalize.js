/**
 * Turns engine results into one shape the app UI renders:
 *   { id, title, stats: [{label, value}], findings: [...with group], canRemove, removeNote, notes }
 * Pure, used by the desktop app (Node.js) and the Android app (browser).
 */

let counter = 0;
const newId = () => `scan-${Date.now()}-${++counter}`;

function topFolder(p) {
  const parts = String(p || '').split('!/')[0].split('/');
  return parts.length > 1 ? parts[0] : 'Files';
}

/** gitsafty Full Scan result(s) (folder, or several single files). */
function fromFullScan(results, title) {
  const list = Array.isArray(results) ? results : [results];
  const findings = [];
  for (const r of list) {
    for (const f of r.findings) findings.push({ ...f, group: f.archive || (list.length > 1 ? (f.filePath || '').split('!/')[0] : topFolder(f.filePath)) });
  }
  const sum = (k) => list.reduce((n, r) => n + (typeof r[k] === 'number' ? r[k] : (r[k] || []).length), 0);
  const notes = [];
  const problems = list.flatMap(r => r.archives || []).filter(a => (a.problems && a.problems.length) || (a.encrypted && a.encrypted.length));
  if (problems.length) notes.push(`${problems.length} archive(s) could not be fully checked (password-protected, damaged or too big).`);
  return {
    id: newId(),
    title,
    stats: [
      { label: 'Files checked', value: sum('files') },
      { label: 'Archives opened', value: sum('archives') },
      { label: 'Git projects inside', value: sum('repos') },
      { label: 'Dependency folders skipped', value: sum('skippedDirs') }
    ],
    findings,
    canRemove: true,
    notes
  };
}

/** Advanced Scanner result(s): one per project. */
function fromProjects(results, title) {
  const list = Array.isArray(results) ? results : [results];
  const findings = [];
  for (const r of list) for (const f of r.findings) findings.push({ ...f, group: r.project });
  return {
    id: newId(),
    title,
    stats: [
      { label: 'Projects', value: list.length },
      { label: 'Files checked', value: list.reduce((n, r) => n + r.files, 0) },
      { label: 'Clean projects', value: list.filter(r => !r.findings.length).length }
    ],
    findings,
    canRemove: true,
    notes: list.some(r => r.archives) ? ['Zip/rar files were not opened here. Use "Scan everything in a folder" to look inside them.'] : []
  };
}

/** GitHub repo scan. */
function fromGitHub(r) {
  const notes = [];
  if (r.skipped) notes.push(`Very large repo: ${r.skipped} more file(s) were not checked.`);
  if (r.failed) notes.push(`${r.failed} file(s) could not be downloaded.`);
  if (r.truncated) notes.push('GitHub returned only part of the file list (repo too large).');
  return {
    id: newId(),
    title: `${r.owner}/${r.repo}`,
    stats: [
      { label: 'Repo', value: `${r.owner}/${r.repo} (${r.branch})` },
      { label: 'Files in repo', value: r.totalFiles },
      { label: 'Files checked', value: r.scannedFiles },
      { label: 'Inside archives', value: r.archiveFiles },
      { label: 'Time', value: `${(r.durationMs / 1000).toFixed(1)}s` }
    ],
    findings: r.findings.map(f => ({ ...f, group: f.archive || topFolder(f.filePath) })),
    canRemove: false,
    removeNote: 'This code is on GitHub, not on your device. Do not clone or run it; tell the owner.',
    notes
  };
}

module.exports = { fromFullScan, fromProjects, fromGitHub, newId };
