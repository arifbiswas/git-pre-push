/**
 * Runs scans off the main thread so the window stays responsive.
 * Receives { job, args } and posts { type: 'progress' | 'done' | 'error' }.
 */
const { parentPort, workerData } = require('worker_threads');
const path = require('path');

const engine = (p) => require(path.join(__dirname, 'engine', p));
const progress = (done, total, label) => parentPort.postMessage({ type: 'progress', done, total, label });

async function run({ job, args }) {
  if (job === 'project') {
    const { scanProject } = engine('src/advancedScanner');
    progress(0, 0, 'Scanning the project…');
    return { kind: 'projects', raw: [scanProject(args.folder)] };
  }
  if (job === 'projects') {
    const { scanProject, findProjects } = engine('src/advancedScanner');
    const dirs = findProjects(args.folder);
    const raw = [];
    dirs.forEach((dir, i) => {
      progress(i, dirs.length, `Project ${i + 1} of ${dirs.length}: ${path.basename(dir)}`);
      raw.push(scanProject(dir));
    });
    return { kind: 'projects', raw };
  }
  if (job === 'everything') {
    const { fullScan } = engine('src/fullScanner');
    const raw = fullScan(args.folder, { onProgress: (r) => progress(r.files, 0, `${r.files} files, ${r.archives.length} archives checked…`) });
    return { kind: 'full', raw: [raw] };
  }
  if (job === 'files') {
    const { fullScan } = engine('src/fullScanner');
    const raw = args.files.map((f, i) => {
      progress(i, args.files.length, `File ${i + 1} of ${args.files.length}: ${path.basename(f)}`);
      return fullScan(f);
    });
    return { kind: 'full', raw };
  }
  if (job === 'github') {
    const { scanGitHubRepo } = engine('src/remoteDeepScan');
    const raw = await scanGitHubRepo(args.url, { token: args.token, onProgress: (d, t) => progress(d, t) });
    return { kind: 'github', raw };
  }
  throw new Error(`Unknown job ${job}`);
}

run(workerData).then(
  (result) => parentPort.postMessage({ type: 'done', result }),
  (err) => parentPort.postMessage({ type: 'error', message: err && err.message ? err.message : String(err) })
);
