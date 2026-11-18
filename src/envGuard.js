/**
 * .env guard for git push.
 *
 * A .env file must never reach the remote. When a push contains one:
 *   1. The push is blocked.
 *   2. .env patterns are added to .gitignore (examples/templates stay allowed).
 *   3. The .env file is removed from every commit that is not on the remote yet
 *      (only local, unpushed commits are rewritten, so no force push is needed).
 *      The file itself stays on your disk, now ignored.
 *   4. .env that git still tracks ("cached", even if .gitignore lists it) is
 *      untracked with `git rm --cached`, and the .gitignore change is committed.
 *   5. The cleaned branch is pushed right away (the original push, which still
 *      had the .env, is the one git reports as failed).
 *
 * Rewriting uses git plumbing on a temporary index, so it works with
 * uncommitted changes in the working tree and never touches them.
 * Merge commits in the unpushed range are not rewritten: the user gets the
 * exact commands instead.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ZERO_OID = '0000000000000000000000000000000000000000';
const GITIGNORE_LINES = ['.env', '.env.*', '!.env.example', '!.env.sample', '!.env.template', '!.env.dist', '!.env.defaults'];

/** True for .env, .env.local, .env.production …, but not for examples / templates. */
function isEnvFile(filePath) {
  const base = String(filePath).replace(/\\/g, '/').split('/').pop().toLowerCase();
  if (!/^\.env(\.[^/]+)?$/.test(base)) return false;
  return !/(example|sample|template|dist|defaults?|schema)/.test(base);
}

function git(args, cwd, opts = {}) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, ...opts });
  return { ok: r.status === 0, out: (r.stdout || '').toString(), err: (r.stderr || '').toString() };
}

function must(args, cwd, opts) {
  const r = git(args, cwd, opts);
  if (!r.ok) throw new Error(`git ${args.join(' ')}: ${r.err.trim()}`);
  return r.out;
}

function lines(text) {
  return text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
}

/** Commits being pushed that the remote does not have yet, oldest first. */
function unpushedCommits(localOid, cwd) {
  const r = git(['rev-list', '--reverse', '--topo-order', localOid, '--not', '--remotes'], cwd);
  return r.ok ? lines(r.out) : [];
}

/** .env files the push would put on the remote (in the pushed tip, or added by an unpushed commit). */
function envFilesInPush(push, cwd) {
  const found = new Set();
  for (const f of lines(git(['ls-tree', '-r', '--name-only', push.localOid], cwd).out)) {
    if (isEnvFile(f)) found.add(f);
  }
  const commits = unpushedCommits(push.localOid, cwd);
  if (commits.length) {
    const r = git(['log', '--format=', '--name-only', '--diff-filter=ACMR', push.localOid, '--not', '--remotes'], cwd);
    for (const f of lines(r.out)) if (isEnvFile(f)) found.add(f);
  }
  return [...found];
}

function tmpIndex() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-idx-'));
  return { file: path.join(dir, 'index'), done: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

/** Raw commit -> { tree, parents, author, committer, message } */
function readCommit(oid, cwd) {
  const raw = must(['cat-file', 'commit', oid], cwd);
  const split = raw.indexOf('\n\n');
  const header = raw.slice(0, split);
  const message = raw.slice(split + 2);
  const get = (k) => (header.match(new RegExp(`^${k} (.*)$`, 'm')) || [])[1];
  const parents = [...header.matchAll(/^parent (\S+)$/gm)].map(m => m[1]);
  return { tree: get('tree'), parents, author: get('author'), committer: get('committer'), message, signed: /^gpgsig /m.test(header) };
}

function identityEnv(ident, prefix) {
  const m = String(ident).match(/^(.*) <(.*)> (\d+ [+-]\d{4})$/);
  if (!m) return {};
  return { [`GIT_${prefix}_NAME`]: m[1], [`GIT_${prefix}_EMAIL`]: m[2], [`GIT_${prefix}_DATE`]: m[3] };
}

/** Tree of `oid` without the given paths. */
function treeWithout(treeish, files, cwd) {
  const idx = tmpIndex();
  try {
    const env = { ...process.env, GIT_INDEX_FILE: idx.file };
    must(['read-tree', treeish], cwd, { env });
    must(['rm', '--cached', '--ignore-unmatch', '-q', '--', ...files], cwd, { env });
    return must(['write-tree'], cwd, { env }).trim();
  } finally {
    idx.done();
  }
}

/**
 * Rewrites the unpushed commits of `ref` without `files`.
 * @returns {{ ok: boolean, newTip?: string, rewritten?: number, dropped?: number, reason?: string, signed?: boolean }}
 */
function rewriteUnpushed(ref, localOid, files, cwd) {
  const commits = unpushedCommits(localOid, cwd);
  if (!commits.length) return { ok: true, newTip: localOid, rewritten: 0, dropped: 0 };
  const map = new Map();
  let dropped = 0;
  let signed = false;
  for (const oid of commits) {
    const c = readCommit(oid, cwd);
    if (c.parents.length > 1) return { ok: false, reason: 'merge commits in the unpushed range' };
    signed = signed || c.signed;
    const parent = c.parents[0] ? (map.get(c.parents[0]) || c.parents[0]) : null;
    const tree = treeWithout(oid, files, cwd);
    const parentTree = parent ? must(['rev-parse', `${parent}^{tree}`], cwd).trim() : null;
    const origParentTree = c.parents[0] ? must(['rev-parse', `${c.parents[0]}^{tree}`], cwd).trim() : null;
    // A commit that only added the .env file becomes empty: drop it.
    if (parent && tree === parentTree && c.tree !== origParentTree) {
      map.set(oid, parent);
      dropped++;
      continue;
    }
    const env = { ...process.env, ...identityEnv(c.author, 'AUTHOR'), ...identityEnv(c.committer, 'COMMITTER') };
    const args = ['commit-tree', tree];
    if (parent) args.push('-p', parent);
    const newOid = must(args, cwd, { env, input: c.message }).trim();
    map.set(oid, newOid);
  }
  const newTip = map.get(localOid);
  must(['update-ref', '-m', 'GitSafty: remove .env from unpushed commits', ref, newTip, localOid], cwd);
  return { ok: true, newTip, rewritten: commits.length - dropped, dropped, signed };
}

/** Lines of GITIGNORE_LINES that .gitignore does not have yet. */
function missingIgnoreLines(text) {
  const have = new Set(lines(text));
  return GITIGNORE_LINES.filter(l => !have.has(l));
}

function appendLines(text, add) {
  if (!add.length) return text;
  const base = text && !text.endsWith('\n') ? text + '\n' : text;
  return `${base}${base ? '\n' : ''}# Environment files: never commit (added by GitSafty)\n${add.join('\n')}\n`;
}

/**
 * Commits the .gitignore update on top of `ref` (only for the checked-out branch),
 * and updates the working tree / index copy without touching other changes.
 */
function commitGitignore(ref, cwd, files = []) {
  const head = must(['rev-parse', ref], cwd).trim();
  const inHead = git(['show', `${head}:.gitignore`], cwd);
  const headText = inHead.ok ? inHead.out : '';
  const add = missingIgnoreLines(headText);

  // Working tree copy (may contain the user's own unstaged edits: keep them).
  const wtFile = path.join(cwd, '.gitignore');
  const wtText = fs.existsSync(wtFile) ? fs.readFileSync(wtFile, 'utf8') : '';
  const wtAdd = missingIgnoreLines(wtText);
  if (wtAdd.length) fs.writeFileSync(wtFile, appendLines(wtText, wtAdd));
  // .env files still in the tip (e.g. pushed earlier): this commit removes them too.
  const stillThere = lines(git(['ls-tree', '-r', '--name-only', head, '--', ...files], cwd).out);
  if (!add.length && !stillThere.length) return null;

  const blob = must(['hash-object', '-w', '--stdin'], cwd, { input: appendLines(headText, add) }).trim();
  const idx = tmpIndex();
  let commit;
  try {
    const env = { ...process.env, GIT_INDEX_FILE: idx.file };
    must(['read-tree', head], cwd, { env });
    if (stillThere.length) must(['rm', '--cached', '-q', '--', ...stillThere], cwd, { env });
    if (add.length) must(['update-index', '--add', '--cacheinfo', `100644,${blob},.gitignore`], cwd, { env });
    const tree = must(['write-tree'], cwd, { env }).trim();
    const msg = stillThere.length ? 'chore: stop tracking .env files' : 'chore: never commit .env files';
    commit = must(['commit-tree', tree, '-p', head], cwd, { input: `${msg}\n\nAdded by GitSafty: .env files are ignored and kept out of git.\n` }).trim();
  } finally {
    idx.done();
  }
  must(['update-ref', '-m', 'GitSafty: ignore .env files', ref, commit, head], cwd);

  // Real index: if it had HEAD's .gitignore (nothing staged there), move it to the new one.
  const staged = git(['ls-files', '-s', '--', '.gitignore'], cwd).out.split(/\s+/)[1];
  const oldBlob = inHead.ok ? must(['rev-parse', `${head}:.gitignore`], cwd).trim() : undefined;
  if (add.length && (staged === oldBlob || (!staged && !oldBlob))) {
    must(['update-index', '--add', '--cacheinfo', `100644,${blob},.gitignore`], cwd);
  }
  return commit;
}

/**
 * Runs the guard for a pre-push.
 * @param {Array<{localRef, localOid, remoteRef, remoteOid}>} pushes
 * @returns {{ blocked: boolean, files: string[], fixes: string[], manual: string[], alreadyOnRemote: boolean, repush: Array<{ref, remoteRef}> }}
 */
function guardEnvOnPush(pushes, cwd = process.cwd()) {
  const result = { blocked: false, files: [], fixes: [], manual: [], alreadyOnRemote: false, repush: [] };
  const currentRef = git(['symbolic-ref', '-q', 'HEAD'], cwd).out.trim();

  for (const push of pushes) {
    if (!push || push.localOid === ZERO_OID) continue;
    const files = envFilesInPush(push, cwd);
    if (!files.length) continue;
    result.blocked = true;
    result.files.push(...files.filter(f => !result.files.includes(f)));

    if (push.remoteOid && push.remoteOid !== ZERO_OID && git(['cat-file', '-e', push.remoteOid], cwd).ok) {
      const onRemote = lines(git(['ls-tree', '-r', '--name-only', push.remoteOid], cwd).out).filter(isEnvFile);
      if (onRemote.length) result.alreadyOnRemote = true;
    }

    const ref = push.localRef;
    const refNow = ref.startsWith('refs/heads/') ? git(['rev-parse', '-q', '--verify', ref], cwd).out.trim() : '';
    if (!ref.startsWith('refs/heads/') || refNow !== push.localOid) {
      result.manual.push(`Pushed ${push.localRef || push.localOid} is not a local branch tip, so it was not rewritten. Remove the file: git rm --cached ${files.map(f => `"${f}"`).join(' ')} && git commit --amend`);
      continue;
    }

    const rw = rewriteUnpushed(ref, push.localOid, files, cwd);
    if (!rw.ok) {
      result.manual.push(`Could not rewrite ${ref.replace('refs/heads/', '')} automatically (${rw.reason}). Run: git rm --cached ${files.map(f => `"${f}"`).join(' ')} && git commit -m "Remove .env" ; then remove it from history with git rebase -i or git filter-repo`);
      continue;
    }
    if (rw.rewritten || rw.dropped) {
      result.fixes.push(`Removed ${files.join(', ')} from ${rw.rewritten + rw.dropped} unpushed commit(s) on ${ref.replace('refs/heads/', '')}${rw.dropped ? ` (${rw.dropped} commit(s) that only added it were dropped)` : ''}. New commit ids.`);
      if (rw.signed) result.fixes.push('Some of those commits were GPG/SSH signed; the rewritten ones are not signed anymore.');
    }

    if (ref === currentRef) {
      // Keep the files on disk, but out of the index.
      const tracked = lines(git(['ls-files', '--', ...files], cwd).out);
      if (tracked.length) must(['rm', '--cached', '-q', '--', ...tracked], cwd);
      if (commitGitignore(ref, cwd, files)) result.fixes.push('Added .env patterns to .gitignore and committed it.');
      else result.fixes.push('.gitignore already ignores .env files.');
    } else {
      const left = lines(git(['ls-tree', '-r', '--name-only', ref, '--', ...files], cwd).out);
      if (left.length) {
        result.manual.push(`${ref.replace('refs/heads/', '')} is not checked out. Switch to it and push again, GitSafty will finish the fix: git switch ${ref.replace('refs/heads/', '')}`);
        continue;
      }
    }
    // Fully fixed: safe to push the cleaned branch.
    result.repush.push({ ref, remoteRef: push.remoteRef });
  }
  if (result.blocked && result.files.length) {
    result.fixes.push(`Your ${result.files.join(', ')} is still on your disk, now ignored by git.`);
  }
  return result;
}

module.exports = {
  isEnvFile,
  guardEnvOnPush,
  envFilesInPush,
  GITIGNORE_LINES
};
