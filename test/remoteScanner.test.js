const { describe, it } = require('node:test');
const assert = require('node:assert');
const { parseGitHubUrl } = require('../src/remoteScanner');

describe('Remote Scanner URL Parser', () => {
  it('should parse standard https GitHub URL', () => {
    const result = parseGitHubUrl('https://github.com/sparktechagency/gantle-backend');
    assert.deepStrictEqual(result, {
      owner: 'sparktechagency',
      repo: 'gantle-backend',
      branch: undefined
    });
  });

  it('should parse URL with .git extension', () => {
    const result = parseGitHubUrl('https://github.com/facebook/react.git');
    assert.strictEqual(result.owner, 'facebook');
    assert.strictEqual(result.repo, 'react');
  });

  it('should parse SSH git URL', () => {
    const result = parseGitHubUrl('git@github.com:vercel/next.js.git');
    assert.strictEqual(result.owner, 'vercel');
    assert.strictEqual(result.repo, 'next.js');
  });

  it('should parse short owner/repo format', () => {
    const result = parseGitHubUrl('arifbiswas/git-pre-push');
    assert.strictEqual(result.owner, 'arifbiswas');
    assert.strictEqual(result.repo, 'git-pre-push');
  });

  it('should extract branch if specified in URL', () => {
    const result = parseGitHubUrl('https://github.com/expressjs/express/tree/develop');
    assert.strictEqual(result.branch, 'develop');
  });

  it('should return null on invalid input', () => {
    assert.strictEqual(parseGitHubUrl(''), null);
    assert.strictEqual(parseGitHubUrl('invalid-url-without-slash'), null);
  });
});

