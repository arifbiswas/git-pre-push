const { describe, it } = require('node:test');
const assert = require('node:assert');
const { isNewerVersion, printUpdateNotification } = require('../src/updateNotifier');

describe('Update Notifier Semver Comparison', () => {
  it('should identify patch updates', () => {
    assert.strictEqual(isNewerVersion('1.0.0', '1.0.1'), true);
    assert.strictEqual(isNewerVersion('1.0.9', '1.0.10'), true);
  });

  it('should identify minor and major updates', () => {
    assert.strictEqual(isNewerVersion('1.0.5', '1.1.0'), true);
    assert.strictEqual(isNewerVersion('1.5.0', '2.0.0'), true);
  });

  it('should return false when current is equal or greater', () => {
    assert.strictEqual(isNewerVersion('1.0.5', '1.0.5'), false);
    assert.strictEqual(isNewerVersion('1.1.0', '1.0.9'), false);
    assert.strictEqual(isNewerVersion('2.0.0', '1.9.9'), false);
  });

  it('should handle v prefix gracefully', () => {
    assert.strictEqual(isNewerVersion('v1.0.0', 'v1.0.1'), true);
    assert.strictEqual(isNewerVersion('v1.0.5', 'v1.0.5'), false);
  });

  it('should render notification box cleanly', () => {
    // Should not throw
    printUpdateNotification('1.0.0', '1.1.0');
  });
});


describe('Update installer: install kind detection', () => {
  const { installKind } = require('../src/updateNotifier');
  it('recognises npx and project-dependency copies (never auto-installs those)', () => {
    assert.strictEqual(installKind('/home/u/.npm/_npx/abc/node_modules/@arifbiswas/git-pre-push/bin/cli.js'), 'npx');
    assert.strictEqual(installKind('/work/app/node_modules/@arifbiswas/git-pre-push/bin/cli.js'), 'local-dependency');
  });
});
