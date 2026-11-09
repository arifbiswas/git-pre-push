const { describe, it } = require('node:test');
const assert = require('node:assert');
const { verifyWebhookSignature } = require('../server/webhook');
const { scanRemoteRepository } = require('../server/cloudScanner');

describe('Cloud Scanner Webhook Signature Verification', () => {
  it('should verify valid HMAC SHA-256 signature', () => {
    const crypto = require('crypto');
    const secret = 'test-secret-12345';
    const payload = JSON.stringify({ ref: 'refs/heads/main', repository: { name: 'demo' } });

    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payload, 'utf8');
    const signature = 'sha256=' + hmac.digest('hex');

    const isValid = verifyWebhookSignature(payload, signature, secret);
    assert.strictEqual(isValid, true);
  });

  it('should reject invalid signature', () => {
    const isValid = verifyWebhookSignature('{"foo":"bar"}', 'sha256=invalid', 'secret');
    assert.strictEqual(isValid, false);
  });
});

describe('Cloud Scanner Remote Tree Audit', () => {
  it('should detect malicious files in mock remote tree', async () => {
    // Mock GitHubApi
    const mockApi = {
      async getTree() {
        return {
          tree: [
            { path: 'src/index.js', type: 'blob', sha: 'sha1' },
            { path: 'temp_auto_push.bat', type: 'blob', sha: 'sha2' },
            { path: '.vscode/tasks.json', type: 'blob', sha: 'sha3' }
          ]
        };
      },
      async getBlob(owner, repo, sha) {
        if (sha === 'sha3') {
          return JSON.stringify({
            tasks: [{ command: 'powershell.exe -enc AAAA', runOptions: { runOn: 'folderOpen' } }]
          });
        }
        return '';
      },
      async deleteFile() {
        return { commit: { sha: 'delete-commit-sha' } };
      }
    };

    const result = await scanRemoteRepository(mockApi, 'test-owner', 'test-repo', 'main', { autoRemediate: true });
    assert.strictEqual(result.totalFilesScanned, 3);
    assert.ok(result.threatsFound.length >= 2, 'Should detect temp_auto_push.bat and malicious tasks.json');
    assert.ok(result.remediatedFiles.some(f => f.path === 'temp_auto_push.bat'));
  });
});

