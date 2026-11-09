# 🛡️ git-safty

**Zero-dependency Git pre-push security guard** that prevents malware, injected Trojan scripts, compromised IDE configs, and leaked credentials from ever reaching GitHub or remote repositories.

---

## 🌟 Why git-safty?

Developer machines are frequent targets for info-stealers and supply-chain attacks. Once compromised, malware typically tries to:
1. Inject sneaky batch/shell scripts (e.g. `temp_auto_push.bat`, `temp_interactive_push.bat`, `autorun.bat`, `*.ps1`, `*.vbs`).
2. Rig `.vscode/tasks.json` or `.vscode/settings.json` to auto-execute malware as soon as another developer opens the project.
3. Exfiltrate `.env` files, API keys, or private keys to Discord webhooks or Telegram bots.
4. Auto-commit and `git push` backdoored code to your remote GitHub/GitLab repositories.

**`git-safty` intercepts git push right at the source (your local machine)**, inspects outgoing commits and diffs in milliseconds, and **hard-blocks** the push if any malicious signatures are found.

---

## 🚀 Quick Start

### Option 1: Automatic Setup via npm (Recommended)

Add `git-safty` as a dev dependency to any project:

```bash
npm install -D git-safty
```

That's it! The `postinstall` script **automatically configures the `.git/hooks/pre-push` guard** in your project.

You can also add it to your `package.json` scripts:
```json
{
  "scripts": {
    "prepare": "git-safty init"
  }
}
```

---

### Option 2: Run via npx (Zero Installation)

In any existing Git repository:

```bash
npx git-safty init
```

Your repository is instantly protected.

---

## ⚡ How It Works

```
Developer runs `git push` (from Terminal, VS Code, or any GUI)
                      │
                      ▼
        Git triggers `.git/hooks/pre-push`
                      │
                      ▼
          🛡️  GitSafty Scanner Engine
   ┌─────────────────────────────────────────┐
   │ 1. Scan outgoing filenames & extensions │
   │ 2. Scan diff for malicious payloads     │
   │ 3. Inspect .vscode & .idea configs      │
   │ 4. Detect leaked secrets & .env files   │
   └─────────────────────────────────────────┘
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
   [Threats Found]           [Clean Scan]
         │                         │
 ❌ PUSH REJECTED            ✅ PUSH ALLOWED
 (Malware blocked)           (Pushed to GitHub)
```

---

## 🔍 What Attacks Does It Block?

### 1. Injected Batch & Shell Scripts
- `temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`
- `autorun.bat`, `hidden_push.sh`, `auto_push.bat`
- Windows scripts & executables: `*.vbs`, `*.ps1`, `*.exe`, `*.scr`, `*.msi`, `*.dll`
- Disguised double extensions (e.g., `document.pdf.exe`)

### 2. Compromised IDE & Auto-Run Tasks
- `.vscode/tasks.json` with auto-executing tasks (`runOn: "folderOpen"`)
- `.vscode/settings.json` with terminal shell/environment hijacking
- JetBrains `.idea/` configs running suspicious external binaries

### 3. Obfuscated Payloads & Droppers
- PowerShell encoded execution: `powershell -enc ...`
- PowerShell download cradles: `Invoke-WebRequest`, `DownloadString`, `IEX`
- Remote pipe-to-shell: `curl ... | bash` or `wget ... | sh`
- Obfuscated dynamic evaluation: `eval(base64_decode(...))`
- Windows LOLBins abuse: `certutil -urlcache`, `bitsadmin /transfer`, `mshta`
- Interactive TCP reverse shells: `/bin/sh -i >& /dev/tcp/...`

### 4. Credential Exfiltration & Leaks
- Discord Webhook credential dumps (`https://discord.com/api/webhooks/...`)
- Telegram Bot token exfiltration
- Public file droppers & request loggers (`webhook.site`, etc.)
- Committed unencrypted `.env` files
- Cryptographic private keys (`BEGIN RSA PRIVATE KEY`, `ghp_...`, AWS keys)

---

## 🛠️ CLI Commands

| Command | Description |
|---|---|
| `npx git-safty init` | Installs the pre-push security hook into `.git/hooks/pre-push` |
| `npx git-safty scan` | Manually audits the entire repository and staged changes |
| `npx git-safty scan-push` | Executed automatically by Git during `git push` |
| `npx git-safty uninstall` | Removes the GitSafty hook cleanly |

---

## 📦 Zero External Runtime Dependencies

`git-safty` uses **100% pure Node.js built-ins** (`node:fs`, `node:path`, `node:child_process`, `node:readline`).
- **No bloat**: Instant startup in < 50ms.
- **No supply-chain risk**: Cannot be compromised through third-party npm dependency trees.
- **Cross-platform**: Works seamlessly on macOS, Linux, and Windows (PowerShell, CMD, Git Bash).
- **Graceful Shell Fallback**: Even in minimal environments where Node is not in PATH, the hook contains an embedded shell scanner fallback so pushes are never unprotected.

---

## 📄 License

MIT © 2026
