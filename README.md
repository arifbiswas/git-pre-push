# 🛡️ git-pre-push (GitSafty)

> **Zero-Dependency Pre-Push Security Guard & Infostealer Blocker for Git.**  
> Intercepts `git push` in real-time to prevent malware, Trojan scripts, compromised IDE configs, and leaked credentials from ever reaching GitHub or poisoning your software supply chain.

[![Release](https://img.shields.io/github/v/release/arifbiswas/git-pre-push?style=flat-square&color=blue)](https://github.com/arifbiswas/git-pre-push/releases)
[![CI Test Suite](https://github.com/arifbiswas/git-pre-push/actions/workflows/ci.yml/badge.svg)](https://github.com/arifbiswas/git-pre-push/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@arifbiswas/git-pre-push.svg?style=flat-square)](https://www.npmjs.com/package/@arifbiswas/git-pre-push)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(Pure%20Node.js)-brightgreen.svg?style=flat-square)](#-zero-external-runtime-dependencies)
[![Tests Passing](https://img.shields.io/badge/tests-20%2F20%20passing-success.svg?style=flat-square)](#-test-coverage)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg?style=flat-square)](#-cross-platform--zero-dependencies)

---

## 📌 Why Do You Need This?

Developer workstations are high-value targets for infostealer malware (RedLine, Lumma, Vidar, etc.) and supply-chain attacks. Once a machine is compromised, malware silently:

1. **Injects auto-commit/push scripts** into your Git repositories (e.g., `temp_auto_push.bat`, `temp_interactive_push.bat`, `autorun.bat`, `*.ps1`, `*.vbs`).
2. **Backdoors your IDE configs** (e.g., `.vscode/tasks.json` with `runOn: "folderOpen"`) so that opening the project immediately triggers remote shell execution on any teammate's machine.
3. **Exfiltrates secrets & `.env` files** to attacker-controlled Discord webhooks or Telegram bots.
4. **Leverages stored Git credentials / SSH keys** to automatically push backdoored code straight to GitHub.
5. **Poisons the Software Supply Chain**, affecting every teammate who pulls the code and every production build deployed from it.

**`git-pre-push` stops this attack chain at the source.**  
Whenever `git push` is invoked—from terminal, VS Code UI, or any Git GUI—it intercepts the push in milliseconds, inspects outgoing files and commit diffs, and **hard-blocks the push** if any malicious patterns are found.

---

## 🚀 Quick Start

### Option 1: Automatic Setup via npm (Recommended)

Add `git-pre-push` to your project:

```bash
npm install -D @arifbiswas/git-pre-push
```

> **Zero Configuration Required:** The `postinstall` script automatically installs the `.git/hooks/pre-push` guard in your repository.

---

### Option 2: Instant Setup via npx (Zero Installation)

In any Git repository, run:

```bash
npx @arifbiswas/git-pre-push init
```

Your repository is immediately protected.

---

### Option 3: Lock Down an Entire Machine (Global Protection)

If you suspect your workstation has been compromised, lock down **all Git repositories on your computer** with a single command:

```bash
npx @arifbiswas/git-pre-push init --global
```

This configures `git config --global core.hooksPath`, ensuring every repository on your PC runs the security scanner before any push.

---

## ⚡ How It Works

```
           Developer or Malware executes: git push
                              │
                              ▼
           Git triggers: .git/hooks/pre-push
                              │
                              ▼
            🛡️ GitSafty Scanner Engine (< 5ms)
 ┌─────────────────────────────────────────────────────────┐
 │ 1. Blacklist check (temp_*_push.bat, .exe, .ps1, .vbs)  │
 │ 2. Outgoing commit diff inspection for payload cradles  │
 │ 3. IDE backdoor inspection (.vscode/tasks.json, .idea)  │
 │ 4. Credential & secret leak detection (.env, RSA keys)  │
 └─────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┴─────────────────────┐
        ▼                                           ▼
  [Threats Found]                             [Clean Scan]
        │                                           │
 ❌ PUSH REJECTED                            ✅ PUSH ALLOWED
(Malware blocked locally)                   (Pushed cleanly to GitHub)
```

---

## 🎯 Threat Detection Capabilities

### 1. Injected Scripts & Trojan Filenames
- Known malicious auto-push scripts: `temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `autorun.bat`, `hidden_push.sh`
- Blocked executable extensions: `*.exe`, `*.scr`, `*.msi`, `*.dll`, `*.vbs`, `*.ps1`, `*.hta`, `*.pif`, `*.cpl`
- Deceptive double-extension tricks: `document.pdf.exe`, `invoice.xlsx.bat`

### 2. Obfuscated Payloads & Reverse Shells
- PowerShell obfuscated execution: `powershell -enc`, `powershell -encodedcommand`
- Web download cradles: `Invoke-WebRequest`, `DownloadString`, `IEX`
- Remote pipe-to-shell: `curl ... | bash`, `wget ... | sh`, `curl ... | python`
- Dynamic base64 evaluation: `eval(base64_decode(...))`, `Buffer.from(..., 'base64')`
- Windows LOLBins abuse: `certutil -urlcache`, `bitsadmin /transfer`, `mshta http`
- TCP socket reverse shells: `/bin/sh -i >& /dev/tcp/...`, `nc -e /bin/sh`

### 3. IDE Configuration Backdoors
- `.vscode/tasks.json`: Auto-executing shell tasks triggered on folder open (`runOn: "folderOpen"`)
- `.vscode/settings.json`: Malicious terminal profile overrides or shell binary path hijacking
- JetBrains `.idea/`: Suspicious external tool execution in `workspace.xml` or `tasks.xml`

### 4. Credential Exfiltration & Secret Leaks
- Hardcoded Discord webhook dumps (`https://discord.com/api/webhooks/...`)
- Telegram Bot token exfiltration endpoints
- Temporary file drop & webhook logging services (`webhook.site`, `pipedream.net`, `filebin.net`)
- Unencrypted production `.env` files being committed
- Leaked cryptographic private keys (`BEGIN RSA PRIVATE KEY`, `ghp_...`, AWS Access Keys)

---

## 🛠️ CLI Command Reference

| Command | Description |
|---|---|
| `npx @arifbiswas/git-pre-push init` | Installs the pre-push security hook into `.git/hooks/pre-push` |
| `npx @arifbiswas/git-pre-push init --global` | Protects **all** Git repositories across the entire PC |
| `npx @arifbiswas/git-pre-push scan` | Manually audits workspace files, untracked scripts & staged diffs |
| `npx @arifbiswas/git-pre-push clean` | Unstages and quarantines injected malware files to `.git/git-safty-quarantine/` |
| `npx @arifbiswas/git-pre-push action` | Generates a `.github/workflows/git-safty.yml` CI workflow |
| `npx @arifbiswas/git-pre-push uninstall` | Cleanly removes the hook from `.git/hooks` |

---

## 🧹 Quarantine & Remediation (`clean`)

If malware has already generated files in your project, clean them up instantly:

```bash
npx @arifbiswas/git-pre-push clean
```

```
================================================================
       🛡️  GitSafty: Pre-Push Malware & Secret Guard        
================================================================
Scanning workspace for injected malware scripts to quarantine...

⚠ Quarantined 2 malicious file(s):
   ✖ temp_auto_push.bat
   ✖ config.bat

✔ Cleaned from staging area and moved to quarantine folder (.git/git-safty-quarantine/).
```

---

## 🛡️ Defense-in-Depth: GitHub Actions CI Guard

To guard against attackers attempting to bypass local hooks using `git push --no-verify`, install the GitHub Actions workflow:

```bash
npx @arifbiswas/git-pre-push action
```

This creates `.github/workflows/git-safty.yml`. Any pull request or push containing blacklisted scripts or suspicious payloads will fail CI on GitHub's servers automatically.

---

## ☁️ Cloud Scanner & Webhook Platform (`server/`)

The repository includes a standalone cloud scanner microservice in `server/` that integrates with GitHub Apps and Webhooks:
- **Webhook Endpoint (`POST /webhook`):** Verifies HMAC SHA-256 signatures and audits incoming pushes.
- **REST Scan API (`POST /api/scan`):** Recursively fetches remote repository trees (`/git/trees/{sha}?recursive=1`) and inspects file blobs.
- **Auto-Remediation:** Automatically creates remediation commits via GitHub REST API to isolate and remove compromised files.

---

## ⚙️ Optional Configuration (`.gitsafetyrc.json`)

Works out-of-the-box with zero configuration. You can optionally customize behavior with a `.gitsafetyrc.json` file in your project root:

```json
{
  "ignoreFiles": [
    "tests/fixtures/mock-payload.js"
  ],
  "ignoreRules": [],
  "strict": false
}
```

---

## 💎 Comparison: Why git-pre-push Stands Out

| Feature | Generic Git Hooks / Linters | git-pre-push |
|---|:---:|:---:|
| **Runtime Dependencies** | ❌ 50+ packages (heavy) | ✅ **0 (Pure Node.js built-ins)** |
| **Supply Chain Vulnerability** | ⚠️ High (dependency tree) | 🛡️ **Zero** (no external modules) |
| **Execution Overhead** | 🐢 1 - 3 seconds | ⚡ **< 5 milliseconds** |
| **Infostealer Malware Detection** | ❌ No | ✅ **Full signature & payload engine** |
| **IDE Backdoor Detection (.vscode)** | ❌ No | ✅ **Built-in static analysis** |
| **Global Machine Lockdown (`--global`)** | ❌ No | ✅ **One-command PC protection** |
| **Auto-Quarantine Cleaner (`clean`)** | ❌ No | ✅ **Automatic remediation** |
| **Shell Fallback Guard** | ❌ No | ✅ **Built-in POSIX shell fallback** |

---

## 🧪 Test Coverage

Verified with Node.js native test runner across all supported platforms:

```bash
npm test
```
```
✔ Cloud Scanner Webhook Signature Verification (2 tests)
✔ Cloud Scanner Remote Tree Audit (1 test)
✔ Filename & Extension Checks (4 tests)
✔ Payload Signatures Detection (5 tests)
✔ Secret & Credential Checks (3 tests)
✔ IDE Configuration Tampering (2 tests)
✔ Hook Installer and Uninstaller (1 test)

ℹ tests 18 | pass 18 | fail 0 | duration_ms ~300ms
```

---

## 📄 License

MIT License © 2026

---

**Built with 🛡️ to safeguard developers, teams, and the global software supply chain.**
