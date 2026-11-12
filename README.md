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

### Option 2: Instant Interactive Menu via npx

Run without arguments to open the interactive selection dashboard:

```bash
npx @arifbiswas/git-pre-push
```

Or if installed globally (`npm i -g @arifbiswas/git-pre-push`):
```bash
gitsafty
```

```text
================================================================
       🛡️  GitSafty: Pre-Push Malware & Secret Guard        
================================================================

Select an action to perform:

  ── Protection ──
  [1]  🛡️   Install Local Hook       - Protect current repo (push + checkout + pull)
  [2]  🌐  Install Global Hook      - Protect EVERY repo on this PC: scan on clone, pull & push
  [8]  ❌  Uninstall Hook           - Remove GitSafty hooks (this repo or whole PC)

  ── Malware scan & removal ──
  [3]  🔍  Scan Local Workspace     - Deep scan this repo, auto-remove confirmed malware
  [10] 🧹  Sweep All Repos          - Scan every git repo in a folder (whole device)
  [5]  🗑️   Clean & Quarantine       - Remove confirmed malware + trojan scripts here
  [4]  🚀  Scan Remote GitHub Repo  - Zero-clone audit (no download/clone)

  ── GitHub login vault (device stays logged out) ──
  [11] 🔐  Vault Setup              - Encrypt token with Touch ID / Windows Hello / passphrase
  [12] 📋  Vault Status             - Check vault, credential helper & SSH keys
  [13] 🔓  Vault Test Unlock        - Try one unlock prompt (token is not used)
  [14] 🚫  Vault Remove             - Back to normal git login

  ── Other ──
  [6]  ⚡  Run Push Intercept Demo  - Simulate a blocked malware push
  [7]  🤖  Setup GitHub Action CI   - Guard repository on GitHub server-side
  [9]  🔄  Check for Updates        - Check if a new version is available on npm
  [15] 🩺  Doctor                   - Something broken? Find it and show/apply the fix
  [0]  🚪  Exit

Enter your choice (1-15, 0 to exit):
```

---

### Option 3: Lock Down an Entire Machine (Global Protection)

If you suspect your workstation has been compromised, lock down **all Git repositories on your computer** with a single command:

```bash
npx @arifbiswas/git-pre-push init --global
```

This configures `git config --global core.hooksPath`, ensuring every repository on your PC runs the security scanner before any push, **and after every `git clone`, `git checkout` and `git pull`**.

> Already installed globally? Run `init --global` again after updating so the new clone/pull hooks are added.

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

### 5. Deep Malware Engine (clone, pull, push)
Built from real samples of a repository-injection campaign. Every finding gets a verdict:

| Verdict | Meaning | What GitSafty does |
|---|---|---|
| **MALWARE** (confirmed) | Proof-level signature that legitimate code never produces | Reports it, backs the file up, **removes it automatically**, re-scans to verify |
| **SUSPECT** | Dangerous-looking but can be legitimate | Reports only, never touches the file |

Confirmed signatures:
- Exact SHA-256 of known malware samples
- `global['!']='9-5756'` loader marker next to an obfuscated decoder
- Obfuscated payload hidden after 120+ spaces at the end of a normal line (e.g. infected `tailwind.js`). Only the hidden part is cut out, the rest of the file is kept
- Script disguised as a font or image (`.woff2`, `.ttf`, `.png`, ... whose bytes are JavaScript, not the real format; Git LFS pointers are ignored)
- `.vscode/tasks.json` task with `runOn: folderOpen` that runs a font/image with `node`/`python`/... or pipes the internet into a shell. Only that task is removed
- `package.json` install scripts that run a font/image as code

Backups (read-only) and a `report.json` go to `.git/gitsafty-quarantine/<time>/`. Turn auto-removal off with `"autoClean": false` or `GITSAFTY_NO_AUTOCLEAN=1`.

---

## 🔐 Always-Logged-Out Vault (last line of defence)

If a machine might still be compromised, the most valuable thing on it is your GitHub token (macOS Keychain, `~/.git-credentials`, `gh`). The vault makes sure there is **no usable token on the device**:

```bash
npx @arifbiswas/git-pre-push vault setup
```

1. You paste a GitHub token once. It is checked with GitHub, then stored **only encrypted** in `~/.gitsafty/vault.json` (mode 600), locked to this device's **security chip**:

   | OS | Protection | Each push asks for |
   |---|---|---|
   | macOS (Apple Silicon / T2) | **Secure Enclave** P-256 key (`.userPresence`), ECDH → HKDF-SHA256 → **AES-256-GCM** | Touch ID or Mac password (system dialog) |
   | Windows 10/11 | **Windows Hello** key in the **TPM**, signature of a random challenge → SHA-256 → HKDF-SHA256 → **AES-256-GCM** | Hello PIN, face or fingerprint |
   | Linux / no chip | Passphrase → **scrypt** (N=2¹⁷, r=8, p=1) → **AES-256-GCM** | Your vault passphrase |

   The chip key never leaves the chip, so a copied `vault.json` is useless on any other machine, and the system prompt can't be approved by malware. All metadata is bound as GCM additional data, so edits are detected. On macOS a small Swift helper is compiled once on your Mac during setup (needs `xcode-select --install`). Force the passphrase mode with `vault setup --passphrase`.
2. GitSafty becomes the **only** git credential helper for `github.com`. Other helpers (osxkeychain, Windows Credential Manager, `store`, `gh`) are switched off for GitHub, and saved GitHub logins in the macOS Keychain and `~/.git-credentials` are deleted.
3. On `git push`, git asks GitSafty for a login. GitSafty shows the chip prompt, decrypts the token **in memory**, gives it to git for that one command and wipes it. Git's "save this login" step is ignored, so after the push the device is **logged out again**.
4. Every unlock and every refused unlock shows a desktop notification. A prompt or notification for a push you did not start means someone else is on your machine: press Cancel.

```bash
npx @arifbiswas/git-pre-push vault status   # helper, chip, vault and SSH key checks
npx @arifbiswas/git-pre-push vault test     # one unlock prompt, token is not used
npx @arifbiswas/git-pre-push vault remove   # back to normal git login
```

Limits, honestly: the chip stops token theft (copying files, Keychain or browser stores), which is how stealers work. It can't stop malware that is running while you approve your own push from riding along with that one approved command, and in passphrase mode a keylogger can capture the passphrase. So also use a **fine-grained token with a short expiry and only the repos you need**, and rotate it. SSH remotes do not use git credential helpers: `vault status` warns about SSH private keys without a passphrase (`ssh-keygen -p -f ~/.ssh/id_ed25519`).

---

## 🩺 Troubleshooting (`doctor`)

Something not working? One command finds out what and prints the exact fix:

```bash
gitsafty doctor          # report
gitsafty doctor --fix    # apply the safe fixes (rewrite hooks, re-register the vault helper)
```

It checks Node.js, git, the global hooks (missing, outdated, or pointing to a GitSafty that was uninstalled or moved), and the GitHub login helper (e.g. it points to a Node.js version that nvm removed). Every GitSafty error also ends with a "💡 What to do" hint, and if GitSafty itself is gone, every `git clone` / `git pull` / `git push` prints how to reinstall or turn it off.

**Can't install or update?**

| npm error | Fix |
|---|---|
| `EACCES` / permission denied | Use a user-owned npm folder: `mkdir -p ~/.npm-global && npm config set prefix ~/.npm-global`, add `~/.npm-global/bin` to `PATH`, install again (Windows: run as Administrator or use nvm-windows) |
| `ENOTFOUND` / `ETIMEDOUT` | Network/proxy: `npm config get registry`, `npm cache verify`, try again |
| `Unexpected token` / engine warning | Node.js too old: install Node 18+ (`nvm install --lts`) |

**Turn GitSafty off without the CLI** (works even when it can't be installed):

```bash
git config --global --unset core.hooksPath
rm -rf ~/.git-hooks-safty                                   # Windows PowerShell: Remove-Item -Recurse -Force "$HOME\.git-hooks-safty"
git config --global --remove-section credential.https://github.com   # only if you used the vault
```

---

## 🛠️ CLI Command Reference

| Command | Description |
|---|---|
| `npx @arifbiswas/git-pre-push init` | Installs the pre-push security hook into `.git/hooks/pre-push` |
| `npx @arifbiswas/git-pre-push init --global` | Protects **all** Git repositories across the entire PC |
| `npx @arifbiswas/git-pre-push scan` | Manually audits local workspace files, untracked scripts & staged diffs |
| `npx @arifbiswas/git-pre-push scan-remote` | **Zero-Clone Audit:** Scans any remote GitHub repo without cloning or downloading |
| `npx @arifbiswas/git-pre-push sweep [folder]` | Scans **every** Git repo under a folder (e.g. your projects folder) and removes confirmed malware |
| `npx @arifbiswas/git-pre-push vault setup` | Keeps the device logged out of GitHub; token is encrypted and unlocked only for each push |
| `npx @arifbiswas/git-pre-push clean` | Unstages and quarantines injected malware files to `.git/git-safty-quarantine/` |
| `npx @arifbiswas/git-pre-push demo` | Simulates a blocked push in terminal |
| `npx @arifbiswas/git-pre-push action` | Generates a `.github/workflows/git-safty.yml` CI workflow |
| `npx @arifbiswas/git-pre-push doctor [--fix]` | Finds broken/outdated installs and shows (or applies) the exact fix |
| `npx @arifbiswas/git-pre-push uninstall` | Cleanly removes the hook from `.git/hooks` |

---

## 🌐 Zero-Clone Remote Repository Scanner (`scan-remote`)

Scan any GitHub repository **without cloning or downloading code to your hard drive**:

```bash
npx @arifbiswas/git-pre-push scan-remote
```

The CLI will prompt you for the GitHub URL:
```text
? Enter GitHub Repository URL: https://github.com/my-org/my-project
```

Or pass the URL directly:
```bash
npx @arifbiswas/git-pre-push scan-remote https://github.com/my-org/my-project
```

**How it works:**
1. Fetches the repository's recursive Git tree metadata via GitHub REST API in **1 single HTTP request**.
2. Performs instant in-memory path matching against all trojan filenames and blacklisted extensions.
3. Only if a suspicious file is discovered, fetches the specific blob directly into RAM for static payload/secret analysis.
4. **0 MB downloaded to disk** — fast, lightweight, and completely bandwidth-friendly.

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
  "strict": false,
  "autoClean": true
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
