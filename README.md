# GitSafty (`@arifbiswas/git-pre-push`)

Protects your code and your GitHub account from malware, without changing how you work.

[![npm version](https://img.shields.io/npm/v/@arifbiswas/git-pre-push.svg?style=flat-square)](https://www.npmjs.com/package/@arifbiswas/git-pre-push)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey.svg?style=flat-square)](#)

---

## What you get

- **Malware never reaches GitHub.** Every `git push` is checked. A push with malware is stopped before it leaves your computer.
- **Infected projects are cleaned for you.** After every `git clone` and `git pull`, the project is checked and malware that GitSafty is sure about is removed automatically. Anything it is not 100% sure about is only reported, never touched.
- **Your `.env` stays private.** If a push contains a `.env` file, GitSafty takes it out, adds it to `.gitignore`, and pushes your code without it.
- **Your GitHub login can't be stolen.** With safe login on, your computer stays logged out of GitHub. Each push asks for Touch ID, Windows Hello or a password, and logs out again.
- **Check everything at once.** Scan a whole folder of projects, your Downloads, zip/rar files, or a GitHub repo before you clone it.
- **Backups of everything removed**, and a clear report of what was found and what was done.
- Works with the terminal, VS Code and any git app, on macOS, Windows and Linux. No extra packages are installed.

---

## Install (2 minutes)

You need [Node.js](https://nodejs.org) 18 or newer and git.

```bash
npm install -g @arifbiswas/git-pre-push
```

```bash
gitsafty init --global
```

That's it. Every git project on this computer is now protected.

- Use `-g`. Without it GitSafty only lands inside one project and the `gitsafty` command does not exist. If you forget, GitSafty asks to install itself globally the first time it runs.
- **Windows: `'gitsafty' is not recognized`?** Open a new terminal. Still not found? Add the folder shown by `npm config get prefix` to your `Path`.
- `init --global` also turns on the check for pulls that say *"Already up to date"*. Open a new terminal once so it takes effect.

Protect only one project instead:

```bash
cd my-project
gitsafty init
```

---

## The menu

Run `gitsafty` with nothing after it:

```text
What do you want to do?

  Protect your code
   1. Protect this project               Check every push, clone and pull in this project
   2. Protect all projects on this PC    Same, for every git project on this computer
   3. Scan every git pull                On by default, also "Already up to date". Turn off/on
   4. Remove protection                  Uninstall GitSafty from this project or this PC

  Scan and clean
   5. Scan this project                  Find malware here and remove it automatically
   6. Scan all projects in a folder      Malware, hidden backdoors and leaked passwords/keys
   7. Scan everything in a folder        Also zip/rar files and folders that are not git projects
   8. Scan all git repos under a folder  Quick malware check, e.g. your whole disk
   9. Clean this project                 Move malware files in this project to quarantine
  10. Scan a GitHub repo before cloning  Check a GitHub link without downloading it

  Safe GitHub login (stay logged out)
  11. Turn on safe GitHub login          Touch ID / Windows Hello / password before every push
  12. Check safe login status            See if your GitHub login is protected
  13. Test safe login                    Try the unlock prompt once
  14. Turn off safe login                Go back to normal git login

  Help and tools
  15. Fix problems                       Find what is broken and how to fix it
  16. Check for updates                  Install the newest GitSafty
  17. Add GitSafty to GitHub Actions     Check every push on GitHub too
  18. See a demo                         Show what a blocked push looks like

   0. Exit
```

Everything in the menu is also a command, listed below.

---

## Everyday use

After `gitsafty init --global` you don't need to do anything. Use git as usual:

| You run | GitSafty does |
|---|---|
| `git push` | Checks what you push. Blocks malware and leaked secrets. Takes `.env` files out and pushes without them. |
| `git clone` | Checks the new project and removes confirmed malware right away. |
| `git pull` | Checks the project again after new code arrives. |

When something is removed, you see what it was and where the backup is. Files inside a project are changed only in your working folder: check `git status`, then commit the clean version.

### Scan every pull (on by default)

Git runs nothing when a pull says *"Already up to date"*, so GitSafty adds a small `git` helper to your shell profile (`.zshrc`, `.bashrc`, fish or PowerShell) that checks those pulls too. It is **on by default** with the global install, and existing installs get it after updating. Open a new terminal once so it takes effect.

Don't want it? Turn it off. GitSafty remembers this and never turns it back on by itself:

```bash
gitsafty pull-scan off
```

```bash
gitsafty pull-scan on
```

Menu option **3** does the same. Pulls that bring new code are always checked, even with this off.

---

## Scanning

### This project

```bash
gitsafty scan
```

Checks the whole project and removes confirmed malware. Add `--no-clean` to only report. Menu **5**.

### All projects in a folder

```bash
gitsafty scan-projects ~/projects
```

```bash
gitsafty scan-projects ~/projects --clean
```

For a folder with many projects. For each project it reports malware, hidden backdoors (things that run code when you open the project or use git), and passwords or API keys written in the code. At the end you get a table per project: what was found, what was removed, and what you still need to look at, with the command to fix it. Only `--clean` removes anything. Menu **6**.

- `--deep` also checks `node_modules` and ignored files.
- `--json` gives machine-readable output.

### Everything in a folder, zip files too

```bash
gitsafty full-scan ~/Downloads
```

```bash
gitsafty full-scan ~/Downloads --clean
```

Checks every file, also folders that are not git projects, and the files **inside** zip, rar, 7z, tar.gz, jar, apk and similar archives, without unpacking them. Use it for downloads, old backups or a project someone sent you as a zip. `node_modules`, `vendor` and other downloaded packages are skipped. With `--clean`, an infected archive is moved to quarantine. Menu **7**.

### All git repos on your disk

```bash
gitsafty sweep ~
```

A fast malware check of every git repository under a folder. Menu **8**.

### A GitHub repo before you clone it

```bash
gitsafty scan-remote https://github.com/owner/repo
```

Nothing is downloaded to your disk. Menu **10**.

---

## Your `.env` file never gets pushed

If you commit a `.env` (or `.env.local`, `.env.production` …) and push, GitSafty:

1. Stops that push.
2. Adds `.env` to `.gitignore`. `.env.example` stays allowed.
3. Takes the `.env` out of git, including a `.env` that git kept tracking even though it was already in `.gitignore`. The file stays on your computer.
4. Removes it from your commits that were not pushed yet.
5. Pushes your code without it.

Git then shows `failed to push` for the first attempt, the one that still had the `.env`. That is expected: your code is already on GitHub without it.

If a `.env` was pushed **before** you used GitSafty, it is removed from GitHub with your next push, but old versions can still be seen in the history. **Change the passwords and keys in it.**

---

## Safe GitHub login

Malware on a computer usually steals saved logins. With safe login on, there is no saved GitHub login to steal.

```bash
gitsafty vault setup
```

1. Paste a GitHub token once. GitSafty stores it encrypted and locks it to this computer's security chip.
2. Your other saved GitHub logins are removed.
3. On every push you confirm with **Touch ID or your Mac password** (macOS), **Windows Hello** (Windows), or a passphrase (Linux / no chip). After the push you are logged out again.
4. A prompt you did not expect means someone else is trying to push: press Cancel.

The token file is useless on any other computer.

```bash
gitsafty vault status
```

```bash
gitsafty vault test
```

```bash
gitsafty vault remove
```

Tips:

- Use a fine-grained token that expires and only has access to the repos you need.
- Safe login covers HTTPS remotes. If you push over SSH, give your SSH key a passphrase: `ssh-keygen -p -f ~/.ssh/id_ed25519`.

---

## Protect the repository on GitHub too

Someone can skip local checks with `git push --no-verify`. Add the same check to GitHub Actions:

```bash
gitsafty action
```

This adds `.github/workflows/git-safty.yml`. Commit and push it. Menu **17**.

---

## Updates

When you open `gitsafty` it tells you if a new version is out and asks `Install now? (Y/n)`. Or update yourself:

```bash
npm install -g @arifbiswas/git-pre-push
```

npm 11 may print `install scripts not yet covered by allowScripts`. The update still worked. GitSafty finishes its setup by itself the next time it runs.

---

## Something not working?

```bash
gitsafty doctor
```

It finds what is wrong and shows the exact fix. `gitsafty doctor --fix` applies the safe fixes. Menu **15**.

| Problem | Fix |
|---|---|
| `EACCES` / permission denied while installing | `mkdir -p ~/.npm-global && npm config set prefix ~/.npm-global`, add `~/.npm-global/bin` to your `PATH`, install again. Windows: run the terminal as Administrator. |
| `ENOTFOUND` / `ETIMEDOUT` | Network or proxy problem: check your connection and try again. |
| Errors about the Node version | Install Node.js 18 or newer. |

**Turn GitSafty off without the `gitsafty` command:**

```bash
git config --global --unset core.hooksPath
```

```bash
rm -rf ~/.git-hooks-safty
```

On Windows PowerShell: `Remove-Item -Recurse -Force "$HOME\.git-hooks-safty"`.

If you used safe login, also run:

```bash
git config --global --remove-section credential.https://github.com
```

---

## All commands

| Command | What it does |
|---|---|
| `gitsafty` | Open the menu |
| `gitsafty init --global` | Protect every project on this computer |
| `gitsafty init` | Protect only this project |
| `gitsafty uninstall` | Remove protection from this project (`--global` for the whole computer) |
| `gitsafty pull-scan off` / `on` | Check pulls that say "Already up to date" (on by default) |
| `gitsafty scan` | Scan this project and remove confirmed malware |
| `gitsafty scan-projects <folder>` | Scan all projects in a folder (`--clean`, `--deep`, `--json`) |
| `gitsafty full-scan <folder or file>` | Scan everything, including zip/rar files and non-git folders (`--clean`, `--json`) |
| `gitsafty sweep <folder>` | Quick malware check of every git repo under a folder |
| `gitsafty scan-remote <github url>` | Scan a GitHub repo without downloading it |
| `gitsafty clean` | Move malware files in this project to quarantine |
| `gitsafty vault setup` / `status` / `test` / `remove` | Safe GitHub login |
| `gitsafty action` | Add the check to GitHub Actions |
| `gitsafty doctor` | Find and fix problems (`--fix`) |
| `gitsafty demo` | Show a blocked push |

Using `npx` instead of a global install? Put `npx @arifbiswas/git-pre-push` in place of `gitsafty`.

---

## Settings (optional)

Nothing to set up. To change a project's behaviour, add `.gitsafetyrc.json` to the project folder:

```json
{
  "ignoreFiles": ["tests/fixtures/sample-payload.js"],
  "autoClean": true,
  "envGuard": true,
  "envGuardAutoPush": true
}
```

| Setting | Meaning |
|---|---|
| `ignoreFiles` | Files to skip for name and secret checks (for example test files). Malware checks always run. |
| `autoClean` | `false` = report malware but don't remove it. |
| `envGuard` | `false` = don't take `.env` files out of pushes. |
| `envGuardAutoPush` | `false` = take the `.env` out, but let you run `git push` again yourself. |

Backups of removed files are kept in `.git/gitsafty-quarantine/` inside the project, or in `~/.gitsafty/quarantine/` for full scans. Reports are saved in `~/.gitsafty/reports/`.

---

## License

MIT
