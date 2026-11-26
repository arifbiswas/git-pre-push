# GitSafty apps (developer guide)

This folder holds the desktop app (Electron) and the Android app (Capacitor). Both use the same UI and the same scan engine as the npm package.

## Layout

- `ui/`: shared UI (plain HTML, CSS and JS). It talks only to `window.gitsafty`.
- `engine/normalize.js`: turns engine results into one shape that the UI can read.
- `desktop/`: Electron app.
  - `main.js`: window and IPC.
  - `preload.js`: the `window.gitsafty` API.
  - `worker.js`: runs scans in a worker thread.
  - `scripts/prepare.js`: copies the repo `src/`, `app/engine` and `app/ui` into the app folder.
  - `scripts/dist.js`: builds the installers with the package version.
  - `scripts/make-icon.js`: writes `build/icon.png`.
  - `scripts/smoke.js`: development check. It clicks through the app and saves screenshots.
- `mobile/`: Android app with Capacitor 6.
  - `mobile-api.js`: the `window.gitsafty` API for the phone.
  - `build.js`: bundles the engine with esbuild into `www/`. It replaces Node built-ins with files in `shims/`: crypto is pure JS SHA-256, zlib is pako, and child_process, fs and os are stubs.
  - `scripts/android-icon.js`: writes the launcher icons.
- `icon.js`: draws the app icon PNG at any size.

## Design rule

The desktop app scans with its bundled engine. Protection (git hooks, pull scan, doctor) always runs the installed `gitsafty` command. Hooks never point inside the app folder, because that path changes on every app update.

## Desktop app

Run in development:

```bash
cd app/desktop
```

```bash
npm install
```

```bash
npm start
```

With npm 11, Electron's download script may be blocked. If so, run this once:

```bash
node node_modules/electron/install.js
```

Build installers for the current OS. Output goes to `app/desktop/dist/`:

```bash
npm run dist
```

Smoke check. It scans the folder you give and saves screenshots:

```bash
SMOKE_DIR=<folder to scan> SMOKE_OUT=<folder for screenshots> npx electron scripts/smoke.js
```

Add `SMOKE_REMOVE=1` to also press Remove.

## Android app

You need JDK 17 and the Android SDK.

```bash
cd app/mobile
```

```bash
npm install
```

```bash
node build.js
```

First time only:

```bash
npx cap add android
```

```bash
node scripts/android-icon.js
```

```bash
npx cap sync android
```

```bash
cd android && ./gradlew assembleDebug
```

The APK is at `android/app/build/outputs/apk/debug/app-debug.apk`.

The `android/` and `www/` folders are generated. They are not committed.

### Try the phone UI in a browser

After `node build.js`, serve `app/mobile/www` with any static server, for example:

```bash
python3 -m http.server 8765 -d app/mobile/www
```

Open it in a browser at phone width.

## Releases

`.github/workflows/apps.yml` runs after each successful npm publish. You can also run it by hand. It builds:

- macOS: arm64 and x64 dmg
- Windows: nsis exe
- Linux: AppImage and deb
- Android: debug-signed APK

It uploads them to the GitHub Release `vX.Y.Z`. The builds are unsigned.

## Known limits

Keep this list. It is for the next developer.

- Safe GitHub login setup is terminal-only.
- The apps are unsigned.
- Android cannot open 7z or rar files.
- The Android APK is debug-signed.
- There is no iOS app.
