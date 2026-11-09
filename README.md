# 🛡️ git-pre-push (GitSafty)

> **The Zero-Dependency Pre-Push Security Guard & Malware Blocker for Git.**  
> Stops infostealers, injected Trojan scripts, IDE backdoors, and leaked credentials from ever reaching GitHub or poisoning your software supply chain.

[![npm version](https://img.shields.io/badge/npm-v1.0.0-blue.svg)](https://www.npmjs.com/package/git-pre-push)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(Pure%20Node.js)-brightgreen.svg)](#-zero-external-runtime-dependencies)
[![Tests Passing](https://img.shields.io/badge/tests-15%2F15%20passing-success.svg)](#-test-coverage)

---

## 📌 কেন আপনার এই প্যাকেজটি প্রয়োজন? (Why Do You Need This?)

আজকাল ডেভেলপারদের পিসি প্রায়ই ইনফোস্টিলার (Infostealer) ম্যালওয়্যার দ্বারা আক্রান্ত হয়। পিসিতে একবার ম্যালওয়্যার ঢুকলে তা ব্যাকগ্রাউন্ডে বসে:
1. আপনার কোডবেজে ক্ষতিকর স্ক্রিপ্ট ইনজেক্ট করে (যেমন: `temp_auto_push.bat`, `temp_interactive_push.bat`, `autorun.bat`, `*.ps1`, `*.vbs`)।
2. `.vscode/tasks.json` বা `.vscode/settings.json` ফাইলে ব্যাকডোর তৈরি করে, যাতে অন্য কোনো ডেভেলপার বা আপনি প্রোজেক্ট ওপেন করলেই ম্যালওয়্যার অটো-রান হয়ে যায়।
3. আপনার প্রোজেক্টের `.env` ফাইল বা প্রাইভেট এপিআই কী Discord Webhook বা Telegram Bot-এ পাচার করে।
4. সবচেয়ে মারাত্মক বিষয়: আপনার পিসির সংরক্ষিত GitHub Credentials বা SSH Key ব্যবহার করে **অটোমেটিকভাবে GitHub-এ ম্যালওয়্যার পুশ করে দেয়!**
5. এর ফলে আপনার পুরো টিম এবং ক্লায়েন্টদের সফটওয়্যার সাপ্লাই চেইন (Supply Chain) আক্রান্ত হয়ে পড়ে।

**`git-pre-push` ঠিক এই আক্রমণের বিরুদ্ধেই প্রাচীর হিসেবে কাজ করে।**  
ডেভেলপার টার্মিনাল, VS Code কিংবা যেকোনো Git GUI থেকে `git push` দিলে, কোড GitHub-এ যাওয়ার আগেই মিলিসেকেন্ডের মধ্যে আউটগোয়িং কোড ও ফাইল স্ক্যান করে ম্যালওয়্যার শনাক্ত হওয়া মাত্র **পুশ রিজেক্ট (Hard Block)** করে দেয়!

---

## 🚀 এক নজরে ইনস্টলেশন ও ব্যবহার (Quick Start)

### ১. যেকোনো প্রজেক্টে অটোমেটিক সেটআপ (Recommended)

আপনার প্রজেক্টে প্যাকেজটি ইনস্টল করুন:

```bash
npm install -D git-pre-push
```

> **ম্যাজিক:** ইনস্টল হওয়ার সাথে সাথেই এর `postinstall` স্ক্রিপ্ট আপনার প্রজেক্টের `.git/hooks/pre-push` ফাইলটি স্বয়ংক্রিয়ভাবে তৈরি করে প্রোটেকশন চালু করে দেবে। আপনার আর কোনো ম্যানুয়াল কনফিগারেশন করতে হবে না!

---

### ২. কোনো কিছু ইনস্টল না করে সরাসরি চালানো (Zero Install via npx)

যেকোনো Git রিপোজিটরিতে ঢুকে টার্মিনালে রান করুন:

```bash
npx git-pre-push init
```

ব্যস! আপনার রিপোজিটরি সাথে সাথে সুরক্ষিত।

---

### ৩. আক্রান্ত পিসির সব প্রজেক্ট একসাথে লক করা (Global Protection)

আপনার পিসি যদি অলরেডি কোনো ম্যালওয়্যার দ্বারা আক্রান্ত হয়ে থাকে, তবে একটি কমান্ডেই পিসির সমস্ত গিট রিপোজিটরি সুরক্ষিত করুন:

```bash
npx git-pre-push init --global
```

এটি আপনার সিস্টেমের `git config --global core.hooksPath` সেট করে দেয়, ফলে আপনার পিসির **যেকোনো ফোল্ডার বা প্রজেক্ট** থেকে পুশ দিলে স্বয়ংক্রিয়ভাবে সিকিউরিটি গার্ড সক্রিয় থাকবে।

---

## ⚡ কীভাবে কাজ করে? (Architecture Flow)

```
             ডেভেলপার বা ম্যালওয়্যার রান করলো: git push
                                 │
                                 ▼
             Git ইন্টারসেপ্ট করবে: .git/hooks/pre-push
                                 │
                                 ▼
               🛡️ GitSafty Scanner ইঞ্জিন (< 5ms)
    ┌────────────────────────────────────────────────────────┐
    │ 1. ফাইলনেম ব্লকলিস্ট চেক (temp_*_push.bat, .exe, .ps1)  │
    │ 2. আউটগোয়িং কোড ডিফে ম্যালিসিয়াস পেলোড স্ক্যান       │
    │ 3. .vscode ও .idea ব্যাকডোর কনফিগারেশন চেকিং           │
    │ 4. লিক হওয়া গোপন তথ্য (.env, API Key, Private Key)    │
    └────────────────────────────────────────────────────────┘
                                 │
          ┌──────────────────────┴──────────────────────┐
          ▼                                             ▼
    [ম্যালওয়্যার পাওয়া গেছে]                         [সব ক্লিন আছে]
          │                                             │
   ❌ PUSH REJECTED (Blocked)                    ✅ PUSH ALLOWED
(GitHub-এ ক্ষতিকর কোড যেতে পারবে না)         (নিরাপদে GitHub-এ পুশ হবে)
```

---

## 🎯 আমরা কী কী সমস্যার সমাধান (Solutions) করেছি?

### ১. ইনজেক্টেড ব্যাচ ও ট্রোজান স্ক্রিপ্ট প্রতিরোধ
- `temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `autorun.bat`, `hidden_push.sh`
- বিপজ্জনক এক্সটেনশন: `*.vbs`, `*.ps1`, `*.exe`, `*.scr`, `*.msi`, `*.dll`, `*.hta`
- ছদ্মবেশী ডাবল এক্সটেনশন ব্লকিং (যেমন: `invoice.pdf.exe`)

### ২. অবফাসকেটেড ম্যালওয়্যার পেলোড ও রিভার্স শেল ডিটেকশন
- PowerShell Encoded Commands: `powershell -enc ...`, `powershell -encodedcommand`
- PowerShell Download Cradles: `DownloadString`, `Invoke-WebRequest`, `IEX`
- রিমোট পাইপ এক্সিকিউশন: `curl ... | bash` বা `wget ... | sh`
- ডায়নামিক কোড ইভালুয়েশন: `eval(base64_decode(...))`, `Buffer.from(..., 'base64')`
- Windows LOLBins এক্সপ্লয়েট: `certutil -urlcache`, `bitsadmin /transfer`, `mshta`
- সরাসরি সকেট রিভার্স শেল: `/bin/sh -i >& /dev/tcp/...`, `nc -e /bin/sh`

### ৩. IDE ব্যাকডোর ও অটো-রান টাস্ক প্রতিরোধ
- `.vscode/tasks.json`-এ প্রোজেক্ট ওপেন হওয়ার সাথে সাথে অটো-রান ব্যাকডোর (`runOn: "folderOpen"`) শনাক্ত ও ব্লক।
- `.vscode/settings.json`-এ টার্মিনাল এনভায়রনমেন্ট বা শেল হাইজ্যাকিং প্রতিরোধ।
- JetBrains `.idea/` ফোল্ডারে লুকানো এক্সটার্নাল স্ক্রিপ্ট টাস্ক শনাক্তকরণ।

### ৪. ক্রেডেনশিয়াল চুরি ও ডেটা এক্সফিল্ট্রেশন রোধ
- Discord Webhook টোকেন স্টিলার (`https://discord.com/api/webhooks/...`)
- Telegram Bot API দিয়ে ডেটা চুরি
- পাবলিক ড্রপার বা রিকোয়েস্ট লগার (`webhook.site`, `pipedream`, ইত্যাদি)
- ভুলবশত প্রোডাকশন `.env` ফাইল কমিট হওয়া প্রতিরোধ
- প্রাইভেট ক্রিপ্টোগ্রাফিক কী (`BEGIN RSA PRIVATE KEY`, `ghp_...`, AWS Access Keys)

### ৫. অলরেডি আক্রান্ত পিসি ক্লিন করা (Auto-Quarantine & Fix)
আক্রান্ত পিসিতে ম্যালওয়্যার যেসব ফাইল তৈরি করে রেখেছে, তা খুঁজতে হবে না। সরাসরি রান করুন:
```bash
npx git-pre-push clean
```
এটি সাথে সাথে রিপোজিটরির সব সংক্রামিত ফাইল শনাক্ত করে গিট ইনডেক্স থেকে আনস্টেজ করবে এবং নিরাপদ কোয়ারেন্টাইন ডিরেক্টরিতে (`.git/git-safty-quarantine/`) পাঠিয়ে দেবে।

### ৬. Zero-Bypass CI Defense (GitHub Action)
ম্যালওয়্যার যদি কখনো লোকাল হুক বাইপাস করার জন্য `git push --no-verify` কমান্ড ব্যবহার করে, তবে ক্লাউড লেভেলের সুরক্ষার জন্য রান করুন:
```bash
npx git-pre-push action
```
এটি রিপোজিটরিতে `.github/workflows/git-safty.yml` ফাইল তৈরি করে দেবে। ফলে কেউ লোকাল হুক এড়িয়ে পুশ দিলেও GitHub Actions-এ PR বা পুশ সাথে সাথে ফেইল হয়ে ব্লক হয়ে যাবে।

### ৭. ক্লাউড ও রিমোট রিপোজিটরি স্ক্যানার (Cloud Scanner Engine)
আমরা `server/` ডিরেক্টরিতে একটি সম্পূর্ণ লাইটওয়েট ক্লাউড স্ক্যানার ইঞ্জিন তৈরি করেছি যা GitHub Webhook বা GitHub REST API-এর মাধ্যমে রিমোট রিপোজিটরির ফুল ফাইল ট্রি স্ক্যান করতে পারে এবং ম্যালওয়্যার পাওয়া গেলে স্বয়ংক্রিয়ভাবে `git commit` দিয়ে ফাইল রিমুভ (Auto-Remediation) করতে পারে।

---

## 🛠️ CLI কমান্ড রেফারেন্স (Command Reference)

| কমান্ড | বিবরণ |
|---|---|
| `npx git-pre-push init` | বর্তমান রিপোজিটরিতে লোকাল `pre-push` সিকিউরিটি হুক ইনস্টল করে |
| `npx git-pre-push init --global` | আক্রান্ত পিসির **সবগুলো** গিট প্রজেক্ট একসাথে এক কমান্ডে লক করে |
| `npx git-pre-push scan` | বর্তমান ওয়ার্কস্পেস ও স্টেজড ফাইলে কোনো ম্যালওয়্যার আছে কিনা অডিট করে |
| `npx git-pre-push clean` | ম্যালওয়্যারের ইনজেক্ট করা সব ফাইল কোয়ারেন্টাইনে পাঠিয়ে পিসি সুরক্ষিত করে |
| `npx git-pre-push action` | সার্ভার-সাইড সুরক্ষার জন্য GitHub Actions CI ওয়ার্কফ্লো তৈরি করে |
| `npx git-pre-push uninstall` | রিপোজিটরি থেকে হুকটি পরিষ্কারভাবে রিমুভ করে |

---

## ⚙️ কাস্টম কনফিগারেশন (Optional `.gitsafetyrc.json`)

কোনো স্পেসিফিক ফাইল বা রুল ইগনোর করতে চাইলে রুট ফোল্ডারে `.gitsafetyrc.json` তৈরি করতে পারেন (বাই ডিফল্ট কোনো কনফিগারেশন ছাড়াই এটি সেরা পারফরম্যান্সে চলে):

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

## 💎 কেন `git-pre-push` অন্যান্য টুলস থেকে আলাদা?

| ফিচার | সাধারণ লিন্টার / হুক্স | git-pre-push |
|---|:---:|:---:|
| **Zero Runtime Dependencies** | ❌ (শতাধিক ডিপেনডেন্সি) | ✅ (১০০% পিওর Node.js built-ins) |
| **সাপ্লাই চেইন রিস্ক** | ⚠️ রয়েছে | 🛡️ শূন্য (কোনো থার্ড পার্টি প্যাকেজ নেই) |
| **এক্সিকিউশন টাইম** | 🐢 ১ - ৩ সেকেন্ড | ⚡ < ৫ মিলিসেকেন্ড |
| **Infostealer ম্যালওয়্যার ব্লকিং** | ❌ নেই | ✅ ফুল ব্লকলিস্ট ও সিগনেচার ডিটেকশন |
| **IDE ব্যাকডোর চেকার (.vscode)** | ❌ নেই | ✅ ইনবিল্ট স্বয়ংক্রিয় অ্যানালাইসিস |
| **গ্লোবাল পিসি প্রোটেকশন (`--global`)** | ❌ নেই | ✅ এক কমান্ডেই পুরো পিসির সব প্রজেক্ট লক |
| **ইনফেক্টেড ফাইল কোয়ারেন্টাইন (`clean`)** | ❌ নেই | ✅ স্বয়ংক্রিয়ভাবে ক্লিনআপ |
| **শেল ফলব্যাক সাপোর্ট** | ❌ নেই | ✅ Node না থাকলেও শেল স্ক্রিপ্ট প্রটেক্ট করে |

---

## 🧪 টেস্ট কভারেজ (Test Coverage)

আমাদের টেস্ট স্যুট সম্পূর্ণ Node.js নেটিভ টেস্ট রানার দিয়ে পরিচালিত:

```bash
npm test
```
```
✔ Filename & Extension Checks (4 tests)
✔ Payload Signatures Detection (5 tests)
✔ Secret & Credential Checks (3 tests)
✔ IDE Configuration Tampering (2 tests)
✔ Hook Installer and Uninstaller (1 test)

ℹ tests 15 | pass 15 | fail 0 | duration_ms ~160ms
```

---

## 📄 লাইসেন্স (License)

MIT License © 2026

---

**Made with 🛡️ to protect developers, teams, and the open-source software supply chain.**
