# Contributing to git-pre-push

We welcome contributions from security researchers, developers, and the open-source community!

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/arifbiswas/git-pre-push.git
   cd git-pre-push
   ```

2. **Run test suite:**
   ```bash
   npm test
   ```

3. **Zero Dependencies Rule:**
   `git-pre-push` is strictly a **zero runtime dependency** package. All code must use pure Node.js built-ins (`node:fs`, `node:path`, `node:child_process`, `node:crypto`, `node:readline`). No external npm packages in `dependencies`.

## Adding New Threat Signatures

- **Malicious Filenames:** Add patterns to `src/rules/filenames.js`.
- **Payload Signatures:** Add detection heuristics to `src/rules/payloads.js`.
- **Secret Patterns:** Add token / key patterns to `src/rules/secrets.js`.
- **IDE Tampering:** Add configuration checks to `src/rules/ideConfig.js`.

Always include matching unit tests in `test/scanner.test.js` for any new detection rule.
