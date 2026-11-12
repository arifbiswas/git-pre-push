const fs = require('fs');
const path = require('path');

const WORKFLOW_YAML = `name: GitSafty Security Guard

on:
  push:
    branches: [ "**" ]
  pull_request:
    branches: [ "**" ]

jobs:
  security-scan:
    name: Scan Outgoing Commits for Malware & Secrets
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Run GitSafty Security Audit
        # Scoped package name: an unscoped "git-safty" does not exist on npm
        # and could be registered by anyone.
        run: |
          npx --yes @arifbiswas/git-pre-push scan --no-clean
`;

/**
 * Creates .github/workflows/git-safty.yml for defense in depth
 * @param {string} [cwd] 
 * @returns {{ success: boolean, message: string }}
 */
function setupGitHubAction(cwd = process.cwd()) {
  try {
    const workflowDir = path.join(cwd, '.github', 'workflows');
    if (!fs.existsSync(workflowDir)) {
      fs.mkdirSync(workflowDir, { recursive: true });
    }

    const workflowFile = path.join(workflowDir, 'git-safty.yml');
    fs.writeFileSync(workflowFile, WORKFLOW_YAML.trim() + '\n', 'utf8');

    return {
      success: true,
      message: `Created GitHub Actions workflow at: ${workflowFile}`
    };
  } catch (err) {
    return {
      success: false,
      message: `Failed to create GitHub Action: ${err.message}`
    };
  }
}

module.exports = {
  setupGitHubAction,
  WORKFLOW_YAML
};

