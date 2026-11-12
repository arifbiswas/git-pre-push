/**
 * Terminal output for `gitsafty vault <sub>` (shared by the CLI and the menu).
 */

const { colors } = require('./reporter');
const { printHint } = require('./doctor');

/**
 * @param {string} sub setup | status | test | remove
 * @param {{ host?: string, passphrase?: boolean }} [options]
 * @returns {Promise<number>} exit code
 */
async function runVaultCommand(sub = 'status', { host, passphrase = false } = {}) {
  const vault = require('./vault');
  sub = String(sub || 'status').toLowerCase();

  if (sub === 'setup' || sub === 'on' || sub === 'enable') {
    const res = await vault.setupVault({ host: host || 'github.com', mode: passphrase ? 'passphrase' : 'auto' });
    if (!res.success) {
      console.error(`\n${colors.red}${colors.bold}✖ ${res.message}${colors.reset}`);
      printHint(new Error(res.message));
      return 1;
    }
    console.log(`\n${colors.green}${colors.bold}✔ ${res.message}${colors.reset}`);
    for (const step of res.steps) console.log(`  ${colors.dim}•${colors.reset} ${step}`);
    for (const key of res.sshWarnings) {
      console.log(`\n${colors.yellow}⚠ SSH key without passphrase: ${key}${colors.reset}`);
      console.log(`  ${colors.dim}Anyone who copies it can push as you. Protect it: ${colors.reset}ssh-keygen -p -f ${key}`);
    }
    console.log('');
    return 0;
  }

  if (sub === 'test') {
    const res = vault.testUnlock();
    console.log(`\n${res.success ? colors.green + '✔' : colors.red + '✖'} ${res.message}${colors.reset}\n`);
    if (!res.success) printHint(new Error(res.message));
    return res.success ? 0 : 1;
  }

  if (sub === 'remove' || sub === 'off' || sub === 'disable') {
    const res = vault.removeVault({ host });
    console.log(`\n${colors.yellow}${colors.bold}✔ ${res.message}${colors.reset}\n`);
    return 0;
  }

  const st = vault.vaultStatus({ host });
  const ok = (b) => (b ? `${colors.green}✔` : `${colors.red}✖`) + colors.reset;
  console.log(`\n${colors.bold}GitSafty Vault (${st.host})${colors.reset}`);
  console.log(`  ${ok(st.vaultExists)} Encrypted token vault ${st.vaultExists ? `(${st.username}, file mode ${st.vaultMode})` : '(not set up: run gitsafty vault setup)'}`);
  if (st.vaultExists) {
    const hw = st.protection !== 'passphrase';
    console.log(`  ${ok(hw)} Locked to this device's security chip ${hw ? `(${st.protection})` : '(passphrase only: run vault setup again on a Mac with Secure Enclave or Windows with Hello)'}`);
  }
  if (st.tokenExpiresAt) console.log(`    ${colors.dim}Token expires: ${st.tokenExpiresAt}${colors.reset}`);
  console.log(`  ${ok(st.helperActive)} GitSafty is git's credential helper for ${st.host}`);
  console.log(`  ${ok(st.otherHelpers.length === 0)} No other helper can store or hand out a token${st.otherHelpers.length ? `: ${st.otherHelpers.join(', ')}` : ''}`);
  console.log(`  ${ok(st.sshWarnings.length === 0)} SSH private keys are passphrase-protected${st.sshWarnings.length ? `: ${st.sshWarnings.join(', ')}` : ''}`);
  console.log('');
  return 0;
}

module.exports = { runVaultCommand };
