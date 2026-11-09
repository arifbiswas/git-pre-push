const fs = require('fs');
const readline = require('readline');

/**
 * Asks the user an interactive confirmation prompt, even when process.stdin was redirected
 * @param {string} questionText 
 * @returns {Promise<boolean>}
 */
async function promptUser(questionText) {
  // If non-interactive environment (CI/CD), skip prompt
  if (process.env.CI || process.env.CONTINUOUS_INTEGRATION || !process.stdout.isTTY) {
    return true;
  }

  let inputHandle;
  try {
    const ttyDevice = process.platform === 'win32' ? 'CONIN$' : '/dev/tty';
    inputHandle = fs.openSync(ttyDevice, 'r');
  } catch (err) {
    // If /dev/tty or CONIN$ fails, fallback to process.stdin if it is TTY
    if (process.stdin.isTTY) {
      inputHandle = process.stdin;
    } else {
      return true;
    }
  }

  const inputStream = typeof inputHandle === 'number' ? new fs.ReadStream('', { fd: inputHandle }) : inputHandle;

  const rl = readline.createInterface({
    input: inputStream,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(questionText, (answer) => {
      rl.close();
      if (typeof inputHandle === 'number') {
        try {
          fs.closeSync(inputHandle);
        } catch (_) {}
      }
      const trimmed = answer.trim().toLowerCase();
      resolve(trimmed === 'y' || trimmed === 'yes');
    });
  });
}

module.exports = {
  promptUser
};

