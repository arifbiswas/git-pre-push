const crypto = require('crypto');
const { scanRemoteRepository } = require('./cloudScanner');
const { GitHubApi } = require('./githubApi');

/**
 * Verifies GitHub webhook HMAC SHA256 signature
 * @param {string} payload 
 * @param {string} signatureHeader 
 * @param {string} secret 
 * @returns {boolean}
 */
function verifyWebhookSignature(payload, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;

  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payload, 'utf8');
  const expected = 'sha256=' + hmac.digest('hex');

  try {
    return crypto.timingSafeEqual(Buffer.from(signatureHeader), Buffer.from(expected));
  } catch (_) {
    return false;
  }
}

/**
 * Handles incoming GitHub webhook payload
 * @param {any} event 
 * @param {any} payload 
 * @param {string} githubToken 
 * @param {{ autoRemediate?: boolean }} [options] 
 */
async function handleWebhookEvent(event, payload, githubToken, options = { autoRemediate: true }) {
  if (event === 'ping') {
    return { status: 'ok', message: 'Pong! Webhook connected.' };
  }

  // Handle Push Event
  if (event === 'push') {
    const repository = payload.repository;
    if (!repository) return { status: 'ignored', message: 'No repository info' };

    const owner = repository.owner.name || repository.owner.login;
    const repo = repository.name;
    const branch = (payload.ref || 'refs/heads/main').replace('refs/heads/', '');

    const api = new GitHubApi(githubToken);
    const scanResult = await scanRemoteRepository(api, owner, repo, branch, options);

    return {
      status: 'success',
      event: 'push',
      scanResult
    };
  }

  return { status: 'ignored', message: `Event ${event} not handled` };
}

module.exports = {
  verifyWebhookSignature,
  handleWebhookEvent
};

