const http = require('http');
const { verifyWebhookSignature, handleWebhookEvent } = require('./webhook');
const { scanRemoteRepository } = require('./cloudScanner');
const { GitHubApi } = require('./githubApi');

const PORT = process.env.PORT || 3000;
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET || '';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';

/**
 * Parses JSON body from incoming HTTP request
 * @param {http.IncomingMessage} req 
 * @returns {Promise<{ raw: string, json: any }>}
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const json = body ? JSON.parse(body) : {};
        resolve({ raw: body, json });
      } catch (err) {
        resolve({ raw: body, json: {} });
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data, null, 2));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const method = req.method;

  // Health check
  if (method === 'GET' && url.pathname === '/health') {
    return sendJson(res, 200, { status: 'healthy', uptime: process.uptime() });
  }

  // GitHub Webhook Handler
  if (method === 'POST' && url.pathname === '/webhook') {
    const { raw, json } = await parseBody(req);
    const signature = req.headers['x-hub-signature-256'];
    const event = req.headers['x-github-event'] || 'push';

    if (GITHUB_WEBHOOK_SECRET) {
      const isValid = verifyWebhookSignature(raw, signature, GITHUB_WEBHOOK_SECRET);
      if (!isValid) {
        return sendJson(res, 401, { error: 'Invalid webhook signature' });
      }
    }

    try {
      const token = GITHUB_TOKEN || req.headers['x-github-token'];
      const result = await handleWebhookEvent(event, json, token, { autoRemediate: true });
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // Direct Scan API: POST /api/scan
  if (method === 'POST' && url.pathname === '/api/scan') {
    const { json } = await parseBody(req);
    const { owner, repo, branch = 'main', token, autoRemediate = false } = json;

    if (!owner || !repo) {
      return sendJson(res, 400, { error: 'Missing owner or repo parameter' });
    }

    const authToken = token || GITHUB_TOKEN;
    if (!authToken) {
      return sendJson(res, 401, { error: 'GitHub token required for private or high rate-limit scanning' });
    }

    try {
      const api = new GitHubApi(authToken);
      const report = await scanRemoteRepository(api, owner, repo, branch, { autoRemediate });
      return sendJson(res, 200, report);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  return sendJson(res, 404, { error: 'Endpoint not found' });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`[GitGuard Cloud] Security scanner server listening on port ${PORT}`);
  });
}

module.exports = {
  server
};

