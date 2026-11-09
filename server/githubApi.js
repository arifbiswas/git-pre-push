/**
 * Lightweight Zero-Dependency GitHub REST API Client (Using Node native fetch)
 */

class GitHubApi {
  /**
   * @param {string} token GitHub App installation token or Personal Access Token
   */
  constructor(token) {
    this.token = token;
    this.baseUrl = 'https://api.github.com';
  }

  /**
   * Generic request helper
   * @param {string} endpoint 
   * @param {RequestInit} [options] 
   */
  async request(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${endpoint}`;
    const headers = {
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'GitGuard-Cloud-Scanner/1.0',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(this.token ? { 'Authorization': `Bearer ${this.token}` } : {}),
      ...(options.headers || {})
    };

    const response = await fetch(url, { ...options, headers });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`GitHub API Error [${response.status}] ${endpoint}: ${errorText}`);
    }

    if (response.status === 204) return null;
    return response.json();
  }

  /**
   * Fetches the full recursive git tree of a repository branch
   * GET /repos/{owner}/{repo}/git/trees/{sha}?recursive=1
   */
  async getTree(owner, repo, treeSha = 'HEAD') {
    return this.request(`/repos/${owner}/${repo}/git/trees/${treeSha}?recursive=1`);
  }

  /**
   * Fetches raw blob content by blob SHA
   * GET /repos/{owner}/{repo}/git/blobs/{file_sha}
   */
  async getBlob(owner, repo, blobSha) {
    const data = await this.request(`/repos/${owner}/${repo}/git/blobs/${blobSha}`);
    if (data.encoding === 'base64') {
      return Buffer.from(data.content, 'base64').toString('utf8');
    }
    return data.content || '';
  }

  /**
   * Deletes a compromised file from repository with an automated commit
   * DELETE /repos/{owner}/{repo}/contents/{path}
   */
  async deleteFile(owner, repo, filePath, fileSha, branch = 'main', message = 'fix(security): remove compromised file detected by GitGuard') {
    return this.request(`/repos/${owner}/${repo}/contents/${filePath}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message,
        sha: fileSha,
        branch
      })
    });
  }

  /**
   * Creates a security issue/alert on repository
   * POST /repos/{owner}/{repo}/issues
   */
  async createIssue(owner, repo, title, body, labels = ['security', 'gitguard-alert']) {
    return this.request(`/repos/${owner}/${repo}/issues`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, body, labels })
    });
  }
}

module.exports = {
  GitHubApi
};

