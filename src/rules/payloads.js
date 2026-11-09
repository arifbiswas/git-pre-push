/**
 * Malicious payload signatures for outgoing commit diff and content inspection
 */

const PAYLOAD_SIGNATURES = [
  // 1. PowerShell execution & download cradles
  {
    name: 'PowerShell Obfuscated/Encoded Execution',
    regex: /powershell(\.exe)?\s+(-[a-z]*e[a-z]*|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{10,}/i,
    severity: 'CRITICAL',
    description: 'Encoded PowerShell command execution commonly used by droppers.'
  },
  {
    name: 'PowerShell Web Download Cradle',
    regex: /(invoke-webrequest|invoke-restmethod|downloadstring|downloadfile)\s*\(?['"][^'"]*https?:\/\//i,
    severity: 'CRITICAL',
    description: 'PowerShell downloading remote scripts or binaries.'
  },
  {
    name: 'PowerShell IEX Execution Cradle',
    regex: /iex\s*\(?(new-object\s+net\.webclient|invoke-webrequest|irm|curl)/i,
    severity: 'CRITICAL',
    description: 'PowerShell IEX download-and-execute cradle.'
  },

  // 2. Shell download & pipe to bash / sh
  {
    name: 'Remote Pipe to Shell',
    regex: /(curl|wget)\s+[^|\n]+(\|\s*(ba)?sh|\|\s*python|\|\s*perl)/i,
    severity: 'CRITICAL',
    description: 'Piping remote web content directly into shell interpreter.'
  },

  // 3. Obfuscated evaluation & decoding
  {
    name: 'Obfuscated Base64 Eval',
    regex: /eval\s*\(\s*(base64_decode|atob|Buffer\.from\([^)]*base64)/i,
    severity: 'CRITICAL',
    description: 'Dynamic execution of base64 decoded string.'
  },
  {
    name: 'PowerShell Base64 Decode',
    regex: /\[System\.Convert\]::FromBase64String/i,
    severity: 'WARNING',
    description: 'Base64 decoding in PowerShell script.'
  },

  // 4. Windows Lolbins / Dropper tools
  {
    name: 'Certutil Remote Cache Download',
    regex: /certutil(\.exe)?\s+(-urlcache|-f|-split)/i,
    severity: 'CRITICAL',
    description: 'Certutil abuse to download external payloads.'
  },
  {
    name: 'Bitsadmin Download Transfer',
    regex: /bitsadmin(\.exe)?\s+\/transfer/i,
    severity: 'CRITICAL',
    description: 'Bitsadmin background transfer abuse.'
  },
  {
    name: 'MSHTA Remote Script Execution',
    regex: /mshta(\.exe)?\s+(http|vbscript|javascript):/i,
    severity: 'CRITICAL',
    description: 'MSHTA executing remote scripts.'
  },
  {
    name: 'Rundll32 Remote DLL Execution',
    regex: /rundll32(\.exe)?\s+javascript:/i,
    severity: 'CRITICAL',
    description: 'Rundll32 abuse executing script protocols.'
  },

  // 5. Reverse shells
  {
    name: 'TCP Reverse Shell Pattern',
    regex: /((\/bin\/sh|\/bin\/bash)\s+-i\s+>&?\s*\/dev\/tcp\/|0<&196;exec\s+196<>\/dev\/tcp\/|nc(\.traditional)?\s+-[a-z0-9]*e\s+(\/bin\/sh|\/bin\/bash|cmd\.exe))/i,
    severity: 'CRITICAL',
    description: 'Direct interactive reverse shell socket invocation.'
  },

  // 6. Suspicious Exfiltration Endpoints in scripts
  {
    name: 'Discord Webhook Exfiltration Candidate',
    regex: /https:\/\/discord(app)?\.com\/api\/webhooks\/[0-9]{15,22}\/[A-Za-z0-9_-]{50,80}/i,
    severity: 'CRITICAL',
    description: 'Discord webhook URL commonly used by infostealers to dump credentials.'
  },
  {
    name: 'Telegram Bot Token in Outgoing Diff',
    regex: /https:\/\/api\.telegram\.org\/bot[0-9]{8,12}:[A-Za-z0-9_-]{35}/i,
    severity: 'CRITICAL',
    description: 'Telegram Bot Token used to transmit stolen logs.'
  },
  {
    name: 'Public Exfiltration Service Hook',
    regex: /https?:\/\/(webhook\.site|requestbin\.(com|net)|pipedream\.net|filebin\.net)\/[a-z0-9-]+/i,
    severity: 'WARNING',
    description: 'Temporary upload or webhook logging service detected.'
  }
];

/**
 * Scans content (diff or file text) for payload signatures
 * @param {string} content 
 * @param {string} [filePath]
 * @returns {Array<{ name: string, severity: 'CRITICAL' | 'WARNING', description: string, line: string, lineNumber?: number }>}
 */
function scanPayloads(content, filePath = '') {
  const findings = [];
  if (!content) return findings;

  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // In a unified git diff, only check added lines (+) or entire file if scanning full content
    if (content.startsWith('diff --git') && !line.startsWith('+')) {
      continue;
    }
    // Ignore the +++ file headers in git diff
    if (line.startsWith('+++')) continue;

    const cleanLine = line.startsWith('+') ? line.slice(1).trim() : line.trim();
    if (!cleanLine) continue;

    for (const signature of PAYLOAD_SIGNATURES) {
      if (signature.regex.test(cleanLine)) {
        findings.push({
          name: signature.name,
          severity: signature.severity,
          description: signature.description,
          line: cleanLine.slice(0, 160),
          lineNumber: i + 1,
          filePath
        });
      }
    }
  }

  return findings;
}

module.exports = {
  PAYLOAD_SIGNATURES,
  scanPayloads
};

