/**
 * Checks one piece of content (a file on disk, inside an archive, or fetched
 * from GitHub). Pure: no file system or process access, so it also runs in
 * the browser / Android app.
 */

const { detectMalware } = require('./rules/malware');
const { checkFilename } = require('./rules/filenames');
const { inspectIdeConfig } = require('./rules/ideConfig');

// document.pdf.exe style names, and Windows script/screensaver types that are almost only used by malware.
const DECEPTIVE_NAME = /\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|mp4|mp3|zip|rar)\.(exe|scr|com|bat|cmd|vbs|js|jse|ps1|hta|lnk)$|\.(scr|pif|cpl|hta|vbe|jse|wsf)$/i;
const KNOWN_GOOD_SCRIPTS = new Set(['gradlew.bat', 'mvnw.cmd', 'gradlew', 'mvnw']);

/**
 * @param {string} displayPath path shown to the user (may contain "archive.zip!/inner")
 * @param {string} innerPath real file path, used for type checks
 * @param {Buffer} buf content
 * @returns {Array<object>} findings
 */
function inspectContent(displayPath, innerPath, buf, { names = true } = {}) {
  const out = [];
  for (const f of detectMalware(innerPath, buf)) out.push({ category: 'malware', ...f, filePath: displayPath });
  const base = innerPath.split('/').pop();
  // Only names that are almost never legitimate: plain .exe/.dll/.bin are normal in downloads and app bundles.
  const nameRule = names && !KNOWN_GOOD_SCRIPTS.has(base) ? checkFilename(innerPath) : null;
  if (nameRule && (DECEPTIVE_NAME.test(base) || /^Known malicious/.test(nameRule.rule))) {
    out.push({ category: 'file', verdict: 'SUSPECT', severity: 'CRITICAL', name: nameRule.rule, description: 'Disguised or known-malicious file name.', filePath: displayPath });
  }
  const norm = innerPath.replace(/\\/g, '/');
  if (/(^|\/)\.vscode\/(tasks|settings)\.json$/.test(norm) || /(^|\/)\.idea\/workspace\.xml$/.test(norm)) {
    for (const f of inspectIdeConfig(innerPath, buf.toString('utf8'))) {
      out.push({ category: 'ide', verdict: 'SUSPECT', ...f, filePath: displayPath });
    }
  }
  return out;
}

module.exports = { inspectContent, DECEPTIVE_NAME };
