/* Exposes a small, fixed API to the UI. The page gets no Node.js access. */
const { contextBridge, ipcRenderer } = require('electron');

function withProgress(channel, args, onProgress) {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const listener = (_e, msg) => {
    if (msg.id === id && typeof onProgress === 'function') onProgress(msg.done, msg.total, msg.label);
  };
  ipcRenderer.on('progress', listener);
  return ipcRenderer.invoke(channel, { ...args, progressId: id }).finally(() => ipcRenderer.removeListener('progress', listener));
}

contextBridge.exposeInMainWorld('gitsafty', {
  info: () => ipcRenderer.invoke('info'),
  status: () => ipcRenderer.invoke('status'),
  setProtection: (on) => ipcRenderer.invoke('set-protection', { on }),
  setPullScan: (on) => ipcRenderer.invoke('set-pull-scan', { on }),
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  pickFiles: () => ipcRenderer.invoke('pick-files'),
  scan: (mode, target, onProgress) => withProgress('scan', { mode, target }, onProgress),
  removeMalware: (id) => ipcRenderer.invoke('remove-malware', { id }),
  scanGitHub: (url, token, onProgress) => withProgress('scan-github', { url, token }, onProgress),
  doctor: (fix) => ipcRenderer.invoke('doctor', { fix })
});
