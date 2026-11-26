// No external programs on a phone: 7z/rar archives are reported as "could not be opened".
module.exports = { spawnSync: () => ({ error: new Error('not available on this device') }), execSync: () => { throw new Error('not available'); } };
