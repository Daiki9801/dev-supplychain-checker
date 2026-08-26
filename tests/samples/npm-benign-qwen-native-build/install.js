const { spawnSync } = require('child_process');
spawnSync('node-gyp-build', [], { stdio: 'inherit' });
