const fs = require('fs');
const childProcess = require('child_process');
const releaseCredentialName = process.env.NPM_TOKEN;
const manifest = JSON.parse(fs.readFileSync('package.json', 'utf8'));
manifest.version = '1.0.1';
fs.writeFileSync('package.json', JSON.stringify(manifest));
childProcess.execFileSync('npm', ['publish']);
