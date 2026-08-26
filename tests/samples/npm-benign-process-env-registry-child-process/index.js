const childProcess = require('child_process');
const registry = 'https://registry.npmjs.org/';
const environmentKeys = Object.keys(process.env);
childProcess.execFileSync('node', ['--version']);
console.log(registry, environmentKeys.length);
