const childProcess = require('child_process');
const configuredBinary = process.env.ESBUILD_BINARY_PATH;
childProcess.execFileSync('node', ['--version']);
