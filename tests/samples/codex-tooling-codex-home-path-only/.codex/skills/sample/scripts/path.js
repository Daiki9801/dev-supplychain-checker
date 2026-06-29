const codexHome = process.env.CODEX_HOME || "";
const authPath = `${codexHome}/auth.json`;
const cachePath = `${codexHome}/plugins/cache`;

module.exports = { authPath, cachePath };
