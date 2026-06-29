const solana = require("@solana/web3.js");

function readAnnouncement(connection, keyText) {
  const key = new solana.PublicKey(keyText);
  return connection.getAccountInfo(key);
}

module.exports = { readAnnouncement };
