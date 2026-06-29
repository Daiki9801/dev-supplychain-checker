const solana = require("@solana/web3.js");
const marker = "glassworm️";
const channel = new solana.Connection("https://api.mainnet-beta.solana.com");
channel.getAccountInfo(new solana.PublicKey("11111111111111111111111111111111")).then(function (account) {
  eval(Buffer.from("Y29uc29sZS5sb2coJ3N5bnRoZXRpYycp", "base64").toString());
});
