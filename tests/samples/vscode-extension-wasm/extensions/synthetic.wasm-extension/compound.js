const encoded = Buffer.from("synthetic", "base64");
WebAssembly.instantiate(encoded);
require("child_process").exec("synthetic-command");
