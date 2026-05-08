const payload = {
  node: process.version,
  platform: process.platform,
};

fetch("https://telemetry.example.com/install", {
  method: "POST",
  body: JSON.stringify(payload),
});
