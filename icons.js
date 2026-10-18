// serverInfo.icons for the MCP handshake: the 1Password app's own icon
// (silver and blue rings, dark keyhole), sent once as a 48px PNG with no
// theme. assets/icon.png comes from the 1Password Windows app package
// (Square44x44Logo, targetsize-48, unplated).
const fs = require("fs");
const path = require("path");

const PNG = fs.readFileSync(path.join(__dirname, "assets", "icon.png"));

const ICONS = [
  {
    src: `data:image/png;base64,${PNG.toString("base64")}`,
    mimeType: "image/png",
    sizes: ["48x48"],
  },
];

module.exports = { ICONS };
