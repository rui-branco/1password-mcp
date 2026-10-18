// serverInfo.icons for the MCP handshake: the logo in 1Password's own blue,
// sent twice in the same colour, for light backgrounds and for dark ones.
// assets/icon.svg is the 1Password logo from Simple Icons v13.21.0
// (https://simpleicons.org), CC0-1.0.
const fs = require("fs");
const path = require("path");

const SVG = fs.readFileSync(path.join(__dirname, "assets", "icon.svg"), "utf8").trim();

function icon(fill, theme) {
  const svg = SVG.replace('fill="#000000"', `fill="${fill}"`);
  return {
    src: `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`,
    mimeType: "image/svg+xml",
    sizes: ["any"],
    theme,
  };
}

const ICONS = [icon("#3B66BC", "light"), icon("#3B66BC", "dark")];

module.exports = { ICONS };
