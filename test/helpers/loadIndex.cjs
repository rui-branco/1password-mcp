// Loads index.js as a module for unit tests: the MCP SDK is stubbed so no
// stdio transport opens, and the home dir is a throwaway one so the config
// read at load time is never the user's real one.

const fs = require("fs");
const os = require("os");
const path = require("path");

function stub(request, exports) {
  const file = require.resolve(request);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

function loadIndex(config) {
  const captured = {};
  stub("@modelcontextprotocol/sdk/server/index.js", {
    Server: class {
      constructor(info, options) {
        captured.info = info;
        captured.options = options;
        return { setRequestHandler: () => {}, connect: () => Promise.resolve() };
      }
    },
  });
  stub("@modelcontextprotocol/sdk/types.js", {
    ListToolsRequestSchema: "ListToolsRequestSchema",
    CallToolRequestSchema: "CallToolRequestSchema",
  });
  stub("@modelcontextprotocol/sdk/server/stdio.js", {
    StdioServerTransport: class {},
  });

  const home = fs.mkdtempSync(path.join(os.tmpdir(), "op-mcp-unit-"));
  process.on("exit", () => {
    try {
      fs.rmSync(home, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  if (config) {
    const dir = path.join(home, ".config", "1password-mcp");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify(config));
  }
  // The update check at load time must not reach the registry from a test.
  globalThis.fetch = async () => {
    throw new Error("offline in tests");
  };
  return { home, server: captured, index: require("../../index.js") };
}

module.exports = { loadIndex };
