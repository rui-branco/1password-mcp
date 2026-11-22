// Starts real `index.js` processes in a throwaway home, with the 1Password
// SDK swapped for the stand-in (fakeSdk.cjs), and talks MCP to them.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const ENTRY = path.join(__dirname, "..", "..", "index.js");
// What stands in for 1Password: the whole SDK ("sdk"), or only the desktop
// app behind the real SDK ("app").
const STAND_INS = {
  sdk: path.join(__dirname, "fakeSdk.cjs"),
  app: path.join(__dirname, "fakeApp.cjs"),
};

/**
 * A home dir of its own: the config, the broker's pipe and key all derive
 * from it, so nothing here can meet the user's real setup.
 */
function sandbox(config, { standIn = "sdk", env: extraEnv } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "op-mcp-"));
  const configDir = path.join(home, ".config", "1password-mcp");
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(path.join(configDir, "config.json"), JSON.stringify(config));
  const sdkLog = path.join(home, "sdk-calls.jsonl");
  fs.writeFileSync(sdkLog, "");
  const appState = path.join(home, "app-state");
  fs.writeFileSync(appState, "unlocked");
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    OP_MCP_TEST_SDK_LOG: sdkLog,
    OP_MCP_TEST_APP_STATE: appState,
    // Forward slashes: NODE_OPTIONS treats a backslash as an escape.
    NODE_OPTIONS: `--require "${STAND_INS[standIn].replace(/\\/g, "/")}"`,
    ...extraEnv,
  };
  return {
    home,
    configDir,
    env,
    /** Locks the stand-in desktop app, as 1Password does by itself when idle. */
    lockApp() {
      fs.writeFileSync(appState, "locked");
    },
    /**
     * Makes the stand-in app fail every request with a passing IPC error
     * (true) or work again (false), without ending any session.
     */
    glitchApp(on) {
      fs.writeFileSync(appState, on ? "glitch" : "unlocked");
    },
    /** What the stand-in SDK recorded, in order. */
    sdkCalls() {
      return fs
        .readFileSync(sdkLog, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line));
    },
    brokerLog() {
      try {
        return fs.readFileSync(path.join(configDir, "broker.log"), "utf8");
      } catch {
        return "";
      }
    },
    setConfig(next) {
      fs.writeFileSync(path.join(configDir, "config.json"), JSON.stringify(next));
    },
    /** Deletes the home dir, once its processes have let go of it. */
    async remove() {
      for (let attempt = 0; attempt < 20; attempt++) {
        try {
          fs.rmSync(home, { recursive: true, force: true });
          return;
        } catch {
          await new Promise((r) => setTimeout(r, 100));
        }
      }
    },
  };
}

/** One MCP server process, as an MCP client would start it. */
function startServer(box, { cwd, env } = {}) {
  const child = spawn(process.execPath, [ENTRY], {
    cwd: cwd || box.home,
    env: { ...box.env, ...env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let buf = "";
  let nextId = 1;
  const waiting = new Map();
  let stderr = "";
  child.stderr.on("data", (d) => {
    stderr += d;
  });
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      const msg = JSON.parse(line);
      const done = waiting.get(msg.id);
      if (done) {
        waiting.delete(msg.id);
        done(msg);
      }
    }
  });
  const rpc = (method, params) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(
        () => reject(new Error(`no answer to ${method}; stderr: ${stderr}`)),
        20000,
      );
      waiting.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  const exited = new Promise((resolve) => child.on("exit", resolve));
  return {
    pid: child.pid,
    async init() {
      const answer = await rpc("initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "test", version: "0" },
      });
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`,
      );
      return answer.result;
    },
    /** Calls a tool and returns { text, isError }. */
    async call(name, args = {}) {
      const answer = await rpc("tools/call", { name, arguments: args });
      if (answer.error) throw new Error(answer.error.message);
      return {
        text: answer.result.content.map((c) => c.text).join(""),
        isError: !!answer.result.isError,
      };
    },
    /** Ends it the way a client does when its chat closes. */
    async stop() {
      child.kill();
      await exited;
    },
  };
}

/** Runs `index.js read ...` to the end. */
function runRead(box, args) {
  const out = spawnSync(process.execPath, [ENTRY, "read", ...args], {
    cwd: box.home,
    env: box.env,
    encoding: "utf8",
    timeout: 30000,
  });
  return { status: out.status, stdout: out.stdout, stderr: out.stderr };
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM";
  }
}

async function until(check, ms = 10000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await check()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}

module.exports = { ENTRY, sandbox, startServer, runRead, alive, until };
