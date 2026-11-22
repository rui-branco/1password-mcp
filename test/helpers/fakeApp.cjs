// Preloaded (node --require) into real server processes by the tests. Unlike
// fakeSdk.cjs the REAL 1Password SDK runs here; only its last step, the
// native call into the desktop app, is played by this file. That keeps the
// SDK's own behaviour in the test, above all that it goes back to the app for
// a new approval by itself when a session is gone.
//
// The stand-in app follows the real one's rules as far as they matter:
//   - a process with no session has to be approved ("prompt" in the log; in
//     the real app the user is asked there), and approving unlocks the app
//   - an approved process is not asked again
//   - locking the app ends every session; a request on an ended session is
//     answered with the SDK's session-expired error or, as the real app does
//     once it has dropped a client, a plain "invalid client id"
//     (OP_MCP_TEST_LOCK_ANSWER=invalid-client-id)
//   - it answers one request at a time, keeps one more waiting and refuses a
//     third with "IPC operation failed: -2"
// The lock state is the file in OP_MCP_TEST_APP_STATE, which a test flips.

const fs = require("fs");
const path = require("path");

const LOG = process.env.OP_MCP_TEST_SDK_LOG;
const STATE = process.env.OP_MCP_TEST_APP_STATE;
const APPROVE_MS = Number(process.env.OP_MCP_TEST_APPROVE_MS || 0);
const PLAIN_ANSWER = process.env.OP_MCP_TEST_LOCK_ANSWER === "invalid-client-id";

function note(event, extra) {
  fs.appendFileSync(LOG, `${JSON.stringify({ event, pid: process.pid, ...extra })}\n`);
}

function locked() {
  try {
    return fs.readFileSync(STATE, "utf8").trim() === "locked";
  } catch {
    return false;
  }
}

// A server looks for a newer version on npm when it starts and installs it.
// A test must never do that, so the registry is unreachable in here.
globalThis.fetch = async () => {
  throw new Error("offline in tests");
};

// The desktop app's own library is never loaded, on a machine that has it too.
const dlopen = process.dlopen;
process.dlopen = function (mod, filename, ...rest) {
  if (/op_sdk_ipc_client/i.test(String(filename))) {
    throw new Error("no desktop app in tests");
  }
  return dlopen.call(this, mod, filename, ...rest);
};
// The SDK reports that on stderr for every client; not worth showing.
const error = console.error;
console.error = (...args) => {
  if (String(args[0]).includes("loading the native addon")) return;
  error(...args);
};

const sdk = require("@1password/sdk");
const { SharedLibCore } = require(
  path.join(path.dirname(require.resolve("@1password/sdk")), "shared_lib_core.js"),
);

const VAULTS = [
  { id: "v1", title: "Shared" },
  { id: "v2", title: "Private" },
];

const sessions = new Set(); // client ids this PROCESS holds an approved session for
let nextId = 1;

// The real app answers one request at a time and keeps one more waiting. A
// third that arrives meanwhile is refused at once (measured against it: of 6
// calls started together, 4 came back "IPC operation failed: -2" in 10 ms).
let inApp = 0;
let appTurn = Promise.resolve();

async function throughApp(work) {
  if (inApp >= 2) throw new Error("IPC operation failed: -2");
  inApp++;
  const mine = appTurn.then(async () => {
    await new Promise((r) => setTimeout(r, 15));
    return work();
  });
  appTurn = mine.catch(() => {});
  try {
    return await mine;
  } finally {
    inApp--;
  }
}

SharedLibCore.prototype.callSharedLibrary = function (input, kind) {
  if (kind !== "init_client" && kind !== "invoke") return Promise.resolve(""); // release_client
  return throughApp(() => answer.call(this, input, kind));
};

async function answer(input, kind) {
  const account = this.acccountName;
  if (kind === "init_client") {
    if (locked() || sessions.size === 0) {
      note("prompt", { account });
      if (APPROVE_MS) await new Promise((r) => setTimeout(r, APPROVE_MS));
      fs.writeFileSync(STATE, "unlocked");
    }
    const id = String(nextId++);
    sessions.add(id);
    return id;
  }
  if (kind === "invoke") {
    const { clientId, parameters } = JSON.parse(input).invocation;
    if (locked()) sessions.clear();
    if (!sessions.has(String(clientId))) {
      if (PLAIN_ANSWER) throw new Error("invalid client id");
      throw new sdk.DesktopSessionExpiredError("desktop session expired");
    }
    note("request", { account, name: parameters.name });
    if (parameters.name === "VaultsList") return JSON.stringify(VAULTS);
    return "[]";
  }
  return "";
}
