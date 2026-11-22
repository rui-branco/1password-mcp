"use strict";

// ============================================================================
// One approval for everything (desktop-app auth)
//
// The 1Password desktop app approves each calling PROCESS on its own, and an
// approval ends after ten quiet minutes. MCP clients start one server per chat
// (or per project folder), so every one of them made the app ask again; on
// Windows that is the Windows Hello / password popup each time.
//
// The broker is ONE detached background process that owns the SDK client.
// Every server process, and the `read` command, hands its desktop-auth calls
// to it over a local pipe, so the app sees a single caller and asks once.
//
// This file is the plumbing only and knows nothing about 1Password:
//   - endpointFor / loadKey   where the pipe is and the secret both ends share
//   - serve / request / start the pipe protocol (JSON lines, both ends prove
//                             they hold the key before anything is sent)
//   - createKeeper            when an approval is kept alive and when it is
//                             let go
// ============================================================================

const net = require("net");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");

const PROTOCOL = 1;
const MAX_LINE = 64 * 1024 * 1024;
const HANDSHAKE_MS = 5000;
const CONNECT_MS = 2000;
const START_MS = 8000;

// 1Password ends an approval after ten minutes without a request.
const LAPSE_MS = 10 * 60 * 1000;
// Past this much quiet the approval is treated as ended and is never touched
// again: a request then could only make the app ask the user, unprompted.
const STALE_MS = LAPSE_MS - 30 * 1000;
// A kept approval is refreshed once it has been quiet this long.
const PING_AFTER_MS = 4 * 60 * 1000;
// The same hard limit 1Password CLI puts on an approval.
const MAX_HOLD_MS = 12 * 60 * 60 * 1000;
// With no server connected and no call for this long, nobody is there to use
// the approval and it is no longer refreshed. An hour bridges the gaps in a
// working day (a client stops the servers of chats that sit idle) without
// holding 1Password open for a computer nobody is using it from.
const UNUSED_MS = 60 * 60 * 1000;

/**
 * Where the broker listens: a named pipe on Windows, a socket file elsewhere.
 * The name carries the config dir (one broker per user profile, and a test's
 * throwaway home gets its own) and the package version (after an update the
 * new servers start a new broker instead of talking to old code).
 */
function endpointFor(configDir, version) {
  const dir = path.resolve(configDir);
  const id = crypto
    .createHash("sha256")
    .update(`${process.platform === "win32" ? dir.toLowerCase() : dir}|${version}`)
    .digest("hex")
    .slice(0, 16);
  if (process.platform === "win32") return `\\\\.\\pipe\\1password-mcp-${id}`;
  const inConfig = path.join(dir, `broker-${id}.sock`);
  // A socket path holds about 104 bytes on macOS and 108 on Linux.
  if (Buffer.byteLength(inConfig) <= 100) return inConfig;
  return path.join(os.tmpdir(), `1password-mcp-${id}.sock`);
}

/**
 * The secret the broker and its callers prove to each other. It lives in the
 * config dir with the same 0600 protection as the config itself, so only this
 * user's processes can talk to the broker, and a stranger holding the pipe
 * name cannot pose as it.
 */
function loadKey(configDir) {
  const file = path.join(configDir, "broker.key");
  for (let attempt = 0; attempt < 3; attempt++) {
    let exists = false;
    try {
      const hex = fs.readFileSync(file, "utf8").trim();
      if (/^[0-9a-f]{64}$/.test(hex)) return Buffer.from(hex, "hex");
      exists = true;
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
    // Write the whole key beside the target first, then link it into place:
    // linking fails when another process got there first, so nobody ever
    // reads a half written key and two starters end up with the same one.
    fs.mkdirSync(configDir, { recursive: true });
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}`;
    fs.writeFileSync(tmp, crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
    try {
      if (exists) fs.renameSync(tmp, file); // unreadable content: replace it
      else fs.linkSync(tmp, file);
    } catch (e) {
      // EEXIST: someone else just created it, read theirs on the next pass.
      // Anything else (a filesystem without hard links): fall back to a move.
      if (e.code !== "EEXIST") {
        try {
          fs.renameSync(tmp, file);
        } catch {
          /* read whatever is there on the next pass */
        }
      }
    } finally {
      try {
        fs.unlinkSync(tmp);
      } catch {
        /* already moved into place */
      }
    }
  }
  throw new Error("could not read or create the broker key");
}

function proof(key, who, clientNonce, brokerNonce) {
  return crypto
    .createHmac("sha256", key)
    .update(`${who}|${clientNonce}|${brokerNonce}`)
    .digest("hex");
}

function sameProof(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** Calls onMessage for every JSON line the socket receives. */
function onMessages(sock, onMessage) {
  let buf = "";
  sock.setEncoding("utf8");
  sock.on("data", (chunk) => {
    buf += chunk;
    if (buf.length > MAX_LINE) return sock.destroy();
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        return sock.destroy();
      }
      onMessage(msg);
    }
  });
}

/** True when something accepts connections on the endpoint. */
function answers(endpoint) {
  return new Promise((resolve) => {
    const sock = net.connect(endpoint);
    const done = (alive) => {
      clearTimeout(timer);
      sock.destroy();
      resolve(alive);
    };
    const timer = setTimeout(() => done(true), 1000);
    sock.on("connect", () => done(true));
    sock.on("error", () => done(false));
  });
}

function listenOnce(server, endpoint) {
  return new Promise((resolve, reject) => {
    const onError = (e) => {
      server.removeListener("listening", onListening);
      reject(e);
    };
    const onListening = () => {
      server.removeListener("error", onError);
      if (process.platform !== "win32") {
        try {
          fs.chmodSync(endpoint, 0o600);
        } catch {
          /* the umask below already kept it private */
        }
      }
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    // A socket file is created with the process umask: keep it to this user.
    const umask = process.platform === "win32" ? null : process.umask(0o177);
    try {
      server.listen(endpoint);
    } finally {
      if (umask !== null) process.umask(umask);
    }
  });
}

async function listen(server, endpoint) {
  try {
    await listenOnce(server, endpoint);
  } catch (e) {
    // A broker that died without cleaning up leaves its socket file behind,
    // and the name then looks taken although nobody listens. A pipe on
    // Windows vanishes with its process, so there the name really is taken.
    if (e.code !== "EADDRINUSE" || process.platform === "win32") throw e;
    if (await answers(endpoint)) throw e;
    try {
      fs.unlinkSync(endpoint);
    } catch {
      /* gone already */
    }
    await listenOnce(server, endpoint);
  }
}

/**
 * Starts the broker's listener. Rejects when the endpoint is already served
 * (another broker is up), which the caller treats as "not needed".
 *
 * `handle(msg)` answers one request. `onPresence(sock, msg)` receives the
 * connection of a caller that stays connected to say "I am still running".
 *
 * `server.calls` holds every caller that connected and has no answer yet. A
 * broker about to leave checks it, so it never walks out on a caller that has
 * already handed over its request.
 */
async function serve({ endpoint, key, version, handle, onPresence }) {
  const calls = new Set();
  const server = net.createServer((sock) => {
    calls.add(sock);
    let stage = 0;
    let clientNonce;
    let brokerNonce;
    const timer = setTimeout(() => sock.destroy(), HANDSHAKE_MS);
    const send = (msg) => {
      if (!sock.destroyed) sock.write(`${JSON.stringify(msg)}\n`);
    };
    sock.on("error", () => {});
    sock.on("close", () => {
      clearTimeout(timer);
      calls.delete(sock);
    });
    onMessages(sock, (msg) => {
      if (stage === 0) {
        if (!msg || msg.v !== PROTOCOL || typeof msg.nonce !== "string") {
          return sock.destroy();
        }
        clientNonce = msg.nonce;
        brokerNonce = crypto.randomBytes(16).toString("hex");
        stage = 1;
        return send({
          v: PROTOCOL,
          nonce: brokerNonce,
          proof: proof(key, "broker", clientNonce, brokerNonce),
          pid: process.pid,
          version,
        });
      }
      if (stage !== 1) return; // one request per connection
      if (!msg || !sameProof(msg.proof, proof(key, "client", clientNonce, brokerNonce))) {
        return sock.destroy();
      }
      clearTimeout(timer);
      stage = 2;
      if (msg.method === "presence") {
        calls.delete(sock);
        send({ ok: true });
        if (onPresence) onPresence(sock, msg);
        return;
      }
      Promise.resolve()
        .then(() => handle(msg))
        .then(
          (reply) => send(reply),
          (e) => send({ ok: false, error: (e && e.message) || String(e) }),
        )
        .then(() => sock.end());
    });
  });
  server.calls = calls;
  await listen(server, endpoint);
  return server;
}

/**
 * Sends one request to the broker and resolves with its reply.
 *
 * A rejection carries `sent`: false means the request never left (nobody
 * listens, or the listener is not ours), so the caller may safely do the work
 * itself; true means the broker had it and went away, so doing it again could
 * repeat a change.
 */
function request({ endpoint, key, payload, keepOpen = false, connectMs = CONNECT_MS }) {
  return new Promise((resolve, reject) => {
    const clientNonce = crypto.randomBytes(16).toString("hex");
    let stage = 0;
    let sent = false;
    let settled = false;
    let brokerInfo = null;
    const sock = net.connect(endpoint);
    const fail = (code, message) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      reject(Object.assign(new Error(message), { code, sent }));
    };
    const timer = setTimeout(
      () => fail("EUNREACHABLE", "the shared 1Password process did not answer"),
      connectMs,
    );
    sock.on("connect", () => {
      sock.write(`${JSON.stringify({ v: PROTOCOL, nonce: clientNonce })}\n`);
    });
    sock.on("error", (e) => fail(sent ? "ELOST" : "EUNREACHABLE", e.message));
    sock.on("close", () =>
      fail(sent ? "ELOST" : "EUNREACHABLE", "the shared 1Password process closed the connection"),
    );
    onMessages(sock, (msg) => {
      if (stage === 0) {
        const ours =
          msg &&
          msg.v === PROTOCOL &&
          typeof msg.nonce === "string" &&
          sameProof(msg.proof, proof(key, "broker", clientNonce, msg.nonce));
        if (!ours) return fail("EAUTH", "the process on the broker pipe is not ours");
        clearTimeout(timer);
        brokerInfo = { pid: msg.pid, version: msg.version };
        stage = 1;
        sock.write(
          `${JSON.stringify({ ...payload, proof: proof(key, "client", clientNonce, msg.nonce) })}\n`,
        );
        sent = true;
        return;
      }
      if (settled) return;
      settled = true;
      if (!keepOpen) sock.end();
      resolve({ reply: msg, broker: brokerInfo, sock: keepOpen ? sock : null });
    });
  });
}

/**
 * Starts a broker process and waits until it answers. Detached with no stdio,
 * so it outlives the server that started it (that server belongs to one chat)
 * and never holds the MCP client's pipes open. Its folder is the home dir so
 * it does not keep a project folder locked on Windows.
 */
async function start({ endpoint, key, entry, waitMs = START_MS }) {
  const child = spawn(process.execPath, [entry, "--broker"], {
    detached: true,
    stdio: "ignore",
    windowsHide: true,
    cwd: os.homedir(),
  });
  child.on("error", () => {});
  child.unref();
  const until = Date.now() + waitMs;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 100));
    try {
      await request({ endpoint, key, payload: { method: "ping" }, connectMs: 1000 });
      return true;
    } catch (e) {
      if (e.code === "EAUTH") return false;
    }
  }
  return false;
}

/**
 * Decides, per 1Password account, whether the approval is kept alive.
 *
 * An approval is refreshed (one cheap request) while all of these hold:
 *   - keeping is on (`keepAuthorized`), and a refresh can be made without any
 *     chance of the app asking the user (`canPing`)
 *   - somebody is there to use it: a server is connected (`inUse`), or one
 *     was, or a call came in (`wanted`), within the last hour
 *   - the approval is younger than twelve hours
 * Otherwise it simply runs out by 1Password's own ten minute rule. Once it
 * has run out, or a refresh fails (the app locked, quit or was updated), the
 * account is dropped: the next real call asks the user, a refresh never does.
 *
 * `tick()` resolves to true while any account is still worth staying up for.
 */
function createKeeper({
  now = Date.now,
  ping,
  drop,
  canPing = () => true,
  inUse = () => true,
  keepAuthorized = () => true,
  speed = 1,
}) {
  // `speed` runs the clock faster for the tests of the real process.
  const staleMs = STALE_MS / speed;
  const pingAfterMs = PING_AFTER_MS / speed;
  const maxHoldMs = MAX_HOLD_MS / speed;
  const unusedMs = UNUSED_MS / speed;
  const accounts = new Map(); // account → { authorizedAt, lastOkAt }
  let lastWantedAt = now();
  return {
    accounts,
    /** A caller asked for something just now. */
    wanted() {
      lastWantedAt = now();
    },
    /**
     * The app just let a request, or a new client, for this account through.
     * The first time after `expired` counts as the approval; the twelve
     * hours run from there and nothing later stretches them, because a
     * process that is already approved gets new clients without the user
     * being asked.
     */
    used(account) {
      if (!account) return;
      const known = accounts.get(account);
      if (known) known.lastOkAt = now();
      else accounts.set(account, { authorizedAt: now(), lastOkAt: now() });
    },
    /** The app reported this account's session gone. */
    expired(account) {
      accounts.delete(account);
    },
    async tick() {
      if (inUse()) lastWantedAt = now();
      for (const [account, state] of [...accounts]) {
        const quiet = now() - state.lastOkAt;
        if (quiet > staleMs) {
          accounts.delete(account);
          drop(account, "the approval ran out");
          continue;
        }
        const keep =
          keepAuthorized() &&
          canPing(account) &&
          now() - lastWantedAt < unusedMs &&
          now() - state.authorizedAt < maxHoldMs;
        if (!keep || quiet < pingAfterMs) continue;
        try {
          await ping(account);
          state.lastOkAt = now();
        } catch (e) {
          accounts.delete(account);
          drop(account, `the approval ended (${(e && e.message) || e})`);
        }
      }
      return accounts.size > 0;
    },
  };
}

/** Appends timestamped lines to a small log file, rolled over once. */
function logger(file, maxBytes = 512 * 1024) {
  return (line) => {
    try {
      try {
        if (fs.statSync(file).size > maxBytes) fs.renameSync(file, `${file}.1`);
      } catch {
        /* no log yet */
      }
      fs.appendFileSync(file, `${new Date().toISOString()} ${line}\n`, { mode: 0o600 });
    } catch {
      /* logging must never break a call */
    }
  };
}

module.exports = {
  endpointFor,
  loadKey,
  serve,
  request,
  start,
  createKeeper,
  logger,
  LAPSE_MS,
  STALE_MS,
  PING_AFTER_MS,
  MAX_HOLD_MS,
  UNUSED_MS,
};
