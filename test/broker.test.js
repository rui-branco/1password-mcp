const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const net = require("net");

const broker = require("../broker.js");

const POSIX = process.platform !== "win32";
const MINUTE = 60 * 1000;

const tmpDirs = [];
function tmpDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "op-mcp-broker-"));
  tmpDirs.push(dir);
  return dir;
}
process.on("exit", () => {
  for (const dir of tmpDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* a socket in it is still closing */
    }
  }
});

async function until(check, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return false;
}

// ---------------------------------------------------------------------------
// Where the broker listens
// ---------------------------------------------------------------------------

describe("endpointFor", () => {
  it("is stable for one config dir and version", () => {
    const dir = tmpDir();
    assert.equal(broker.endpointFor(dir, "1.0.0"), broker.endpointFor(dir, "1.0.0"));
  });

  it("differs per version, so updated servers never talk to old code", () => {
    const dir = tmpDir();
    assert.notEqual(broker.endpointFor(dir, "1.0.0"), broker.endpointFor(dir, "1.0.1"));
  });

  it("differs per config dir, so a throwaway home gets its own broker", () => {
    assert.notEqual(
      broker.endpointFor(tmpDir(), "1.0.0"),
      broker.endpointFor(tmpDir(), "1.0.0"),
    );
  });

  it("is a named pipe on Windows and a socket file elsewhere", () => {
    const endpoint = broker.endpointFor(tmpDir(), "1.0.0");
    if (POSIX) assert.match(endpoint, /\.sock$/);
    else assert.match(endpoint, /^\\\\\.\\pipe\\1password-mcp-[0-9a-f]{16}$/);
  });

  it("stays within the socket path limit for a deep config dir", { skip: !POSIX }, () => {
    const deep = path.join(os.tmpdir(), "a".repeat(60), "b".repeat(60));
    const endpoint = broker.endpointFor(deep, "1.0.0");
    assert.ok(Buffer.byteLength(endpoint) <= 100, endpoint);
  });
});

// ---------------------------------------------------------------------------
// The shared key
// ---------------------------------------------------------------------------

describe("loadKey", () => {
  it("creates a 32 byte key and returns the same one afterwards", () => {
    const dir = tmpDir();
    const first = broker.loadKey(dir);
    assert.equal(first.length, 32);
    assert.deepEqual(broker.loadKey(dir), first);
  });

  it("creates the config dir when it is missing", () => {
    const dir = path.join(tmpDir(), "not", "there", "yet");
    assert.equal(broker.loadKey(dir).length, 32);
  });

  it("keeps the key file to this user", { skip: !POSIX }, () => {
    const dir = tmpDir();
    broker.loadKey(dir);
    const mode = fs.statSync(path.join(dir, "broker.key")).mode & 0o777;
    assert.equal(mode, 0o600);
  });

  it("replaces a key file it cannot use", () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, "broker.key"), "not a key");
    const key = broker.loadKey(dir);
    assert.equal(key.length, 32);
    assert.deepEqual(broker.loadKey(dir), key);
  });

  it("leaves no temporary files behind", () => {
    const dir = tmpDir();
    broker.loadKey(dir);
    assert.deepEqual(fs.readdirSync(dir), ["broker.key"]);
  });
});

// ---------------------------------------------------------------------------
// The pipe
// ---------------------------------------------------------------------------

describe("serve and request", () => {
  const open = [];
  after(() => {
    for (const server of open) server.close();
  });

  async function up(handle, extra = {}) {
    const dir = tmpDir();
    const link = { endpoint: broker.endpointFor(dir, "t"), key: broker.loadKey(dir) };
    const sockets = new Set();
    const server = await broker.serve({ ...link, version: "9.9.9", handle, ...extra });
    server.on("connection", (s) => sockets.add(s));
    open.push(server);
    return { ...link, dir, server, sockets };
  }

  it("answers a request and says who answered", async () => {
    const link = await up(async (msg) => ({ ok: true, text: `ran ${msg.name}` }));
    const { reply, broker: info } = await broker.request({
      ...link,
      payload: { method: "tool", name: "op_list_vaults" },
    });
    assert.deepEqual(reply, { ok: true, text: "ran op_list_vaults" });
    assert.equal(info.pid, process.pid);
    assert.equal(info.version, "9.9.9");
  });

  it("hands the handler the caller's arguments", async () => {
    let got;
    const link = await up(async (msg) => {
      got = msg;
      return { ok: true };
    });
    await broker.request({
      ...link,
      payload: { method: "tool", name: "x", args: { vault: "Shared" }, from: { pid: 7 } },
    });
    assert.equal(got.method, "tool");
    assert.deepEqual(got.args, { vault: "Shared" });
    assert.deepEqual(got.from, { pid: 7 });
  });

  it("turns a handler that throws into an error reply", async () => {
    const link = await up(async () => {
      throw new Error("Vault not found.");
    });
    const { reply } = await broker.request({ ...link, payload: { method: "tool" } });
    assert.deepEqual(reply, { ok: false, error: "Vault not found." });
  });

  it("carries a large reply whole", async () => {
    const big = "x".repeat(3 * 1024 * 1024);
    const link = await up(async () => ({ ok: true, text: big }));
    const { reply } = await broker.request({ ...link, payload: { method: "tool" } });
    assert.equal(reply.text.length, big.length);
  });

  it("serves several callers at once", async () => {
    const link = await up(async (msg) => {
      await new Promise((r) => setTimeout(r, 30));
      return { ok: true, text: String(msg.n) };
    });
    const replies = await Promise.all(
      [1, 2, 3, 4, 5].map((n) => broker.request({ ...link, payload: { method: "tool", n } })),
    );
    assert.deepEqual(replies.map((r) => r.reply.text), ["1", "2", "3", "4", "5"]);
  });

  it("reports nobody listening as not sent", async () => {
    const dir = tmpDir();
    await assert.rejects(
      broker.request({
        endpoint: broker.endpointFor(dir, "t"),
        key: broker.loadKey(dir),
        payload: { method: "ping" },
      }),
      (e) => e.code === "EUNREACHABLE" && e.sent === false,
    );
  });

  it("does not send the request to a listener that lacks the key", async () => {
    let ran = false;
    const link = await up(async () => {
      ran = true;
      return { ok: true };
    });
    const otherKey = broker.loadKey(tmpDir());
    await assert.rejects(
      broker.request({ ...link, key: otherKey, payload: { method: "tool", args: { secret: 1 } } }),
      (e) => e.code === "EAUTH" && e.sent === false,
    );
    assert.equal(ran, false);
  });

  it("never shows the request to a stranger holding the pipe name", async () => {
    const dir = tmpDir();
    const endpoint = broker.endpointFor(dir, "t");
    const received = [];
    const stranger = net.createServer((sock) => {
      sock.setEncoding("utf8");
      sock.on("error", () => {});
      sock.on("data", (d) => {
        received.push(d);
        // Answers the greeting like a broker would, without the key.
        sock.write(`${JSON.stringify({ v: 1, nonce: "00", proof: "ff", pid: 1, version: "x" })}\n`);
      });
    });
    await new Promise((resolve) => stranger.listen(endpoint, resolve));
    open.push(stranger);
    await assert.rejects(
      broker.request({
        endpoint,
        key: broker.loadKey(dir),
        payload: { method: "tool", args: { value: "the-secret" } },
      }),
      (e) => e.code === "EAUTH" && e.sent === false,
    );
    assert.ok(!received.join("").includes("the-secret"));
  });

  it("cuts off a caller that cannot prove it holds the key", async () => {
    let ran = false;
    const link = await up(async () => {
      ran = true;
      return { ok: true };
    });
    const closed = await new Promise((resolve) => {
      const sock = net.connect(link.endpoint);
      sock.setEncoding("utf8");
      sock.on("error", () => resolve(true));
      sock.on("close", () => resolve(true));
      sock.on("connect", () => sock.write(`${JSON.stringify({ v: 1, nonce: "abc" })}\n`));
      sock.on("data", () => {
        sock.write(`${JSON.stringify({ proof: "guess", method: "tool", name: "op_list_vaults" })}\n`);
      });
    });
    assert.equal(closed, true);
    assert.equal(ran, false);
  });

  it("reports a broker that went away mid call as sent", async () => {
    const link = await up(() => new Promise(() => {}));
    const pending = broker.request({ ...link, payload: { method: "tool" } });
    await until(() => link.sockets.size === 1);
    await new Promise((r) => setTimeout(r, 50));
    for (const sock of link.sockets) sock.destroy();
    await assert.rejects(pending, (e) => e.code === "ELOST" && e.sent === true);
  });

  it("refuses a second listener on the same endpoint", async () => {
    const link = await up(async () => ({ ok: true }));
    await assert.rejects(
      broker.serve({ ...link, version: "9.9.9", handle: async () => ({ ok: true }) }),
      (e) => e.code === "EADDRINUSE" || e.code === "EACCES",
    );
    // The first one is untouched.
    const { reply } = await broker.request({ ...link, payload: { method: "tool" } });
    assert.equal(reply.ok, true);
  });

  it("takes over a socket file a dead broker left behind", { skip: !POSIX }, async () => {
    const dir = tmpDir();
    const endpoint = broker.endpointFor(dir, "t");
    const key = broker.loadKey(dir);
    fs.writeFileSync(endpoint, ""); // a name that looks taken and has no listener
    const server = await broker.serve({
      endpoint,
      key,
      version: "9.9.9",
      handle: async () => ({ ok: true, text: "alive" }),
    });
    open.push(server);
    const { reply } = await broker.request({ endpoint, key, payload: { method: "tool" } });
    assert.equal(reply.text, "alive");
  });

  it("keeps the socket file to this user", { skip: !POSIX }, async () => {
    const link = await up(async () => ({ ok: true }));
    assert.equal(fs.statSync(link.endpoint).mode & 0o777, 0o600);
  });

  it("counts a caller that stays connected, until it goes", async () => {
    const present = new Set();
    const link = await up(async () => ({ ok: true }), {
      onPresence: (sock) => {
        present.add(sock);
        sock.on("close", () => present.delete(sock));
      },
    });
    const { reply, sock } = await broker.request({
      ...link,
      payload: { method: "presence" },
      keepOpen: true,
    });
    assert.deepEqual(reply, { ok: true });
    assert.equal(present.size, 1);
    sock.destroy();
    assert.ok(await until(() => present.size === 0));
  });
});

// ---------------------------------------------------------------------------
// Keeping an approval
// ---------------------------------------------------------------------------

describe("createKeeper", () => {
  const ACCOUNT = "team.example.com";

  function rig(over = {}) {
    const state = { t: 1_700_000_000_000, pings: [], drops: [], pingFails: false };
    const keeper = broker.createKeeper({
      now: () => state.t,
      ping: async (account) => {
        state.pings.push(account);
        if (state.pingFails) throw new Error("locked");
      },
      drop: (account, why) => state.drops.push([account, why]),
      ...over,
    });
    /** Lets `ms` pass with a tick every 30 seconds, like the broker does. */
    state.run = async (ms) => {
      let held = keeper.accounts.size > 0;
      for (let passed = 0; passed < ms; passed += 30 * 1000) {
        state.t += 30 * 1000;
        held = await keeper.tick();
      }
      return held;
    };
    return { keeper, state };
  }

  it("has nothing to keep before any approval", async () => {
    const { keeper, state } = rig();
    assert.equal(await keeper.tick(), false);
    assert.deepEqual(state.pings, []);
  });

  it("leaves a fresh approval alone", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    assert.equal(await state.run(3 * MINUTE), true);
    assert.deepEqual(state.pings, []);
  });

  it("refreshes an approval before the ten quiet minutes are up", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    await state.run(4 * MINUTE);
    assert.deepEqual(state.pings, [ACCOUNT]);
  });

  it("keeps one approval for hours while 1Password stays unlocked", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    assert.equal(await state.run(6 * 60 * MINUTE), true);
    assert.deepEqual(state.drops, []);
    // One refresh every four minutes or so, never a gap near ten.
    assert.ok(state.pings.length >= 80 && state.pings.length <= 90, String(state.pings.length));
  });

  it("does not refresh while chats are using it anyway", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    for (let i = 0; i < 20; i++) {
      await state.run(3 * MINUTE);
      keeper.used(ACCOUNT);
    }
    assert.deepEqual(state.pings, []);
    assert.deepEqual(state.drops, []);
  });

  it("drops the approval at once when a refresh fails, as when 1Password locks", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    state.pingFails = true;
    assert.equal(await state.run(4 * MINUTE), false);
    assert.equal(state.drops.length, 1);
    assert.equal(state.drops[0][0], ACCOUNT);
    // And it is left alone afterwards: only a real call may ask the user.
    await state.run(30 * MINUTE);
    assert.equal(state.pings.length, 1);
  });

  it("stops refreshing after twelve hours and lets the approval run out", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    await state.run(12 * 60 * MINUTE);
    const before = state.pings.length;
    assert.equal(await state.run(15 * MINUTE), false);
    assert.equal(state.pings.length, before);
    assert.equal(state.drops.length, 1);
  });

  it("starts a new twelve hours when the user approves again after a lock", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    await state.run(11 * 60 * MINUTE);
    keeper.expired(ACCOUNT); // a call met the locked app...
    keeper.used(ACCOUNT); // ...and the user approved it
    assert.equal(await state.run(2 * 60 * MINUTE), true);
    assert.deepEqual(state.drops, []);
  });

  it("does not stretch the twelve hours when calls keep coming", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    for (let hour = 0; hour < 12; hour++) {
      await state.run(60 * MINUTE);
      keeper.used(ACCOUNT); // a call, or a new client for the approved process
    }
    const before = state.pings.length;
    assert.equal(await state.run(15 * MINUTE), false);
    assert.equal(state.pings.length, before);
  });

  it("keeps it through a gap with no chat connected", async () => {
    let chats = 1;
    const { keeper, state } = rig({ inUse: () => chats > 0 });
    keeper.used(ACCOUNT);
    await state.run(8 * MINUTE);
    chats = 0; // the client stopped the idle chats' servers
    assert.equal(await state.run(50 * MINUTE), true);
    chats = 1; // and one came back
    assert.equal(await state.run(3 * 60 * MINUTE), true);
    assert.deepEqual(state.drops, []);
  });

  it("lets it run out once nobody has been there for an hour", async () => {
    let chats = 1;
    const { keeper, state } = rig({ inUse: () => chats > 0 });
    keeper.used(ACCOUNT);
    await state.run(8 * MINUTE);
    chats = 0;
    assert.equal(await state.run(58 * MINUTE), true);
    const before = state.pings.length;
    assert.equal(await state.run(15 * MINUTE), false);
    assert.equal(state.pings.length, before);
    assert.equal(state.drops.length, 1);
  });

  it("counts a call as somebody being there", async () => {
    const { keeper, state } = rig({ inUse: () => false });
    keeper.used(ACCOUNT);
    await state.run(55 * MINUTE);
    keeper.wanted(); // `read` from a shell, with no server running
    assert.equal(await state.run(55 * MINUTE), true);
    assert.deepEqual(state.drops, []);
  });

  it("lets it run out by the ten minute rule when keeping is turned off", async () => {
    const { keeper, state } = rig({ keepAuthorized: () => false });
    keeper.used(ACCOUNT);
    assert.equal(await state.run(9 * MINUTE), true);
    assert.equal(await state.run(2 * MINUTE), false);
    assert.deepEqual(state.pings, []);
  });

  it("never refreshes an account it cannot refresh without a prompt", async () => {
    const { keeper, state } = rig({ canPing: () => false });
    keeper.used(ACCOUNT);
    assert.equal(await state.run(12 * MINUTE), false);
    assert.deepEqual(state.pings, []);
  });

  it("does not touch an approval that ran out while the computer slept", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    await state.run(2 * MINUTE);
    state.t += 45 * MINUTE; // lid closed: no tick ran in between
    assert.equal(await keeper.tick(), false);
    assert.deepEqual(state.pings, []);
    assert.equal(state.drops.length, 1);
  });

  it("starts keeping an account from its first successful call", async () => {
    const { keeper, state } = rig();
    keeper.used(ACCOUNT);
    await state.run(4 * MINUTE);
    assert.deepEqual(state.pings, [ACCOUNT]);
  });

  it("ignores a call with no account", async () => {
    const { keeper } = rig();
    keeper.used(undefined);
    keeper.expired(undefined);
    assert.equal(await keeper.tick(), false);
  });

  it("keeps each account on its own", async () => {
    const { keeper, state } = rig({
      canPing: (account) => account === ACCOUNT,
    });
    keeper.used(ACCOUNT);
    keeper.used("other.example.com");
    assert.equal(await state.run(12 * MINUTE), true);
    assert.deepEqual([...keeper.accounts.keys()], [ACCOUNT]);
    assert.deepEqual(state.drops.map((d) => d[0]), ["other.example.com"]);
  });
});

describe("logger", () => {
  it("appends timestamped lines and rolls a full file over once", () => {
    const file = path.join(tmpDir(), "broker.log");
    const log = broker.logger(file, 200);
    for (let i = 0; i < 10; i++) log(`line ${i} ${"x".repeat(40)}`);
    assert.ok(fs.existsSync(`${file}.1`));
    assert.match(fs.readFileSync(file, "utf8"), /^\d{4}-\d\d-\d\dT[^ ]+ line \d/);
    assert.ok(fs.statSync(file).size < 400);
  });
});
