const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");

const broker = require("../broker.js");
const { sandbox, startServer, alive, until } = require("./helpers/processes.cjs");

// The real SDK in real processes, against a stand-in desktop app (see
// helpers/fakeApp.cjs), with the shared process on a clock 200 times faster:
// 1Password's ten quiet minutes pass in three seconds.
//
// What is counted is the stand-in app's "prompt": the step where the real app
// asks the user. A background refresh must never be the cause of one.

const SPEED = 200;
const VERSION = require("../package.json").version;
const ACCOUNT = "team.example.com";

const minutes = (n) => new Promise((r) => setTimeout(r, (n * 60 * 1000) / SPEED));

const boxes = [];
const servers = [];

function box(extra, env) {
  const made = sandbox(
    {
      instances: [{ name: "work", authType: "desktop", accountName: ACCOUNT }],
      defaultInstance: "work",
      ...extra,
    },
    { standIn: "app", env: { OP_MCP_TEST_SPEED: String(SPEED), ...env } },
  );
  /** The processes the app asked the user about, in order. */
  made.prompts = () =>
    made
      .sdkCalls()
      .filter((c) => c.event === "prompt")
      .map((c) => c.pid);
  /** How many requests reached the app. */
  made.requests = () => made.sdkCalls().filter((c) => c.event === "request").length;
  boxes.push(made);
  return made;
}

async function server(home) {
  const started = startServer(home);
  servers.push(started);
  await started.init();
  return started;
}

after(async () => {
  for (const started of servers) await started.stop().catch(() => {});
  for (const made of boxes) {
    await broker
      .request({
        endpoint: broker.endpointFor(made.configDir, VERSION),
        key: broker.loadKey(made.configDir),
        payload: { method: "stop" },
      })
      .catch(() => {});
    await made.remove();
  }
});

describe("one approval while 1Password stays unlocked", () => {
  const home = box();
  let chat;
  let sharedPid;

  it("asks the user once, for the first call", async () => {
    chat = await server(home);
    const answer = await chat.call("op_list_vaults");
    assert.match(answer.text, /Shared/);
    const asked = home.prompts();
    assert.equal(asked.length, 1);
    sharedPid = asked[0];
    assert.notEqual(sharedPid, chat.pid);
    assert.match(home.brokerLog(), /team\.example\.com: approved after \d+ ms, for op_list_vaults from pid/);
  });

  it("keeps it alive past the ten quiet minutes without asking anybody", async () => {
    const before = home.requests();
    await minutes(14);
    assert.equal(alive(sharedPid), true);
    // The shared process made requests of its own to keep the session going.
    assert.ok(home.requests() >= before + 2, `${home.requests()} requests`);
    assert.deepEqual(home.prompts(), [sharedPid]);
  });

  it("serves the next call from that same approval", async () => {
    const answer = await chat.call("op_list_vaults");
    assert.match(answer.text, /Shared/);
    assert.deepEqual(home.prompts(), [sharedPid]);
  });

  it("finds out that 1Password locked, and does not ask anybody", async () => {
    home.lockApp();
    assert.ok(await until(() => !alive(sharedPid), 10000), "still running after the lock");
    // The refresh met a dead session. The SDK's reflex is to go back to the
    // app for approval, which would have put a prompt on the user's screen.
    assert.deepEqual(home.prompts(), [sharedPid]);
    assert.match(home.brokerLog(), /team\.example\.com: the approval ended/);
    assert.match(home.brokerLog(), /exit: nothing left to keep/);
  });

  it("asks again only when a call needs 1Password", async () => {
    const answer = await chat.call("op_list_vaults");
    assert.match(answer.text, /Shared/);
    const asked = home.prompts();
    assert.equal(asked.length, 2);
    assert.notEqual(asked[1], sharedPid);
    assert.notEqual(asked[1], chat.pid);
  });
});

describe("when the locked app answers a plain \"invalid client id\"", () => {
  // What the real app sends once it has dropped a client. The SDK does not
  // ask again by itself for this one; the server's own retry does.
  const home = box({}, { OP_MCP_TEST_LOCK_ANSWER: "invalid-client-id" });
  let chat;
  let sharedPid;

  it("lets the approval go without asking anybody", async () => {
    chat = await server(home);
    await chat.call("op_list_vaults");
    [sharedPid] = home.prompts();
    home.lockApp();
    assert.ok(await until(() => !alive(sharedPid), 10000), "still running after the lock");
    assert.deepEqual(home.prompts(), [sharedPid]);
    assert.match(home.brokerLog(), /the approval ended \(invalid client id\)/);
  });

  it("recovers on the next call, with one prompt", async () => {
    const answer = await chat.call("op_list_vaults");
    assert.equal(answer.isError, false, answer.text);
    assert.match(answer.text, /Shared/);
    assert.equal(home.prompts().length, 2);
  });

  it("recovers too when the call comes before the lock was noticed", async () => {
    const [, secondPid] = home.prompts();
    home.lockApp();
    const answer = await chat.call("op_list_vaults");
    assert.equal(answer.isError, false, answer.text);
    // Same process, asked once more: the dead client was replaced in place.
    assert.deepEqual(home.prompts().slice(1), [secondPid, secondPid]);
  });
});

describe("after a call failed on a passing IPC error", () => {
  // Seen against the real app: such a failure throws the cached client away,
  // and the approval was then given up at the next refresh although the app
  // still held it, so the following call asked the user again.
  const home = box();
  let chat;
  let sharedPid;

  it("reports the failure of that call", async () => {
    chat = await server(home);
    await chat.call("op_list_vaults");
    [sharedPid] = home.prompts();
    home.glitchApp(true);
    const failed = await chat.call("op_list_vaults");
    assert.equal(failed.isError, true);
    assert.match(failed.text, /IPC connection closed/);
    home.glitchApp(false);
  });

  it("still keeps the approval alive", async () => {
    const before = home.requests();
    await minutes(11);
    assert.equal(alive(sharedPid), true);
    assert.ok(home.requests() > before, "no refresh was made");
    assert.ok(!home.brokerLog().includes("the approval ended"), home.brokerLog());
  });

  it("serves the next call without asking", async () => {
    const answer = await chat.call("op_list_vaults");
    assert.equal(answer.isError, false, answer.text);
    assert.deepEqual(home.prompts(), [sharedPid]);
  });
});

describe("calls that start at the same instant", () => {
  // The stand-in app, like the real one, refuses a third request while it
  // holds two. Chats send several calls at once, and all chats share it.

  it("all go through, from two chats at once", async () => {
    const home = box();
    const one = await server(home);
    const two = await server(home);
    await one.call("op_list_vaults");
    const answers = await Promise.all([
      ...Array.from({ length: 6 }, () => one.call("op_list_vaults")),
      ...Array.from({ length: 4 }, () => two.call("op_search_items", { query: "x" })),
      two.call("op_list_items", { vault: "Shared" }),
    ]);
    for (const answer of answers) assert.equal(answer.isError, false, answer.text);
    assert.equal(home.prompts().length, 1);
    assert.ok(!home.brokerLog().includes("not approved"), home.brokerLog());
  });

  it("all go through when they are the very first calls", async () => {
    const home = box();
    const chat = await server(home);
    const answers = await Promise.all(
      Array.from({ length: 5 }, () => chat.call("op_list_vaults")),
    );
    for (const answer of answers) assert.equal(answer.isError, false, answer.text);
    assert.equal(home.prompts().length, 1);
  });
});

describe("with keepAuthorized turned off", () => {
  const home = box({ keepAuthorized: false });

  it("makes no request of its own and leaves when the ten minutes are up", async () => {
    const chat = await server(home);
    await chat.call("op_list_vaults");
    const [sharedPid] = home.prompts();
    const made = home.requests();
    await minutes(6);
    // Still inside 1Password's own window: a call now would not be asked about.
    assert.equal(alive(sharedPid), true);
    assert.equal(home.requests(), made);
    assert.ok(await until(() => !alive(sharedPid), 8000), "still running after the window");
    assert.equal(home.requests(), made);
    assert.match(home.brokerLog(), /team\.example\.com: the approval ran out/);
    assert.deepEqual(home.prompts(), [sharedPid]);
  });
});
