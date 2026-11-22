const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const broker = require("../broker.js");
const {
  sandbox,
  startServer,
  runRead,
  alive,
  until,
} = require("./helpers/processes.cjs");

// Real server processes, as an MCP client starts them, against a stand-in
// SDK. In the real app every distinct process that creates a client is one
// approval prompt for the user, so the tests count those processes.

const VERSION = require("../package.json").version;
const ACCOUNT = "team.example.com";
const DESKTOP = {
  instances: [
    { name: "work", authType: "desktop", accountName: ACCOUNT },
    { name: "ci", authType: "serviceAccount", token: "ops_test_token" },
  ],
  defaultInstance: "work",
};

const boxes = [];
const servers = [];

function box(config) {
  const made = sandbox(config);
  made.link = () => ({
    endpoint: broker.endpointFor(made.configDir, VERSION),
    key: broker.loadKey(made.configDir),
  });
  /** Pids that created an SDK client for the desktop account. */
  made.approvals = () =>
    made
      .sdkCalls()
      .filter((c) => c.event === "createClient" && c.account === ACCOUNT)
      .map((c) => c.pid);
  boxes.push(made);
  return made;
}

async function server(home, options) {
  const started = startServer(home, options);
  servers.push(started);
  await started.init();
  return started;
}

function folder(home, name) {
  const dir = path.join(home.home, name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

after(async () => {
  for (const started of servers) await started.stop().catch(() => {});
  for (const made of boxes) {
    await broker
      .request({ ...made.link(), payload: { method: "stop" } })
      .catch(() => {});
    await made.remove();
  }
});

describe("one approval for every server process", () => {
  const home = box(DESKTOP);
  let sharedPid;

  it("servers in different folders ask the app once, even at the same moment", async () => {
    // The stand-in takes a while to "approve", so the calls overlap.
    const slow = { env: { OP_MCP_TEST_APPROVE_MS: "400" } };
    const a = await server(home, { cwd: folder(home, "project-a"), ...slow });
    const b = await server(home, { cwd: folder(home, "project-b"), ...slow });
    const c = await server(home, { cwd: folder(home, "project-c"), ...slow });

    const answers = await Promise.all([
      a.call("op_list_vaults"),
      b.call("op_list_vaults"),
      c.call("op_search_items", { query: "deploy" }),
      a.call("op_list_items", { vault: "Shared" }),
    ]);
    for (const answer of answers) assert.equal(answer.isError, false, answer.text);
    assert.match(answers[0].text, /Shared/);
    assert.match(answers[2].text, /Deploy key/);

    const approvals = home.approvals();
    assert.equal(approvals.length, 1, JSON.stringify(home.sdkCalls()));
    sharedPid = approvals[0];
    assert.ok(![a.pid, b.pid, c.pid].includes(sharedPid));
  });

  it("later calls from any of them ask nothing more", async () => {
    const [a, b] = servers;
    await a.call("op_get_item", { vault: "Shared", item: "Deploy key" });
    await b.call("op_get_secret", { reference: "op://Shared/Deploy key/password" });
    await b.call("op_list_vaults", { instance: "work" });
    assert.deepEqual(home.approvals(), [sharedPid]);
  });

  it("returns exactly what the tool returns in its own process", async () => {
    const [a] = servers;
    const shared = await a.call("op_get_item", { vault: "Shared", item: "Deploy key" });
    assert.match(shared.text, /^# Deploy key \(Login\)/);
    assert.match(shared.text, /\[REDACTED\]/);
    const missing = await a.call("op_list_items", { vault: "Nope" });
    assert.equal(missing.isError, true);
    assert.equal(missing.text, 'Error: Vault "Nope" not found.');
  });

  it("makes a change once", async () => {
    const [a] = servers;
    const made = await a.call("op_create_item", { vault: "Shared", title: "New thing" });
    assert.match(made.text, /Created item \*\*New thing\*\*/);
    const creates = home.sdkCalls().filter((c) => c.event === "create");
    assert.deepEqual(creates.map((c) => c.pid), [sharedPid]);
  });

  it("keeps tools that need no account in the server itself", async () => {
    const [a] = servers;
    assert.match((await a.call("op_generate_password")).text, /generated-locally/);
    assert.match((await a.call("op_list_instances")).text, /\*\*work\*\* \*\*\(default\)\*\*/);
    assert.deepEqual(home.approvals(), [sharedPid]);
  });

  it("keeps a service account in the server that was asked", async () => {
    const [a] = servers;
    const answer = await a.call("op_list_vaults", { instance: "ci" });
    assert.equal(answer.isError, false, answer.text);
    const ci = home.sdkCalls().filter((c) => c.account === "service-account");
    assert.deepEqual(ci.map((c) => c.pid), [a.pid]);
  });

  it("read prints only the value, through the same approval", async () => {
    const out = runRead(home, ["op://Shared/Deploy key/password"]);
    assert.equal(out.status, 0, out.stderr);
    assert.equal(out.stdout, "value-of:op://Shared/Deploy key/password\n");
    const bare = runRead(home, ["-n", "op://Shared/Deploy key/password"]);
    assert.equal(bare.stdout, "value-of:op://Shared/Deploy key/password");
    assert.deepEqual(home.approvals(), [sharedPid]);
  });

  it("read refuses anything that is not a secret reference", async () => {
    const out = runRead(home, ["Deploy key"]);
    assert.equal(out.status, 2);
    assert.equal(out.stdout, "");
    assert.match(out.stderr, /Usage: 1password-mcp read/);
  });

  it("outlives the servers that used it, so a new chat asks nothing", async () => {
    while (servers.length) await servers.pop().stop();
    assert.equal(alive(sharedPid), true);
    const late = await server(home, { cwd: folder(home, "project-d") });
    assert.match((await late.call("op_list_vaults")).text, /Shared/);
    assert.deepEqual(home.approvals(), [sharedPid]);
  });

  it("sees an instance another process added after it started", async () => {
    const [late] = servers;
    home.setConfig({
      ...DESKTOP,
      instances: [
        ...DESKTOP.instances,
        { name: "second", authType: "desktop", accountName: "other.example.com" },
      ],
    });
    const answer = await late.call("op_list_vaults", { instance: "second" });
    assert.equal(answer.isError, false, answer.text);
    const other = home.sdkCalls().filter((c) => c.account === "other.example.com");
    assert.deepEqual(other.map((c) => c.pid), [sharedPid]);
  });

  it("writes down who asked, and no arguments", async () => {
    const log = home.brokerLog();
    assert.match(log, /started: pid \d+/);
    assert.match(log, /op_list_vaults from pid \d+ in .*project-a/);
    assert.match(log, /read from pid \d+/);
    assert.ok(!log.includes("New thing"));
    assert.ok(!log.includes("op://"));
  });

  it("leaves when asked, and the next call starts a fresh one", async () => {
    await broker.request({ ...home.link(), payload: { method: "stop" } });
    assert.ok(await until(() => !alive(sharedPid)), "the shared process is still running");
    const [late] = servers;
    assert.match((await late.call("op_list_vaults")).text, /Shared/);
    const approvals = home.approvals();
    assert.equal(approvals.length, 2);
    assert.notEqual(approvals[1], sharedPid);
    assert.notEqual(approvals[1], late.pid);
  });
});

describe("what the model is told", () => {
  it("steers a desktop-auth setup away from the op CLI, with the read command", async () => {
    const home = box(DESKTOP);
    const started = startServer(home);
    servers.push(started);
    const { instructions } = await started.init();
    assert.match(instructions, /Never run the `op` CLI/);
    assert.match(instructions, /index\.js" read "op:\/\/vault\/item\/field"/);
    assert.ok(!instructions.includes("\\"), "the command must paste into any shell");
  });

  it("says nothing of the kind to a service-account setup", async () => {
    const home = box({
      instances: [{ name: "ci", authType: "serviceAccount", token: "ops_test_token" }],
      defaultInstance: "ci",
    });
    const started = startServer(home);
    servers.push(started);
    const result = await started.init();
    assert.equal(result.instructions, undefined);
  });
});

describe("when the shared process cannot be used", () => {
  it("runs each call in its own server when sharing is turned off", async () => {
    const home = box({ ...DESKTOP, sharedApproval: false });
    const a = await server(home);
    const b = await server(home);
    assert.match((await a.call("op_list_vaults")).text, /Shared/);
    assert.match((await b.call("op_list_vaults")).text, /Shared/);
    assert.deepEqual(home.approvals().sort(), [a.pid, b.pid].sort());
    assert.equal(home.brokerLog(), "");
  });

  it("runs the call itself rather than trust a stranger on the pipe", async () => {
    const home = box(DESKTOP);
    // Something else already answers on the broker's pipe, without the key.
    const stranger = await broker.serve({
      endpoint: home.link().endpoint,
      key: Buffer.alloc(32, 7),
      version: VERSION,
      handle: async () => ({ ok: true, text: "forged" }),
    });
    try {
      const a = await server(home);
      const answer = await a.call("op_list_vaults");
      assert.match(answer.text, /Shared/);
      assert.ok(!answer.text.includes("forged"));
      assert.deepEqual(home.approvals(), [a.pid]);
    } finally {
      stranger.close();
    }
  });
});
