const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const { loadIndex } = require("./helpers/loadIndex.cjs");

const { index } = loadIndex();
const { guardDesktopApp, noPrompt } = index;

// The SDK's own classes, loaded the way the guard finds them. Nothing here
// reaches the 1Password app: the native call is replaced per test.
const sdk = require("@1password/sdk");
const sdkDir = path.dirname(require.resolve("@1password/sdk"));
const { SharedLibCore } = require(path.join(sdkDir, "shared_lib_core.js"));
const { SharedCore, InnerClient } = require(path.join(sdkDir, "core.js"));

const ACCOUNT = "team.example.com";
const LIST_VAULTS = () => ({
  invocation: { clientId: 1, parameters: { name: "VaultsList", parameters: {} } },
});

/**
 * An SDK client wired to a scripted desktop app. `app(kind)` plays the app:
 * it answers "init_client" (the step where the real app asks the user) and
 * "invoke" (a request on an approved session).
 */
function client(app) {
  const transport = Object.create(SharedLibCore.prototype); // no native library loaded
  transport.acccountName = ACCOUNT;
  const calls = [];
  transport.callSharedLibrary = async (input, kind) => {
    calls.push(kind);
    return app(kind);
  };
  const core = new SharedCore();
  core.setInner(transport);
  return { inner: new InnerClient(1, core, { accountName: ACCOUNT }), calls };
}

/** An app whose session is gone: the next request is refused until re-approved. */
function lockedApp() {
  let approved = false;
  return (kind) => {
    if (kind === "init_client") {
      approved = true;
      return "2";
    }
    if (!approved) throw new sdk.DesktopSessionExpiredError("session expired");
    return "[]";
  };
}

describe("guardDesktopApp", () => {
  it("finds the SDK's desktop-app transport", () => {
    assert.equal(guardDesktopApp({}), true);
  });

  it("lets a real call ask for a new approval when the session is gone", async () => {
    const seen = [];
    guardDesktopApp({ authorized: (account) => seen.push(account) });
    const { inner, calls } = client(lockedApp());
    assert.equal(await inner.invoke(LIST_VAULTS()), "[]");
    // The SDK went back to the app for approval: the step that prompts.
    assert.deepEqual(calls, ["invoke", "init_client", "invoke"]);
    assert.deepEqual(seen, [ACCOUNT]);
  });

  it("never asks for a new approval while keeping one alive", async () => {
    const seen = [];
    guardDesktopApp({
      authorized: (account) => seen.push(account),
      refused: (account) => seen.push(`refused ${account}`),
    });
    const { inner, calls } = client(lockedApp());
    await assert.rejects(
      noPrompt.run(true, () => inner.invoke(LIST_VAULTS())),
      (e) => e instanceof sdk.DesktopSessionExpiredError,
    );
    // The request found the session gone, and the app was not asked again.
    assert.deepEqual(calls, ["invoke"]);
    assert.deepEqual(seen, []);
  });

  it("does not let the block leak into calls made at the same time", async () => {
    guardDesktopApp({});
    const kept = client(lockedApp());
    const asked = client(lockedApp());
    const [refresh, real] = await Promise.allSettled([
      noPrompt.run(true, () => kept.inner.invoke(LIST_VAULTS())),
      asked.inner.invoke(LIST_VAULTS()),
    ]);
    assert.equal(refresh.status, "rejected");
    assert.equal(real.status, "fulfilled");
    assert.deepEqual(kept.calls, ["invoke"]);
    assert.deepEqual(asked.calls, ["invoke", "init_client", "invoke"]);
  });

  it("reports a session the app declared gone", async () => {
    const gone = [];
    guardDesktopApp({ expired: (account) => gone.push(account) });
    const { inner } = client(lockedApp());
    await inner.invoke(LIST_VAULTS());
    assert.deepEqual(gone, [ACCOUNT]);
  });

  it("reports each request that went through, by account", async () => {
    const used = [];
    guardDesktopApp({ used: (account) => used.push(account) });
    const { inner } = client(() => "[]");
    await inner.invoke(LIST_VAULTS());
    await noPrompt.run(true, () => inner.invoke(LIST_VAULTS()));
    assert.deepEqual(used, [ACCOUNT, ACCOUNT]);
  });

  it("reports an approval the user refused, and passes the error on", async () => {
    const refused = [];
    guardDesktopApp({ refused: (account, ms, e) => refused.push([account, e.message]) });
    const { inner } = client((kind) => {
      if (kind === "init_client") throw new Error("authorization denied");
      throw new sdk.DesktopSessionExpiredError("session expired");
    });
    await assert.rejects(inner.invoke(LIST_VAULTS()), /authorization denied/);
    assert.deepEqual(refused, [[ACCOUNT, "authorization denied"]]);
  });

  it("wraps the transport once however often it is installed", async () => {
    const first = [];
    const second = [];
    guardDesktopApp({ used: (a) => first.push(a) });
    guardDesktopApp({ used: (a) => second.push(a) });
    const { inner, calls } = client(() => "[]");
    await inner.invoke(LIST_VAULTS());
    assert.deepEqual(calls, ["invoke"]);
    assert.deepEqual(first, []);
    assert.deepEqual(second, [ACCOUNT]);
  });
});

// The real app answers one request at a time, keeps one more waiting and
// refuses a third with "IPC operation failed: -2".
describe("requests reach the desktop app in turn", () => {
  const BUSY = "IPC operation failed: -2";

  /** An app that counts how many requests are inside it at once. */
  function countingApp() {
    const seen = { inside: 0, most: 0 };
    const app = async () => {
      seen.inside++;
      seen.most = Math.max(seen.most, seen.inside);
      await new Promise((r) => setTimeout(r, 10));
      seen.inside--;
      return "[]";
    };
    return { app, seen };
  }

  it("hands over one request at a time, however many start together", async () => {
    guardDesktopApp({});
    const { app, seen } = countingApp();
    const { inner } = client(app);
    const answers = await Promise.all(
      Array.from({ length: 8 }, () => inner.invoke(LIST_VAULTS())),
    );
    assert.deepEqual(answers, Array(8).fill("[]"));
    assert.equal(seen.most, 1);
  });

  it("keeps one line for every client in the process", async () => {
    guardDesktopApp({});
    const { app, seen } = countingApp();
    const a = client(app);
    const b = client(app);
    await Promise.all([
      a.inner.invoke(LIST_VAULTS()),
      b.inner.invoke(LIST_VAULTS()),
      a.inner.invoke(LIST_VAULTS()),
      b.inner.invoke(LIST_VAULTS()),
    ]);
    assert.equal(seen.most, 1);
  });

  it("goes on with the next request after one fails", async () => {
    guardDesktopApp({});
    let n = 0;
    const { inner } = client(async () => {
      if (++n === 1) throw new Error("item not found");
      return "[]";
    });
    const [first, second] = await Promise.allSettled([
      inner.invoke(LIST_VAULTS()),
      inner.invoke(LIST_VAULTS()),
    ]);
    assert.equal(first.status, "rejected");
    assert.equal(second.value, "[]");
  });

  it("tries again when another program has the app busy", async () => {
    guardDesktopApp({});
    let n = 0;
    const { inner, calls } = client(async () => {
      if (++n <= 2) throw new Error(BUSY);
      return "[]";
    });
    assert.equal(await inner.invoke(LIST_VAULTS()), "[]");
    assert.deepEqual(calls, ["invoke", "invoke", "invoke"]);
  });

  it("tries a refused approval request again too, without reporting a refusal", async () => {
    const refused = [];
    const approved = [];
    guardDesktopApp({
      refused: (account) => refused.push(account),
      authorized: (account) => approved.push(account),
    });
    let n = 0;
    const { inner, calls } = client(async (kind) => {
      if (kind === "init_client") {
        if (++n === 1) throw new Error(BUSY);
        return "2";
      }
      if (n === 0) throw new sdk.DesktopSessionExpiredError("session expired");
      return "[]";
    });
    assert.equal(await inner.invoke(LIST_VAULTS()), "[]");
    assert.deepEqual(calls, ["invoke", "init_client", "init_client", "invoke"]);
    assert.deepEqual(refused, []);
    assert.deepEqual(approved, [ACCOUNT]);
  });

  it("gives up on an app that stays busy, with the app's own error", async () => {
    guardDesktopApp({});
    const { inner, calls } = client(async () => {
      throw new Error(BUSY);
    });
    await assert.rejects(inner.invoke(LIST_VAULTS()), /IPC operation failed: -2/);
    assert.equal(calls.length, 6);
  });

  it("does not try an ordinary error again", async () => {
    guardDesktopApp({});
    const { inner, calls } = client(async () => {
      throw new Error("item not found");
    });
    await assert.rejects(inner.invoke(LIST_VAULTS()), /item not found/);
    assert.deepEqual(calls, ["invoke"]);
  });
});
