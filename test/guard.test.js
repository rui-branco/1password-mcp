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
