// Preloaded (node --require) into real server processes by the tests: swaps
// `@1password/sdk` for a stand-in so no test ever reaches the 1Password app.
//
// Every createClient is written to the file in OP_MCP_TEST_SDK_LOG with the
// pid that made it. In the real app each distinct pid there is one approval
// prompt for the user, so that file is what the tests count.

const fs = require("fs");
const Module = require("module");

const LOG = process.env.OP_MCP_TEST_SDK_LOG;
// How long the "user" takes to approve, so parallel calls overlap.
const APPROVE_MS = Number(process.env.OP_MCP_TEST_APPROVE_MS || 0);

function note(event, extra) {
  if (!LOG) return;
  fs.appendFileSync(
    LOG,
    `${JSON.stringify({ event, pid: process.pid, ...extra })}\n`,
  );
}

class DesktopAuth {
  constructor(accountName) {
    this.accountName = accountName;
  }
}

class DesktopSessionExpiredError extends Error {}

const VAULTS = [
  { id: "v1", title: "Shared", description: "" },
  { id: "v2", title: "Private", description: "" },
];
const ITEMS = [{ id: "i1", title: "Deploy key", category: "Login", vaultId: "v1" }];

const fake = {
  DesktopAuth,
  DesktopSessionExpiredError,
  ItemCategory: { Login: "Login", SecureNote: "SecureNote" },
  ItemFieldType: { Text: "Text", Concealed: "Concealed" },
  AutofillBehavior: { AnywhereOnWebsite: "AnywhereOnWebsite", Never: "Never" },
  SeparatorType: { Digits: "digits" },
  WordListType: { FullWords: "fullWords" },
  Secrets: { generatePassword: () => ({ password: "generated-locally" }) },
  createClient: async ({ auth }) => {
    const account = auth instanceof DesktopAuth ? auth.accountName : "service-account";
    note("createClient", { account });
    if (APPROVE_MS) await new Promise((r) => setTimeout(r, APPROVE_MS));
    return {
      vaults: {
        list: async () => VAULTS,
      },
      items: {
        list: async () => ITEMS,
        get: async (vaultId, id) => ({
          ...ITEMS[0],
          vaultId,
          id,
          tags: [],
          websites: [],
          sections: [],
          fields: [{ id: "f1", title: "password", fieldType: "Concealed", value: "hunter2" }],
        }),
        create: async (item) => {
          note("create", { title: item.title });
          return { id: "new1", title: item.title };
        },
      },
      secrets: {
        resolve: async (reference) => `value-of:${reference}`,
      },
    };
  },
};

// A server looks for a newer version on npm when it starts and installs it.
// A test must never do that, so the registry is unreachable in here.
globalThis.fetch = async () => {
  throw new Error("offline in tests");
};

const load = Module._load;
Module._load = function (request, ...rest) {
  if (request === "@1password/sdk") return fake;
  return load.call(this, request, ...rest);
};
