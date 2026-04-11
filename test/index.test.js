const { describe, it, before } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

// ---------------------------------------------------------------------------
// Stubs: prevent the MCP SDK from actually opening stdio, and keep index.js
// from reading the real user config.
// ---------------------------------------------------------------------------

const mockServer = {
  setRequestHandler: () => {},
  connect: () => Promise.resolve(),
};
const sdkIndexPath = require.resolve(
  "@modelcontextprotocol/sdk/server/index.js",
);
require.cache[sdkIndexPath] = {
  id: sdkIndexPath,
  filename: sdkIndexPath,
  loaded: true,
  exports: {
    Server: class {
      constructor() {
        return mockServer;
      }
    },
  },
};
const sdkTypesPath = require.resolve("@modelcontextprotocol/sdk/types.js");
require.cache[sdkTypesPath] = {
  id: sdkTypesPath,
  filename: sdkTypesPath,
  loaded: true,
  exports: {
    ListToolsRequestSchema: "ListToolsRequestSchema",
    CallToolRequestSchema: "CallToolRequestSchema",
  },
};
const sdkStdioPath = require.resolve(
  "@modelcontextprotocol/sdk/server/stdio.js",
);
require.cache[sdkStdioPath] = {
  id: sdkStdioPath,
  filename: sdkStdioPath,
  loaded: true,
  exports: { StdioServerTransport: class {} },
};

// Point HOME at a throwaway dir so the config load at module time never
// touches the user's real ~/.config/1password-mcp/config.json.
const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "op-mcp-test-"));
process.env.HOME = tmpHome;

const {
  loadConfigFile,
  saveConfigFile,
  normalizeInstance,
  collect,
  resolveVault,
  resolveItem,
  redactField,
  formatItem,
  TOOL_DEFINITIONS,
  HANDLERS,
  generatePasswordHandler,
  searchItemsHandler,
  searchItems,
} = require("../index.js");

// ---------------------------------------------------------------------------
// Fake 1Password client for resolver tests
// ---------------------------------------------------------------------------

function makeFakeClient({
  vaults = [],
  itemsByVault = {},
  fullItemsById = {},
} = {}) {
  return {
    vaults: {
      list: async () =>
        (async function* () {
          for (const v of vaults) yield v;
        })(),
    },
    items: {
      list: async (vaultId) =>
        (async function* () {
          for (const i of itemsByVault[vaultId] || []) yield i;
        })(),
      get: async (vaultId, itemId) => {
        const full = fullItemsById[itemId];
        if (!full) throw new Error(`item ${itemId} not found`);
        return full;
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Handler completeness (drift guard)
// ---------------------------------------------------------------------------

describe("handler map completeness", () => {
  it("every declared tool has a handler", () => {
    for (const tool of TOOL_DEFINITIONS) {
      assert.equal(
        typeof HANDLERS[tool.name],
        "function",
        `missing handler for ${tool.name}`,
      );
    }
  });

  it("every handler is declared in TOOL_DEFINITIONS", () => {
    const declared = new Set(TOOL_DEFINITIONS.map((t) => t.name));
    for (const name of Object.keys(HANDLERS)) {
      assert.ok(declared.has(name), `handler ${name} has no tool definition`);
    }
  });

  it("ships at least 13 tools", () => {
    assert.ok(TOOL_DEFINITIONS.length >= 13);
  });
});

// ---------------------------------------------------------------------------
// Config round-trip
// ---------------------------------------------------------------------------

describe("config load/save", () => {
  it("persists and reloads an instance list", () => {
    const cfg = {
      instances: [
        {
          name: "work",
          authType: "desktop",
          accountName: "my.1password.com",
          description: "test",
        },
      ],
      defaultInstance: "work",
    };
    saveConfigFile(cfg);
    const loaded = loadConfigFile();
    assert.deepEqual(loaded, cfg);
  });

  it("writes the config file with 0600 permissions on POSIX", () => {
    saveConfigFile({ instances: [] });
    const configPath = path.join(
      process.env.HOME,
      ".config/1password-mcp/config.json",
    );
    const mode = fs.statSync(configPath).mode & 0o777;
    // Skip on non-POSIX filesystems where chmod silently no-ops
    if (process.platform !== "win32") {
      assert.equal(mode, 0o600);
    }
  });
});

// ---------------------------------------------------------------------------
// normalizeInstance
// ---------------------------------------------------------------------------

describe("normalizeInstance", () => {
  it("defaults missing authType to serviceAccount when a token is present", () => {
    const n = normalizeInstance({ name: "a", token: "ops_abc" });
    assert.equal(n.authType, "serviceAccount");
  });

  it("defaults missing authType to desktop when no token is present", () => {
    const n = normalizeInstance({ name: "a", accountName: "my.1password.com" });
    assert.equal(n.authType, "desktop");
  });

  it("honors an explicit authType", () => {
    const n = normalizeInstance({
      name: "a",
      authType: "desktop",
      accountName: "my.1password.com",
    });
    assert.equal(n.authType, "desktop");
  });

  it("fills description default", () => {
    const n = normalizeInstance({ name: "a", token: "ops_x" });
    assert.equal(n.description, "");
  });
});

// ---------------------------------------------------------------------------
// collect()
// ---------------------------------------------------------------------------

describe("collect", () => {
  it("drains an async iterable into an array", async () => {
    async function* src() {
      yield 1;
      yield 2;
      yield 3;
    }
    assert.deepEqual(await collect(src()), [1, 2, 3]);
  });
});

// ---------------------------------------------------------------------------
// resolveVault
// ---------------------------------------------------------------------------

describe("resolveVault", () => {
  const vaults = [
    { id: "v1", title: "Private" },
    { id: "v2", title: "42-ITO.Share" },
    { id: "v3", title: "KONE.MSS" },
  ];
  const client = makeFakeClient({ vaults });

  it("returns null for null/undefined/empty input", async () => {
    assert.equal(await resolveVault(client, null), null);
    assert.equal(await resolveVault(client, ""), null);
  });

  it("matches by id", async () => {
    const v = await resolveVault(client, "v2");
    assert.equal(v.id, "v2");
  });

  it("matches by exact title (case-insensitive)", async () => {
    const v = await resolveVault(client, "private");
    assert.equal(v.id, "v1");
  });

  it("falls back to prefix matching", async () => {
    const v = await resolveVault(client, "42-ito");
    assert.equal(v.id, "v2");
  });

  it("returns null when nothing matches", async () => {
    assert.equal(await resolveVault(client, "nonexistent"), null);
  });
});

// ---------------------------------------------------------------------------
// resolveItem
// ---------------------------------------------------------------------------

describe("resolveItem", () => {
  const vault = { id: "v1", title: "42-ITO.Share" };
  const items = [
    { id: "i1", title: "Door Entrance Office" },
    { id: "i2", title: "Door Entrance Garage" },
    { id: "i3", title: "Wifi" },
  ];
  const client = makeFakeClient({ itemsByVault: { v1: items } });

  it("matches by id", async () => {
    const i = await resolveItem(client, vault, "i3");
    assert.equal(i.id, "i3");
  });

  it("matches by exact title (case-insensitive)", async () => {
    const i = await resolveItem(client, vault, "WIFI");
    assert.equal(i.id, "i3");
  });

  it("matches by title prefix", async () => {
    const i = await resolveItem(client, vault, "door entrance o");
    assert.equal(i.id, "i1");
  });

  it("returns null on miss", async () => {
    assert.equal(await resolveItem(client, vault, "garbage"), null);
  });
});

// ---------------------------------------------------------------------------
// redactField
// ---------------------------------------------------------------------------

describe("redactField", () => {
  it("redacts Concealed fields by default", () => {
    const r = redactField(
      {
        id: "password",
        title: "password",
        fieldType: "Concealed",
        value: "super-secret",
      },
      false,
    );
    assert.equal(r.value, "[REDACTED]");
  });

  it("reveals Concealed values when includeConcealed=true", () => {
    const r = redactField(
      {
        id: "password",
        title: "password",
        fieldType: "Concealed",
        value: "super-secret",
      },
      true,
    );
    assert.equal(r.value, "super-secret");
  });

  it("passes Text fields through untouched", () => {
    const r = redactField(
      { id: "u", title: "username", fieldType: "Text", value: "alice" },
      false,
    );
    assert.equal(r.value, "alice");
  });

  it("surfaces OTP codes when concealed is revealed", () => {
    const r = redactField(
      {
        id: "otp",
        title: "one-time password",
        fieldType: "Totp",
        value: "otpauth://...",
        details: { type: "Otp", content: { code: "123456" } },
      },
      true,
    );
    assert.equal(r.otp, "123456");
  });

  it("redacts Totp value AND omits OTP when concealed is not revealed", () => {
    const r = redactField(
      {
        id: "otp",
        title: "one-time password",
        fieldType: "Totp",
        value: "otpauth://...",
        details: { type: "Otp", content: { code: "123456" } },
      },
      false,
    );
    assert.equal(r.value, "[REDACTED]");
    assert.equal(r.otp, undefined);
  });

  it("does not crash on missing details", () => {
    const r = redactField(
      { id: "x", title: "x", fieldType: "Text", value: "plain" },
      true,
    );
    assert.equal(r.value, "plain");
    assert.equal(r.otp, undefined);
  });
});

// ---------------------------------------------------------------------------
// formatItem
// ---------------------------------------------------------------------------

describe("formatItem", () => {
  it("returns a flat shape with fields mapped through redactField", () => {
    const item = {
      id: "abc",
      title: "GitHub",
      category: "Login",
      vaultId: "vault1",
      tags: ["dev"],
      websites: [{ url: "https://github.com", label: "website" }],
      sections: [],
      fields: [
        { id: "u", title: "username", fieldType: "Text", value: "alice" },
        { id: "p", title: "password", fieldType: "Concealed", value: "hunter2" },
      ],
    };
    const out = formatItem(item, false);
    assert.equal(out.id, "abc");
    assert.equal(out.fields.length, 2);
    assert.equal(out.fields[0].value, "alice");
    assert.equal(out.fields[1].value, "[REDACTED]");
  });

  it("defaults missing arrays to empty", () => {
    const out = formatItem(
      {
        id: "x",
        title: "x",
        category: "Login",
        vaultId: "v1",
      },
      false,
    );
    assert.deepEqual(out.tags, []);
    assert.deepEqual(out.websites, []);
    assert.deepEqual(out.fields, []);
    assert.deepEqual(out.sections, []);
  });
});

// ---------------------------------------------------------------------------
// generatePasswordHandler — exercises the real SDK generator (pure function,
// does not talk to 1Password).
// ---------------------------------------------------------------------------

describe("searchItems", () => {
  const vaults = [
    { id: "v1", title: "Private" },
    { id: "v2", title: "42-ITO.Share" },
  ];
  const itemsByVault = {
    v1: [{ id: "i0", title: "Personal Wifi", category: "Login" }],
    v2: [
      { id: "i1", title: "Door Entrance Office", category: "Password" },
      { id: "i2", title: "Door Entrance Garage", category: "Password" },
      { id: "i3", title: "42-ITO WiFi", category: "Login" },
    ],
  };
  const fullItemsById = {
    i1: {
      id: "i1",
      title: "Door Entrance Office",
      category: "Password",
      fields: [
        {
          id: "password",
          title: "password",
          fieldType: "Concealed",
          value: "52007",
        },
      ],
      websites: [],
    },
    i2: {
      id: "i2",
      title: "Door Entrance Garage",
      category: "Password",
      fields: [
        {
          id: "password",
          title: "password",
          fieldType: "Concealed",
          value: "93175",
        },
      ],
      websites: [],
    },
  };

  const client = makeFakeClient({ vaults, itemsByVault, fullItemsById });

  it("list mode returns a bullet list without secret values", async () => {
    const out = await searchItems(client, { query: "door" });
    assert.match(out, /# Search: "door" \(2\)/);
    assert.match(out, /Door Entrance Office/);
    assert.match(out, /Door Entrance Garage/);
    assert.ok(!out.includes("52007"));
    assert.ok(!out.includes("93175"));
  });

  it("reveal mode returns full field values in one call", async () => {
    const out = await searchItems(client, { query: "door", reveal: true });
    assert.match(out, /# Search \(revealed\): "door" \(2\)/);
    assert.match(out, /## Door Entrance Office/);
    assert.match(out, /## Door Entrance Garage/);
    assert.ok(out.includes("52007"), "office password should be revealed");
    assert.ok(out.includes("93175"), "garage password should be revealed");
  });

  it("scopes search to a single vault when vault is passed", async () => {
    const out = await searchItems(client, { query: "wifi", vault: "Private" });
    assert.match(out, /Personal Wifi/);
    assert.ok(!out.includes("42-ITO WiFi"));
  });

  it("returns zero-match message when nothing matches", async () => {
    const out = await searchItems(client, { query: "nothinghere" });
    assert.match(out, /No items matched "nothinghere"\./);
  });

  it("throws when vault filter resolves to nothing", async () => {
    await assert.rejects(
      () => searchItems(client, { query: "x", vault: "doesnotexist" }),
      /not found/,
    );
  });
});

describe("generatePasswordHandler", () => {
  it("generates a Random password of the requested length", () => {
    const out = generatePasswordHandler({ type: "Random", length: 24 });
    // Output shape: "Generated (Random):\n<password>"
    const [, pwd] = out.split("\n");
    assert.equal(pwd.length, 24);
  });

  it("generates a Pin of digits", () => {
    const out = generatePasswordHandler({ type: "Pin", length: 6 });
    const [, pwd] = out.split("\n");
    assert.match(pwd, /^\d{6}$/);
  });

  it("generates a Memorable phrase with digit separators", () => {
    const out = generatePasswordHandler({ type: "Memorable", wordCount: 4 });
    const [, pwd] = out.split("\n");
    // Should contain at least one alphabetic run
    assert.match(pwd, /[A-Za-z]/);
  });

  it("defaults to Random when type is omitted", () => {
    const out = generatePasswordHandler({});
    assert.match(out, /^Generated \(Random\):/);
  });
});
