const { describe, it, before } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

// Stub the MCP SDK so importing index.js does not try to talk to stdio.
const mockServer = {
  setRequestHandler: () => {},
  connect: () => Promise.resolve(),
};
const sdkPath = require.resolve("@modelcontextprotocol/sdk/server/index.js");
require.cache[sdkPath] = {
  id: sdkPath,
  filename: sdkPath,
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
const stdioPath = require.resolve(
  "@modelcontextprotocol/sdk/server/stdio.js",
);
require.cache[stdioPath] = {
  id: stdioPath,
  filename: stdioPath,
  loaded: true,
  exports: { StdioServerTransport: class {} },
};

// Point the module at a throwaway config file so we don't touch the real one.
const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "op-mcp-test-"));
process.env.HOME = tmpHome;

const { redactField, formatItem } = require("../index.js");

describe("redactField", () => {
  it("redacts Concealed fields by default", () => {
    const field = {
      id: "password",
      title: "password",
      fieldType: "Concealed",
      value: "super-secret",
    };
    const r = redactField(field, false);
    assert.equal(r.value, "[REDACTED]");
  });

  it("reveals Concealed values when includeConcealed=true", () => {
    const field = {
      id: "password",
      title: "password",
      fieldType: "Concealed",
      value: "super-secret",
    };
    const r = redactField(field, true);
    assert.equal(r.value, "super-secret");
  });

  it("passes Text fields through untouched", () => {
    const field = { id: "u", title: "username", fieldType: "Text", value: "alice" };
    const r = redactField(field, false);
    assert.equal(r.value, "alice");
  });

  it("surfaces OTP codes when concealed is revealed", () => {
    const field = {
      id: "otp",
      title: "one-time password",
      fieldType: "Totp",
      value: "otpauth://...",
      details: { type: "Otp", content: { code: "123456" } },
    };
    const r = redactField(field, true);
    assert.equal(r.otp, "123456");
  });

  it("redacts Totp field value when concealed is NOT revealed", () => {
    const field = {
      id: "otp",
      title: "one-time password",
      fieldType: "Totp",
      value: "otpauth://...",
      details: { type: "Otp", content: { code: "123456" } },
    };
    const r = redactField(field, false);
    assert.equal(r.value, "[REDACTED]");
    assert.equal(r.otp, undefined);
  });
});

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
});
