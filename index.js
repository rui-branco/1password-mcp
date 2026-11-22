#!/usr/bin/env node

// ============================================================================
// 1Password MCP Server
//
// Exposes 1Password vault/item operations as MCP tools for Claude Code. Uses
// the official @1password/sdk with either a service-account token or desktop
// app auth (delegating unlock to 1Password 8 via DesktopAuth).
//
// Multi-instance: several 1Password accounts can be configured; each tool
// accepts an optional `instance` parameter to pick which one to hit.
//
// Desktop-app auth goes through one shared background process (broker.js), so
// the app asks the user to approve once for every chat instead of once per
// server process. See "One approval for everything" below.
// ============================================================================

// Handle `1password-mcp setup` subcommand
if (process.argv[2] === "setup") {
  require("./setup.js");
  return;
}

// What this process is: the MCP server (default), the shared background
// process (`--broker`, started by a server, never by hand), the `read`
// command, or a module loaded by the tests.
const RUN_AS =
  require.main !== module
    ? "module"
    : process.argv[2] === "--broker"
      ? "broker"
      : process.argv[2] === "read"
        ? "read"
        : "server";
const IS_SERVER = RUN_AS === "server" || RUN_AS === "module";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { AsyncLocalStorage } = require("async_hooks");
const sdk = require("@1password/sdk");
const { ICONS } = require("./icons.js");
const broker = require("./broker.js");
const { spawn } = require("child_process");

const PKG_VERSION = require("./package.json").version;
const INTEGRATION_NAME = "1password-mcp";

// ============================================================================
// Auto-update — same pattern as jira-mcp: ask the npm registry on every start
// what the latest published version is, and install it in the background when
// it isn't the one we're running. The package ships through npm, so there's no
// git involved: a plain fetch plus an npm install. Runs detached from startup
// so the server begins serving stdio immediately.
// ============================================================================
const NPM_PACKAGE = "@rui.branco/1password-mcp";
(async () => {
  // Only the server looks for updates: the shared process and `read` run the
  // code a server already brought up to date.
  if (!IS_SERVER) return;
  try {
    const res = await fetch(
      `https://registry.npmjs.org/${encodeURIComponent(NPM_PACKAGE)}/latest`,
      { signal: AbortSignal.timeout(5000) },
    );
    const latest = (await res.json()).version;
    if (latest && latest !== PKG_VERSION) {
      // Passed as one shell string rather than an argv array: npm is npm.cmd on
      // Windows, and since Node 18.20.2 spawning a .cmd without a shell throws
      // EINVAL outright (CVE-2024-27980 hardening). shell:true picks cmd.exe
      // there and /bin/sh elsewhere, so this stays portable — unlike the old
      // hardcoded `sh`, which simply doesn't exist on Windows. The command is a
      // fixed literal with no interpolation, so there's nothing to inject.
      const child = spawn(`npm install -g ${NPM_PACKAGE}`, {
        shell: true,
        stdio: "ignore",
      });
      // A spawn failure (npm missing from PATH) arrives as an async 'error'
      // event, which no try/catch around the spawn can see — left unhandled it
      // would take the whole server down at startup. Swallow it here.
      child.on("error", () => {});
    }
  } catch {
    /* offline, slow registry, or bad response — no-op */
  }
})();

// ============================================================================
// Config
// ============================================================================

const CONFIG_DIR = path.join(os.homedir(), ".config", "1password-mcp");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");

function ensureConfigDir() {
  if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

function loadConfigFile() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  } catch {
    return {};
  }
}

function saveConfigFile(cfg) {
  ensureConfigDir();
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
  try {
    fs.chmodSync(CONFIG_PATH, 0o600);
  } catch {
    /* chmod can fail on non-POSIX filesystems — non-fatal */
  }
}

ensureConfigDir();

/**
 * Normalize a persisted config entry into the runtime instance shape.
 * Accepts legacy records that only had a token and infers authType.
 */
function normalizeInstance(raw) {
  return {
    name: raw.name,
    authType: raw.authType || (raw.token ? "serviceAccount" : "desktop"),
    token: raw.token,
    accountName: raw.accountName,
    description: raw.description || "",
  };
}

let instances = [];
let defaultInstance = null;

// Options beside the instance list, both on unless the config says `false`:
//   sharedApproval  desktop-app calls go through the one shared process
//   keepAuthorized  that process keeps the approval alive while 1Password
//                   stays unlocked, instead of letting it end after ten
//                   quiet minutes
const settings = { sharedApproval: true, keepAuthorized: true };

// Cache SDK clients per instance — createClient spins up a WASM runtime and
// negotiates an auth session, so we want exactly one per process lifetime.
// The PROMISE is cached, not the client: tool calls often arrive together,
// and two of them would otherwise each create a client and each ask the
// desktop app for approval.
const clientCache = new Map();
// What each cached client was built from, so a client for an instance that
// was since removed or pointed at another account is not reused.
const clientAuth = new Map();

function authOf(instance) {
  return `${instance.authType}|${instance.accountName || ""}|${instance.token || ""}`;
}

/**
 * Read the config file again. The file is shared: another server process, the
 * setup wizard or the shared process may have changed it since this process
 * started, and a call must not run against an instance list that is out of
 * date.
 */
function reloadConfig() {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  } catch (e) {
    // There but unreadable: another process is writing it this instant. Keep
    // what we have rather than run the call with no instances at all.
    if (e.code !== "ENOENT") return;
    raw = {};
  }
  instances = (raw.instances || []).map(normalizeInstance);
  defaultInstance =
    (raw.defaultInstance &&
      instances.find((i) => i.name === raw.defaultInstance)) ||
    instances[0] ||
    null;
  settings.sharedApproval = raw.sharedApproval !== false;
  settings.keepAuthorized = raw.keepAuthorized !== false;
  for (const [name, built] of clientAuth) {
    const inst = instances.find((i) => i.name === name);
    if (!inst || authOf(inst) !== built) invalidateClient(name);
  }
}

reloadConfig();

/**
 * Resolve an instance by name, falling back to the default if the name is
 * omitted or unknown. Returns null only when no instances are configured at all.
 */
function getInstanceByName(name) {
  if (!name) return defaultInstance;
  return instances.find((i) => i.name === name) || defaultInstance;
}

// ============================================================================
// 1Password SDK client
// ============================================================================

function buildAuth(instance) {
  if (instance.authType === "desktop") {
    if (!instance.accountName) {
      throw new Error(
        `Instance "${instance.name}" is desktop-auth but has no accountName. Re-run setup.`,
      );
    }
    return new sdk.DesktopAuth(instance.accountName);
  }
  if (!instance.token) {
    throw new Error(`Instance "${instance.name}" has no service account token.`);
  }
  return instance.token;
}

async function getClient(instance) {
  if (!instance) {
    throw new Error(
      "No 1Password instance configured. Run `1password-mcp setup` or call op_add_instance.",
    );
  }
  let pending = clientCache.get(instance.name);
  if (!pending) {
    pending = sdk.createClient({
      auth: buildAuth(instance),
      integrationName: INTEGRATION_NAME,
      integrationVersion: `v${PKG_VERSION}`,
    });
    clientCache.set(instance.name, pending);
    clientAuth.set(instance.name, authOf(instance));
    // A refused or failed approval must not stick: the next call asks again.
    pending.catch(() => {
      if (clientCache.get(instance.name) === pending) {
        invalidateClient(instance.name);
      }
    });
  }
  return pending;
}

function invalidateClient(name) {
  clientCache.delete(name);
  clientAuth.delete(name);
}

/**
 * Detect errors that indicate the IPC / desktop-app session is dead so the
 * cached SDK client can be discarded and a fresh one created on retry.
 */
function isSessionError(e) {
  if (e instanceof sdk.DesktopSessionExpiredError) return true;
  // Belt-and-suspenders: catch IPC / auth wording from the native layer even
  // when the SDK wraps it in a generic Error. "invalid client id" is what the
  // desktop app answers once it has dropped a client, e.g. after a lock.
  return /IPC|session.expired|desktop.auth|socket.closed|invalid.client.id/i.test(e.message);
}

// ============================================================================
// Helpers — vault/item resolution, redaction, formatting
// ============================================================================

async function collect(asyncIterable) {
  const out = [];
  for await (const x of asyncIterable) out.push(x);
  return out;
}

/**
 * Resolve a vault from a reference that may be an id, exact title (case-insensitive),
 * or prefix of a title. Returns null when nothing matches.
 */
async function resolveVault(client, vaultRef) {
  if (!vaultRef) return null;
  const vaults = await collect(await client.vaults.list());
  const byId = vaults.find((v) => v.id === vaultRef);
  if (byId) return byId;
  const lower = String(vaultRef).toLowerCase();
  return (
    vaults.find((v) => (v.title || "").toLowerCase() === lower) ||
    vaults.find((v) => (v.title || "").toLowerCase().startsWith(lower)) ||
    null
  );
}

/**
 * Same strategy as resolveVault but for items inside a specific vault.
 */
async function resolveItem(client, vault, itemRef) {
  if (!itemRef) return null;
  const items = await collect(await client.items.list(vault.id));
  const byId = items.find((i) => i.id === itemRef);
  if (byId) return byId;
  const lower = String(itemRef).toLowerCase();
  return (
    items.find((i) => (i.title || "").toLowerCase() === lower) ||
    items.find((i) => (i.title || "").toLowerCase().startsWith(lower)) ||
    null
  );
}

/**
 * Shape a single 1Password field for output. Concealed and TOTP values are
 * replaced with "[REDACTED]" unless includeConcealed=true. OTP codes are only
 * surfaced when concealed values are revealed.
 */
function redactField(field, includeConcealed) {
  const out = {
    id: field.id,
    title: field.title,
    type: field.fieldType,
    sectionId: field.sectionId || undefined,
  };
  const isSecret = field.fieldType === "Concealed" || field.fieldType === "Totp";
  if (!isSecret || includeConcealed) {
    out.value = field.value;
    if (
      field.details &&
      field.details.type === "Otp" &&
      field.details.content &&
      field.details.content.code
    ) {
      out.otp = field.details.content.code;
    }
  } else {
    out.value = "[REDACTED]";
  }
  return out;
}

/**
 * Flatten a full 1Password item (as returned by client.items.get) into a
 * stable JSON shape that's safe to display to the model.
 */
function formatItem(item, includeConcealed) {
  return {
    id: item.id,
    title: item.title,
    category: item.category,
    vaultId: item.vaultId,
    tags: item.tags || [],
    websites: (item.websites || []).map((w) => ({
      url: w.url,
      label: w.label,
    })),
    fields: (item.fields || []).map((f) => redactField(f, includeConcealed)),
    sections: (item.sections || []).map((s) => ({ id: s.id, title: s.title })),
  };
}

// ============================================================================
// Tool definitions (exposed via tools/list)
// ============================================================================

const TOOL_DEFINITIONS = [
  {
    name: "op_list_instances",
    description:
      "List configured 1Password instances (service accounts or desktop). Tokens are never returned.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "op_add_instance",
    description:
      "Add or update a 1Password instance. Two auth modes: (1) 'serviceAccount' — provide token (ops_...). (2) 'desktop' — provide accountName (e.g. 'my.1password.com'); auth is delegated to the installed 1Password 8 desktop app via biometric unlock. Config is stored at ~/.config/1password-mcp/config.json with 0600 permissions.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Unique name (e.g., 'work', 'personal').",
        },
        authType: {
          type: "string",
          description: "'serviceAccount' (default) or 'desktop'.",
        },
        token: {
          type: "string",
          description:
            "Service account token (ops_...) — required for authType=serviceAccount.",
        },
        accountName: {
          type: "string",
          description:
            "1Password account (e.g. 'my.1password.com' or shorthand) — required for authType=desktop. Uses the logged-in 1Password 8 app.",
        },
        description: {
          type: "string",
          description: "Optional human-readable description.",
        },
        setDefault: {
          type: "boolean",
          description: "Set this instance as the default (default: false).",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "op_remove_instance",
    description:
      "Remove a 1Password instance by name. Cannot remove the last one.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Instance name to remove." },
      },
      required: ["name"],
    },
  },
  {
    name: "op_list_vaults",
    description:
      "List all vaults visible to the given instance's 1Password account.",
    inputSchema: {
      type: "object",
      properties: {
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: [],
    },
  },
  {
    name: "op_list_items",
    description:
      "List items in a vault. `vault` accepts a vault id or title (case-insensitive exact, then prefix).",
    inputSchema: {
      type: "object",
      properties: {
        vault: { type: "string", description: "Vault id or title." },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["vault"],
    },
  },
  {
    name: "op_search_items",
    description:
      "Search items by title across vaults. When the user asks for a specific credential by name (e.g. 'give me the wifi password', 'what's my GitHub login'), call this with `reveal: true` to get the password/credential values back in a single call — no follow-up op_get_item needed. If `vault` is omitted, searches every vault the account can see. When there are 1–5 matches with reveal=true, return all of them; the user already consented to seeing concealed values by asking for them.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Case-insensitive substring of the item title.",
        },
        vault: {
          type: "string",
          description: "Optional vault id or title to scope the search.",
        },
        limit: {
          type: "number",
          description: "Max results (default 25, or 5 when reveal=true to avoid fetching too many items).",
        },
        reveal: {
          type: "boolean",
          description:
            "If true, fetch each match's full item and return concealed field values (passwords, TOTPs) in cleartext. Use this when the user is asking for a credential by name — one call gets search + retrieval + reveal. Defaults to false.",
        },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "op_get_item",
    description:
      "Fetch a full item with all fields. By default concealed fields (passwords, TOTP) are redacted; set includeConcealed=true to return them in cleartext. `item` and `vault` accept ids or titles.",
    inputSchema: {
      type: "object",
      properties: {
        vault: { type: "string", description: "Vault id or title." },
        item: { type: "string", description: "Item id or title." },
        includeConcealed: {
          type: "boolean",
          description: "Return concealed values in cleartext (default: false).",
        },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["vault", "item"],
    },
  },
  {
    name: "op_get_secret",
    description:
      "Resolve a 1Password secret reference (op://vault/item/field) and return the value.",
    inputSchema: {
      type: "object",
      properties: {
        reference: {
          type: "string",
          description: "Secret reference like 'op://Private/GitHub/password'.",
        },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "op_generate_password",
    description:
      "Generate a password using 1Password's generator (Random / Memorable / Pin). Does not talk to the account.",
    inputSchema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          description: "'Random' (default), 'Memorable', or 'Pin'.",
        },
        length: {
          type: "number",
          description: "Length for Random/Pin (default 20/8).",
        },
        includeDigits: {
          type: "boolean",
          description: "Random only (default true).",
        },
        includeSymbols: {
          type: "boolean",
          description: "Random only (default true).",
        },
        wordCount: {
          type: "number",
          description: "Memorable only (default 5).",
        },
        capitalize: {
          type: "boolean",
          description: "Memorable only (default true).",
        },
      },
      required: [],
    },
  },
  {
    name: "op_create_item",
    description:
      "Create a new item in a vault. Fields is an array of { title, type, value, sectionId? }. Type is Text | Concealed | Totp | Email | Url | Phone.",
    inputSchema: {
      type: "object",
      properties: {
        vault: { type: "string", description: "Vault id or title." },
        title: { type: "string", description: "Item title." },
        category: {
          type: "string",
          description:
            "Item category (default: Login). One of: Login, SecureNote, Password, ApiCredentials, Database, Server, Email, Identity, CreditCard, etc.",
        },
        fields: {
          type: "array",
          description:
            "Field definitions: [{ title, type, value, sectionId? }].",
          items: {
            type: "object",
            properties: {
              title: { type: "string" },
              type: { type: "string" },
              value: { type: "string" },
              sectionId: { type: "string" },
            },
            required: ["title", "type", "value"],
          },
        },
        tags: { type: "array", items: { type: "string" } },
        websites: {
          type: "array",
          items: {
            type: "object",
            properties: {
              url: { type: "string" },
              label: { type: "string" },
            },
            required: ["url"],
          },
        },
        notes: {
          type: "string",
          description:
            "Optional notes (stored as a Text field called 'notesPlain').",
        },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["vault", "title"],
    },
  },
  {
    name: "op_update_item",
    description:
      "Update any part of an existing item — title, category, fields, tags, websites, sections, or notes. Omitted parameters are preserved. Fields are patched by title (existing fields match case-insensitively; new fields require `type`). Tags, websites, and sections are REPLACED when passed.",
    inputSchema: {
      type: "object",
      properties: {
        vault: { type: "string", description: "Vault id or title." },
        item: { type: "string", description: "Item id or title to update." },
        title: { type: "string", description: "New title (optional)." },
        category: {
          type: "string",
          description:
            "New category (rare). One of Login, SecureNote, Password, ApiCredentials, Database, Server, Email, Identity, CreditCard, etc.",
        },
        fields: {
          type: "array",
          description:
            "Field patches: [{title, value, type?, sectionId?}]. Existing fields matched by title have their values replaced. New fields require `type` (Text | Concealed | Totp | Email | Url | Phone).",
          items: {
            type: "object",
            properties: {
              title: { type: "string" },
              value: { type: "string" },
              type: { type: "string" },
              sectionId: { type: "string" },
            },
            required: ["title", "value"],
          },
        },
        tags: {
          type: "array",
          items: { type: "string" },
          description:
            "Replace the tag list. Omit to preserve existing tags; pass [] to clear.",
        },
        websites: {
          type: "array",
          description:
            "Replace the website list. Each website is {url, label?, autofillBehavior?}. Omit to preserve existing websites.",
          items: {
            type: "object",
            properties: {
              url: { type: "string" },
              label: { type: "string" },
              autofillBehavior: {
                type: "string",
                description: "'AnywhereOnWebsite' (default) or 'Never'.",
              },
            },
            required: ["url"],
          },
        },
        sections: {
          type: "array",
          description: "Replace the section list. Each section is {title, id?}.",
          items: {
            type: "object",
            properties: {
              title: { type: "string" },
              id: { type: "string" },
            },
            required: ["title"],
          },
        },
        notes: {
          type: "string",
          description:
            "Replace the notesPlain field. Omit to preserve existing notes.",
        },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["vault", "item"],
    },
  },
  {
    name: "op_update_vault",
    description:
      "Update a vault's title and/or description. Pass at least one of them.",
    inputSchema: {
      type: "object",
      properties: {
        vault: { type: "string", description: "Vault id or title." },
        title: { type: "string", description: "New title (optional)." },
        description: {
          type: "string",
          description: "New description (optional).",
        },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["vault"],
    },
  },
  {
    name: "op_delete_item",
    description: "Delete an item by vault + item reference.",
    inputSchema: {
      type: "object",
      properties: {
        vault: { type: "string", description: "Vault id or title." },
        item: { type: "string", description: "Item id or title." },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["vault", "item"],
    },
  },
  {
    name: "op_create_vault",
    description: "Create a new vault.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "Vault title." },
        description: {
          type: "string",
          description: "Optional description.",
        },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["title"],
    },
  },
  {
    name: "op_delete_vault",
    description: "Delete a vault by id or title.",
    inputSchema: {
      type: "object",
      properties: {
        vault: { type: "string", description: "Vault id or title." },
        instance: {
          type: "string",
          description: "Instance name. Uses default if omitted.",
        },
      },
      required: ["vault"],
    },
  },
];

// ============================================================================
// Handlers
//
// Each handler is keyed by tool name and receives the tool arguments. It
// should return a plain string (rendered as text content by the dispatcher)
// or throw on failure. The dispatcher handles MCP wrapping and error shape.
// ============================================================================

async function addInstanceHandler(args) {
  const instName = args.name.trim();
  const authType = args.authType || (args.token ? "serviceAccount" : "desktop");

  if (authType === "serviceAccount") {
    if (!args.token) {
      throw new Error("serviceAccount authType requires a token.");
    }
    if (!/^ops_[A-Za-z0-9_\-]+/.test(args.token)) {
      throw new Error(
        "Token does not look like a 1Password service account token (expected prefix 'ops_').",
      );
    }
  } else if (authType === "desktop") {
    if (!args.accountName) {
      throw new Error(
        "desktop authType requires accountName (e.g. 'my.1password.com').",
      );
    }
  } else {
    throw new Error(`Unknown authType "${authType}".`);
  }

  // Validate by creating a client and listing one vault.
  const probeAuth =
    authType === "desktop" ? new sdk.DesktopAuth(args.accountName) : args.token;
  const tempClient = await sdk.createClient({
    auth: probeAuth,
    integrationName: INTEGRATION_NAME,
    integrationVersion: `v${PKG_VERSION}`,
  });
  const probe = [];
  for await (const v of await tempClient.vaults.list()) {
    probe.push(v);
    if (probe.length >= 1) break;
  }

  const newInst = {
    name: instName,
    authType,
    token: authType === "serviceAccount" ? args.token : undefined,
    accountName: authType === "desktop" ? args.accountName : undefined,
    description: args.description || "",
  };
  const existingIdx = instances.findIndex((i) => i.name === instName);
  if (existingIdx >= 0) instances[existingIdx] = newInst;
  else instances.push(newInst);
  invalidateClient(instName);

  const savedConfig = loadConfigFile();
  if (!savedConfig.instances) savedConfig.instances = [];
  const savedIdx = savedConfig.instances.findIndex((i) => i.name === instName);
  const toSave = { name: instName, authType };
  if (authType === "serviceAccount") toSave.token = args.token;
  if (authType === "desktop") toSave.accountName = args.accountName;
  if (args.description) toSave.description = args.description;
  if (savedIdx >= 0) savedConfig.instances[savedIdx] = toSave;
  else savedConfig.instances.push(toSave);
  if (args.setDefault || !savedConfig.defaultInstance) {
    savedConfig.defaultInstance = instName;
    defaultInstance = newInst;
  }
  saveConfigFile(savedConfig);

  const verb = existingIdx >= 0 ? "Updated" : "Added";
  const suffix = args.setDefault ? " Set as default." : "";
  return `${verb} instance "${instName}" (${authType}).${suffix}`;
}

async function removeInstanceHandler(args) {
  if (instances.length <= 1) {
    throw new Error("Cannot remove the last remaining instance.");
  }
  const idx = instances.findIndex((i) => i.name === args.name);
  if (idx < 0) throw new Error(`Instance "${args.name}" not found.`);

  instances.splice(idx, 1);
  invalidateClient(args.name);

  const savedConfig = loadConfigFile();
  if (savedConfig.instances) {
    savedConfig.instances = savedConfig.instances.filter(
      (i) => i.name !== args.name,
    );
    if (savedConfig.defaultInstance === args.name) {
      savedConfig.defaultInstance = savedConfig.instances[0]?.name || null;
      defaultInstance = instances[0] || null;
    }
    saveConfigFile(savedConfig);
  }
  return `Removed instance "${args.name}".`;
}

function listInstancesHandler() {
  if (instances.length === 0) {
    return "No instances configured. Run `1password-mcp setup` or call op_add_instance.";
  }
  const def = defaultInstance?.name;
  const lines = instances.map((inst) => {
    const isDefault = inst.name === def ? " **(default)**" : "";
    const desc = inst.description ? ` - ${inst.description}` : "";
    const auth =
      inst.authType === "desktop"
        ? ` (desktop: ${inst.accountName})`
        : " (serviceAccount)";
    return `- **${inst.name}**${isDefault}${auth}${desc}`;
  });
  return `# 1Password Instances (${instances.length})\n\n${lines.join("\n")}`;
}

async function listVaultsHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const vaults = await collect(await client.vaults.list());
  if (vaults.length === 0) {
    return "No vaults visible to this instance.";
  }
  const lines = vaults.map((v) => `- **${v.title}** (id: ${v.id})`);
  return `# Vaults (${vaults.length})\n\n${lines.join("\n")}`;
}

async function listItemsHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const vault = await resolveVault(client, args.vault);
  if (!vault) throw new Error(`Vault "${args.vault}" not found.`);

  const items = await collect(await client.items.list(vault.id));
  if (items.length === 0) {
    return `No items in vault "${vault.title}".`;
  }
  const lines = items.map(
    (i) => `- **${i.title}** (id: ${i.id}, category: ${i.category})`,
  );
  return `# Items in ${vault.title} (${items.length})\n\n${lines.join("\n")}`;
}

/**
 * Core search implementation — pulled out of the handler so it can be unit
 * tested with a fake client. Accepts an already-resolved client.
 */
async function searchItems(client, { query, vault, reveal, limit }) {
  const wantReveal = !!reveal;
  const max = limit || (wantReveal ? 5 : 25);
  const q = String(query).toLowerCase();

  let targetVaults;
  if (vault) {
    const v = await resolveVault(client, vault);
    if (!v) throw new Error(`Vault "${vault}" not found.`);
    targetVaults = [v];
  } else {
    targetVaults = await collect(await client.vaults.list());
  }

  const hits = [];
  for (const v of targetVaults) {
    for await (const it of await client.items.list(v.id)) {
      if ((it.title || "").toLowerCase().includes(q)) {
        hits.push({ ...it, _vaultId: v.id, _vaultTitle: v.title });
        if (hits.length >= max) break;
      }
    }
    if (hits.length >= max) break;
  }

  if (hits.length === 0) return `No items matched "${query}".`;

  if (!wantReveal) {
    const lines = hits.map(
      (it) =>
        `- **${it.title}** (id: ${it.id}, vault: ${it._vaultTitle}, category: ${it.category})`,
    );
    return `# Search: "${query}" (${hits.length})\n\n${lines.join("\n")}`;
  }

  // reveal=true: fetch each hit's full item in parallel and render every
  // field (including concealed values). One-shot path for "give me the X
  // credential" style queries.
  const full = await Promise.all(
    hits.map(async (it) => {
      try {
        const item = await client.items.get(it._vaultId, it.id);
        return { item, _vaultTitle: it._vaultTitle, _error: null };
      } catch (e) {
        return { item: it, _vaultTitle: it._vaultTitle, _error: e.message };
      }
    }),
  );

  const sections = full.map((entry) => {
    if (entry._error) {
      return `## ${entry.item.title}\n\n_Failed to fetch: ${entry._error}_`;
    }
    const it = entry.item;
    const fields = (it.fields || [])
      .map((f) => redactField(f, true))
      .filter((f) => f.value !== undefined && f.value !== "");
    const fieldLines = fields.length
      ? fields
          .map((f) => {
            const otp = f.otp ? ` (OTP now: ${f.otp})` : "";
            return `- **${f.title}** (${f.type}): ${f.value}${otp}`;
          })
          .join("\n")
      : "_(no fields)_";
    const websites = (it.websites || []).map((w) => w.url).filter(Boolean);
    const websiteLine = websites.length
      ? `- **URLs:** ${websites.join(", ")}\n`
      : "";
    return `## ${it.title} (${it.category})\n\n- **Vault:** ${entry._vaultTitle}\n- **Item ID:** ${it.id}\n${websiteLine}\n${fieldLines}`;
  });

  return `# Search (revealed): "${query}" (${hits.length})\n\n${sections.join("\n\n")}`;
}

async function searchItemsHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  return searchItems(client, args);
}

async function getItemHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const vault = await resolveVault(client, args.vault);
  if (!vault) throw new Error(`Vault "${args.vault}" not found.`);
  const itemRef = await resolveItem(client, vault, args.item);
  if (!itemRef) {
    throw new Error(
      `Item "${args.item}" not found in vault "${vault.title}".`,
    );
  }
  const full = await client.items.get(vault.id, itemRef.id);
  const formatted = formatItem(full, !!args.includeConcealed);

  const lines = [
    `# ${formatted.title} (${formatted.category})`,
    "",
    `- **Vault:** ${vault.title} (${formatted.vaultId})`,
    `- **Item ID:** ${formatted.id}`,
  ];
  if (formatted.tags.length) lines.push(`- **Tags:** ${formatted.tags.join(", ")}`);
  if (formatted.websites.length) {
    lines.push(
      `- **Websites:** ${formatted.websites.map((w) => w.url).join(", ")}`,
    );
  }
  if (formatted.fields.length) {
    lines.push("", "## Fields", "");
    for (const f of formatted.fields) {
      const val = f.value === undefined ? "" : f.value;
      const otp = f.otp ? ` (OTP now: ${f.otp})` : "";
      lines.push(`- **${f.title}** (${f.type}): ${val}${otp}`);
    }
  }
  if (!args.includeConcealed) {
    lines.push(
      "",
      "_Concealed fields are redacted. Call with includeConcealed=true to reveal._",
    );
  }
  return lines.join("\n");
}

async function getSecretHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const value = await client.secrets.resolve(args.reference);
  return `Secret for ${args.reference}:\n${value}`;
}

function generatePasswordHandler(args) {
  const type = args.type || "Random";
  let generated;
  if (type === "Pin") {
    generated = sdk.Secrets.generatePassword({
      type: "Pin",
      parameters: { length: args.length || 8 },
    });
  } else if (type === "Memorable") {
    generated = sdk.Secrets.generatePassword({
      type: "Memorable",
      parameters: {
        separatorType: sdk.SeparatorType.Digits,
        capitalize: args.capitalize !== false,
        wordListType: sdk.WordListType.FullWords,
        wordCount: args.wordCount || 5,
      },
    });
  } else {
    generated = sdk.Secrets.generatePassword({
      type: "Random",
      parameters: {
        includeDigits: args.includeDigits !== false,
        includeSymbols: args.includeSymbols !== false,
        length: args.length || 20,
      },
    });
  }
  const pwd =
    typeof generated === "string" ? generated : generated.password || generated;
  return `Generated (${type}):\n${pwd}`;
}

async function updateItemHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const vault = await resolveVault(client, args.vault);
  if (!vault) throw new Error(`Vault "${args.vault}" not found.`);
  const itemRef = await resolveItem(client, vault, args.item);
  if (!itemRef) {
    throw new Error(
      `Item "${args.item}" not found in vault "${vault.title}".`,
    );
  }

  const current = await client.items.get(vault.id, itemRef.id);
  const updated = { ...current };

  // --- title (rename) ---
  if (args.title) updated.title = args.title;

  // --- category (rarely changed, but the SDK allows it) ---
  if (args.category) {
    const cat = sdk.ItemCategory[args.category];
    if (!cat) throw new Error(`Unknown category "${args.category}".`);
    updated.category = cat;
  }

  // --- tags (replace when passed; preserved when omitted) ---
  if (args.tags) updated.tags = args.tags;

  // --- websites (replace when passed; preserved when omitted) ---
  if (Array.isArray(args.websites)) {
    updated.websites = args.websites.map((w) => ({
      url: w.url,
      label: w.label || "website",
      autofillBehavior:
        w.autofillBehavior === "Never"
          ? sdk.AutofillBehavior.Never
          : sdk.AutofillBehavior.AnywhereOnWebsite,
    }));
  }

  // --- sections (replace when passed; preserved when omitted) ---
  if (Array.isArray(args.sections)) {
    updated.sections = args.sections.map((s) => ({
      id: s.id || s.title.toLowerCase().replace(/\s+/g, "_"),
      title: s.title,
    }));
  }

  // --- fields (patch by title, add new ones with explicit type) ---
  const nextFields = [...(current.fields || [])];
  const fieldIndexByTitle = new Map(
    nextFields.map((f, idx) => [(f.title || "").toLowerCase(), idx]),
  );

  function upsertField({ title, value, type, sectionId }) {
    const key = title.toLowerCase();
    const existingIdx = fieldIndexByTitle.get(key);
    if (existingIdx !== undefined) {
      nextFields[existingIdx] = { ...nextFields[existingIdx], value };
      return;
    }
    if (!type) {
      throw new Error(
        `Field "${title}" doesn't exist on the item — pass a 'type' to add it as a new field.`,
      );
    }
    const ft = sdk.ItemFieldType[type];
    if (!ft) throw new Error(`Unknown field type "${type}".`);
    const added = {
      id: title.toLowerCase().replace(/\s+/g, "_"),
      title,
      fieldType: ft,
      value,
    };
    if (sectionId) added.sectionId = sectionId;
    fieldIndexByTitle.set(key, nextFields.length);
    nextFields.push(added);
  }

  if (Array.isArray(args.fields)) {
    for (const patch of args.fields) upsertField(patch);
  }

  // --- notes: stored as a 'notesPlain' Text field, so patch it the same way ---
  if (args.notes !== undefined) {
    upsertField({ title: "notesPlain", value: args.notes, type: "Text" });
  }

  updated.fields = nextFields;

  const result = await client.items.put(updated);
  return `Updated item "${result.title}" (id: ${result.id}) in vault "${vault.title}".`;
}

async function updateVaultHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const vault = await resolveVault(client, args.vault);
  if (!vault) throw new Error(`Vault "${args.vault}" not found.`);
  if (!args.title && args.description === undefined) {
    throw new Error("Provide at least one of title or description.");
  }
  await client.vaults.update(vault.id, {
    title: args.title || vault.title,
    description: args.description !== undefined ? args.description : vault.description || "",
  });
  return `Updated vault "${args.title || vault.title}" (id: ${vault.id}).`;
}

async function createItemHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const vault = await resolveVault(client, args.vault);
  if (!vault) throw new Error(`Vault "${args.vault}" not found.`);

  const category = sdk.ItemCategory[args.category || "Login"];
  if (!category) throw new Error(`Unknown category "${args.category}".`);

  const fields = (args.fields || []).map((f) => {
    const ft = sdk.ItemFieldType[f.type];
    if (!ft) throw new Error(`Unknown field type "${f.type}"`);
    const out = {
      id: f.title.toLowerCase().replace(/\s+/g, "_"),
      title: f.title,
      fieldType: ft,
      value: f.value,
    };
    if (f.sectionId) out.sectionId = f.sectionId;
    return out;
  });
  if (args.notes) {
    fields.push({
      id: "notesPlain",
      title: "notesPlain",
      fieldType: sdk.ItemFieldType.Text,
      value: args.notes,
    });
  }

  const item = await client.items.create({
    title: args.title,
    category,
    vaultId: vault.id,
    fields,
    tags: args.tags || [],
    websites: (args.websites || []).map((w) => ({
      url: w.url,
      label: w.label || "website",
      autofillBehavior: sdk.AutofillBehavior.AnywhereOnWebsite,
    })),
  });
  return `Created item **${item.title}** (id: ${item.id}) in vault "${vault.title}".`;
}

async function deleteItemHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const vault = await resolveVault(client, args.vault);
  if (!vault) throw new Error(`Vault "${args.vault}" not found.`);
  const itemRef = await resolveItem(client, vault, args.item);
  if (!itemRef) {
    throw new Error(
      `Item "${args.item}" not found in vault "${vault.title}".`,
    );
  }
  await client.items.delete(vault.id, itemRef.id);
  return `Deleted item "${itemRef.title}" from vault "${vault.title}".`;
}

async function createVaultHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const vault = await client.vaults.create({
    title: args.title,
    description: args.description || "",
  });
  return `Created vault **${vault.title}** (id: ${vault.id}).`;
}

async function deleteVaultHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const vault = await resolveVault(client, args.vault);
  if (!vault) throw new Error(`Vault "${args.vault}" not found.`);
  await client.vaults.delete(vault.id);
  return `Deleted vault "${vault.title}".`;
}

const HANDLERS = {
  op_list_instances: listInstancesHandler,
  op_add_instance: addInstanceHandler,
  op_remove_instance: removeInstanceHandler,
  op_list_vaults: listVaultsHandler,
  op_list_items: listItemsHandler,
  op_search_items: searchItemsHandler,
  op_get_item: getItemHandler,
  op_get_secret: getSecretHandler,
  op_generate_password: generatePasswordHandler,
  op_create_item: createItemHandler,
  op_update_item: updateItemHandler,
  op_delete_item: deleteItemHandler,
  op_create_vault: createVaultHandler,
  op_update_vault: updateVaultHandler,
  op_delete_vault: deleteVaultHandler,
};

// Drift guard: every declared tool must have a handler and vice versa. This is
// evaluated at module load so a missing/extra handler fails fast.
(function assertHandlerCompleteness() {
  const toolNames = new Set(TOOL_DEFINITIONS.map((t) => t.name));
  const handlerNames = new Set(Object.keys(HANDLERS));
  for (const name of toolNames) {
    if (!handlerNames.has(name)) {
      throw new Error(`Tool "${name}" is declared but has no handler.`);
    }
  }
  for (const name of handlerNames) {
    if (!toolNames.has(name)) {
      throw new Error(`Handler "${name}" exists but is not declared in TOOL_DEFINITIONS.`);
    }
  }
})();

// ============================================================================
// Running a call
// ============================================================================

/**
 * Runs `fn`. If the desktop-app session turns out to be dead, the cached
 * clients are thrown away and it runs once more, so the SDK opens a fresh
 * session.
 */
async function withSessionRetry(fn) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      if (attempt > 0 || !isSessionError(e)) throw e;
      clientCache.clear();
      clientAuth.clear();
    }
  }
}

/** Runs a tool in THIS process and returns its text. */
function runTool(name, args) {
  return withSessionRetry(async () => String(await HANDLERS[name](args)));
}

/** Resolves an `op://` reference in THIS process. */
function readSecret(instanceName, reference) {
  return withSessionRetry(async () => {
    const client = await getClient(getInstanceByName(instanceName));
    return client.secrets.resolve(reference);
  });
}

// ============================================================================
// One approval for everything (desktop-app auth)
//
// The 1Password app approves each calling process separately. A call that
// needs the desktop app is therefore not made here: it is handed to the one
// shared background process (see broker.js) that every server process and the
// `read` command use. The app sees a single caller and asks once.
//
// Service-account instances never make the app ask, so their calls stay in
// this process. If the shared process cannot be reached, the call runs here
// as it always did; the only cost is that the app may ask again.
// ============================================================================

const BROKER_ENDPOINT = broker.endpointFor(CONFIG_DIR, PKG_VERSION);

// Tools that never talk to a 1Password account.
const LOCAL_TOOLS = new Set([
  "op_list_instances",
  "op_remove_instance",
  "op_generate_password",
]);

/** True when running the tool makes the desktop app approve the caller. */
function usesDesktopApp(name, args) {
  if (LOCAL_TOOLS.has(name)) return false;
  if (name === "op_add_instance") {
    // Adding a desktop instance checks it against the app first.
    const authType = args.authType || (args.token ? "serviceAccount" : "desktop");
    return authType === "desktop";
  }
  const inst = getInstanceByName(args.instance);
  return !!inst && inst.authType === "desktop";
}

let brokerStarting = null;
let presence = null;

function brokerLink() {
  return { endpoint: BROKER_ENDPOINT, key: broker.loadKey(CONFIG_DIR) };
}

/**
 * Stay connected to the shared process for as long as this server runs. That
 * open connection is how it knows a chat is still there: once none has been
 * for an hour, it stops keeping the approval alive.
 */
function holdPresence(link) {
  if (presence || RUN_AS === "read") return;
  presence = broker
    .request({ ...link, payload: { method: "presence" }, keepOpen: true })
    .then(
      ({ sock }) => {
        // Must not keep this server running once its own client is gone.
        sock.unref();
        sock.on("close", () => {
          presence = null;
        });
        return sock;
      },
      () => {
        presence = null;
      },
    );
}

/**
 * Hands a request to the shared process, starting it when none is running.
 * Resolves with its reply, or with null when it cannot be used (turned off,
 * would not start, or the pipe is held by something that is not ours) and
 * the caller should do the work itself.
 */
async function viaBroker(payload) {
  if (!settings.sharedApproval) return null;
  let link;
  try {
    link = brokerLink();
  } catch {
    return null;
  }
  const from = { pid: process.pid, cwd: process.cwd() };
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const { reply } = await broker.request({
        ...link,
        payload: { ...payload, from },
      });
      holdPresence(link);
      return reply;
    } catch (e) {
      // It had the request and went away. Running the call again here could
      // repeat a change (a second item, a second delete), so report instead.
      if (e.sent) {
        throw new Error(
          "The shared 1Password process stopped while handling this call. Try again.",
        );
      }
      if (attempt > 0 || e.code !== "EUNREACHABLE") return null;
      if (!brokerStarting) {
        brokerStarting = broker
          .start({ ...link, entry: __filename })
          .catch(() => false)
          .finally(() => {
            brokerStarting = null;
          });
      }
      if (!(await brokerStarting)) return null;
    }
  }
  return null;
}

/** Runs a tool call wherever it belongs and returns its text. */
async function callTool(name, args) {
  reloadConfig();
  if (usesDesktopApp(name, args)) {
    const reply = await viaBroker({ method: "tool", name, args });
    if (reply) {
      if (!reply.ok) throw new Error(reply.error);
      return reply.text;
    }
  }
  return runTool(name, args);
}

// ============================================================================
// The shared process (`--broker`)
// ============================================================================

// Set while an approval is being refreshed. Inside it the SDK is refused a
// new approval, so a refresh can find out that the approval ended but can
// never be the reason the app asks the user.
const noPrompt = new AsyncLocalStorage();
const GUARD = Symbol.for("1password-mcp.guard");

/**
 * Hooks into the SDK's desktop-app transport. It tells `watch` when the app
 * approved an account, when a request for it went through and when the app
 * reported its session gone, and it refuses
 * a new approval inside `noPrompt`: the SDK asks again by itself whenever the
 * app reports the session gone, which is right for a call the user asked for
 * and wrong for a background refresh.
 *
 * The transport is not part of the SDK's public API. When it cannot be found
 * this returns false, and an approval is then never refreshed: it just
 * follows 1Password's own ten minute rule.
 */
function guardDesktopApp(watch = {}) {
  try {
    const file = path.join(
      path.dirname(require.resolve("@1password/sdk")),
      "shared_lib_core.js",
    );
    const proto = require(file).SharedLibCore.prototype;
    if (proto[GUARD]) {
      proto[GUARD].watch = watch;
      return true;
    }
    const { initClient, invoke } = proto;
    if (typeof initClient !== "function" || typeof invoke !== "function") {
      return false;
    }
    const state = { watch };
    // "acccountName" is the SDK's own spelling.
    const accountOf = (core) => core.acccountName || core.accountName;
    proto.initClient = async function (config) {
      if (noPrompt.getStore()) {
        throw new sdk.DesktopSessionExpiredError("the approval ended");
      }
      const started = Date.now();
      try {
        const id = await initClient.call(this, config);
        state.watch.authorized?.(accountOf(this), Date.now() - started);
        return id;
      } catch (e) {
        state.watch.refused?.(accountOf(this), Date.now() - started, e);
        throw e;
      }
    };
    proto.invoke = async function (config) {
      let out;
      try {
        out = await invoke.call(this, config);
      } catch (e) {
        // The app says so in two ways: the SDK's own error, or a plain
        // "invalid client id" once it has dropped the client (after a lock).
        if (
          e instanceof sdk.DesktopSessionExpiredError ||
          /invalid.client.id/i.test((e && e.message) || "")
        ) {
          state.watch.expired?.(accountOf(this));
        }
        throw e;
      }
      state.watch.used?.(accountOf(this));
      return out;
    };
    proto[GUARD] = state;
    return true;
  } catch {
    return false;
  }
}

// The tests run the shared process on a faster clock. It can only ever
// shorten how long an approval is kept, never stretch it.
const SPEED = Math.max(1, Number(process.env.OP_MCP_TEST_SPEED) || 1);
const TICK_MS = (30 * 1000) / SPEED;
// A shared process holding no approval leaves this long after its last call.
const LINGER_MS = (60 * 1000) / SPEED;

async function brokerMain() {
  process.title = "1password-mcp-broker";
  const log = broker.logger(path.join(CONFIG_DIR, "broker.log"));
  const asker = new AsyncLocalStorage(); // the call that is running, for the log
  const chats = new Set(); // one open connection per running server
  const seen = new Set(); // accounts whose approval went through the guard
  let inFlight = 0;
  let lastCallAt = Date.now();
  let stopping = false;
  let guarded = false;
  let listener = null;

  const leave = (why) => {
    log(`exit: ${why}`);
    try {
      listener?.close();
    } catch {
      /* going away anyway */
    }
    process.exit(0);
  };
  process.on("uncaughtException", (e) => {
    log(`crashed: ${(e && e.stack) || e}`);
    process.exit(1);
  });
  process.on("unhandledRejection", (e) => {
    log(`unhandled: ${(e && e.message) || e}`);
  });

  const keeper = broker.createKeeper({
    speed: SPEED,
    // Only where the guard is known to sit on the path the SDK really takes.
    canPing: (account) => guarded && seen.has(account),
    inUse: () => chats.size > 0,
    keepAuthorized: () => settings.keepAuthorized,
    ping: async (account) => {
      const inst = instances.find(
        (i) =>
          i.authType === "desktop" &&
          i.accountName === account &&
          clientCache.has(i.name),
      );
      if (!inst) throw new Error("no client left");
      const client = await clientCache.get(inst.name);
      await noPrompt.run(true, () => client.vaults.list());
    },
    drop: (account, why) => {
      seen.delete(account);
      for (const inst of instances) {
        if (inst.accountName === account) invalidateClient(inst.name);
      }
      log(`${account}: ${why}`);
    },
  });

  guarded = guardDesktopApp({
    authorized: (account, ms) => {
      seen.add(account);
      keeper.used(account);
      log(`${account}: approved after ${ms} ms, for ${asker.getStore() || "a call"}`);
    },
    refused: (account, ms, e) => {
      log(
        `${account}: not approved after ${ms} ms (${(e && e.message) || e}), for ${asker.getStore() || "a call"}`,
      );
    },
    used: (account) => keeper.used(account),
    expired: (account) => keeper.expired(account),
  });

  // The account a request reaches, for the keeper.
  const accountOf = (msg) => {
    const args = msg.args || {};
    if (msg.method === "tool" && msg.name === "op_add_instance") {
      return args.accountName;
    }
    const inst = getInstanceByName(
      msg.method === "tool" ? args.instance : msg.instance,
    );
    return inst && inst.authType === "desktop" ? inst.accountName : undefined;
  };

  // A caller that has connected may already have handed over its request.
  const busy = () => inFlight > 0 || (listener && listener.calls.size > 0);

  const stopSoon = () => {
    if (!busy()) leave("asked to stop");
    else setTimeout(stopSoon, 200);
  };

  const handle = async (msg) => {
    if (msg.method === "ping") return { ok: true };
    if (msg.method === "stop") {
      stopping = true;
      setTimeout(stopSoon, 50);
      return { ok: true };
    }
    inFlight++;
    lastCallAt = Date.now();
    keeper.wanted();
    try {
      reloadConfig();
      const from = msg.from
        ? `pid ${msg.from.pid} in ${msg.from.cwd}`
        : "an unknown caller";
      let text;
      if (msg.method === "tool") {
        if (!HANDLERS[msg.name]) {
          return { ok: false, error: `Unknown tool: ${msg.name}` };
        }
        const what = `${msg.name} from ${from}`;
        log(what);
        text = await asker.run(what, () => runTool(msg.name, msg.args || {}));
      } else if (msg.method === "resolve") {
        const what = `read from ${from}`;
        log(what);
        text = await asker.run(what, () =>
          readSecret(msg.instance, msg.reference),
        );
      } else {
        return { ok: false, error: `Unknown request: ${msg.method}` };
      }
      keeper.used(accountOf(msg));
      return { ok: true, text };
    } catch (e) {
      return { ok: false, error: (e && e.message) || String(e) };
    } finally {
      inFlight--;
      lastCallAt = Date.now();
    }
  };

  let ticking = false;
  const tick = async () => {
    if (ticking || busy() || stopping) return;
    ticking = true;
    try {
      reloadConfig();
      const holding = await keeper.tick();
      if (busy() || stopping) return;
      if (!holding && Date.now() - lastCallAt > LINGER_MS) {
        leave("nothing left to keep");
      }
    } finally {
      ticking = false;
    }
  };

  try {
    listener = await broker.serve({
      endpoint: BROKER_ENDPOINT,
      key: broker.loadKey(CONFIG_DIR),
      version: PKG_VERSION,
      handle,
      onPresence: (sock) => {
        chats.add(sock);
        sock.on("close", () => chats.delete(sock));
      },
    });
  } catch (e) {
    // The name is taken: another shared process is already up, use that one.
    if (e.code !== "EADDRINUSE" && e.code !== "EACCES") {
      log(`could not listen: ${e.message}`);
    }
    process.exit(0);
  }
  log(
    `started: pid ${process.pid}, v${PKG_VERSION}, guard ${guarded ? "on" : "off"}`,
  );
  setInterval(tick, TICK_MS);
}

// ============================================================================
// `1password-mcp read <op://vault/item/field>`
//
// Prints one secret to stdout through the same shared approval, for shell
// commands that need a value without it passing through the chat:
//   TOKEN=$(1password-mcp read "op://Private/GitHub/token")
// Without it a model reaches for the `op` CLI, and on Windows every `op` call
// makes the app ask the user again.
// ============================================================================

async function readMain(argv) {
  let instanceName;
  let reference;
  let newline = true;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--instance" || arg === "-i") instanceName = argv[++i];
    else if (arg === "-n" || arg === "--no-newline") newline = false;
    else if (reference === undefined) reference = arg;
    else reference = null;
  }
  if (!reference || !reference.startsWith("op://")) {
    console.error(
      'Usage: 1password-mcp read [--instance <name>] [-n] "op://vault/item/field"',
    );
    process.exit(2);
  }
  reloadConfig();
  const inst = getInstanceByName(instanceName);
  if (!inst) {
    throw new Error(
      "No 1Password instance configured. Run `1password-mcp setup`.",
    );
  }
  let value;
  if (inst.authType === "desktop") {
    const reply = await viaBroker({
      method: "resolve",
      instance: inst.name,
      reference,
    });
    if (reply) {
      if (!reply.ok) throw new Error(reply.error);
      value = reply.text;
    }
  }
  if (value === undefined) value = await readSecret(inst.name, reference);
  process.stdout.write(newline ? `${value}\n` : String(value), () =>
    process.exit(0),
  );
}

// ============================================================================
// MCP server wiring
// ============================================================================

/**
 * What the MCP client tells the model about this server. Only for desktop-app
 * auth: a service account never makes the app ask, so the advice against the
 * `op` CLI would be wrong there.
 */
function serverInstructions() {
  if (!instances.some((i) => i.authType === "desktop")) return undefined;
  const read = `node "${__filename.replace(/\\/g, "/")}" read`;
  return [
    "# 1Password",
    "",
    "- Reach 1Password only through these tools. Never run the `op` CLI or the 1Password SDK from a shell or a script: each such call makes the 1Password app ask the user to approve again (on Windows with the Windows Hello or password popup, every time). These tools share one approval across all chats.",
    `- To use a secret inside a shell command without printing it, read it through that same approval: \`${read} "op://vault/item/field"\` writes only the value to stdout (vault and item by name or id, \`--instance <name>\` for another instance). Example: \`TOKEN=$(${read} "op://Private/GitHub/token")\`.`,
    "- Keep lookups short: op_search_items with `reveal: true` finds an item and returns its values in one call.",
  ].join("\n");
}

let server = null;

if (IS_SERVER) {
  const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
  const {
    CallToolRequestSchema,
    ListToolsRequestSchema,
  } = require("@modelcontextprotocol/sdk/types.js");

  server = new Server(
    { name: INTEGRATION_NAME, version: PKG_VERSION, icons: ICONS },
    { capabilities: { tools: {} }, instructions: serverInstructions() },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFINITIONS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    if (!HANDLERS[name]) {
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
    }
    try {
      const text = await callTool(name, args || {});
      return { content: [{ type: "text", text }] };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${e.message}` }],
        isError: true,
      };
    }
  });
}

async function main() {
  const {
    StdioServerTransport,
  } = require("@modelcontextprotocol/sdk/server/stdio.js");
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // A shared process that is already up learns that this chat is here too.
  // It is not started for this: that happens on the first call that needs it.
  if (
    settings.sharedApproval &&
    instances.some((i) => i.authType === "desktop")
  ) {
    try {
      holdPresence(brokerLink());
    } catch {
      /* the first call sorts it out */
    }
  }
}

if (RUN_AS === "server") {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
} else if (RUN_AS === "broker") {
  brokerMain().catch(() => process.exit(1));
} else if (RUN_AS === "read") {
  readMain(process.argv.slice(3)).catch((e) => {
    console.error(`1password-mcp: ${(e && e.message) || e}`);
    process.exit(1);
  });
}

// ============================================================================
// Test exports
// ============================================================================

if (typeof module !== "undefined") {
  module.exports = {
    // config
    CONFIG_DIR,
    CONFIG_PATH,
    loadConfigFile,
    saveConfigFile,
    normalizeInstance,
    reloadConfig,
    settings,
    // instance resolution
    getInstanceByName,
    // running a call, and the shared approval
    getClient,
    clientCache,
    callTool,
    runTool,
    usesDesktopApp,
    LOCAL_TOOLS,
    BROKER_ENDPOINT,
    noPrompt,
    guardDesktopApp,
    serverInstructions,
    // helpers
    isSessionError,
    collect,
    resolveVault,
    resolveItem,
    redactField,
    formatItem,
    searchItems,
    // handler map + tool list (for drift guard tests)
    TOOL_DEFINITIONS,
    HANDLERS,
    // direct handler access for unit tests that don't need the MCP transport
    listInstancesHandler,
    listVaultsHandler,
    listItemsHandler,
    searchItemsHandler,
    getItemHandler,
    generatePasswordHandler,
    updateItemHandler,
    updateVaultHandler,
  };
}
