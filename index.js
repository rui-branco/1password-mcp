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
// ============================================================================

// Handle `1password-mcp setup` subcommand
if (process.argv[2] === "setup") {
  require("./setup.js");
  return;
}

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const {
  StdioServerTransport,
} = require("@modelcontextprotocol/sdk/server/stdio.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");
const fs = require("fs");
const path = require("path");
const sdk = require("@1password/sdk");
const { spawn, execSync } = require("child_process");

const PKG_VERSION = require("./package.json").version;
const INTEGRATION_NAME = "1password-mcp";

// ============================================================================
// Auto-update — same pattern as jira-mcp: check GitHub for a newer commit on
// every start, install in a detached background process if found.
// ============================================================================
const GITHUB_REPO = "rui-branco/1password-mcp";
const INSTALLED_SHA_FILE = path.join(__dirname, ".installed-sha");
try {
  const localSha = fs.existsSync(INSTALLED_SHA_FILE)
    ? fs.readFileSync(INSTALLED_SHA_FILE, "utf-8").trim()
    : "";
  const remoteSha = execSync(
    `git ls-remote https://github.com/${GITHUB_REPO}.git HEAD`,
    { stdio: "pipe", timeout: 5000 },
  )
    .toString()
    .split("\t")[0]
    .trim();
  if (remoteSha && remoteSha !== localSha) {
    const child = spawn(
      "sh",
      [
        "-c",
        `npm install -g git+ssh://git@github.com/${GITHUB_REPO}.git && echo "${remoteSha}" > "${INSTALLED_SHA_FILE}"`,
      ],
      { stdio: "ignore", detached: true },
    );
    child.unref();
  }
} catch {
  /* offline or git not available — no-op */
}

// ============================================================================
// Config
// ============================================================================

const CONFIG_DIR = path.join(process.env.HOME, ".config/1password-mcp");
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

const rawConfig = fs.existsSync(CONFIG_PATH)
  ? loadConfigFile()
  : { instances: [] };

let instances = (rawConfig.instances || []).map(normalizeInstance);

let defaultInstance =
  (rawConfig.defaultInstance &&
    instances.find((i) => i.name === rawConfig.defaultInstance)) ||
  instances[0] ||
  null;

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

// Cache SDK clients per instance — createClient spins up a WASM runtime and
// negotiates an auth session, so we want exactly one per process lifetime.
const clientCache = new Map();

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
  if (clientCache.has(instance.name)) return clientCache.get(instance.name);

  const client = await sdk.createClient({
    auth: buildAuth(instance),
    integrationName: INTEGRATION_NAME,
    integrationVersion: `v${PKG_VERSION}`,
  });
  clientCache.set(instance.name, client);
  return client;
}

function invalidateClient(name) {
  clientCache.delete(name);
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
      "Search items by title across vaults. If `vault` is omitted, searches every vault the account can see.",
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
          description: "Max results (default 25).",
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

async function searchItemsHandler(args) {
  const client = await getClient(getInstanceByName(args.instance));
  const limit = args.limit || 25;
  const q = String(args.query).toLowerCase();

  let targetVaults;
  if (args.vault) {
    const v = await resolveVault(client, args.vault);
    if (!v) throw new Error(`Vault "${args.vault}" not found.`);
    targetVaults = [v];
  } else {
    targetVaults = await collect(await client.vaults.list());
  }

  const hits = [];
  for (const v of targetVaults) {
    for await (const it of await client.items.list(v.id)) {
      if ((it.title || "").toLowerCase().includes(q)) {
        hits.push({ ...it, _vaultTitle: v.title });
        if (hits.length >= limit) break;
      }
    }
    if (hits.length >= limit) break;
  }

  if (hits.length === 0) return `No items matched "${args.query}".`;
  const lines = hits.map(
    (it) =>
      `- **${it.title}** (id: ${it.id}, vault: ${it._vaultTitle}, category: ${it.category})`,
  );
  return `# Search: "${args.query}" (${hits.length})\n\n${lines.join("\n")}`;
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
  op_delete_item: deleteItemHandler,
  op_create_vault: createVaultHandler,
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
// MCP server wiring
// ============================================================================

const server = new Server(
  { name: INTEGRATION_NAME, version: PKG_VERSION },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOL_DEFINITIONS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const handler = HANDLERS[name];
  if (!handler) {
    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    };
  }
  try {
    const result = await handler(args || {});
    return { content: [{ type: "text", text: String(result) }] };
  } catch (e) {
    return {
      content: [{ type: "text", text: `Error: ${e.message}` }],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
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
    // instance resolution
    getInstanceByName,
    // helpers
    collect,
    resolveVault,
    resolveItem,
    redactField,
    formatItem,
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
  };
}
