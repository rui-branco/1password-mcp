#!/usr/bin/env node

// Handle setup subcommand
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

// Auto-update: check GitHub for new commits, install in background
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
} catch {}

// ============ CONFIG ============

const configDir = path.join(process.env.HOME, ".config/1password-mcp");
const configPath = path.join(configDir, "config.json");

if (!fs.existsSync(configDir)) {
  fs.mkdirSync(configDir, { recursive: true });
}

function loadConfigFile() {
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    return {};
  }
}

function saveConfigFile(cfg) {
  fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2));
  try {
    fs.chmodSync(configPath, 0o600);
  } catch {}
}

const rawConfig = fs.existsSync(configPath) ? loadConfigFile() : { instances: [] };

let instances = (rawConfig.instances || []).map((i) => ({
  name: i.name,
  token: i.token,
  description: i.description || "",
}));

const defaultInstance =
  (rawConfig.defaultInstance && instances.find((i) => i.name === rawConfig.defaultInstance)) ||
  instances[0] ||
  null;

function getInstanceByName(name) {
  if (!name) return defaultInstance;
  return instances.find((i) => i.name === name) || defaultInstance;
}

// ============ 1PASSWORD CLIENT ============

// Cache SDK clients per instance so we don't re-auth on every call. The SDK
// client holds a WebAssembly runtime internally, so recreating it every call
// would be wasteful.
const clientCache = new Map();

async function getClient(instance) {
  if (!instance) {
    throw new Error(
      "No 1Password instance configured. Run `1password-mcp setup` or call op_add_instance.",
    );
  }
  if (clientCache.has(instance.name)) return clientCache.get(instance.name);
  if (!instance.token) {
    throw new Error(`Instance "${instance.name}" has no service account token.`);
  }
  const client = await sdk.createClient({
    auth: instance.token,
    integrationName: INTEGRATION_NAME,
    integrationVersion: `v${PKG_VERSION}`,
  });
  clientCache.set(instance.name, client);
  return client;
}

function invalidateClient(name) {
  clientCache.delete(name);
}

// ============ HELPERS ============

// Pick a vault by id OR by title (case-insensitive exact match, then prefix).
async function resolveVault(client, vaultRef) {
  if (!vaultRef) return null;
  const vaults = [];
  for await (const v of await client.vaults.list()) vaults.push(v);
  const byId = vaults.find((v) => v.id === vaultRef);
  if (byId) return byId;
  const lower = String(vaultRef).toLowerCase();
  const exact = vaults.find((v) => (v.title || "").toLowerCase() === lower);
  if (exact) return exact;
  const prefix = vaults.find((v) => (v.title || "").toLowerCase().startsWith(lower));
  if (prefix) return prefix;
  return null;
}

async function resolveItem(client, vault, itemRef) {
  if (!itemRef) return null;
  const items = [];
  for await (const it of await client.items.list(vault.id)) items.push(it);
  const byId = items.find((i) => i.id === itemRef);
  if (byId) return byId;
  const lower = String(itemRef).toLowerCase();
  const exact = items.find((i) => (i.title || "").toLowerCase() === lower);
  if (exact) return exact;
  const prefix = items.find((i) => (i.title || "").toLowerCase().startsWith(lower));
  if (prefix) return prefix;
  return null;
}

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
    if (field.details && field.details.type === "Otp" && field.details.content) {
      out.otp = field.details.content.code || undefined;
    }
  } else {
    out.value = "[REDACTED]";
  }
  return out;
}

function formatItem(item, includeConcealed) {
  return {
    id: item.id,
    title: item.title,
    category: item.category,
    vaultId: item.vaultId,
    tags: item.tags || [],
    websites: (item.websites || []).map((w) => ({ url: w.url, label: w.label })),
    fields: (item.fields || []).map((f) => redactField(f, includeConcealed)),
    sections: (item.sections || []).map((s) => ({ id: s.id, title: s.title })),
  };
}

// ============ MCP SERVER ============

const server = new Server(
  { name: INTEGRATION_NAME, version: PKG_VERSION },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "op_list_instances",
        description:
          "List configured 1Password instances (service accounts). Tokens are never returned.",
        inputSchema: { type: "object", properties: {}, required: [] },
      },
      {
        name: "op_add_instance",
        description:
          "Add or update a 1Password service-account instance. Provide name + token (and optional description). Token is stored in ~/.config/1password-mcp/config.json with 0600 permissions.",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string", description: "Unique name (e.g., 'work', 'personal')." },
            token: {
              type: "string",
              description: "1Password service account token (ops_... prefix).",
            },
            description: { type: "string", description: "Optional human-readable description." },
            setDefault: {
              type: "boolean",
              description: "Set this instance as the default (default: false).",
            },
          },
          required: ["name", "token"],
        },
      },
      {
        name: "op_remove_instance",
        description: "Remove a 1Password instance by name. Cannot remove the last one.",
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
        description: "List all vaults visible to the given instance's service account.",
        inputSchema: {
          type: "object",
          properties: {
            instance: { type: "string", description: "Instance name. Uses default if omitted." },
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
            instance: { type: "string", description: "Instance name. Uses default if omitted." },
          },
          required: ["vault"],
        },
      },
      {
        name: "op_search_items",
        description:
          "Search items by title across vaults. If `vault` is omitted, searches every vault the service account can see.",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", description: "Case-insensitive substring of the item title." },
            vault: { type: "string", description: "Optional vault id or title to scope the search." },
            limit: { type: "number", description: "Max results (default 25)." },
            instance: { type: "string", description: "Instance name. Uses default if omitted." },
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
            instance: { type: "string", description: "Instance name. Uses default if omitted." },
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
            instance: { type: "string", description: "Instance name. Uses default if omitted." },
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
            length: { type: "number", description: "Length for Random/Pin (default 20/8)." },
            includeDigits: { type: "boolean", description: "Random only (default true)." },
            includeSymbols: { type: "boolean", description: "Random only (default true)." },
            wordCount: { type: "number", description: "Memorable only (default 5)." },
            capitalize: { type: "boolean", description: "Memorable only (default true)." },
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
              description: "Field definitions: [{ title, type, value, sectionId? }].",
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
            notes: { type: "string", description: "Optional notes (stored as a Text field called 'notesPlain')." },
            instance: { type: "string", description: "Instance name. Uses default if omitted." },
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
            instance: { type: "string", description: "Instance name. Uses default if omitted." },
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
            description: { type: "string", description: "Optional description." },
            instance: { type: "string", description: "Instance name. Uses default if omitted." },
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
            instance: { type: "string", description: "Instance name. Uses default if omitted." },
          },
          required: ["vault"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    if (name === "op_list_instances") {
      if (instances.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: "No instances configured. Run `1password-mcp setup` or call op_add_instance.",
            },
          ],
        };
      }
      const def = defaultInstance?.name;
      let text = `# 1Password Instances (${instances.length})\n\n`;
      for (const inst of instances) {
        const isDefault = inst.name === def ? " **(default)**" : "";
        const desc = inst.description ? ` - ${inst.description}` : "";
        text += `- **${inst.name}**${isDefault}${desc}\n`;
      }
      return { content: [{ type: "text", text }] };
    }

    if (name === "op_add_instance") {
      const instName = args.name.trim();
      if (!/^ops_[A-Za-z0-9_\-]+/.test(args.token)) {
        return {
          content: [
            {
              type: "text",
              text: "Token does not look like a 1Password service account token (expected prefix 'ops_').",
            },
          ],
          isError: true,
        };
      }

      // Validate by creating a client and listing vaults.
      try {
        const tempClient = await sdk.createClient({
          auth: args.token,
          integrationName: INTEGRATION_NAME,
          integrationVersion: `v${PKG_VERSION}`,
        });
        // consume iterator to force a real API call
        const probe = [];
        for await (const v of await tempClient.vaults.list()) {
          probe.push(v);
          if (probe.length >= 1) break;
        }
      } catch (e) {
        return {
          content: [
            { type: "text", text: `Token validation failed: ${e.message}` },
          ],
          isError: true,
        };
      }

      const newInst = {
        name: instName,
        token: args.token,
        description: args.description || "",
      };
      const existingIdx = instances.findIndex((i) => i.name === instName);
      if (existingIdx >= 0) instances[existingIdx] = newInst;
      else instances.push(newInst);
      invalidateClient(instName);

      const savedConfig = loadConfigFile();
      if (!savedConfig.instances) savedConfig.instances = [];
      const savedIdx = savedConfig.instances.findIndex((i) => i.name === instName);
      const toSave = { name: instName, token: args.token };
      if (args.description) toSave.description = args.description;
      if (savedIdx >= 0) savedConfig.instances[savedIdx] = toSave;
      else savedConfig.instances.push(toSave);
      if (args.setDefault || !savedConfig.defaultInstance) {
        savedConfig.defaultInstance = instName;
      }
      saveConfigFile(savedConfig);

      return {
        content: [
          {
            type: "text",
            text: `${existingIdx >= 0 ? "Updated" : "Added"} instance "${instName}".${args.setDefault ? " Set as default." : ""}`,
          },
        ],
      };
    }

    if (name === "op_remove_instance") {
      if (instances.length <= 1) {
        return {
          content: [{ type: "text", text: "Cannot remove the last remaining instance." }],
          isError: true,
        };
      }
      const idx = instances.findIndex((i) => i.name === args.name);
      if (idx < 0) {
        return {
          content: [{ type: "text", text: `Instance "${args.name}" not found.` }],
          isError: true,
        };
      }
      instances.splice(idx, 1);
      invalidateClient(args.name);
      const savedConfig = loadConfigFile();
      if (savedConfig.instances) {
        savedConfig.instances = savedConfig.instances.filter((i) => i.name !== args.name);
        if (savedConfig.defaultInstance === args.name) {
          savedConfig.defaultInstance = savedConfig.instances[0]?.name || null;
        }
        saveConfigFile(savedConfig);
      }
      return { content: [{ type: "text", text: `Removed instance "${args.name}".` }] };
    }

    if (name === "op_list_vaults") {
      const inst = getInstanceByName(args.instance);
      const client = await getClient(inst);
      const vaults = [];
      for await (const v of await client.vaults.list()) vaults.push(v);
      if (vaults.length === 0) {
        return { content: [{ type: "text", text: "No vaults visible to this service account." }] };
      }
      let text = `# Vaults (${vaults.length})\n\n`;
      for (const v of vaults) text += `- **${v.title}** (id: ${v.id})\n`;
      return { content: [{ type: "text", text }] };
    }

    if (name === "op_list_items") {
      const inst = getInstanceByName(args.instance);
      const client = await getClient(inst);
      const vault = await resolveVault(client, args.vault);
      if (!vault) {
        return {
          content: [{ type: "text", text: `Vault "${args.vault}" not found.` }],
          isError: true,
        };
      }
      const items = [];
      for await (const it of await client.items.list(vault.id)) items.push(it);
      if (items.length === 0) {
        return { content: [{ type: "text", text: `No items in vault "${vault.title}".` }] };
      }
      let text = `# Items in ${vault.title} (${items.length})\n\n`;
      for (const it of items) {
        text += `- **${it.title}** (id: ${it.id}, category: ${it.category})\n`;
      }
      return { content: [{ type: "text", text }] };
    }

    if (name === "op_search_items") {
      const inst = getInstanceByName(args.instance);
      const client = await getClient(inst);
      const limit = args.limit || 25;
      const q = String(args.query).toLowerCase();

      let targetVaults = [];
      if (args.vault) {
        const v = await resolveVault(client, args.vault);
        if (!v) {
          return {
            content: [{ type: "text", text: `Vault "${args.vault}" not found.` }],
            isError: true,
          };
        }
        targetVaults = [v];
      } else {
        for await (const v of await client.vaults.list()) targetVaults.push(v);
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

      if (hits.length === 0) {
        return {
          content: [{ type: "text", text: `No items matched "${args.query}".` }],
        };
      }
      let text = `# Search: "${args.query}" (${hits.length})\n\n`;
      for (const it of hits) {
        text += `- **${it.title}** (id: ${it.id}, vault: ${it._vaultTitle}, category: ${it.category})\n`;
      }
      return { content: [{ type: "text", text }] };
    }

    if (name === "op_get_item") {
      const inst = getInstanceByName(args.instance);
      const client = await getClient(inst);
      const vault = await resolveVault(client, args.vault);
      if (!vault) {
        return {
          content: [{ type: "text", text: `Vault "${args.vault}" not found.` }],
          isError: true,
        };
      }
      const itemRef = await resolveItem(client, vault, args.item);
      if (!itemRef) {
        return {
          content: [{ type: "text", text: `Item "${args.item}" not found in vault "${vault.title}".` }],
          isError: true,
        };
      }
      const full = await client.items.get(vault.id, itemRef.id);
      const formatted = formatItem(full, !!args.includeConcealed);
      let text = `# ${formatted.title} (${formatted.category})\n\n`;
      text += `- **Vault:** ${vault.title} (${formatted.vaultId})\n`;
      text += `- **Item ID:** ${formatted.id}\n`;
      if (formatted.tags.length > 0) text += `- **Tags:** ${formatted.tags.join(", ")}\n`;
      if (formatted.websites.length > 0) {
        text += `- **Websites:** ${formatted.websites.map((w) => w.url).join(", ")}\n`;
      }
      if (formatted.fields.length > 0) {
        text += `\n## Fields\n\n`;
        for (const f of formatted.fields) {
          const val = f.value === undefined ? "" : f.value;
          text += `- **${f.title}** (${f.type}): ${val}${f.otp ? ` (OTP now: ${f.otp})` : ""}\n`;
        }
      }
      if (!args.includeConcealed) {
        text += `\n_Concealed fields are redacted. Call with includeConcealed=true to reveal._`;
      }
      return { content: [{ type: "text", text }] };
    }

    if (name === "op_get_secret") {
      const inst = getInstanceByName(args.instance);
      const client = await getClient(inst);
      const value = await client.secrets.resolve(args.reference);
      return {
        content: [{ type: "text", text: `Secret for ${args.reference}:\n${value}` }],
      };
    }

    if (name === "op_generate_password") {
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
      const pwd = typeof generated === "string" ? generated : generated.password || generated;
      return { content: [{ type: "text", text: `Generated (${type}):\n${pwd}` }] };
    }

    if (name === "op_create_item") {
      const inst = getInstanceByName(args.instance);
      const client = await getClient(inst);
      const vault = await resolveVault(client, args.vault);
      if (!vault) {
        return {
          content: [{ type: "text", text: `Vault "${args.vault}" not found.` }],
          isError: true,
        };
      }
      const category = sdk.ItemCategory[args.category || "Login"];
      if (!category) {
        return {
          content: [{ type: "text", text: `Unknown category "${args.category}".` }],
          isError: true,
        };
      }
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
      return {
        content: [
          {
            type: "text",
            text: `Created item **${item.title}** (id: ${item.id}) in vault "${vault.title}".`,
          },
        ],
      };
    }

    if (name === "op_delete_item") {
      const inst = getInstanceByName(args.instance);
      const client = await getClient(inst);
      const vault = await resolveVault(client, args.vault);
      if (!vault) {
        return {
          content: [{ type: "text", text: `Vault "${args.vault}" not found.` }],
          isError: true,
        };
      }
      const itemRef = await resolveItem(client, vault, args.item);
      if (!itemRef) {
        return {
          content: [{ type: "text", text: `Item "${args.item}" not found in vault "${vault.title}".` }],
          isError: true,
        };
      }
      await client.items.delete(vault.id, itemRef.id);
      return {
        content: [
          {
            type: "text",
            text: `Deleted item "${itemRef.title}" from vault "${vault.title}".`,
          },
        ],
      };
    }

    if (name === "op_create_vault") {
      const inst = getInstanceByName(args.instance);
      const client = await getClient(inst);
      const vault = await client.vaults.create({
        title: args.title,
        description: args.description || "",
      });
      return {
        content: [
          { type: "text", text: `Created vault **${vault.title}** (id: ${vault.id}).` },
        ],
      };
    }

    if (name === "op_delete_vault") {
      const inst = getInstanceByName(args.instance);
      const client = await getClient(inst);
      const vault = await resolveVault(client, args.vault);
      if (!vault) {
        return {
          content: [{ type: "text", text: `Vault "${args.vault}" not found.` }],
          isError: true,
        };
      }
      await client.vaults.delete(vault.id);
      return { content: [{ type: "text", text: `Deleted vault "${vault.title}".` }] };
    }

    throw new Error(`Unknown tool: ${name}`);
  } catch (error) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
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

// Export for testing
if (typeof module !== "undefined") {
  module.exports = {
    loadConfigFile,
    saveConfigFile,
    getInstanceByName,
    redactField,
    formatItem,
  };
}
