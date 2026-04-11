#!/usr/bin/env node

const readline = require("readline");
const fs = require("fs");
const path = require("path");

const configDir = path.join(process.env.HOME, ".config/1password-mcp");
const configPath = path.join(configDir, "config.json");

let args = process.argv.slice(2);
if (args[0] === "setup") args = args.slice(1);

function loadConfig() {
  try {
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, "utf8"));
    }
  } catch {}
  return null;
}

function saveConfig(cfg) {
  if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2));
  try {
    fs.chmodSync(configPath, 0o600);
  } catch {}
}

// Non-interactive: setup add <name> <token> [description]
//                  setup add-desktop <name> <accountName> [description]
if (args[0] === "add" && args.length >= 3) {
  const [, name, token, ...descArgs] = args;
  const description = descArgs.join(" ").trim();
  const config = loadConfig() || {};
  if (!config.instances) config.instances = [];
  const existing = config.instances.findIndex((i) => i.name === name);
  const instance = { name, authType: "serviceAccount", token };
  if (description) instance.description = description;
  if (existing >= 0) config.instances[existing] = instance;
  else config.instances.push(instance);
  if (!config.defaultInstance) config.defaultInstance = name;
  saveConfig(config);
  console.log(`Instance "${name}" saved to ${configPath} (serviceAccount)`);
  process.exit(0);
}

if (args[0] === "add-desktop" && args.length >= 3) {
  const [, name, accountName, ...descArgs] = args;
  const description = descArgs.join(" ").trim();
  const config = loadConfig() || {};
  if (!config.instances) config.instances = [];
  const existing = config.instances.findIndex((i) => i.name === name);
  const instance = { name, authType: "desktop", accountName };
  if (description) instance.description = description;
  if (existing >= 0) config.instances[existing] = instance;
  else config.instances.push(instance);
  if (!config.defaultInstance) config.defaultInstance = name;
  saveConfig(config);
  console.log(`Instance "${name}" saved to ${configPath} (desktop: ${accountName})`);
  console.log("Make sure the 1Password 8 desktop app is installed and the CLI integration is enabled (Settings → Developer → Connect with 1Password CLI).");
  process.exit(0);
}

// Non-interactive: setup remove <name>
if (args[0] === "remove" && args.length >= 2) {
  const config = loadConfig();
  if (!config || !config.instances) {
    console.error("No config found.");
    process.exit(1);
  }
  config.instances = config.instances.filter((i) => i.name !== args[1]);
  if (config.defaultInstance === args[1]) {
    config.defaultInstance = config.instances[0]?.name || null;
  }
  saveConfig(config);
  console.log(`Instance "${args[1]}" removed.`);
  process.exit(0);
}

// Interactive
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function ask(q) {
  return new Promise((r) => rl.question(q, r));
}

async function setup() {
  console.log("\n=== 1Password MCP Setup ===\n");
  const existing = loadConfig();
  if (existing?.instances?.length) {
    console.log("Existing instances:");
    for (const inst of existing.instances) {
      const isDefault = inst.name === existing.defaultInstance ? " (default)" : "";
      const desc = inst.description ? ` - ${inst.description}` : "";
      console.log(`  - ${inst.name}${isDefault}${desc}`);
    }
    console.log();
    const action = await ask("Add another instance? (y/N): ");
    if (action.trim().toLowerCase() !== "y") {
      rl.close();
      return;
    }
  }

  console.log("Pick auth mode:");
  console.log("  1. Desktop app (recommended for personal use — uses 1Password 8 biometric unlock, full vault access)");
  console.log("  2. Service account token (recommended for CI/shared — needs admin to provision, scoped vaults only)\n");
  const mode = (await ask("Auth mode (1/2, default 1): ")).trim() || "1";

  const name = (await ask("Instance name (e.g., work): ")).trim();
  const description = (await ask("Description (optional): ")).trim();

  const config = existing || { instances: [] };
  if (!config.instances) config.instances = [];
  const idx = config.instances.findIndex((i) => i.name === name);
  let instance;

  if (mode === "2") {
    console.log("\nCreate a service account token at:");
    console.log("  https://start.1password.com/developer-tools/infrastructure-secrets/serviceaccount");
    const token = (await ask("Service account token (ops_...): ")).trim();
    instance = { name, authType: "serviceAccount", token };
  } else {
    console.log("\nYour 1Password account name can be found in the desktop app URL");
    console.log("(e.g. 'my.1password.com' or the shorthand shown on the account switcher).\n");
    console.log("IMPORTANT: Enable CLI integration in 1Password 8:");
    console.log("  Settings → Developer → 'Connect with 1Password CLI'\n");
    const accountName = (await ask("Account name (e.g., my.1password.com): ")).trim();
    instance = { name, authType: "desktop", accountName };
  }

  if (description) instance.description = description;
  if (idx >= 0) config.instances[idx] = instance;
  else config.instances.push(instance);

  if (!config.defaultInstance) config.defaultInstance = name;
  else {
    const setDefault = await ask(`Set "${name}" as default? (y/N): `);
    if (setDefault.trim().toLowerCase() === "y") config.defaultInstance = name;
  }

  saveConfig(config);
  console.log(`\nConfig saved to ${configPath} (mode 0600)`);
  console.log("\nAdd to Claude Code with:");
  console.log("  claude mcp add --transport stdio 1password -- node $HOME/WebstormProjects/1password-mcp/index.js");
  rl.close();
}

setup().catch((e) => {
  console.error("Setup failed:", e.message);
  rl.close();
  process.exit(1);
});
