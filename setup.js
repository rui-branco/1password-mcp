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
    console.log("\n=== One-time 1Password 8 setup (required for desktop auth) ===");
    console.log("");
    console.log("Open the 1Password 8 desktop app (not the browser — the Mac/Windows app).");
    console.log("");
    console.log("  1. Open Settings (cmd+, on Mac / ctrl+, on Windows)");
    console.log("  2. Click the 'Developer' tab on the left");
    console.log("  3. Tick 'Integrate with 1Password CLI'");
    console.log("     (under 'Command-Line Interface (CLI)')");
    console.log("  4. Tick 'Integrate with other apps'");
    console.log("     (under 'Integrate with the 1Password SDKs')");
    console.log("     ** THIS IS THE KEY ONE — without it the SDK can't unlock. **");
    console.log("  5. (Optional) Settings → Security → 'Unlock using Touch ID'");
    console.log("");
    console.log("The first time the MCP calls 1Password you'll get a system prompt");
    console.log("asking to authorize '1password-mcp' — click Approve.");
    console.log("");
    console.log("=== Finding your account name ===");
    console.log("");
    console.log("Open 1Password 8 → click the account switcher in the top-left.");
    console.log("The signin address shown next to your name is what you want here,");
    console.log("e.g. 'my.1password.com' or 'my-team.1password.com'.");
    console.log("");
    const accountName = (await ask("Account name (e.g., my.1password.com): ")).trim();
    if (!accountName) {
      console.error("Account name is required. Aborting.");
      rl.close();
      process.exit(1);
    }
    instance = { name, authType: "desktop", accountName };

    // Validate by actually trying to talk to the desktop app. This will pop the
    // OS-level authorization prompt on first use.
    console.log("\nValidating with 1Password desktop app (you may get an auth prompt)…");
    try {
      const sdk = require("@1password/sdk");
      const client = await sdk.createClient({
        auth: new sdk.DesktopAuth(accountName),
        integrationName: "1password-mcp-setup",
        integrationVersion: "v1",
      });
      const probe = [];
      for await (const v of await client.vaults.list()) {
        probe.push(v);
        if (probe.length >= 1) break;
      }
      console.log(`Validated. Saw vault: ${probe[0]?.title || "(none visible)"}.`);
    } catch (e) {
      console.error("");
      console.error("Validation failed: " + e.message);
      console.error("");
      console.error("Common causes:");
      console.error("  - 'Integrate with other apps' is NOT ticked in 1Password Settings → Developer");
      console.error("  - 1Password 8 desktop app is not running or locked");
      console.error("  - Account name is wrong (check the account switcher in 1Password 8)");
      console.error("");
      console.error("Fix the issue and re-run this setup.");
      rl.close();
      process.exit(1);
    }
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
