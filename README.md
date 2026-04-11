# 1Password MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for [1Password](https://1password.com/) that runs **entirely locally** — no external services, no telemetry, no leaks. Uses the official [`@1password/sdk`](https://www.npmjs.com/package/@1password/sdk) with a 1Password Service Account token.

Built to mirror the multi-instance pattern of [jira-mcp](https://github.com/rui-branco/jira-mcp) so you can point the same Claude Code session at multiple 1Password accounts (e.g. `work` and `personal`).

## Features

- **Multi-instance** — add several service accounts, switch per tool call via `instance` parameter
- **Local only** — all calls go directly from your machine to 1Password over TLS; the config file is stored `0600` in `~/.config/1password-mcp/config.json`
- **Redaction by default** — concealed fields (passwords, TOTP) are redacted unless you explicitly pass `includeConcealed: true`
- **Read + write** — list vaults/items, fetch full items, resolve `op://` references, generate passwords, create/delete items, create/delete vaults

## Installation

### Prerequisites

- Node.js 18+
- Either:
  - **The 1Password 8 desktop app** (recommended — no admin permissions needed, and you get access to all vaults you can already see), or
  - A 1Password **service account** token (needs admin to provision, scoped to shared vaults only — good for CI/headless use)

### Step 1: Install and register the MCP

```bash
claude mcp add --scope user --transport stdio 1password -- npx -y @rui.branco/1password-mcp
```

### Step 2: Run setup

```bash
npx @rui.branco/1password-mcp setup
```

The setup wizard walks you through picking an auth mode and validates the connection before saving.

### Step 3 (desktop auth only): One-time 1Password 8 toggles

Desktop auth delegates unlock to the 1Password 8 desktop app, so you need to enable the SDK integration **once** per machine:

1. Open the **1Password 8 desktop app** (not `my.1password.com` in the browser).
2. Open **Settings** (cmd+, on Mac / ctrl+, on Windows).
3. Click the **Developer** tab.
4. Under *Command-Line Interface (CLI)*, tick **"Integrate with 1Password CLI"**.
5. Under *Integrate with the 1Password SDKs*, tick **"Integrate with other apps"**. ← **This is the critical one.** Without it, the SDK cannot unlock and every call will fail with `DesktopSessionExpiredError`.
6. Optional: **Settings → Security → Unlock using Touch ID** so the OS prompt can be cleared with your fingerprint.

The first time the MCP actually calls 1Password, your OS will pop an authorization prompt asking whether `1password-mcp-setup` (during the wizard) and `1password-mcp` (at runtime) can talk to 1Password. Click Approve.

### Finding your account name

When the wizard asks for "Account name", open the 1Password 8 desktop app and click the **account switcher** in the top-left. The signin address shown next to your name is what you want — it looks like `my.1password.com`, `my-team.1password.com`, or similar.

### Step 4: Reconnect

Run `/mcp` in Claude Code to reconnect the 1password server and pick up the new config.

## Tools

| Tool | Description |
|---|---|
| `op_list_instances` | List configured service accounts (tokens never returned) |
| `op_add_instance` | Add/update an instance. Validates the token against the API. |
| `op_remove_instance` | Remove an instance by name |
| `op_list_vaults` | List vaults visible to the service account |
| `op_list_items` | List items in a vault (by vault id or title) |
| `op_search_items` | Title-substring search across one or all vaults |
| `op_get_item` | Fetch a full item. Concealed fields redacted unless `includeConcealed=true`. |
| `op_get_secret` | Resolve a `op://Vault/Item/field` secret reference |
| `op_generate_password` | Generate Random / Memorable / Pin passwords via the 1Password generator |
| `op_create_item` | Create a new item with fields, tags, and websites |
| `op_delete_item` | Delete an item |
| `op_create_vault` | Create a new vault |
| `op_delete_vault` | Delete a vault |

All tools that talk to 1Password accept an optional `instance` parameter. Omit it to use the default instance.

## Security notes

- Tokens live only in `~/.config/1password-mcp/config.json` (chmod 0600) and in the SDK client process. They are never logged or transmitted anywhere except to `*.1password.com`.
- Service accounts only see vaults that have been explicitly shared with them — personal vaults are inaccessible by design.
- Concealed fields are redacted by default in tool output so the model cannot accidentally quote a password back. Pass `includeConcealed: true` only when you actually need the cleartext.

## Config shape

```json
{
  "instances": [
    { "name": "work", "token": "ops_...", "description": "ITO service account" }
  ],
  "defaultInstance": "work"
}
```

## License

MIT
