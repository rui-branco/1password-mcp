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
- A 1Password account with permission to create [service accounts](https://developer.1password.com/docs/service-accounts/)

### Step 1: Create a service account token

1. Go to <https://start.1password.com/developer-tools/infrastructure-secrets/serviceaccount>
2. Create a service account and grant it access to the vaults you want to use
3. Copy the token — it starts with `ops_`

### Step 2: Configure

```bash
node $HOME/WebstormProjects/1password-mcp/setup.js
```

Or non-interactively:

```bash
node $HOME/WebstormProjects/1password-mcp/setup.js add work ops_ABC... "ITO service account"
```

### Step 3: Add to Claude Code

```bash
claude mcp add --transport stdio 1password -- node $HOME/WebstormProjects/1password-mcp/index.js
```

Restart Claude Code and run `/mcp` to verify.

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
