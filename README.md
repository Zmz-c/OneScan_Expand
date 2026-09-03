# OST

[中文说明](README_zh_CN.md) | [Variables and identity guide (Chinese)](docs/REQUEST_VARIABLES_AND_IDENTITY_REPLAY.md)

OST is a Burp Suite extension for authorized web-security testing. It combines request replay,
payload-driven scanning, browser-assisted requests, local result persistence, and an optional
local MCP-style JSON-RPC service.

> Build target: **Java 21**. JDK 8 is not supported.

## Highlights

### Scan Workflow

- Send selected Burp requests to OST from the context menu, or collect eligible proxy traffic.
- Generate request variants with payload dictionaries and request-processing rules.
- Follow redirects when enabled, with configurable cookie propagation and target-host limits.
- Skip paths matching a case-insensitive fragment blocklist before and after request processing.
- Aggregate requests, responses, fingerprints, and collected values in one data board.

### Variables and Identity Profiles

- Create fixed, random, or round-robin named variables backed by editable dictionaries.
- Default random variables are `ip`, `local-ip`, and `ua`, used as `{{random.ip}}`,
  `{{random.local-ip}}`, and `{{random.ua}}`.
- Replay the same request variant with explicitly selected identity Profiles that can override
  Cookie, headers, query parameters, body parameters, and Profile-local variables.
- Compare responses from different Profiles for the same request variant; the comparison shows
  differences but does not determine whether an authorization vulnerability exists.
- Browser Profile replay isolates cookies from the shared browser session.

### Browser, History, and MCP

- Replay requests through Edge or Chrome using DrissionPage, with configurable Python, browser,
  timeout, static-resource, and target-host settings.
- Persist selected result fields locally in SQLite; support manual save, periodic auto-save,
  history labels, import, and CSV export.
- Optionally expose local status, scan, task, fingerprint, collection, wordlist, history, and
  export operations through a localhost MCP-style JSON-RPC endpoint.

## Quick Start

1. Build the extension with JDK 21:

   ```bash
   ./mvnw clean package
   ```

   On Windows:

   ```powershell
   .\mvnw.cmd clean package
   ```

2. Load `extender/target/OST-v1.2.5.jar` in Burp Suite under `Extensions` -> `Add`.

3. Open the OST tab and configure dictionaries, request behavior, browser replay, redirects,
   persistence, and optional MCP from `Config`.

4. If browser replay is needed, install DrissionPage into the configured Python environment:

   ```bash
   python -m pip install DrissionPage
   ```

## Configuration Guide

| Area                   | What it controls                                                                  |
|------------------------|-----------------------------------------------------------------------------------|
| `Variables & Identity` | Named variables, variable dictionaries, and identity Profiles.                    |
| `Payload`              | Path dictionaries and request-processing rules that generate variants.            |
| `Request`              | Request method/suffix filters, browser settings, headers, and the path blocklist. |
| `Redirect`             | Redirect following, cookie propagation, and target-host restrictions.             |
| `Other`                | Local SQLite persistence, save interval, selected fields, and the MCP server.     |

### Variables and Dictionaries

Use `{{value.name}}` for fixed or round-robin variables, and `{{random.name}}` for random
variables. The default entries are ordinary editable named variables:

| Name       | Placeholder           | Default dictionary |
|------------|-----------------------|--------------------|
| `ip`       | `{{random.ip}}`       | `random-ip`        |
| `local-ip` | `{{random.local-ip}}` | `random-local-ip`  |
| `ua`       | `{{random.ua}}`       | `user-agent`       |
| `AuthFuzz` | `{{random.AuthFuzz}}` | `AuthFuzz`         |

They can be edited, replaced, or removed like any other named variable. The `ip`, `local-ip`, and
`ua` entries remain enabled by default; `AuthFuzz` is provided as an opt-in definition and is
disabled until you enable it. AuthFuzz contains common Authorization, API key, Cookie, and Token
request headers; random values come from the associated dictionary.

For the complete variable, Profile, request-processing, and response-comparison behavior, see
the [detailed guide (Chinese)](docs/REQUEST_VARIABLES_AND_IDENTITY_REPLAY.md).

### Identity Profile Replay

Profiles are applied only from the explicit Profile replay context-menu actions. This makes it
possible to replay one processed request variant as several identities without silently changing
ordinary scan traffic. Profile credentials and request values are stored locally; protect the OST
work directory, SQLite database, exports, and screenshots accordingly.

### Path Blocklist

Add one path fragment per line under `Config` -> `Request` -> `Path blocklist`. A request is
skipped when its URL path contains any non-empty fragment, ignoring case. OST checks both the
incoming path and the final path after request processing. Host names and query strings are not
matched by this list.

## MCP / AI Integration

The protocol layer is extracted into the standalone Maven module `mcp-core`
(`burp.zm:mcp-core:1.1.2`). Its public Java package is `burp.zm.mcp`. It only depends on Gson and exposes `McpServer`,
`McpTool`, and `McpToolProvider`, so other Burp extensions can reuse the same local
MCP contract by implementing a provider. The `burp.vaycore.ost.mcp` classes remain
as compatibility facades; OST-specific tools stay in the extension adapter layer.

To run the MCP core independently, execute `./mvnw -pl mcp-core package` and then run
`mcp-core/target/mcp-core-1.1.2-standalone.jar`. The standalone package exposes diagnostic tools by
default; load application tools with `--provider-class` and a `McpToolProvider` implementation.
OpenAPI 3.1 documentation is available at `mcp-core/openapi.yaml` for Swagger Editor or Swagger UI.

MCP is disabled by default. Enable `MCP server` under `Config` -> `Other`; the panel then shows the
actual endpoint and health check. The shared host binds only to `127.0.0.1:8765`. The first plugin
that acquires the port becomes the host; later plugins register their providers and share the same
endpoint instead of opening additional ports. Providers use a heartbeat-backed channel and can take
over the port when the host exits. Tool names must be unique, so extensions should use a namespace.

```text
http://127.0.0.1:8765/mcp
http://127.0.0.1:8765/health
http://127.0.0.1:8765/docs/
```

Treat the MCP endpoint as a privileged local API. It has no separate authentication layer, so do
not expose it through a reverse proxy, port forward, or public listener. Browser requests are
accepted only when their `Origin` host is loopback (`localhost`, `127.0.0.1`, or `::1`); ordinary
desktop MCP clients normally omit `Origin`.

This is a standard HTTP JSON-RPC MCP endpoint. Clients should send `initialize`, notify
`notifications/initialized`, discover operations through `tools/list`, and invoke them through
`tools/call`. The server negotiates and returns `MCP-Protocol-Version`; supported versions are
`2024-11-05`, `2025-03-26`, `2025-06-18`, and `2025-11-25`. POST requests must use
`Content-Type: application/json`; when an `Accept` header is sent, it must permit
`application/json` (standard Streamable HTTP clients commonly advertise JSON and SSE together).
After initialization, clients should send the negotiated version in `MCP-Protocol-Version` on
subsequent requests. The `initialize` response also returns `Mcp-Session-Id`; session-aware clients
should echo it on subsequent requests and may close the session with `DELETE /mcp`. Sessions expire
after 30 minutes of inactivity. For backwards compatibility, POST requests without a session header
remain supported in stateless mode.

In addition to status, scanning, tasks, fingerprints, collection, wordlists, history, and export, MCP
exposes:

- `ost.variables.list` and `ost.variable.get/create/update/delete` for named variables.
- `ost.profiles.list` and `ost.profile.get/create/update/delete` for identity Profiles.
- Optional `profiles: ["reader", "admin"]` on `ost.scan.urls` and `ost.scan.request`; only enabled
  existing Profiles can be applied.
- Read persisted records with `ost.history.tasks.list`; delete selected history labels only with
  `ost.history.delete` and `confirm: true`.
- CSV export requires `confirm: true` before replacing an existing file. Wordlist replacement and
  replace-mode file import also require confirmation.
- Tool annotations identify read-only, destructive, idempotent, and network-scanning behavior.
- `tools/call` validates required fields, basic types, enum values, and array items from each tool's
  `inputSchema` before invoking the provider; OST business-level validation remains in place as a
  second layer.

Profile queries return summaries by default and do not disclose Cookie, headers, parameters, or
Profile-local values. Use `include_sensitive: true` only in a trusted local environment. Likewise, raw
task requests and responses require `include_body: true`.

Initialization example:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-11-25",
    "capabilities": {},
    "clientInfo": { "name": "local-client", "version": "1.0" }
  }
}
```

Tool-call example:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "ost.profiles.list",
    "arguments": {}
  }
}
```


## Requirements

- Burp Suite with support for external Java extensions. The project depends on
  `burp-extender-api 2.3` and `montoya-api 2023.12.1`.
- JDK 21 to build the project.
- Python 3.9+ and DrissionPage only when browser-request mode is used.
- Edge or Chrome only when browser-request mode is used.

## Build Output

Run the Quick Start build command from the repository root. The packaged extension is:

```text
extender/target/OST-v1.2.5.jar
```

## License

This project follows the repository [LICENSE](LICENSE).
