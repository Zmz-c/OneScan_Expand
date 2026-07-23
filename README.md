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

2. Load `extender/target/OST-v1.2.0.jar` in Burp Suite under `Extensions` -> `Add`.

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

They can be edited, replaced, or removed like any other named variable. The random value comes
from the associated dictionary; there is no separate built-in IP or User-Agent generator.

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

MCP is disabled by default. Enable `MCP server` under `Config` -> `Other`. The panel shows the
actual endpoint and health-check URL after startup.

Default endpoint:

```text
http://127.0.0.1:8765/mcp
```

Health check:

```text
http://127.0.0.1:8765/health
```

If the port is occupied, OST tries subsequent ports through `8785`. Start with
`ost.capabilities.list` to discover available operations. Task data, raw requests, responses,
Cookies, and Profile values may contain sensitive information; use the local endpoint only in a
trusted environment.

Example JSON-RPC request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "ost.status.get",
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
extender/target/OST-v1.2.0.jar
```

## License

This project follows the repository [LICENSE](LICENSE).
