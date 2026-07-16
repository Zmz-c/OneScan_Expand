# OST

OST is a Burp Suite extension project, with browser-assisted request replay, local data
persistence,
and an optional MCP interface for AI-assisted security workflows.

This branch has been updated for modern Burp builds and now targets **Java 21**.
It is no longer compatible with **JDK 8**.

---

## Features

### Data Board

- Centralized scan result display
- Request/response summary viewing
- Task stop, history clear, and URL import
- Local data import/export based on SQLite
- Manual save and auto-save for persisted data
- Historical data lookup by timestamp label
- Configurable field-level selective persistence

### Fingerprint Identification

- Rule-based fingerprint recognition
- Fingerprint testing
- Fingerprint history viewing
- Custom fingerprint field extension

### Data Collection

- Useful response data extraction
- Built-in collection for web names and JSON fields

### Payload Processing

- Rule-based request preprocessing
- Request variant generation and batch testing

### Path Scanning / Result Correlation

- Path-level scan handling
- Unified result aggregation into the data board

### Burp Integration

- Burp tab integration
- Context-menu send-to-plugin support
- Proxy traffic listener support

### Browser Request Support

- Browser-assisted target page access
- Edge / Chrome support
- Manual Python path configuration
- Manual browser binary path configuration
- Browser request timeout configuration

### MCP / AI Integration

- Localhost MCP-style JSON-RPC endpoint
- Tool discovery for OST capabilities
- Runtime status, task search, task detail, fingerprint, collect, wordlist, history, and CSV export tools
- Active scan submission through OST URL and raw-request workflows
- Summary-first task responses; raw request/response bodies are opt-in with `include_body`
- In `auto` request mode, suspected interception / verification pages can fall back to browser requests when browser
  request support is enabled

MCP is disabled by default. Enable it in `Config` -> `Other` -> `MCP server`. After it starts, the same panel shows:

- Current status
- Actual MCP endpoint
- Health-check URL

Default endpoint after MCP is enabled:

```text
http://127.0.0.1:8765/mcp
```

If the port is occupied, OST tries the next ports up to `8785`. Use the endpoint shown in the config panel as the source
of truth.

Health check:

```text
http://127.0.0.1:8765/health
```

MCP server name:

```text
ost-burp-mcp
```

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

Useful first tools:

```text
ost.capabilities.list
ost.status.get
ost.tasks.list
ost.tasks.search
ost.fingerprint.check
ost.collect.node.get
ost.wordlists.list
ost.wordlist.select
ost.wordlist.create
ost.wordlist.append
ost.wordlist.put
ost.wordlist.import_file
ost.wordlist.delete
ost.scan.urls
ost.scan.request
```

### MCP Tool Groups

- `ost.status.*`: read runtime status and configuration
- `ost.scan.*`: submit URL or raw HTTP request scan tasks
- `ost.tasks.*`: list, search, and read scan results
- `ost.fingerprint.*`: run or inspect fingerprint rules
- `ost.collect.*`: read collected response data
- `ost.wordlist.*`: read, select, create, update, import, and delete wordlists
- `ost.history.*`: list persisted history labels
- `ost.export.*`: export persisted data to CSV

---

## Runtime Requirements

### Burp Suite

This project depends on:

- `burp-extender-api 2.3`
- `montoya-api 2023.12.1`

A relatively recent Burp Suite version is recommended.
The plugin still works with older Burp-based projects that load external extensions, but the code itself now requires a
modern Java toolchain to build.

### Java

- **JDK 21**
- The project now targets Java 21 bytecode and no longer supports JDK 8.

### Python

- **Python 3.x**
- Recommended: **Python 3.9+**

### Browser

Current browser-request mode supports:

- **Edge**
- **Chrome**

---

## DrissionPage Installation

Browser-request functionality depends on `DrissionPage` in the local Python environment.

Install with:

```bash
pip install DrissionPage
```

If a specific Python interpreter is used:

```bash
python -m pip install DrissionPage
```

Or:

```bash
python3 -m pip install DrissionPage
```

---

## Repository Structure

```text
OST/
|- burp-extender-api/
|- montoya-api/
|- extender/
|  |- src/main/java/
|  |- src/main/resources/
|  `- pom.xml
|- pom.xml
`- README.md
```

---

## Build

Run in the project root:

```bash
./mvnw clean package
```

On Windows:

```powershell
.\mvnw.cmd clean package
```

Default output:

```text
extender/target/OST-v1.1.9.jar
```

---

## Load in Burp Suite

1. Open Burp Suite
2. Go to `Extensions`
3. Click `Add`
4. Select the built JAR file
5. Load the extension

---

## License

This project follows the `LICENSE` file in the repository.
