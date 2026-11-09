# OST

[中文](README_zh_CN.md) · [User manual](docs/user-guide.html)

OST is a Burp Suite extension for web-security testing, combining endpoint scanning, request transformations,
parameter tests, browser replay, fingerprinting and identity comparison.

**Stable release: 1.2.7** · **Runtime: Java 21**

## Release 1.2.7

- **Scope control**: optional Burp Target Scope checks complement existing host and path exclusions.
- **Result filtering**: fingerprint filters and selectable fingerprint/identity conditions.
- **Reflection templates**: editable request-processing and fingerprint presets with the `{{nonce}}` random value.
- **Usability**: improved Chinese/English localization and a bundled offline manual with variable references and worked examples.
- **Reliability**: fixes for mixed-scope request processing, request-correlated fingerprint caching and configuration persistence.

See the [release notes](docs/RELEASE_1.2.7.md) for changes, validation coverage and upgrade steps.
Download `OST-v1.2.7.jar` from this repository's GitHub Releases. The HTML manual is also available separately or from within the extension.

## Features

- **Endpoint scanning** — Send requests from Burp, import URLs or listen to proxy traffic; generate variants with path dictionaries and processing rules.
- **Request processing** — Configure prefix, suffix, match-and-replace and condition-check groups. Built-in templates are editable and can be enabled or removed.
- **Parameter testing** — Discover names, test existing values or define custom positions, with independent endpoint settings and batch execution.
- **Browser replay** — Use Edge/Chrome for browser-session-dependent requests and manage sessions through Browser IDs.
- **Fingerprinting** — Configure request/response conditions, result fields and colors, including request-correlated reflection checks.
- **Identity comparison** — Override credentials and parameters with Profiles and compare responses for the same request variant.
- **Data management** — Dedicated parameter-scan traffic, conditional filters, SQLite persistence, history import and CSV export.
- **Local integration** — An optional MCP interface exposes status, configuration and scan operations to trusted local clients.

## Installation

Run Burp Suite with Java 21. In `Extensions → Add`, select Java and load the bundled OST JAR.

Build from source:

```powershell
.\mvnw.cmd package
```

macOS / Linux:

```bash
./mvnw package
```

Artifact: `extender/target/OST-v1.2.7.jar`.

Ordinary Burp transport needs no Python. Browser transport requires Edge or Chrome and Python 3.9+ with DrissionPage:

```bash
python -m pip install DrissionPage
```

Select that interpreter and the browser executable in Browser settings.

## Quick Start

1. Configure authorized targets in Burp Target Scope and enable `Host → Scope Only` when required.
2. Set QPS, delay, retries and scan depth in Request settings. Select the dictionaries and processing groups needed.
3. Send requests from the Burp context menu or import one URL per line in Databoard.
4. Inspect paired messages and fingerprints, then run parameter scans or identity replay for selected endpoints.
5. Send requests requiring further verification to Repeater, or save and export results as needed.

## Configuration

| Page | Settings |
|------|----------|
| Variables | Named variables, fixed/random/round-robin strategies and variable dictionaries. |
| Payload | Path/Payload dictionaries and request-processing groups. |
| Request | QPS, delay, scan depth, retries, identity Profiles, method/suffix filters, headers and path blocklist. |
| Browser | Python/browser paths, timeout, static resources and target-host rules. |
| Host | Burp Scope, timeout-host blocking and host allow/blocklists. |
| Redirect | Following policy, cookie propagation and destination-host restriction. |
| Other | Language, user manual, persistence and MCP service. |

### Processing Templates

Built-in and custom groups use the same editor. Change a group's name, enabled state and merge mode,
and edit each sub-rule's scope, match expression and replacement. Non-merged groups generate independent
variants; enabled merged groups form an ordered pipeline.

`Reflection probe` contains ordinary query/form match-and-replace rules and uses `{{nonce}}` for random markers.
The paired `Reflection candidate` fingerprint uses `containsRequestMatch` to extract the current request's marker
and find it in the response body, with status, content-type and error-page exclusions. Both groups are editable;
update the extraction expression when changing the marker format.

Reflection is an input-echo lead, not confirmed XSS. Built-in processing templates are disabled by default.

### Parameter and Identity Testing

Each parameter-scan endpoint retains its own mode, dictionaries, methods and transport. Define custom positions
in the request editor and assign dictionaries to names, values or body fragments. Preview the plan before execution;
results appear in `Parameter scan → Scan traffic`.

Create identities in `Request → Identity profiles` and select them through Profile replay actions.
Interpret same-variant response differences in the context of object ownership and expected permissions.

### Dynamic Variables

Ordinary request headers, path Payloads and processing rules support dynamic variables:

| Reference | Purpose and configuration |
|-----------|---------------------------|
| `{{nonce}}` | No setup; 24 lowercase hexadecimal characters per expansion, shared by repeated references in that expansion. |
| `{{random.ip}}` / `{{random.local-ip}}` | Sample `random-ip` / `random-local-ip` variable dictionaries; the actual connection source does not change. |
| `{{random.ua}}` | Select a User-Agent from the `user-agent` variable dictionary. |
| `{{random.AuthFuzz}}` | Disabled by default; when enabled, produces a complete header and belongs on its own header-list line. |
| `{{value.name}}` | Custom `fixed` or `round-robin` variable using a configured value or sequential dictionary entries. |
| `{{random.name}}` | Custom `random` variable sampling its associated variable dictionary. |
| `{{host}}` / `{{protocol}}` / `{{domain}}` / `{{ip}}` | Target host, protocol, hostname without port and resolved target IP; `{{ip}}` is not the random-IP variable. |
| `{{timestamp}}` / `{{date.yyyy}}` / `{{time.HH}}` | Unix timestamp in seconds and date/time components. |
| `{{profile.name}}` | Identity-local variable used during explicit Profile replay. |

Names are case-sensitive and named variables must be defined and enabled. See the [variable reference](docs/user-guide.html#variables) for all domain, subdomain, directory and date/time fields and expansion boundaries.

### Configuration Examples

**Dynamic headers and reflection detection**: create fixed variable `tenant` with value `demo-a`, fixed variable `trace` with value `run-{{nonce}}`, and retain the bundled random variable `ua`. Configure these header-list entries:

```http
User-Agent: {{random.ua}}
X-Tenant-ID: {{value.tenant}}
X-Request-ID: {{value.trace}}
X-Request-ID-Copy: {{value.trace}}
```

Enable header replacement, request processing and the `Reflection probe` group, then send an authorized search request to OST with ordinary Burp transport.
Inspect the expanded headers, query marker and paired fingerprint in Databoard. Both trace headers share a value within that header expansion; the subsequent processing group generates its reflection marker independently.
See the [dynamic-variable worked example](docs/user-guide.html#dynamic-example) for complete steps, expected messages and tenant rotation.

**Multi-position Parameter Fuzz**: mark `q` and `page` as separate positions. Assign a search dictionary containing `apple` and `orange`, and a page dictionary containing `1` and `2`.
Preview should produce four combinations; inspect them in parameter-scan traffic after execution. See the [Parameter Fuzz worked example](docs/user-guide.html#parameter-example).

Parameter Fuzz uses literal Payload dictionary content: **dynamic variables are not expanded, and global headers and ordinary processing groups are not reapplied**.
Assign changing content to position dictionaries; concrete headers inherited from ordinary scans remain unchanged.

### Scope and Data

Burp Scope supplements existing host/path exclusions. Table filters only control display, not request eligibility.
Browser scope checks are not a process-wide firewall; use network isolation for strict-scope assessments.

Credentials, raw messages and exports may contain sensitive information. Protect the local working directory
and sanitize data before sharing it.

## User Manual

Open `Other → Open user guide` inside the extension, or download the [HTML manual](docs/user-guide.html)
and open it directly in a browser. It covers installation, workflow, configuration, rule editing, parameter scans,
identity replay, browser requests, fingerprints and data management. Language switching, search and printing
work offline without a web server.

## MCP Integration

MCP is disabled by default. Enable it in Other to display the local endpoint and service status. Use trusted local
clients only; do not expose the service through public proxies or port forwarding.

See the [mcp-core documentation](mcp-core/README.md) for the standalone protocol module and extension interfaces,
and [OpenAPI](mcp-core/openapi.yaml) for the API definition.

## License

See [LICENSE](LICENSE). Use only for authorized security testing.
