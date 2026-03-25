# OneScan_Expand

OneScan_Expand is a Burp Suite extension project based on **OneScan**.

- features
- runtime requirements
- component and dependency versions
- DrissionPage installation
- build and load steps

---

## Features

### Data Board

- Centralized scan result display
- Request/response summary viewing
- Task stop, history clear, and URL import

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

---

## Runtime Requirements

### Burp Suite

This project depends on:

- `burp-extender-api 2.3`
- `montoya-api 2023.12.1`

A relatively recent Burp Suite version is recommended.

### Java

- **JDK 1.8**

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
OneScan_TX/
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
mvn clean package
```

Default output:

```text
extender/target/OneScan_Dev-v1.0.jar
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
