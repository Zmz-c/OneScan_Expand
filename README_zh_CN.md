# OST

[English](README.md)

OST 是一个 Burp Suite 扩展。提供浏览器辅助请求重放、本地数据持久化和可选 MCP 接口。

当前代码使用 **Java 21** 构建。不兼容 **JDK 8**。

---

## 功能

- **数据面板**：集中查看扫描结果和请求/响应摘要。
- **历史数据**：支持 SQLite 持久化、手动保存、自动保存、按时间标签查询、导入和导出。
- **指纹识别**：支持规则匹配、指纹测试、历史查看和自定义字段。
- **数据收集**：内置站点名称和 JSON 字段收集规则。
- **Payload 处理**：对请求进行规则处理，生成请求变体并批量测试。
- **路径扫描**：进行路径级扫描，统一关联到数据面板。
- **Burp 集成**：支持标签页、右键菜单和代理流量监听。
- **浏览器请求**：通过真实浏览器重放请求，支持 Edge 和 Chrome，可配置 Python 路径、浏览器路径和超时。
- **MCP / AI 集成**：提供本地 JSON-RPC 接口，可读取状态、查询任务、执行指纹、管理字典、查询历史和导出 CSV。

---

## MCP / AI 集成

MCP 默认关闭。在 `Config` -> `Other` -> `MCP server` 中启用后，配置面板会显示运行状态、实际 MCP 端点和健康检查地址。

默认 MCP 端点：

```text
http://127.0.0.1:8765/mcp
```

默认健康检查地址：

```text
http://127.0.0.1:8765/health
```

如果端口被占用，OST 会依次尝试至 `8785`。请以配置面板显示的实际地址为准。

MCP 服务名称：

```text
ost-burp-mcp
```

JSON-RPC 请求示例：

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

常用工具：

```text
ost.capabilities.list
ost.status.get
ost.scan.urls
ost.scan.request
ost.tasks.list
ost.tasks.search
ost.tasks.get
ost.fingerprint.check
ost.collect.node.get
ost.wordlists.list
ost.wordlist.select
ost.wordlist.create
ost.wordlist.append
ost.wordlist.put
ost.wordlist.import_file
ost.wordlist.delete
ost.history.labels
ost.export.csv
```

工具分组：

- `ost.status.*`：读取运行状态和配置。
- `ost.scan.*`：提交 URL 或原始 HTTP 请求扫描任务。
- `ost.tasks.*`：列出、搜索和读取扫描结果。
- `ost.fingerprint.*`：执行或查看指纹规则。
- `ost.collect.*`：读取已收集的响应数据。
- `ost.wordlist.*`：读取、选择、创建、更新、导入和删除字典。
- `ost.history.*`：读取持久化历史标签。
- `ost.export.*`：将持久化数据导出为 CSV。

---

## 运行环境要求

### Burp Suite

本项目依赖：

- `burp-extender-api 2.3`
- `montoya-api 2023.12.1`

建议使用较新版本的 Burp Suite。插件可在支持外部扩展的旧版 Burp 环境中加载，但构建需要现代 Java 工具链。

### Java

- **JDK 21**
- 项目目标字节码为 Java 21，不支持 JDK 8。

### Python

- **Python 3.x**
- 推荐 **Python 3.9+**

### 浏览器

当前浏览器请求模式支持：

- **Edge**
- **Chrome**

---

## 安装 DrissionPage

浏览器请求功能依赖本地 Python 环境中的 `DrissionPage`。

```bash
pip install DrissionPage
```

如果需要指定 Python 解释器：

```bash
python -m pip install DrissionPage
```

或：

```bash
python3 -m pip install DrissionPage
```

---

## 仓库结构

```text
OST/
|- burp-extender-api/
|- montoya-api/
|- extender/
|  |- src/main/java/
|  |- src/main/resources/
|  `- pom.xml
|- pom.xml
|- README.md
`- README_zh_CN.md
```

---

## 构建

在项目根目录执行：

```bash
./mvnw clean package
```

Windows 下执行：

```powershell
.\mvnw.cmd clean package
```

默认产物：

```text
extender/target/OST-v1.1.9.jar
```

---

## 在 Burp Suite 中加载

1. 打开 Burp Suite。
2. 进入 `Extensions`。
3. 点击 `Add`。
4. 选择构建生成的 JAR 文件。
5. 加载扩展。

---

## 许可证

本项目遵循仓库中的 [LICENSE](LICENSE) 文件。