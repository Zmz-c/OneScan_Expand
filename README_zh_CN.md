# OST

[English](README.md) | [动态变量与身份 Profile 详细说明](docs/REQUEST_VARIABLES_AND_IDENTITY_REPLAY.md)

OST 是用于已获授权安全测试的 Burp Suite 扩展，提供请求重放、Payload 驱动扫描、浏览器辅助请求、本地结果持久化，以及可选的本地
MCP 风格 JSON-RPC 服务。

> 构建目标为 **Java 21**，不支持 JDK 8。

## 功能概览

### 扫描与请求流程

- 通过 Burp 右键菜单发送选中的请求到 OST，或监听符合条件的代理流量。
- 使用路径字典和请求包处理规则生成请求变体。
- 可选跟随重定向，并配置 Cookie 传递和目标 Host 限制。
- 在请求处理前后检查路径黑名单，跳过命中大小写无关路径片段的请求。
- 在数据面板集中查看请求、响应、指纹和收集结果。

### 字典、变量与身份 Profile

- 支持固定值、随机和轮询三种命名变量策略，变量取值由可编辑字典提供。
- 默认随机变量为 `ip`、`local-ip`、`ua`，对应 `{{random.ip}}`、
  `{{random.local-ip}}`、`{{random.ua}}`。
- 可通过明确的 Profile 重放菜单，对同一请求变体应用 Cookie、Header、Query、Body
  参数及 Profile 局部变量覆盖。
- 可比较同一请求变体下不同 Profile 的响应差异；比较结果不自动判定权限漏洞。
- 浏览器 Profile 重放会隔离 Cookie，避免与普通浏览器会话或其他 Profile 串用。

### 浏览器、历史与 MCP

- 通过 DrissionPage 使用 Edge 或 Chrome 重放请求；可配置 Python、浏览器路径、超时、
  静态资源加载和目标 Host 限制。
- 支持 SQLite 本地持久化、手动保存、周期自动保存、历史标签、导入及 CSV 导出。
- 可选启用本地 MCP 风格 JSON-RPC 接口，提供状态、扫描、任务、指纹、收集、字典、
  历史和导出能力。

## 快速开始

1. 使用 JDK 21 在项目根目录构建：

   ```bash
   ./mvnw clean package
   ```

   Windows 下：

   ```powershell
   .\mvnw.cmd clean package
   ```

2. 在 Burp Suite 的 `Extensions` -> `Add` 中加载：

   ```text
   extender/target/OST-v1.2.4.jar
   ```

3. 打开 OST 标签页，在 `Config` 中配置字典、请求行为、浏览器重放、重定向、持久化和
   可选 MCP 服务。

4. 如需浏览器请求模式，在配置的 Python 环境中安装 DrissionPage：

   ```bash
   python -m pip install DrissionPage
   ```

## 配置说明

| 配置区域       | 用途                            |
|------------|-------------------------------|
| `字典与变量`    | 命名变量、变量字典和身份 Profile。         |
| `Payload`  | 生成请求变体的路径字典和请求包处理规则。          |
| `Request`  | 请求方法/后缀过滤、浏览器设置、请求头及路径黑名单。    |
| `Redirect` | 重定向跟随、Cookie 传递和目标 Host 限制。   |
| `Other`    | SQLite 持久化、保存周期、选定字段和 MCP 服务。 |

### 命名变量与变量字典

固定值或轮询变量使用 `{{value.name}}`，随机变量使用 `{{random.name}}`。默认项是普通的
可编辑命名变量：

| 名称         | 占位符                   | 默认字典              |
|------------|-----------------------|-------------------|
| `ip`       | `{{random.ip}}`       | `random-ip`       |
| `local-ip` | `{{random.local-ip}}` | `random-local-ip` |
| `ua`       | `{{random.ua}}`       | `user-agent`      |

这三项和其他命名变量一样，可以编辑、替换或删除。随机值由关联字典决定，不存在单独的
内置 IP 或 User-Agent 生成算法。

关于变量、Profile、请求包处理和响应比较的完整行为，请参阅[详细说明](docs/REQUEST_VARIABLES_AND_IDENTITY_REPLAY.md)。

### 身份 Profile 重放

Profile 只会通过右键菜单中明确的 Profile 重放操作应用，因此可以让同一个处理后请求变体
以多个身份发送，而不会悄悄影响普通扫描流量。Profile 凭据和请求值保存在本地，请妥善保护
OST 工作目录、SQLite 数据库、导出文件和截图。

### 路径黑名单

在 `Config` -> `Request` -> `路径黑名单` 中每行填写一个路径片段。URL path 包含任一非空
片段时将跳过扫描，匹配忽略大小写。OST 会检查入口路径和请求包处理后的最终路径；该黑名单
不匹配 Host 或查询参数。

## MCP / AI 集成

MCP 默认关闭。在 `Config` -> `Other` 中启用 `MCP server` 后，界面会显示实际端点和健康
检查地址。服务仅绑定到 `127.0.0.1`；默认端口为 `8765`，若被占用会依次尝试至 `8785`。

```text
http://127.0.0.1:8765/mcp
http://127.0.0.1:8765/health
```

请将 MCP 端点视为本地特权接口。它没有独立的身份认证层，不要通过反向代理、端口转发或公网
监听对外暴露。浏览器请求的 `Origin` Host 仅允许 loopback（`localhost`、`127.0.0.1` 或
`::1`）；普通桌面 MCP 客户端通常不会发送 `Origin`。

这是标准 HTTP JSON-RPC MCP 接口：客户端应先发送 `initialize`，再通知
`notifications/initialized`，之后通过 `tools/list` 发现工具并用 `tools/call` 调用。服务协商并返回
`MCP-Protocol-Version`，目前支持 `2024-11-05`、`2025-03-26`、`2025-06-18` 和
`2025-11-25`。POST 请求必须使用 `Content-Type: application/json`；如发送 `Accept` 请求头，
其中必须允许 `application/json`（标准 Streamable HTTP 客户端通常会同时声明 JSON 与 SSE）。
初始化完成后，后续请求应通过 `MCP-Protocol-Version` 携带协商得到的协议版本。

主要工具包括状态、扫描、任务、指纹、收集、字典、历史和导出，以及：

- `ost.variables.list`、`ost.variable.get/create/update/delete`：管理命名变量。
- `ost.profiles.list`、`ost.profile.get/create/update/delete`：管理身份 Profile。
- `ost.scan.urls`、`ost.scan.request`：可传 `profiles: ["reader", "admin"]`，仅接受已启用的
  Profile，并会按每个身份重放。
- 使用 `ost.history.tasks.list` 读取已持久化记录；`ost.history.delete` 删除指定历史标签时必须传
  `confirm: true`。
- CSV 导出覆盖已有文件前必须传 `confirm: true`；字典整体替换及 replace 模式的文件导入同样需要确认。
- 工具元数据包含只读、破坏性、幂等性和扫描网络提示。

Profile 查询默认只返回摘要，不包含 Cookie、Header、参数或 Profile 局部变量的值。仅在可信的
本地环境中，并明确传递 `include_sensitive: true` 时才返回这些值。任务的原始请求/响应也需要
显式传递 `include_body: true`。

初始化示例：

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

工具调用示例：

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


## 运行环境

- 支持加载外部 Java 扩展的 Burp Suite；项目依赖 `burp-extender-api 2.3` 和
  `montoya-api 2023.12.1`。
- 构建需要 JDK 21。
- 仅使用浏览器请求模式时需要 Python 3.9+ 与 DrissionPage。
- 仅使用浏览器请求模式时需要 Edge 或 Chrome。

## 许可证

本项目遵循仓库中的 [LICENSE](LICENSE)。
