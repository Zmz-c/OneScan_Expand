# 动态变量、身份 Profile 与响应比较

[返回中文 README](../README_zh_CN.md)

## 版本 1.2.3

- 修复目录字典条目不以 / 开头时，保留 base 路径末尾分隔符，避免将路径错误拼接为同一段。

## 版本 1.2.2

- 新增命名变量、身份 Profile 和同变体响应比较。
- Profile 浏览器重放隔离 Cookie，避免多身份或普通浏览器会话串用。
- Profile 重放及其重定向不再触发路径/目录字典扩展。
- Profile 中的 Cookie、Token 和其他认证值按原始值保存、显示和重放；请自行保护本地配置、历史库与导出文件。
- 默认提供 `ip`、`local-ip`、`ua`、`AuthFuzz` 四个可编辑的随机命名变量，分别关联独立变量字典；其中 `AuthFuzz` 默认关闭，需手动启用。
- `AuthFuzz` 不会自动加入默认请求头。启用该变量后，可在 `Config -> Request -> Request Header` 手动添加 `{{random.AuthFuzz}}`，从字典随机加入一条 Authorization、API Key、Cookie 或 Token 认证头。
- 首次初始化会创建但不会启用 GET 转 POST、`;index.jgp`、路径分隔符/规范化和查询分隔符等请求包处理绕过规则；可在 `Config -> Payload` 中按需逐条启用、关闭或删除。
- 目录扫描字典在路径拼接前展开系统变量与命名变量，完整 URL 也在展开后识别。
- “使用其他字典扫描”中的 Burp/浏览器重放均可选择身份 Profile，并按所选字典生成目录变体。
- User-Agent 默认值迁移为变量字典中的 `user-agent` 列表；Profile 仅替换非空 Cookie/请求头，删除请求头仍由“请求配置”管理。

## 使用边界

OST 用于已获得授权的安全测试。Profile 中的 Cookie、Token、Authorization 与业务身份字段会按原始值保存到本地 OST 配置，并会原样用于对应请求；只有在持久化或导出时选择原始请求/响应字段，凭据才会写入历史库或导出数据，便于确认漏洞影响；请自行保护工作目录、SQLite 历史库和导出文件，勿提交生产凭据到仓库、截图、公开 Issue 或共享字典。

## 统一模型

三个维度保持独立：

1. **变量字典**：决定一次请求填入什么值。
2. **请求包处理**：决定是否从原始请求生成额外变体。
3. **身份 Profile**：决定由谁发送同一个变体。

执行顺序为：

```text
原始请求
  -> Payload 生成请求变体，每个变体生成一次
  -> 填充普通动态变量
  -> 对每个变体应用 N 个选定 Profile
  -> 保存 Profile 名称、变体 ID、请求和响应
  -> 发生重定向时沿用已处理请求，不再次执行 Payload Processing
  -> 仅横向比较同一变体的不同 Profile 响应
```

例如目录字典包含 `/api/orders/{{value.tenant}}`，且 `tenant` 配置为轮询字典 `tenant-a`、`tenant-b` 时，目录扫描会先展开变量，再生成对应路径。若选择 `anonymous`、`user-a`、`user-b` 三个 Profile，每个目录变体都会分别以三个身份发送。

Profile 仅通过 Burp 右键菜单中的“使用 Burp 请求重放选中 Profile”或“使用浏览器请求重放选中 Profile”显式启用；不选择 Profile 时，现有扫描行为不变。

顶层的 Profile 重放只发送右键选中的原始请求，不会触发路径/目录字典扩展。通过“使用其他字典扫描”子菜单选择 Profile 重放时，OST 会使用该子菜单选择的目录字典扩展路径，并对每个目录变体应用所选 Profile。已启用的“请求包处理”规则仍会按原有逻辑生成请求变体。Profile 重放产生的重定向会继续使用同一 Profile，但不会继续触发目录字典扩展或再次执行请求包处理；若 Profile 在重定向前被删除，OST 会跳过该重定向，避免在无身份上下文下重放。

## 默认随机命名变量与系统变量

变量写法为 `{{变量名}}`。无法填充的变量会跳过当前请求。

| 变量 | 值来源 | 常见用途 |
| --- | --- | --- |
| `{{random.ip}}` | 命名变量 `ip` 从字典 `random-ip` 随机取一行 | `X-Forwarded-For`、`X-Real-IP` |
| `{{random.local-ip}}` | 命名变量 `local-ip` 从字典 `random-local-ip` 随机取一行 | 模拟内网来源请求头 |
| `{{random.ua}}` | 命名变量 `ua` 从字典 `user-agent` 随机取一行 | `User-Agent` |
| `{{random.AuthFuzz}}` | 命名变量 `AuthFuzz` 从字典 `AuthFuzz` 随机取一行完整请求头 | Authorization、API Key、Cookie、Token |
| `{{protocol}}` | 目标协议 | 请求路径或请求头 |
| `{{host}}` | 目标 Host，非默认端口会保留 | 请求头或请求体 |
| `{{ip}}` | 目标 Host 解析得到的 IP | 请求头或请求体 |
| `{{domain}}`、`{{domain.main}}`、`{{domain.name}}` | 当前域名及其组成部分 | 业务域名拼接 |
| `{{subdomain}}`、`{{subdomains}}`、`{{subdomains.0}}` | 子域名部分 | 多级子域名场景 |
| `{{webroot}}` | URL 的首个路径段 | 路径相关请求 |
| `{{timestamp}}` | 当前 Unix 时间戳 | 签名或缓存绕过参数 |
| `{{date.yyyy}}`、`{{date.MM}}`、`{{date.dd}}` | 当前日期 | 日期参数 |
| `{{time.HH}}`、`{{time.mm}}`、`{{time.ss}}` | 当前时间 | 时间参数 |

没有 `{{random.refer}}`、`{{random.cookie}}`，也不支持任意 JavaScript、Python 或表达式函数。

`ip`、`local-ip`、`ua` 和 `AuthFuzz` 是默认的普通命名变量，会显示在“命名变量”表格中。它们均可编辑、删除或替换：随机策略分别读取 `random-ip`、`random-local-ip`、`user-agent` 和 `AuthFuzz` 字典；其中 AuthFuzz 默认禁用。

### 随机 IP 与 User-Agent

在 `Config -> 字典与变量 -> 变量字典` 中选择 `user-agent` 列表维护随机 User-Agent，并在 `Config -> Request -> Request Header` 添加请求头、在数据面板启用“替换请求头”：

```text
User-Agent: {{random.ua}}
X-Forwarded-For: {{random.ip}}
X-Real-IP: {{random.local-ip}}
```

`{{random.ua}}` 由命名变量 `ua` 的随机策略从 `user-agent` 字典取值。旧 User-Agent 字典的当前内容会在升级时迁移一次，之后直接在变量字典中编辑。固定 Referer 直接配置请求头；随租户、账号或对象变化的 Referer 应放入 Profile。

## 命名变量与变量字典

在 `Config -> 字典与变量`：

1. 在“命名变量”中创建名称和取值策略。
2. 在“变量字典”中创建可复用的值列表。
3. 在请求头、URL、请求体或请求包处理规则中使用显示的占位符。

策略如下：

| 策略 | 占位符 | 行为 |
| --- | --- | --- |
| 固定值 | `{{value.name}}` | 每次使用固定配置值 |
| 随机 | `{{random.name}}` | 每次从指定字典随机选择一行 |
| 轮询 | `{{value.name}}` | 按字典顺序循环选择 |

例如可创建 `tenant`，用字典 `tenant-a`、`tenant-b`，并在请求中放入 `X-Tenant-ID: {{value.tenant}}`。普通变量会在 Profile 执行之前填充一次，不会导致额外的身份请求倍增。

默认会创建以下四个命名变量及其变量字典：

```text
ip -> {{random.ip}} -> random-ip
local-ip -> {{random.local-ip}} -> random-local-ip
ua -> {{random.ua}} -> user-agent
AuthFuzz -> {{random.AuthFuzz}} -> AuthFuzz
```

这些是普通可编辑项：可调整取值策略、关联字典或删除。升级时只会补充一次缺失的默认命名变量；之后用户主动删除的变量不会在每次启动时恢复。

### 在目录字典中使用变量

目录字典行支持命名变量，且会在路径拼接和完整 URL 判断之前展开。例如 `api/{{value.tenant}}/users` 或 `https://{{value.host}}/health`。固定/轮询变量使用 `{{value.name}}`，随机变量使用 `{{random.name}}`；必须先在“命名变量”中创建并启用对应定义。未定义、禁用或取值为空的命名变量会跳过该目录任务，避免将未展开的占位符发送给目标。

`{{payload}}` 不是变量占位符：目录字典的每一行本身就是当前 Payload。需要复用值时，请使用命名变量占位符。
### 路径黑名单

在 `Config -> Request -> 路径黑名单` 中按行填写路径片段。请求路径只要包含任一非空片段就不会扫描，匹配忽略大小写；OST 会同时检查入口路径和请求头/Payload Processing 处理后的最终路径，避免规则改写 URL 后绕过黑名单。黑名单只匹配 URL path，不匹配 Host 或查询参数。
## 身份 Profile

在 `Config -> 字典与变量 -> 身份 Profile` 创建 Profile。每个 Profile 可设置：

- 名称与启用状态。
- Cookie 请求头替换（仅在提供非空值时覆盖原值，可填写 `session=xxx` 或完整的 `Cookie: session=xxx`）。
- Header、Query、Body 替换项；Profile 中的空 Header 值不会删除原请求头。
- Profile 变量。

Header、Query、Body 和 Profile 变量的编辑器使用每行 `key=value` 格式。Profile 只替换非空 Header 值；移除请求头请在 `Config -> Request` 中配置。Query 和 Body 参数的空值会被保留为空值。

Profile 变量可在原始请求以及 Profile 的 Cookie、Header、Query、Body 值中引用：

```text
Profile variables:
tenant=tenant-a
role=reader

Headers:
X-Tenant-ID={{profile.tenant}}
X-Role={{profile.role}}

Cookie:
session={{profile.session}}
```

如果引用的 `{{profile.name}}` 没有值，对应 Profile 请求会被跳过。Cookie 和 Token 具备身份语义，不要将它们做成随机字符串字典。

### 浏览器 Profile Cookie 隔离

通过“使用浏览器请求重放选中 Profile”执行时，浏览器桥接会在请求前清空共享 Cookie jar，再写入该请求的 Cookie，并在请求完成或报错后再次清空。这样不同 Profile、以及 Profile 与普通浏览器重放之间不会串用登录态。

这意味着 Profile 浏览器重放不会继承普通浏览器会话，且完成后不会保留服务端新写入的 Cookie。需要复用浏览器会话时，请使用不带 Profile 的普通浏览器请求；需要验证身份差异时，请始终在原始请求或 Profile 中明确提供非空 Cookie/认证头。

## 请求包处理

在 `Config -> Payload` 配置“请求包处理”。子规则可以作用于请求路径、请求头、请求体或完整请求；已有添加前缀、添加后缀、条件检查和正则匹配/替换。存在有效处理结果时，OST 只发送处理后的请求变体，不会额外发送未处理的原始 GET 请求；勾选“合并到请求”的规则按顺序生成一个变体，未勾选的规则各自生成一个变体。若所有规则均未命中或处理失败，才回退发送原始请求。规则全局生效，建议缩小目标范围并减少字典数量，避免作用到无关扫描请求。

新工作目录首次启动时会自动创建以下独立规则，但默认全部禁用：将 `GET` 改为 `POST`，以及在 URL 末尾追加 `;index.jgp`、`/.`、`/..;/`、`/%2e/`、`//`、`;`、`?`、`%3f` 和 `.json`。旧配置首次升级时会在保留已有请求处理规则的前提下逐条补齐缺失默认项；本次补齐完成后，用户再删除的规则不会在每次启动时恢复。

示例：

```text
匹配正则：(?m)^X-Tenant-ID:.*$
替换为：X-Tenant-ID: tenant-test
作用范围：请求头
```

## 数据面板与响应比较

任务表会记录 `Profile` 和 `请求变体`，并在任务持久化和 MCP 任务查询中保存；原始请求/响应是否进入 SQLite 历史库或导出内容取决于所选持久化字段。选中同一请求变体的至少两条任务，右键选择“比较 Profile 响应”，可以填写可选的正文正则，然后比较：

- HTTP 状态码、响应长度、标题、正文 MD5 和正文相似度。
- 关键响应头：`Content-Type`、`Location`、`WWW-Authenticate`、`Cache-Control`、`Set-Cookie`。
- JSON 字段差异。
- 指定正文正则的全部匹配结果。
- 相对第一个 Profile 的原始正文差异片段。

比较结果只标记“相同”“存在差异”或“差异显著”，不自动判定 IDOR、BOLA、BFLA 或其他权限漏洞。必须结合对象归属、预期权限和实际敏感数据人工确认。

## 覆盖场景

```text
未授权       -> anonymous + authenticated Profile
水平越权     -> user-a + user-b
垂直越权     -> user + admin
租户隔离     -> tenant-a + tenant-b
业务头验证   -> Profile 中替换 X-Role / X-Tenant-ID
```
