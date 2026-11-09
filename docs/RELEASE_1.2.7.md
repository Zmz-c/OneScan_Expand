# OST 1.2.7

正式版本：`1.2.7` · 发布日期：2026-11-09 · 运行环境：Java 21。

## 主要更新

### 范围控制与结果过滤

- 新增“仅扫描 Burp Scope”选项，直接调用 Burp 范围判断，覆盖扫描请求与重定向入口；浏览器桥接对拦截到的页面请求进行范围检查。
- 继续保留主机黑白名单和路径排除；Scope Only 默认关闭，需要时显式启用。
- 数据表支持指纹过滤，指纹和身份条件可从列表选择，保留条件组合与历史配置兼容性。
- 数据表过滤只改变显示，不代替请求范围控制。浏览器范围检查不等于进程级网络隔离。

### 可编辑反射检测预设

- 新增 `Reflection probe` 默认处理组，使用普通匹配替换规则处理查询参数与 POST URL 编码表单。与其他内置模板一致，可编辑、删除，默认禁用。
- 配套 `Reflection candidate` 指纹使用可编辑的请求提取表达式，关联当前请求与响应正文，并提供状态码、内容类型、附件和错误页排除条件。
- 提供 `{{nonce}}` 随机值：每次展开生成 24 个小写十六进制字符，同一次展开重复引用共用取值。
- 从相关开发版本升级时迁移旧处理动作，保留处理组配置和已修改的排除条件；已删除的预设不反复恢复。
- 反射命中是输入回显线索，不代表已确认 XSS。

### 界面、文档与可靠性

- 改善过滤、指纹字段、数据保存选项及启动信息的中英文本地化。
- 内置可离线打开的 HTML 用户手册，支持中英切换、搜索、代码复制和打印。
- 补充内置与自定义变量参考、动态请求头与反射识别案例、多位置参数 Fuzz 案例。
- 修复整包、路径、请求头与正文规则连续执行时的同步问题，以及请求正文长度更新。
- 修复指纹缓存的请求关联与 Cookie 响应复用问题；请求级反射结果不混入站点级指纹历史。
- 指纹配置通过串行快照与原子替换保存，降低异步写入竞争风险。

## 安装与升级

1. 保存当前任务，并备份 OST 工作目录中的配置、字典和历史数据库。
2. 停止任务并卸载旧扩展，再在 Burp Extensions 中加载 `OST-v1.2.7.jar`；不要同时启用多个版本。
3. 使用 Java 21。普通 Burp 请求不依赖 Python；浏览器请求需要 Edge/Chrome 与安装了 DrissionPage 的 Python 环境。
4. 在“其他配置 → 打开使用说明”查看正式版内置手册，或直接打开 Release 附件 `user-guide.html`。
5. 如需回退，卸载本版后加载保留的旧 JAR；必要时恢复升级前配置与数据库备份，不覆盖正在使用的数据库。

参数 Fuzz 按模板和 Payload 字典原文构造请求，不展开动态变量，也不重新应用全局请求头、普通请求处理组或 Profile。

## English Summary

- Optional Burp Target Scope integration supplements host/path exclusions; browser interception is not a process-wide firewall.
- Fingerprint filters and selectable fingerprint/identity conditions improve result triage.
- Editable reflection-processing and fingerprint presets use per-expansion `{{nonce}}` values and paired-request extraction. Presets are opt-in; reflection is not confirmed XSS.
- Improved localization, request-scope synchronization, fingerprint caching and atomic configuration persistence.
- Bundled bilingual offline manual includes built-in/custom variables and complete dynamic-header and Parameter Fuzz examples.
- Back up configuration and history, unload the previous extension, then load `OST-v1.2.7.jar` with Java 21. Browser mode additionally requires Edge/Chrome and DrissionPage.
- Parameter Fuzz keeps dictionary/template content literal; it does not expand dynamic variables or reapply global headers, ordinary processing groups or Profiles.

## 发布验证 / Validation

验证环境：Windows、Java 21、Python 3.14、DrissionPage 4.1.1.2、无头 Edge。

| 范围 / Coverage | 结果 / Result |
| --- | --- |
| Java 全量回归 / Full regression | 225 passed: extender 219, mcp-core 6; no failures or skips |
| Python 单元测试 / Unit tests | 26 passed |
| 本地真实浏览器 / Local browser integration | 13 passed; loopback fixtures and independent browser profiles only |
| 正式 JAR / Release artifact | ZIP CRC, Java 21 bytecode, version and bundled resource checks passed |
| 包内容 / Package hygiene | No debug logs, backup files, Python bytecode or private databases |

浏览器回归覆盖错误与挑战页、Cookie、POST 正文、重复请求抑制、并行会话隔离及 Scope 拦截。
内置手册与仓库 HTML 字节一致，包含随机值、命名变量及组合案例；旧开发版 JAR 保持不变。

本次未在运行中的 Burp GUI 内逐项人工验收，也未验证 macOS/Linux 或所有真实业务挑战页。
自动化通过不代表所有部署环境均无异常。

Tests use local fixtures; this is not exhaustive live-Burp, cross-platform or business-site validation.
The bundled manual matches the repository HTML. Parameter Fuzz retains literal dictionary semantics.

复现构建 / Rebuild:

```powershell
.\mvnw.cmd -o '-Dsurefire.timeout=300' package
```

离线构建要求本地已有依赖；首次构建可去掉 <code>-o</code>。
For a first build, omit <code>-o</code> to download dependencies.

本次发布的 `OST-v1.2.7.jar` SHA-256:

```text
f6458c823536ea9ba5d06613adbaa0f7bb609378f71e958eced34ffb1e6ff934
```

Release 附件包含 JAR、离线手册和 `SHA256SUMS.txt`。重新构建时 ZIP 时间戳等因素可能改变哈希。
Release assets include the JAR, offline manual and checksums; rebuilt hashes may differ because of ZIP timestamps.
