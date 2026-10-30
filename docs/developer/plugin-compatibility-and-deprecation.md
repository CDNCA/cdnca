# 插件兼容与弃用契约

本文定义平台授权端对插件版本、能力和兼容范围的开发者边界。权威 Manifest Schema 是
[`marketplace/v1/plugin-manifest.schema.json`](../../api/schemas/marketplace/v1/plugin-manifest.schema.json)，
固定签名 fixture 是 [`plugin-manifest-v1.json`](../../tests/contracts/plugin-manifest-v1.json)，
机器可读兼容矩阵是
[`plugin-compatibility-v1.json`](examples/plugin-compatibility-v1.json)，权威矩阵 Schema 是
[`plugin-compatibility-matrix.schema.json`](../../api/schemas/marketplace/v1/plugin-compatibility-matrix.schema.json)。这些契约各自版本化，
不得从 OpenAPI、事件或 Agent 的版本推断另一个契约版本。

## 本地验证

下面的验证器接受任意 Manifest、公钥 fixture 和目标 Control API 版本。它校验正式 JSON
Schema、Manifest 摘要、Ed25519 签名、已知权限/事件以及严格的兼容范围。验证成功不等于
可安装：扩展目录中不是 `available` 的能力保持默认拒绝，并在输出中得到
`capabilities_available=false` 与 `installable=false`。

```sh
node docs/developer/examples/validate-plugin-manifest.mjs \
  --control-api-version 0.5.0 \
  tests/contracts/plugin-manifest-v1.json \
  tests/contracts/plugin-publisher-v1.json

node tests/contracts/plugin-developer-negative-cases.mjs
```

发布者私钥不得进入参数、fixture、日志或平台数据库。验证器只读取公开 Ed25519 公钥。
`plugin.json` 的签名域固定为 `cdnca-plugin-manifest/v1`；改变确定性编码、摘要算法、
签名输入或必填字段必须发布新的 Manifest 大版本。

## 兼容矩阵

| 边界 | v1 兼容来源 | 不匹配行为 |
| --- | --- | --- |
| Manifest | `api_version=marketplace.cdnca.io/v1` | 拒绝 Manifest |
| Manifest 签名 | `cdnca-plugin-manifest/v1` 与 `integrity.key_id` | 拒绝 Manifest，不回退到未知 key |
| Control API | `spec.compatibility.control_api` 的 1 到 8 个 canonical SemVer comparator | 禁止安装/升级，保留 LKG |
| License Operator API | `/operator/v1` 和正式 OpenAPI operation | 拒绝未知大版本；写请求保留原幂等键精确重试 |
| Workload identity | `cdnca.plugin-workload-identity/v1` | 默认拒绝运行时请求 |
| Agent | 进程外集成边界 | 不向 Agent 或核心进程加载第三方代码 |
| Control 插件安装 API | `cdnca.control.plugin-installation/v1` 与 Control OpenAPI | 未知大版本或严格响应漂移时拒绝显示成功，保留服务器当前状态 |
| Webhook 签名 | `cdnca.webhook.signature/v2` 与原始请求 bytes | 摘要、时间窗、key ID 或签名不匹配时拒绝且不产生业务副作用 |

安装与升级先读取绑定同一 customer、installation 和 verification 的能力授权。批准的 scope、
event 和 webhook 必须分别是 Manifest 声明集合的子集；未批准、未知、已撤销、过期或来自
其他安装实例的能力都保持拒绝。新增或敏感能力必须在该安装实例下重新确认，不能沿用其他
租户的授权或只靠前端勾选绕过服务端事实。兼容失败和应用失败必须保留最近有效版本并记录
不可变失败回执；保护性禁用和卸载不能被失效的发布者或兼容事实阻断。

平台授权端只发布授权事实和审计，不把第三方代码装入客户 Control 或 Agent。客户 Control
实际执行进程外安装、配置应用和退出清理属于独立挂载边界；在该挂载完成前，不能用
Operator 状态或测试 fixture 宣称插件已经在客户控制面运行。

## 弃用时间线

契约状态依次为 `active -> deprecated -> sunset`，不允许从 active 直接删除。进入
`deprecated` 时必须同时提供 `deprecated_since`、`sunset_after`、替代契约和迁移步骤；
迁移窗口至少覆盖一个稳定发布周期。窗口内旧契约仍按原语义验签和读取，不得静默收紧；
停止新安装可以早于停止历史只读，但必须显示稳定原因并保留 LKG。

破坏性变化包括删除字段、改变字段含义、收紧既有值域、改变 canonical bytes、签名域或
scope 默认值。它们必须发布新大版本和并行验证窗口。非破坏性可选字段仍需旧消费者忽略
策略、固定向量和回滚说明。弃用后的审计、历史安装回执和验证成功记录继续按原 schema
读取，不因新版本上线而重写。
