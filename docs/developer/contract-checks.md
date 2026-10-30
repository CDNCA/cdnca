# 契约文档检查

从仓库根运行：

```sh
./scripts/check-contract-docs.sh
```

该命令固定使用 Redocly `1.34.5` 解析现有 OpenAPI，并直接读取 protobuf 和 marketplace JSON Schema。OpenAPI 索引生成器另以固定的 `yaml` `2.8.1` 结构化解析 YAML `$ref`。检查还执行现有 [`validate-marketplace-contracts.mjs`](../../scripts/validate-marketplace-contracts.mjs)，不生成另一套 endpoint、RPC 或插件字段清单。

## OpenAPI 索引生成

OpenAPI operation 索引和 API README 的契约计数由同一个生成器维护：

```sh
node tools/contract-doc-check/openapi-index.mjs --write
node tools/contract-doc-check/openapi-index.mjs --check
```

`--write` 只更新两个 Markdown 文件的生成标记区；`--check` 不写文件，生成内容有漂移时失败。生成器从四份根契约递归解析仓库内的外部 `$ref`，按契约保留每个 operation，并单独报告完全一致的跨契约 method/path/`operationId` 重叠。

## 自动阻止的漂移

- 开发文档中的本地链接和隐藏契约引用必须存在，路径不能逃出仓库。
- 每份 OpenAPI 的 `operationId` 必须唯一；跨文件复用只能指向相同 method/path，且相同 method/path 不能改用不同 `operationId`。兼容重叠会在索引中逐项列出，任何分叉都失败关闭。
- 每个 operation 必须显式声明或继承 `security`；已命名权限必须是非空 `x-required-permissions`，并提供 `403`；没有命名权限的受保护非认证/会话 operation 至少提供 `401` 或 `403`。
- 已声明 `Idempotency-Key` 的参数必须为必填字符串，并显式提供精确的 `minLength: 1` 与 `maxLength: 128`；`pattern` 不能替代或暗中收窄这两个长度端点，必须至少保留一个 1 字节和一个 128 字节 ASCII 值。operation 级同名同位置参数覆盖 path-item 参数，header 名称不区分大小写。只要 operation 声明任一 2xx/3xx 响应，就必须提供稳定 `409`，仅声明 4xx/5xx 的失败关闭接口不虚构 `409`；所有 4xx/5xx JSON 错误必须含 `code` 和 `request_id`。
- OpenAPI request/response/parameter/schema 示例必须通过相邻 JSON Schema。
- protobuf 文档标记引用的 service、method 和 message 必须存在；每个 service 都必须被索引。
- 插件清单、领域事件和扩展目录示例必须通过当前 JSON Schema；清单 Ed25519 和 Webhook HMAC 固定向量必须验签。
- OpenAPI `info.version`、公开路径 `/vN`、protobuf `.vN` package 及插件版本形状会被检查。弃用必须满足 [`contract-policy.json`](contract-policy.json) 的机器标记。

错误输出使用 `文件#JSON-Pointer` 或 `文件:行:字段`，可直接定位失败契约。

## 自动化边界

检查器不会猜测一个未声明 `Idempotency-Key` 的写接口是否本应幂等，也不能从 OpenAPI 推断运行路由是否已经接线。它验证命名权限标记的结构，但无法证明服务端 RBAC 实现与数据库授权一致。它也不验证 Webhook 真实网络投递、插件安装生命周期、计费副作用或边缘配置激活；这些必须由 Go 集成测试、隔离环境和功能矩阵验收。

## 检查器自身测试

```sh
node tools/contract-doc-check/test.mjs
```

正例夹具覆盖一份最小 OpenAPI、仅失败响应的幂等接口、只声明 `401` 的无命名权限受保护接口、`/auth` 与 `/session` 例外、两个 protobuf service 引用和两类插件签名。反例逐项注入重复 `operationId`、无认证、权限拒绝响应缺失、2xx/3xx 成功响应缺失幂等冲突、可选幂等 key、缺失或非精确 `1..128` 长度边界、误导性 `pattern`、operation 参数覆盖、坏示例、错误码形状、失效 RPC 引用、Schema 失败、签名篡改和弃用标记缺失；每项既断言必需错误定位，也拒绝 allowlist 外的无关诊断。
