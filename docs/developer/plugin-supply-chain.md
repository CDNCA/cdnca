# 插件供应链运营接口

本文面向 CDNCA 平台授权运营人员和受信插件发布者，说明当前已经接线的
发布者登记与单个 manifest 验签接口。接口的权威机器可读契约是
[`license.yaml`](../../api/openapi/v1/license.yaml)，manifest 形状由
[`plugin-manifest.schema.json`](../../api/schemas/marketplace/v1/plugin-manifest.schema.json)
定义。

## 1. 信任域与当前边界

七个接口都属于 `license-service` 的 operator trust domain：

| Method | Path | 用途 |
| --- | --- | --- |
| `GET` | `/operator/v1/plugin-publishers` | 分页读取发布者 |
| `POST` | `/operator/v1/plugin-publishers` | 登记发布者及首个 Ed25519 公钥 |
| `GET` | `/operator/v1/plugin-publishers/{publisher_id}` | 读取发布者及当前公钥 |
| `POST` | `/operator/v1/plugin-publishers/{publisher_id}/disable` | 永久禁用发布者 |
| `GET` | `/operator/v1/plugin-manifest-verifications` | 分页读取成功的不可变验签结果 |
| `POST` | `/operator/v1/plugin-manifest-verifications` | 获取并验证一个目录快照中的 manifest |
| `GET` | `/operator/v1/plugin-manifest-verifications/{verification_id}` | 读取一个成功验签结果 |

它们不是租户插件 API，也不创建安装、服务账号、OAuth client、Webhook
subscription 或插件运行时。成功验签只产生不可变证据；当前响应中的
`installable` 与 `configuration_schema_verified` 都固定为 `false`。插件仍不能直连
平台数据库、在核心进程中执行代码，或用 operator session 充当租户工作负载身份。

## 2. 认证、Origin 与权限

请求只接受 `OperatorSession` Cookie。生产 Cookie 名为
`__Host-cdnca_operator_session`，并由服务端设置 `Secure`、`HttpOnly` 和
`SameSite=Strict`。`Authorization: Bearer`、`CdncaKey`、control-api session、租户
session 或这些凭据的组合都不能替代 operator Cookie。

所有 GET 和 POST 都会在 licensing 数据库事务内实时复查唯一权限
`licensing.plugin_supply_chain.manage`。权限在 session 创建后被撤销时，下一次读取、
写入或成功幂等 replay 都返回 `403 forbidden`。所有写操作还要求当前 operator 通过
`platform_owner` 角色持有该权限；自定义角色仅授予同名 permission 仍不能写入。

所有 POST 同时要求 `Origin` 恰好等于部署配置的 operator-console origin。缺失、
重复或不同的 Origin 返回 `403 invalid_origin`。不要把生产 Cookie 导出到脚本、CI
日志或工单；下列命令只用环境变量说明 wire format。

## 3. 通用请求约束

POST 请求必须同时满足：

- 只有一个 `Content-Type` header field value，且解析后的 media type 是
  `application/json`。缺失、重复、合并值、别名或畸形参数返回
  `415 unsupported_media_type`。
- 正文上限是通用服务上限与 1 MiB 中的较小值；超限返回
  `413 request_too_large`。
- JSON 必须是 UTF-8 对象，不允许重复键、未知字段、尾随 JSON 值，必填字段不能
  省略或为 `null`。违反时返回 `400 invalid_request`。
- `Idempotency-Key` 必须只有一个 header field value，长度为 1 到 128 bytes，
  每个 byte 都在 `0x21..0x7e`。服务端不 trim、不合并、不规范化；格式错误返回
  `400 invalid_idempotency_key`。
- `X-Request-ID` 只做传输与审计关联，和 `Idempotency-Key` 相互独立。调用方应记录
  响应中的 request ID，但不能用它代替幂等 key。

相同 operator、operation、`Idempotency-Key` 和相同 canonical request digest 的
成功 replay 会先实时复查权限，再返回首次成功的状态与正文。manifest replay 不再次
访问网络。相同 key 对应不同 digest 返回 `409 idempotency_conflict`。网络结果未知时
应保留原正文 bytes 和原 key 重试；不要生成新 key。失败的 manifest 验证会持久记录并
审计，但不会占用一个成功幂等结果。

所有路径 UUID 都必须是非零、小写 canonical UUID。分页默认
`page=1&page_size=20`，`page_size` 最大为 100；未知或重复 query 参数会被拒绝。

## 4. 登记与禁用发布者

创建请求只有五个字段：

- `slug`：3 到 128 bytes，匹配
  `^[a-z0-9]+(?:[.-][a-z0-9]+)+$`。
- `display_name_zh_cn`、`display_name_en_us`：有效 UTF-8，去除首尾空白后必须与
  原值相同，各 1 到 200 Unicode code points。
- `key_id`：1 到 128 bytes，匹配
  `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`。
- `public_key`：恰好 32 个 Ed25519 公钥 bytes 的 canonical、无填充 base64url；
  解码后还必须是 canonical prime-subgroup point。

公钥不是 secret，但对应私钥必须留在发布者的受管签名环境中。服务端保存 immutable
key version 1，并返回原公钥及其 SHA-256 无填充 base64url fingerprint。当前切片不提供
换钥接口。

以下 fixture 公钥来自仓库公开契约样例，不包含私钥，不能作为生产签名身份：

```sh
curl --fail-with-body \
  --request POST \
  --cookie "__Host-cdnca_operator_session=${CDNCA_OPERATOR_SESSION}" \
  --header "Origin: ${CDNCA_OPERATOR_ORIGIN}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: docs-create-example-publisher-1" \
  --header "X-Request-ID: docs-create-example-publisher-request" \
  --data-binary '{
    "slug":"com.example",
    "display_name_zh_cn":"示例发布者",
    "display_name_en_us":"Example Publisher",
    "key_id":"publisher-example-2026-01",
    "public_key":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
  }' \
  "${CDNCA_LICENSE_ORIGIN}/operator/v1/plugin-publishers"
```

成功返回 `201`，公共响应形状如下：

```json
{
  "id": "018f47ab-5d9c-7a20-8000-000000000001",
  "slug": "com.example",
  "display_name_zh_cn": "示例发布者",
  "display_name_en_us": "Example Publisher",
  "status": "active",
  "revision": 1,
  "current_key": {
    "version": 1,
    "key_id": "publisher-example-2026-01",
    "algorithm": "Ed25519",
    "public_key": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    "fingerprint": "If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk",
    "created_at": "2026-08-01T00:00:00Z"
  },
  "created_at": "2026-08-01T00:00:00Z",
  "updated_at": "2026-08-01T00:00:00Z"
}
```

active 响应不包含 `disabled_at` 或 `disable_reason`。禁用需要当前正修订和非空原因，
是单向状态转换：

```sh
curl --fail-with-body \
  --request POST \
  --cookie "__Host-cdnca_operator_session=${CDNCA_OPERATOR_SESSION}" \
  --header "Origin: ${CDNCA_OPERATOR_ORIGIN}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: docs-disable-example-publisher-1" \
  --data-binary '{"expected_revision":1,"reason":"发布者信任已由运营审核撤销"}' \
  "${CDNCA_LICENSE_ORIGIN}/operator/v1/plugin-publishers/${PUBLISHER_ID}/disable"
```

成功返回 `200`、`status=disabled`、递增后的 revision、`disabled_at` 和
`disable_reason`。修订漂移返回 `409 revision_conflict`，已禁用发布者返回
`409 plugin_publisher_unavailable`。

发布者列表接受可选 `status=active|disabled`，按
`created_at DESC,id DESC` 排序。发布者 ID 查询只接受 canonical UUID。

## 5. Manifest 形状与签名

完整非生产 manifest fixture 见
[`plugin-manifest-v1.json`](../../tests/contracts/plugin-manifest-v1.json)。服务端要求：

- `api_version` 恰好为 `marketplace.cdnca.io/v1`，`kind` 恰好为 `Plugin`。
- `metadata.id` 和请求 `plugin_id` 完全相同；`metadata.version` 和请求
  `version` 完全相同。发布者 slug 与 `integrity.key_id` 必须命中一个当前 active
  publisher 及其 current immutable key。
- `metadata.version` 是 5 到 128 bytes 的 canonical SemVer，不接受前导 `v`、核心
  版本前导零或非 canonical prerelease。
- `spec.entrypoint.type` 是 schema `oneOf` 的四种之一：`external_https`（`base_url`、
  `health_path`，provider 另带 `provider_response_key`）、`rule_pack` / `theme`（`path`、
  `sha256`，数据包文件随版本上传）、`ui_page`（`origin`、`api_base_url`、`pages`）。字段集合
  互斥，多余字段即拒绝（`plugin_manifest_verifier.go` `validPluginManifestEntrypoint`）。
  这只是 manifest 声明，不代表 license-service 会调用插件 entrypoint。
- `spec.provides` 只允许 `external_https` 入口声明；`kind=cdn` 只限官方发布者。
- manifest 是严格 UTF-8 JSON，不允许重复或未知字段、尾随值、非法 surrogate、
  `null`、number 或 boolean 等 schema 外值。

签名者必须按以下精确步骤产生 `integrity`：

1. 从完整 JSON 对象中移除顶层 `integrity`。
2. 对剩余值做 v1 确定性编码：对象键按 UTF-8 bytes 字典序排列；数组保持原顺序；
   对象、数组和字符串之外的值拒绝；不输出 BOM、空白或尾随换行。
3. 字符串的 `"`、`\\`、backspace、tab、LF、form feed 和 CR 使用短转义；其他
   U+0000 到 U+001F 使用小写 `\\u00xx`；其余 Unicode 直接输出 UTF-8 bytes。
4. 对 canonical payload bytes 做 SHA-256，把 32 bytes 摘要的小写十六进制写入
   `integrity.payload_sha256`。
5. 构造签名消息：ASCII `cdnca-plugin-manifest/v1`、一个 LF byte `0x0a`、再接
   原始 32-byte SHA-256 摘要。这里拼接的是摘要 bytes，不是 64 字符 hex。
6. 用登记的 Ed25519 私钥签名该消息，把 64-byte signature 编为 canonical、无填充
   base64url，写入 `integrity.signature`；`algorithm` 必须是 `Ed25519`，`key_id`
   必须与登记的 current key 完全相同。

不要把普通 `JSON.stringify`、格式化后的源文件 bytes 或 RFC 8785 库未经固定向量验证
就当成签名输入。仓库 fixture、schema 和 contract checks 是当前 v1 的可执行向量。

## 6. 发起 Manifest 验证

POST 正文只接受目录、快照、插件和版本四个 identifier，不接受 URL、请求头、代理、
DNS 结果或 TLS 参数：

```sh
curl --fail-with-body \
  --request POST \
  --cookie "__Host-cdnca_operator_session=${CDNCA_OPERATOR_SESSION}" \
  --header "Origin: ${CDNCA_OPERATOR_ORIGIN}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: docs-verify-example-manifest-1" \
  --header "X-Request-ID: docs-verify-example-manifest-request" \
  --data-binary "{\"catalog_id\":\"cdnca.official\",\"snapshot_id\":\"${SNAPSHOT_ID}\",\"plugin_id\":\"com.example.dns-connector\",\"version\":\"1.0.0\"}" \
  "${CDNCA_LICENSE_ORIGIN}/operator/v1/plugin-manifest-verifications"
```

`catalog_id` 匹配 `^[a-z][a-z0-9._-]{0,95}$`；`snapshot_id` 是 canonical UUID；
`plugin_id` 使用 publisher-slug grammar；`version` 使用 canonical SemVer。指定快照必须
属于指定目录，并且快照中必须恰好存在同一 `plugin_id` 和 `version`，否则返回
`404 not_found`。

HTTP handler 只把这四个 identifier 交给 `PluginManifestVerifier`。verifier 从已验签的
immutable snapshot 读取固定 catalog origin、manifest path 和期望 raw digest，然后：

- 只允许小写 ASCII DNS hostname 的 HTTPS 443 origin，拒绝 IP literal、userinfo、
  query、fragment 和重定向；每次请求重新解析 DNS，所有结果都必须是公网地址。
- pin 本次验证后的拨号地址，同时保留原 hostname 的 TLS SNI 和 HTTP Host；TLS 最低
  为 1.2，不使用环境代理。
- 只接受 `200`、唯一精确
  `application/vnd.cdnca.plugin-manifest.v1+json` Content-Type、无 Content-Encoding，
  正文最多 256 KiB。
- 先常量时间比较 snapshot 中的 raw SHA-256，再做严格解析、canonical digest、
  publisher/key 状态、Ed25519 signature 和 compatibility 验证。
- 在最终提交前重新锁定并比较 candidate、catalog 与 publisher key，避免远程请求期间
  的状态漂移被误记为成功。

成功返回 `201`。以下响应是字段示例，digest 和 UUID 均为非生产占位值：

```json
{
  "id": "018f47ab-5d9c-7a20-8000-000000000002",
  "catalog_id": "cdnca.official",
  "snapshot_id": "018f47ab-5d9c-7a20-8000-000000000003",
  "plugin_id": "com.example.dns-connector",
  "version": "1.0.0",
  "manifest_path": "/manifests/com.example.dns-connector-1.0.0.json",
  "expected_raw_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "raw_manifest_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "canonical_payload_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
  "publisher_id": "018f47ab-5d9c-7a20-8000-000000000001",
  "publisher_slug": "com.example",
  "publisher_key_version": 1,
  "publisher_key_id": "publisher-example-2026-01",
  "control_api_version": "1.0.0",
  "compatibility_constraint": ">=1.0.0 <2.0.0",
  "compatible": true,
  "stable_reason_code": "compatible",
  "installable": false,
  "configuration_schema_verified": false,
  "verified_at": "2026-08-01T00:01:00Z"
}
```

公共响应绝不包含 operator ID、`Idempotency-Key`、request digest、manifest signature
或原始网络/数据库错误。失败 attempt 仍会持久保存脱敏 `stable_reason_code` 并写审计，
但当前没有公开 failed-attempt endpoint。

## 7. Compatibility 语义

`spec.compatibility.control_api` 是 1 到 8 个由单个 ASCII space 分隔的 comparator，
整体不超过 128 bytes。每个 comparator 必须是 `=`、`>`、`>=`、`<` 或 `<=` 加
canonical SemVer；所有 comparator 以 AND 计算。示例：

```text
>=1.4.0 <2.0.0
```

不兼容不是签名失败：验证仍可成功保存，但返回 `compatible=false` 和
`stable_reason_code=control_api_incompatible`。当前无论兼容与否都不会安装插件；未来的
安装或升级流程必须再次检查目标主控版本，不能从 OpenAPI 版本或事件 schema 版本推断
manifest compatibility。

## 8. 查询与错误处理

成功验签列表只包含 immutable success，按 `verified_at DESC,id DESC` 排序。可选过滤器
为精确 `catalog_id`、`plugin_id`、canonical `publisher_id` 和
`compatible=true|false`。GET 不需要 Origin 或 `Idempotency-Key`，但仍需要当前有效的
operator Cookie 和 live permission。

客户端只依赖稳定 `code` 与 `request_id`，不要解析 message 或内部原因：

| HTTP | 稳定 code | 处理建议 |
| --- | --- | --- |
| `400` | `invalid_request`, `invalid_idempotency_key` | 修正严格 JSON、identifier、query 或 header |
| `401` | `unauthorized` | 重新建立 operator session；不要改用其他身份域凭据 |
| `403` | `invalid_origin`, `forbidden` | 修正配置 Origin 或申请唯一所需权限和写入角色 |
| `404` | `not_found` | 检查目录、快照、插件、版本或 canonical resource ID |
| `409` | `conflict`, `idempotency_conflict`, `revision_conflict`, `plugin_publisher_unavailable`, `trusted_catalog_unavailable` | 读取当前资源；只有网络结果未知且 digest 未变时才原 key 重试 |
| `413` | `request_too_large` | 缩小请求正文 |
| `415` | `unsupported_media_type` | 发送唯一的 `application/json` Content-Type |
| `422` | `plugin_manifest_invalid` | 修复 raw digest、严格 JSON、identity、canonical digest、signature 或 compatibility |
| `502` | `plugin_manifest_unavailable` | 远端抓取未安全完成；稍后用原 key 与原正文重试 |
| `504` | `request_timeout` | 结果未知；用原 key 与原正文重试 |
| `500` | `internal_error` | 记录 request ID 并由平台运营排查 |

服务端不会把 DNS 地址、TLS 错误、响应正文、signature、数据库错误或内部
`stable_reason_code` 放入公共错误。发布者应在发布前用
[`plugin-manifest-v1.json`](../../tests/contracts/plugin-manifest-v1.json) 与仓库契约检查
验证 canonicalization、signature 和 schema，再由有权限的 operator 发起远程验签。

## 9. 版本与后续能力

manifest `api_version`、`metadata.version`、`spec.compatibility.control_api`、OpenAPI
版本和事件 schema 独立演进。改变 canonical encoding、signature domain、必填字段语义
或 compatibility grammar 需要新协议版本，不能静默收紧 v1。

当前供应链接口不证明租户安装、运行时认证、配置 schema 内容验签、Webhook 订阅、
插件健康检查或插件执行已经交付。那些能力必须另行提供版本化公开契约、权限、审计、
撤销、失败恢复和真实浏览器/运行时证据。
