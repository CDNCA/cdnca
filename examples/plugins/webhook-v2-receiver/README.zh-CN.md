# Webhook v2 接收器示例

这是一个只依赖 Go 标准库的独立接收器，演示 CDNCA 当前 Webhook v2 的接收契约，并带一项真实业务：接收网站变更事件 `io.cdnca.site.v1.updated`，每个事件 ID 只处理一次。权威协议见 [`webhook-test-event.schema.json`](../../../api/schemas/marketplace/v1/webhook-test-event.schema.json)、[`domain-event.schema.json`](../../../api/schemas/marketplace/v1/domain-event.schema.json) 与 [`plugin-integration.md`](../../../docs/developer/plugin-integration.md)。示例不会导入控制面代码，也不会连接 PostgreSQL、NATS、Redis 或 ClickHouse。

## 文件

| 文件 | 用途 |
| --- | --- |
| `manifest.json` | 与接收器配套的插件清单：`events.site.read` 权限、订阅 `io.cdnca.site.v1.updated`、`external_https` 入口。未签名，上传前用 `cdnca-plugin sign-manifest` 填 `integrity` |
| `schemas/config.schema.json` | 配置 Schema（本示例没有配置项），SHA-256 已写进清单 |
| `receiver.go`、`journal.go`、`main.go` | 接收器 |
| `testdata/site-updated.json` | 规范的网站变更事件正文；Go 测试与 `tests/plugin-example/validate-contracts.mjs` 共用 |

## 支持的事件

| 事件 | 用途 | 接收器怎么处理 |
| --- | --- | --- |
| `io.cdnca.webhook.v1.test` | 只用于验签联调（订阅只选“测试事件”，不绑定安装） | 校验 subject 为 `webhook_subscription/<订阅 ID>`、`data.test=true`，记录投递 |
| `io.cdnca.site.v1.updated` | 网站变更自动化（订阅要绑定已启用的安装，客户已批准 `events.site.read`） | 严格校验 `site_id`、`change`、`changed_fields`、`subject_sequence` 与 subject `site/<site_id>`；第一次收到该事件 ID 时把站点变更写入 journal，同一事件的重试或显式重放不再重复写 |

其他事件类型一律返回 `400 event_invalid`，不会被确认。需要更多事件时，按 `domain-event.schema.json` 增加对应校验，并同步清单的 `permissions` 与 `subscriptions`。

## 验证范围

`POST /cdnca/hooks` 严格执行以下顺序：

1. 检查方法、规范路径、Content-Type 和唯一必需 header。
2. 对原始正文计算 SHA-256，并做常量时间比较。
3. 按 `X-CDNCA-Webhook-Key-Id` 选择当前或仍有效的旧 secret，使用 v2 域分离输入验签。
4. 检查包含边界的正负 300 秒时间窗。
5. 严格解析规范 CloudEvents 1.0 正文（测试事件或网站变更事件），并绑定 event、tenant 和 subscription 身份。
6. 将 delivery、event、正文摘要（网站变更另带站点变更）写入 owner-only journal，并完成 `fsync` 后才返回 2xx。

| 情况 | 响应 |
| --- | --- |
| 新事件第一次投递 | `202 accepted`，业务记录写入 |
| 同一 delivery、同一正文的再次尝试 | `200 replay_accepted` |
| 显式重放（新 delivery、同一事件与正文） | 测试事件 `202 accepted`；网站变更 `200 event_already_processed`，不重复执行业务 |
| 同一 delivery 或事件的不同正文 | `409 delivery_digest_conflict` |
| 签名、时间窗或摘要不对 | `401 webhook_authentication_failed` |
| 租户或订阅不是本接收器配置的 | `403 event_scope_denied` |
| journal 写入或 `fsync` 失败 | `503 journal_unavailable`，平台会重试 |

示例不清理 journal，因此满足至少保留 30 天的下限，但实际部署应提供经过验证的轮转、备份和恢复流程。

## 运行测试

```bash
cd examples/plugins/webhook-v2-receiver
GOWORK=off go test ./... -count=1
```

测试固定 schema 中的 612 字节测试正文、摘要、签名和公开测试 key，覆盖篡改、错误 key、时间窗、scope、derived idempotency key、规范 attempt、零 UUID、全零 trace ID、显式 replay 和 journal `fsync` 失败不返回 2xx；网站变更部分覆盖一次处理、重试与重放不重复、其他租户/订阅/站点/Schema/字段值拒绝，以及清单与接收器支持的事件一致。公开测试 key 绝不能作为真实 Webhook secret。

## 本地启动

控制面返回的 secret 是 43 字符、无 padding 的 base64url。进程会把它严格解码为 32 个 raw bytes，再作为 HMAC key；不能直接把 43 个 ASCII 字节用于 HMAC。

```bash
export CDNCA_WEBHOOK_V2_SECRET_CURRENT='<43-char-base64url-secret>'
export CDNCA_WEBHOOK_V2_SECRET_CURRENT_KEY_ID='<secret-version-uuid>'
export CDNCA_WEBHOOK_V2_TENANT_ID='<tenant-uuid>'
export CDNCA_WEBHOOK_V2_SUBSCRIPTION_ID='<subscription-uuid>'
export CDNCA_WEBHOOK_V2_JOURNAL="$(mktemp -d)/webhook-v2.journal"
export CDNCA_WEBHOOK_V2_LISTEN_ADDR='127.0.0.1:18080'
GOWORK=off go run .
```

一个进程对应一个订阅。先用只选测试事件的订阅验签；再新建选择 `io.cdnca.site.v1.updated` 并绑定已启用安装的业务订阅（也可以同时勾选测试事件），把该订阅的 ID 与 secret 配给接收器，改一个测试站点的普通设置后查看 journal 中的站点变更记录。

轮换窗口内还可以同时设置：

```bash
export CDNCA_WEBHOOK_V2_SECRET_PREVIOUS='<43-char-base64url-secret>'
export CDNCA_WEBHOOK_V2_SECRET_PREVIOUS_KEY_ID='<previous-secret-version-uuid>'
export CDNCA_WEBHOOK_V2_SECRET_PREVIOUS_VALID_UNTIL='2026-08-10T12:00:00Z'
```

旧 secret 只在当前时间严格早于截止时间时可用；到达边界后内存副本被清零。环境变量读取后会立即从进程环境删除。journal 必须是普通文件，进程取得独占锁后强制为 `0600`，拒绝 symlink 和并行 writer。

## 打包签名

平台包是接收器的可执行文件，按要上传的平台交叉编译后打成 `tar.gz`：

```bash
mkdir -p build/linux-amd64 dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOWORK=off go build -trimpath -o build/linux-amd64/webhook-v2-receiver .
tar -czf dist/linux-amd64.tar.gz -C build/linux-amd64 webhook-v2-receiver
./cdnca-plugin sign-manifest -key publisher.key -in manifest.json -out manifest.signed.json
```

上传前把清单里的 `metadata.id`、`publisher`、`base_url` 换成你自己的值。上传 `manifest.signed.json`、`schemas/config.schema.json` 与 `dist/linux-amd64.tar.gz`（表单字段 `package:linux-amd64`）。

## 部署边界

示例监听本机 HTTP 只为开发测试。真实插件入口必须使用 HTTPS，并由可信 TLS 终止层转发到 loopback 或受保护的私网监听；不得将该 HTTP 端口直接暴露到公网。

本目录不是生产部署模板。它没有 TLS 证书管理、多副本共享幂等存储、journal 轮转/备份、容量上限、指标、告警和灾难恢复；不能因为示例测试通过就宣称插件安装、领域事件投递或生产 Webhook 部署已经完成。
