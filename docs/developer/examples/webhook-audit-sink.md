# Webhook 审计接收器示例

## 适用边界

[`webhook-audit-sink`](../../../examples/plugins/webhook-audit-sink) 是独立 Go 进程示例，只使用标准库，不导入控制面代码，也不连接 PostgreSQL、Redis、ClickHouse 或 NATS。它验证当前公开的 Webhook HMAC v1 和 `domain-event` v1，固定接收 `io.cdnca.site.v1.updated`，并按配置租户拒绝越权事件。

该示例不是插件市场闭环。扩展目录中的 `events.site.read` 和站点更新事件仍是 `reserved`；control-api 尚未交付插件安装、OAuth 2.0 工作负载身份、在线 secret、领域 outbox 或投递管理 API。`installation.example.json` 带有 `example_only: true`，仅展示未来安装需要绑定的 service account 类型、授权 scope 和订阅，不是可发送到现有 API 的请求。

## 一条命令验收

从仓库根目录运行：

```bash
./scripts/plugin-example-smoke.sh
```

脚本在 `mktemp` 目录构建二进制，监听 `127.0.0.1:0` 的任务专属端口，执行 schema/manifest 签名校验和真实 HTTP 请求。它覆盖首次接收、相同事件重放、异正文冲突、SIGKILL 后重启、残缺尾部拒绝、预建 `0644` journal 收紧、并发单赢家、乱序 sequence、带截止时间的双 secret、旧 secret 撤销、租户拒绝、时间窗、正文篡改、Content-Type 和敏感字段不落盘。退出时只终止脚本启动的 PID，并删除该临时目录。

可直接交给 CI 的完整检查命令：

```bash
./tests/plugin-example/ci.sh
```

该入口显式使用 `GOWORK=off` 验证 nested module，并同时运行普通/race/vet、ShellCheck、两个 marketplace validator、Markdownlint 和真实 HTTP smoke；它不依赖根 `go.work` 的隐式收集。

## 本地启动

以下值只是本机示例，不是可部署 secret：

```bash
cd examples/plugins/webhook-audit-sink
export CDNCA_WEBHOOK_SECRET_CURRENT='local-example-secret-not-for-production-0001'
export CDNCA_WEBHOOK_TENANT_ID='019b143c-7e64-7cc6-b886-a1354a006283'
export CDNCA_WEBHOOK_JOURNAL="$(mktemp -d)/events.jsonl"
export CDNCA_WEBHOOK_LISTEN_ADDR='127.0.0.1:18080'
GOWORK=off go run .
```

进程提供 `GET /health/ready` 和 `POST /webhooks/cdnca/v1`。journal 正常时 health 返回 `200 ready`；journal poison 或关闭时返回 `503 journal_unavailable`。HTTP server 限制 header、正文、读取、写入和空闲时间；Webhook 只接受精确的 `application/cloudevents+json` 且拒绝 Content-Encoding。manifest 的生产入口仍是 `external_https`；真实部署必须在受管 TLS 入口后运行，不能把本机明文监听直接暴露到公网。

## curl 请求

在另一个终端使用同一个本地示例 secret。签名计算从环境读取 secret，不把它写到命令参数或请求正文：

```bash
export CDNCA_WEBHOOK_SECRET_CURRENT='local-example-secret-not-for-production-0001'
event_file='tests/plugin-example/domain-event-v1.json'
timestamp=$(date +%s)
delivery_id='019b143c-7e64-7cc6-b886-a1354a006299'
body_sha256=$(shasum -a 256 "${event_file}" | awk '{print $1}')
signature=$(
  CDNCA_TIMESTAMP="${timestamp}" \
  CDNCA_DELIVERY_ID="${delivery_id}" \
  CDNCA_BODY_SHA256="${body_sha256}" \
  node -e '
    const {createHmac} = require("node:crypto");
    const input = `cdnca.webhook.signature/v1\n${process.env.CDNCA_TIMESTAMP}\n${process.env.CDNCA_DELIVERY_ID}\n${process.env.CDNCA_BODY_SHA256}`;
    process.stdout.write("v1=" + createHmac("sha256", process.env.CDNCA_WEBHOOK_SECRET_CURRENT).update(input).digest("base64url"));
  '
)

curl --fail-with-body --request POST 'http://127.0.0.1:18080/webhooks/cdnca/v1' \
  --header 'Content-Type: application/cloudevents+json' \
  --header "X-CDNCA-Webhook-Id: ${delivery_id}" \
  --header "X-CDNCA-Webhook-Timestamp: ${timestamp}" \
  --header "X-CDNCA-Webhook-Content-Sha256: ${body_sha256}" \
  --header "X-CDNCA-Webhook-Signature: ${signature}" \
  --header 'X-CDNCA-Idempotency-Key: plugin-example-curl-1' \
  --header 'X-CDNCA-Webhook-Attempt: 1' \
  --data-binary "@${event_file}"
```

首次成功返回：

```json
{"code":"accepted"}
```

相同事件 ID 和完全相同的原始正文再次发送返回：

```json
{"code":"replay_accepted"}
```

## 验证与落盘顺序

接收器按以下顺序处理：严格方法、路径、Content-Type 和六个 Webhook header；有界读取原始正文；恒定时间比较正文 SHA-256；按 `cdnca.webhook.signature/v1` 域分离输入尝试当前和旧 secret；检查正负五分钟时间窗；解析并校验公开 `domain-event` v1；检查租户和订阅；最后追加 journal 并 `fsync`。只有 `fsync` 成功后才返回 2xx。

journal 每行只包含 `event_id`、`body_sha256` 和 `received_at`。打开路径时拒绝 symlink 和非普通文件；取得独占锁后执行 `fchmod(0600)` 并用 `fstat` 复核。相同 event ID 与相同 digest 返回 200；同 event ID 与不同原始正文 digest 返回 409，即使两份 JSON 语义相同。不同事件不依赖 `sequence` 到达顺序。

append 前在同一锁内记录原 EOF。短写、写错误或首次 `fsync` 失败时，接收器必须截断回原 offset、重新定位并再次 `fsync`，本次返回 503；恢复成功后才允许后续重试。如果 truncate、seek 或 rollback sync 失败，journal 被永久 poison 并关闭，当前进程的所有后续请求继续返回 503。进程启动时遇到残缺尾部、未知字段、冲突或无法解析记录会拒绝启动，不会静默跳过或在损坏状态 ACK。

## 轮换与撤销

当前 v1 header 没有 `key_id`。轮换窗口内必须同时设置旧 key 和其严格截止时间：

```bash
export CDNCA_WEBHOOK_SECRET_CURRENT='new-secret-from-secret-manager-at-least-32-bytes'
export CDNCA_WEBHOOK_SECRET_PREVIOUS='old-secret-from-secret-manager-at-least-32-bytes'
export CDNCA_WEBHOOK_SECRET_PREVIOUS_VALID_UNTIL='2026-07-23T09:30:00Z'
```

`CDNCA_WEBHOOK_SECRET_PREVIOUS` 与 `CDNCA_WEBHOOK_SECRET_PREVIOUS_VALID_UNTIL` 必须同时存在或同时省略。截止时间只接受规范 RFC3339 UTC `Z` 格式（可有规范小数秒），不接受 offset、缺失值或非规范变体。当前时间严格早于截止时间时旧 key 才有效；边界及之后的请求会拒绝旧 key 并清零内存副本，即使环境配置仍残留也不能继续验签。接收器不记录命中项。确认控制面只使用新 secret 后，删除两个旧 key 变量并重启；旧 secret 请求稳定返回 401。生产 secret 必须由 secret manager 注入，不能写入 manifest、配置 JSON、日志、journal、shell 历史或镜像。

## 稳定响应

| HTTP | `code` | 重试语义 |
| --- | --- | --- |
| 202 | `accepted` | 已持久接收，不重试 |
| 200 | `replay_accepted` | 同 event/digest 已处理，不重试 |
| 400 | `webhook_headers_invalid` / `request_body_invalid` / `event_invalid` | 永久失败，修正请求 |
| 401 | `webhook_authentication_failed` / `webhook_timestamp_out_of_window` | 永久失败；核对 secret 或时钟后生成新尝试 |
| 403 | `event_scope_denied` | 永久失败，不能扩大租户或订阅 scope |
| 404 | `route_not_found` | 永久失败，修正路径并移除 query |
| 405 | `method_not_allowed` | 永久失败，Webhook 使用 POST，health 使用 GET |
| 409 | `event_digest_conflict` | 永久失败，调查 event ID 复用 |
| 413 | `request_body_too_large` | 永久失败，正文上限 256 KiB |
| 415 | `content_type_invalid` / `content_encoding_unsupported` | 永久失败，修正媒体类型 |
| 503 | `journal_unavailable` | 可重试；必须复用同一事件 ID 和原始正文 |

响应和日志不回显签名、secret、正文或服务端内部错误。示例没有 journal 轮转、备份、指标、TLS 终止和多副本共享存储；这些属于部署及 runtime 接线，不应从本示例推断为已交付。
