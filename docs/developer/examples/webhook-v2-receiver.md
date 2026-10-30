# Webhook v2 接收器示例

[`examples/plugins/webhook-v2-receiver`](../../../examples/plugins/webhook-v2-receiver) 是当前 Webhook v2 的最小接收方示例，带一项真实业务：接收 `io.cdnca.site.v1.updated` 并按事件 ID 只处理一次。它只使用 Go 标准库，直接消费 [`webhook-test-event.schema.json`](../../../api/schemas/marketplace/v1/webhook-test-event.schema.json) 中的权威固定向量，网站变更正文按 [`domain-event.schema.json`](../../../api/schemas/marketplace/v1/domain-event.schema.json) 严格校验，不重新定义 CloudEvents 字段、签名输入或 header。同目录 `manifest.json` 是与接收器配套的清单（`events.site.read`、订阅 `io.cdnca.site.v1.updated`），`tests/plugin-example/validate-contracts.mjs` 校验清单与样例事件符合市场契约。

示例覆盖：原始正文摘要先于 JSON、v2 HMAC 与 `key_id` 轮换、正负 300 秒包含边界的时间窗、`event_id`/正文绑定、`sha256(delivery_id)` 派生幂等键、规范 attempt、delivery attempt 去重、显式 replay 新 delivery、tenant/subscription scope，以及 journal `fsync` 成功后才返回任意 2xx；网站变更另覆盖站点 subject 绑定、change/changed_fields 取值、重试与显式重放不重复执行业务（`event_already_processed`）。其他事件类型一律拒绝。

运行唯一 focused contract：

```bash
cd examples/plugins/webhook-v2-receiver
GOWORK=off go test ./... -count=1
```

本地配置、响应语义和密钥轮换见示例的 [`README.zh-CN.md`](../../../examples/plugins/webhook-v2-receiver/README.zh-CN.md)。生产入口必须是 HTTPS；本地 loopback HTTP、单文件 journal 和公开测试 key 只能用于开发。该示例没有多副本存储、备份、容量治理、指标或生产 secret manager 接线，不能作为可直接上线的部署模板，也不能替代 [`plugin-integration.md`](../plugin-integration.md) 的完整验收门槛。
