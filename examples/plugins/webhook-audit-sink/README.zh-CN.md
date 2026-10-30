# Webhook 审计接收器示例

这是 CDNCA 开放生态的隔离开发示例，不是插件市场、安装运行时或生产接线。进程只接收已签名的站点更新 Webhook，将事件 UUID、原始正文 SHA-256 和接收时间追加到本地 journal；它不连接平台数据库，也不导入控制面代码。

运行和验收步骤见 [`docs/developer/examples/webhook-audit-sink.md`](../../../docs/developer/examples/webhook-audit-sink.md)。
