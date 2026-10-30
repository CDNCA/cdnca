# OpenResty 排空 fixture

`agents/edge-agent/internal/drainruntime` 从 `cdnca.edge.drain/v1` plan 生成三份确定性配置：

- `candidate.conf`：新版本 listener 全部生效；未与新版本占用同一 socket 的旧 listener 继续接受连接，供新端口先健康再迁移。
- `draining.conf`：只保留新版本 listener。reload 后旧 worker 停止接受新连接，既有 HTTP/WebSocket/TCP 会话继续由旧 worker 服务。
- `rollback.conf`：只包含旧版本 listener。健康门禁失败时 reload 回旧版本，不主动终止已经建立的旧连接。

生成器只接受最多 64 字节的 `[A-Za-z0-9._-]` ID、无 zone 的 IPv4/IPv6 字面量和有效端口。HTTP 健康路径禁止 CR/LF/NUL，TCP 探针禁止 CR/LF/NUL；探针和强制终止理由不会写入 Nginx 配置。等价输入会先排序并规范化 JSON，再以 SHA-256 固定 plan 和三份 fixture 的内容。

fixture 不设置 `worker_shutdown_timeout`。自然排空可以超过业务 deadline；deadline 到期默认保持 `draining-old`，只有 plan 明确使用 `after-deadline` 且提供非空理由时，运行时才允许终止已记录的旧 worker。

完整状态、恢复和验收流程见 [边缘长连接排空运行手册](../../../docs/runbooks/edge-graceful-drain.md)。
