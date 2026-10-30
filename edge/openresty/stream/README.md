# OpenResty stream 配置边界

四层配置由 `agents/edge-agent/internal/l4runtime` 从 `cdnca.edge.l4/v1` 契约确定性生成。这里不接受手写 include、用户指令片段或模板变量；生产配置必须经过同一校验、摘要、`openresty -t`、原子激活与 LKG 回退流程。

当前编译器生成完整 `nginx.conf`，包含固定的 stream 审计日志、共享上游 zone、被动失败判定、TCP/UDP listener、Proxy Protocol、超时和按客户端连接上限。此目录只记录 OpenResty stream 的所有权边界，避免出现绕过 edge-agent 状态机的第二套可编辑配置源。

