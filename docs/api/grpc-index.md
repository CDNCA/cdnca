# gRPC 契约索引

protobuf source 是 package、service、RPC、message 和 field tag 的唯一事实源。
生成的 Go 文件位于 `proto/gen/go`，禁止手工修改。

<!-- verify-proto file="../../proto/agent/v1/gateway_service.proto" service="AgentGatewayService" methods="Enroll,RenewCertificate,Connect,StreamTelemetry,FetchArtifact" -->

## agent.v1.AgentGatewayService

| RPC | 方向 | 身份 | 用途 |
| --- | --- | --- | --- |
| `Enroll` | unary | 独立 server-TLS listener + 一次性 enrollment token | 提交 Agent 本地生成的 CSR 和 X25519 公钥 |
| `RenewCertificate` | unary | 节点 mTLS | 轮换短期节点证书，私钥不离开 Agent |
| `Connect` | 双向 stream | 节点 mTLS、URI SAN 绑定 node ID | Hello、心跳、部署命令和状态 |
| `StreamTelemetry` | 双向 stream | 节点 mTLS | 独立传输持久化边缘事件缓冲；不承载命令或心跳状态 |
| `FetchArtifact` | server stream | 节点 mTLS 和 deployment/artifact 绑定 | 分块获取不可变制品并支持受验证 offset 续传 |

源文件：[`gateway_service.proto`](../../proto/agent/v1/gateway_service.proto) 和
[`types.proto`](../../proto/agent/v1/types.proto)。

<!-- verify-proto file="../../proto/controlinternal/v1/control_internal.proto" service="ControlInternalService" methods="AuthorizeEnrollment,CompleteEnrollment,RenewNodeCertificate,GetNodeAuthorization,FetchArtifact" -->

## controlinternal.v1.ControlInternalService

| RPC | 调用方 | 用途 |
| --- | --- | --- |
| `AuthorizeEnrollment` | Gateway | 原子消费一次性 token 或精确重放原结果 |
| `CompleteEnrollment` | Gateway | 在 `control-api` 信任边界完成证书签发与持久化 |
| `RenewNodeCertificate` | Gateway | 验证节点和证书状态后续签 |
| `GetNodeAuthorization` | Gateway | 获取短时 Connect 授权快照 |
| `FetchArtifact` | Gateway | 验证节点、部署和制品绑定后流式返回密文/制品 |

该 service 只允许 Gateway 工作负载 mTLS 调用，不对 Agent、浏览器或插件公开。
源文件：[`control_internal.proto`](../../proto/controlinternal/v1/control_internal.proto)。

## 版本与兼容

当前 package 为 `agent.v1`、`controlinternal.v1` 和 `common.v1`。同一 major
只允许兼容新增；删除字段必须保留 tag/name，破坏性变化创建新 `.vN` package。
兼容检查使用 [`proto/baseline/cdnca.bin`](../../proto/baseline/cdnca.bin) 和固定
Buf 1.47.2。详细握手、sequence、状态机、重试和制品校验见
[`docs/protocol-contracts.md`](../protocol-contracts.md)。
