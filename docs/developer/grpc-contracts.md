# gRPC 契约索引

本文只解释协议边界，不重复定义字段。service、method、message、枚举和字段 tag 均以 [`proto/`](../../proto/) 为唯一事实源；下面的隐藏标记由契约检查器核对，名称漂移会直接失败。

<!-- contract-doc:proto file="../../proto/agent/v1/gateway_service.proto" service="AgentGatewayService" methods="Enroll,RenewCertificate,Connect,StreamTelemetry,FetchArtifact" messages="EnrollRequest,EnrollResponse,RenewCertificateRequest,RenewCertificateResponse,ConnectRequest,ConnectResponse,StreamTelemetryRequest,StreamTelemetryResponse,FetchArtifactRequest,FetchArtifactResponse" -->

## AgentGatewayService

`agent.v1.AgentGatewayService` 是 Agent mTLS 数据面入口。`Enroll` 和 `RenewCertificate` 处理节点证书生命周期，`Connect` 承载双向状态与命令流，`FetchArtifact` 以服务端流传输受摘要和签名约束的制品。消息定义位于 [`types.proto`](../../proto/agent/v1/types.proto)，行为约束见 [`docs/protocol-contracts.md`](../protocol-contracts.md)。

### 升级状态持久确认

`EDGE_UPGRADE` v1（能力编号 22）保持原有升级命令与状态协议。能力 23、24、25 都是独立协商的渐进增强，缺少依赖时不得广告或接受，不能改变能力 22 的兼容语义：

- `EDGE_UPGRADE_STATUS_PUBACK` v1（能力编号 23）依赖能力 22。仅当双方协商能力 23 时，`UpgradeStatusAck.published_stream` 和 `published_sequence` 才必须分别等于 JetStream `AGENT_DEPLOYMENT_STATUS` 及其非零发布序列。
- `EDGE_UPGRADE_STATUS_ACK_RECEIPT` v1（能力编号 24）依赖能力 22 和 23，只增加 `UpgradeStatusAckReceipt` 的双向持久确认，不隐含安装器能力。`ack_sha256` 必须严格等于 `SHA-256(proto.MarshalOptions{Deterministic:true}.Marshal(exact UpgradeStatusAck payload))`；摘要对象不包含 `ConnectResponse` envelope。验收方必须在计算摘要前拒绝 payload 的 protobuf unknown fields。
- `EDGE_UPGRADE_PREPARE_ACTIVATE` v1（能力编号 25）只依赖能力 22。Agent 仅在安装器实现 `InstallerV2`、`ProtocolVersion() == 2`，并且不存在 `Install` 或 `Query` 兼容回退时广告该能力。

能力组合固定为四类：基础兼容链路只协商 22；新版 Gateway 分发 prepare/activate 命令时协商 22+25；精确状态确认链路协商 22+23+24；完整新版链路协商 22+23+24+25。新 Agent 连接旧 Gateway、旧 Agent 连接新 Gateway以及双方能力集合不完整时，必须回退到双方共同支持的上述完整组合，不得把 24 或 25 当作对方已支持。

协商 23+24 后，Gateway 只有在取得精确 JetStream PubAck 并持久保存对应 `UpgradeStatusAck` 后才发送确认。Agent 必须先持久保存且核对 `UpgradeStatusAckReceipt`，再收敛状态 outbox；其确认丢失时双方使用相同 `ack_sha256`、stream 和 sequence 重放，不得重新发布状态。Gateway 只在收到并持久处理 Agent 的确认后清理自己的确认记录。

<!-- contract-doc:proto file="../../proto/controlinternal/v1/control_internal.proto" service="ControlInternalService" methods="AuthorizeEnrollment,CompleteEnrollment,RenewNodeCertificate,GetNodeAuthorization,FetchArtifact" messages="AuthorizeEnrollmentRequest,AuthorizeEnrollmentResponse,CompleteEnrollmentRequest,CompleteEnrollmentResponse,RenewNodeCertificateRequest,RenewNodeCertificateResponse,GetNodeAuthorizationRequest,GetNodeAuthorizationResponse,FetchArtifactRequest,FetchArtifactResponse" -->

## ControlInternalService

`controlinternal.v1.ControlInternalService` 只供 `agent-gateway` 与 `control-api` 的内部 mTLS 链路使用，不是插件或租户公开 API。它负责注册授权/完成、续签授权状态和制品读取；外部集成不得直接调用。

## 版本与弃用

当前包为 `agent.v1`、`controlinternal.v1` 和 `common.v1`。同一大版本只允许兼容新增；破坏性变化必须创建新的 `.vN` package。弃用符号必须同时使用 protobuf `deprecated = true` 和紧邻的 `Deprecated: since=vN replacement=Symbol` 注释，禁止复用删除字段 tag。
