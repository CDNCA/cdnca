# 签名密钥泄露吊销：离线签名与节点侧吊销（1.0.35）

关联：ADR-0004、`docs/runbooks/control-signer-revocation.md`、`docs/runbooks/signer-revocation-offline-root.md`（本任务的运维手册）。

## 1. 现状与缺口

- 授权端只接收**预签** checkpoint（`signercheckpointstore.Store.Import`，要求 keyset 与完整 manifest 链和授权库逐字节一致），但没有导出“待签内容”的入口，也没有离线签名工具；`signercheckpoint.Build/Sign` 只在测试里被调用。
- checkpoint 外层 TTL 两端都硬限 15 分钟（授权端 `signercheckpointstore/verify.go`、主控 `signercheckpoint.DefaultCheckpointTTL`）。离线根密钥人工签名 + 拷回 + 导入 + 主控拉取，15 分钟内走不完，过期后授权端拒绝下发（`FetchAuthenticated` 要求 fresh），新装主控永远拿不到。
- 主控只能从授权端拉取，没有文件导入。
- 节点：`gatewayclient.TrustStore`（`artifact_trust_file` = 授权端 `edge-agent/artifacts.json` ∪ 本主控 `runtime-publisher-trust.json`，见 `install-control.sh configure_control_runtime`）一次加载，验部署包、防火墙命令、回源鉴权、错误页、WAF 扩展（节点插件已在 1.0.35 删除，ADR 0007 §4.6）；无吊销，安装后不刷新。平台节点发布密钥（`cdnca-native-node-*`，离线签）不在授权 lineage keyset 里，B8 的 checkpoint 吊销对它无效。

## 2. A：checkpoint 离线签名

流程（离线根私钥只在离线机）：

1. 在线：`license-service signer-checkpoint export-request -out REQ.json`。一个只读可重复读事务里读出与 `Import` 校验完全相同的 keyset（`readCanonicalKeyset`）、`1..head` 全部 signed manifest 和最新 checkpoint（revision、摘要），写出 `cdnca.signer-revocation-checkpoint-signing-request/v1`，打印其 SHA-256。
2. 离线：`signer-offline-root sign-checkpoint -request REQ.json -key ROOT.pem -key-id ID -generation N [-ttl 720h] -out CP.json`。复用 `signercheckpoint.BuildWithOptions + Sign`，签前打印 revision、head、每条吊销（key/generation/类别/生效时间）供核对；签后用公钥自检。
3. 在线：运营端现有导入接口（`POST /operator/v1/signer-revocation-checkpoints`）或 `license-service signer-checkpoint import -in CP.json`（同 `Store.Import`，记审计）。
4. 主控照旧拉取；隔离环境可 `control-api signer-revocation import-checkpoint -in CP.json`（与 consumer 同一 `CheckpointStore.AcceptV2`，运行中的进程下一次刷新从库里对齐到 runtime）。

TTL：新增 `MaxOfflineCheckpointTTL = 31 天`，授权端验证与主控默认上限都改为它；工具默认签 30 天（720h，每月重签，到期前 7 天提醒）。取舍：外层 TTL 只防“冻结”（扣住新 checkpoint 只发旧的），而主控对 revision/前缀/keyset 回滚已做 CAS，空 LKG 时 gate 本来就放行，冻结的效果与授权端不可用相同；换来离线签名可操作。运营需在到期前重签（同 head 续期、revision+1）。

到期提醒：授权端 `GET /operator/v1/signer-revocation-checkpoints/expiry-reminder`（`signercheckpointstore.ReadExpiryReminderForOperator`）按数据库时间判定最新已导入 checkpoint：`not_imported` / `valid` / `expiring`（剩余 ≤7 天）/ `expired`，返回 `expires_at`、`remaining_days`（向上取整，过期为 0）、`head_sequence`、`level`。head 取授权端已发布吊销清单的头号（checkpoint 只覆盖其前缀）；head=0 时各级降一档（expiring info / expired、not_imported warning，否则 warning / critical）。鉴权、请求面校验与审计同 checkpoint 元数据 GET（实时 RBAC `licensing.signer_revocations.view`，审计 `signer_revocation.view`；未导入仍 200，审计记 `checkpoint_not_found`）。运营后台在 AppShell 顶部全局显示（`SignerCheckpointExpiryReminder`），级别 none 或读取失败时不显示。节点签名者信任文档（`cdnca.edge-signer-trust/v1`）只有 `issued_at`、没有有效期，不需要定期重签。

落后提醒：提醒接口另返回 `checkpoint_head_sequence`（已导入 checkpoint 覆盖的吊销头）与 `lagging`（其小于已发布吊销头）；落后时级别至少 warning，运营后台提示“已发布 N 条新吊销，但离线签名的吊销清单还没包含它们”。

暂停部署的节点：网关对每个会话都上报会话事实；主控对当前证书、管理状态 active/draining/pending 的节点都落库 `node_session_capabilities`，部署暂停时不返回回执（不开升级命令），因此 `ActiveNodes` 看到的是节点实际运行的 agent 能力。

工具 `services/license-service/cmd/signer-offline-root`（复用 license 的 checkpoint wire 包，保证与 `Import` 同一格式）：`keygen`（PKCS#8 PEM 私钥 0600 + 公钥信任文件，同时打印授权端 `LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_TRUST_JSON` 和主控安装参数）、`sign-checkpoint`、`verify-checkpoint`、`sign-edge-trust`、`verify-edge-trust`。

## 3. B：节点侧签名者吊销

**文档**：`cdnca.edge-signer-trust/v1`（`libs/entitlement/edgesignertrust`），离线根签名，与 checkpoint 同一把根、同一个主控 pin（`SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_*`）：

- `revision`（严格递增）、`issued_at`；
- `trusted_keys`：当前平台发布公钥（同 artifacts.json 条目：`key_id` + `public_key_pem`），用于轮换后刷新信任；
- `revoked_keys`：`key_id` + 公钥 SPKI SHA-256 指纹（任一匹配即拒）、`revoked_at`、`reason`。

**发布**：授权端 `POST /operator/v1/edge-signer-trust` 收运营上传的离线签名文件（验签、revision 严格 +1、不丢吊销、追加表 `edge_signer_trust_documents`（license 迁移 091 占位）、审计 `system.signer_trust.publish`），`GET /operator/v1/edge-signer-trust/draft` 生成待签草稿，`GET /public/v1/edge-signer-trust` 公开返回最新版字节（文档自带离线根签名，无需鉴权）。

**主控**：新 worker 每 10 分钟从授权端 `/public/v1/edge-signer-trust` 拉取；用 offline root pin 验签，只接受更高 revision（同 revision 同字节为重放），写追加表（迁移 331，守卫 330）；拉取失败沿用 LKG；拒绝原因记审计并告警日志。另提供 `control-api signer-revocation import-edge-trust -in FILE`。主控同时用最新文档刷新自己的 `downloads/edge-agent/artifacts.json`（∪ trusted − revoked），保证之后新装/重装节点拿到的就是刷新后的信任。

**下发**：主控把离线文档原样放进节点包（`cdnca.edge-signer-trust-bundle/v1`：node_id、文档字节、签发时间），用节点已信任的本主控边缘发布密钥签名（与部署包同一签名器），经 NATS → gateway → agent，agent 回执 applied revision；主控记录每节点已应用 revision，节点上线、文档更新时重发直到回执一致。协议号：能力 `CAPABILITY_NAME_EDGE_SIGNER_TRUST = 38`，`ConnectResponse.edge_signer_trust_bundle = 21`，`ConnectRequest.edge_signer_trust_receipt = 18`。NATS 流 `EDGE_SIGNER_TRUST_COMMANDS/STATUS` 由 gateway 自建（`libs/edgeconfig/signertrust`），投递语义：每节点 durable、只留最新、回执持久化后才 ack。只给最新会话声明了能力 38 的节点发（`edgesignertrustsync.ActiveNodes`），其余按变化记告警；部署被授权快照暂停的节点也下发。

**节点**：

- 验主控签名（用应用前的信任，已吊销的主控 key 签的包也拒），解码文档（结构校验；节点没有离线根 pin，信任边界与站点配置相同：节点本来就信任主控发布密钥），revision 单调（低于已应用拒绝，同 revision 同字节幂等），持久化到 `<journal_dir>/signer-trust/state.json`。
- `TrustStore` 加覆盖层：有效信任 = 本地 artifacts.json ∪ `trusted_keys` − `revoked_keys`（按 key_id 或指纹）。部署包、防火墙/回源/错误页已经按次查 `trust.key`，覆盖层立即生效；WAF 扩展改为验签时查覆盖层，已安装扩展的签名者被吊销时下次 Prepare 视为签名无效（降级为自研检测并上报 `signature_invalid`），不会继续加载。
- 启动时先恢复覆盖层再装配其它组件。
- 安装器：重跑（升级/修复）时不再沿用已有 `artifacts.json`，重新从主控下载；若存在 agent 的 `signer-trust/state.json`，按其吊销列表拒绝以被吊销 key 签的原生包。

**失败语义**：拉取/下发失败保留 LKG（fail-open 于网络）；已知吊销永不因失败解除（fail-closed 于已知吊销）；不影响已在跑的流量（已激活发布不重新验签）。

**验收**：`tests/signer-revocation-e2e/run.sh`（授权端↔主控 checkpoint）；`tests/signer-trust-push-e2e/run.sh`（授权端下载源 → 主控 → NATS → agent-gateway → edge-agent，离线工具签发，覆盖吊销下发/回执/下载信任刷新、无能力节点不下发、agent 重启恢复、部署暂停仍下发、指纹吊销轮换、下载源回退被拒）。替身：节点行与 `node_session_capabilities` 由测试按 gateway 上报的会话能力写入，网关的控制面授权是固定替身。
