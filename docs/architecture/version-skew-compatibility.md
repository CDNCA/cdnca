# 单边升级兼容矩阵（1.0.33 ↔ 1.0.34）

> **1.0.35 起已失效（历史记录）**：兼容基线改为 1.0.35，本文为 1.0.33↔1.0.34 所做的新版侧兼容（降级能力集、会话事实重试、unscoped 遥测回退、兼容挑战、L4 回滚准备、install-node 版本门控、旧二进制写语句回放等）已在 1.0.35 删除，逐项见 `docs/releases/compat-cleanup-1.0.35.md`。下文测试名多数已不存在。1.0.35 以后版本间的单边升级仍走能力协商（不支持即拒绝并列出节点），不再为更早版本做降级。

> **节点运行模式（1.0.35 起）**：动态路由（site_runtime 9）是节点唯一模式，1.0.35 为初始基线。本文提到的 `multi_tenant_runtime`（节点多租户组合部署，能力 33 的协商路径）、单 scope 部署、site_runtime 7/8（每站 `server{}` 编译、站点对象 v1 根 `cdnca.edge.site-root/v1`）与 `siteruntimev2` 适配器**已于 1.0.35 删除**：agent 拒绝 `dynamic_routing.enabled=false`，配置里残留 `multi_tenant_runtime` 段会被严格解码拒绝；主控只产出站点对象 v2 根（`cdnca.edge.site-root/v2`，见 ADR 0009 §8.3 与 `docs/edge/site-object-v2.md`）。下文涉及这些模式的条目只作历史记录。

用户要求（10-16）：只升级主控，或者只升级某一端，都必须能正常工作，不能强制规定升级顺序。

- 旧版 = 当前线上的签名 1.0.33（提交 9150da49）。agent↔网关这一对还另外用 1.0.29（f074efdf，73 机现在跑的版本）验证过。
- 新版 = 集成分支 `task/20261016-r135-compat`，即将发布的 1.0.34。
- 原则：接收方容忍未知字段、未知能力和缺失的新字段，缺失时按旧行为处理。发送方根据对方声明的能力决定是否启用新功能，对方不支持时自动降级并给出提示。绝不能因为对方版本旧就拒绝会话或拒绝升级。旧版代码已经无法修改，所以兼容逻辑全部在新版这一侧实现。
- 打包方式：原生安装包里 control-api 和 agent-gateway 在同一个 release 里，同时切换。Helm 部署时两者可以分开升级，所以“网关↔control-api”这一对也做了兼容。
- 结论用语：兼容 = 已验证，无需修改；已修复 = 发现问题，已在新版侧修复并补了测试；限制 = 新版侧无法完全修复，需要遵守的约束写在旁边。

## 1. edge-agent ↔ agent-gateway

| 方向 | 结论 | 说明 | 测试 |
|---|---|---|---|
| 新 agent + 旧网关 | 已修复 | 新 agent 声明了 32 WAF_CRS_MODULE（还可能有 30/31/33）。旧网关遇到不认识的能力名时会丢弃整份会话事实，导致 EDGE_UPGRADE 永远不启用，节点既不能升级也不能回滚。现在 agent 在发现网关没有启用升级、也没有确认任何高于 29 的能力时，会去掉高于 29 的能力立即重连，并记录告警。这个决定 10 分钟后过期，之后重新尝试完整能力集，这样网关升级后新功能能恢复。如果降级后升级仍然没有启用，10 分钟内不会再次降级，避免反复切换。 | `tests/version-skew-e2e/run.sh`（旧网关 + 新 agent，修复前失败）；`gatewayclient.TestNewAgentFallsBackToLegacyCapabilitiesOnReleasedGateway`、`TestNewAgentKeepsFullCapabilitiesOnCandidateGateway`、`TestUnauthorizedUpgradesDoNotFlapCapabilitySets`、`TestLegacyCapabilityDecisionExpires` |
| 新 agent + 旧网关（多租户遥测） | 已修复（multi_tenant_runtime 已于 1.0.35 删除） | 开启 multi_tenant_runtime 的 agent 会请求 scoped_records，旧网关不会回显这个字段。原来 agent 会因此报 ErrPermanentProtocol，遥测管线直接退出。现在改为在这个会话里发送不带 scope 的记录；如果重试时会话格式变了，未确认的批次会按新格式重建。 | `telemetryclient.TestClientRequiresGatewayToConfirmScopedRecords`、`TestScopedBatchIsRebuiltWhenTheRetryReachesAReleasedGateway` |
| 新 agent + 旧网关（多租户部署） | 兼容（单 scope/多租户部署路径已于 1.0.35 删除） | 降级后的 hello 不声明 33，会话不协商多租户，agent 退回单 scope 的旧路径（`client.go` 中的 multiTenantEnabled）。 | e2e（四种组合） |
| 旧 agent + 新网关 | 兼容 | 旧 agent 声明的能力都在 29 以内，新网关会照常启用 EDGE_UPGRADE。新网关下发的 oneof（market_probe_command=19 等；18 原为节点插件，1.0.35 删除并 reserved）、多租户状态和 scoped 字段，都只在协商出对应能力后才会发送。 | e2e（新网关 + 旧 agent） |
| 新网关 + 未来 agent（例如 1.0.35 的能力 34） | 已修复 | 会话事实里只删除不认识的能力名，其余照常上报，EDGE_UPGRADE 保持可用；注册时也只转发认识的能力名。 | `agent-gateway.TestGatewayKeepsUpgradesForAgentWithUnknownCapability`、`TestGatewayEnrollmentDropsUnknownCapabilities` |
| 限制 | — | 网关对某些已知能力（例如 ACTIVE_CONFIG_IDENTITY、DRAIN_CONTROL）严格要求 api_version 为 v1。今后如果要改这些能力的语义，必须新增能力名，不能直接提升版本号，否则旧网关会拒绝 hello。 | — |
| 限制 | — | 如果 1.0.34 已经在多租户模式下把 scoped 部署下发到节点，在 agent 还没收到 ACK 之前就把网关回滚到 1.0.33，agent 重放的 AGENT_QUEUED 状态会被旧网关拒绝。处理办法：回滚前先关闭节点的 multi_tenant_runtime，或者等部署全部确认后再回滚。（multi_tenant_runtime 已于 1.0.35 删除，本条不再适用。） | — |

## 2. agent 注册（edge-agent ↔ 网关 ↔ control-api）

| 方向 | 结论 | 说明 | 测试 |
|---|---|---|---|
| 新 agent + 旧主控 | 已修复 | 旧 control-api 的 canonicalCapabilities 遇到不认识的能力名会返回 InvalidArgument，这个检查发生在 token 消费之前。agent 收到后，保持 request_id、CSR、token 不变，改用 1.0.33 的能力集重试一次。 | `enrollment.TestRunRetriesWithLegacyCapabilitiesAgainstReleasedControl`（修复前失败）、`TestRunDoesNotRetryOtherRejections` |
| 旧 agent + 新主控 | 兼容 | 新主控认识所有旧能力。 | — |

## 3. agent-gateway ↔ control-api（controlinternal gRPC）

原生安装包里两者一起切换，下面是 Helm 分开升级时的结论。

| 方向 | 结论 | 说明 | 测试 |
|---|---|---|---|
| 新网关 + 旧 control-api（会话事实） | 已修复 | 旧 control-api 收到包含 >29 能力的事实时会返回 InvalidArgument，原来新网关会因此拒绝该节点的每一次连接。现在只重试一次，并且只上报旧版认识的子集。其他错误仍然失败关闭。 | `agent-gateway.TestGatewayRetriesSessionFactsForReleasedControl`（修复前失败）、`TestGatewayDoesNotRetryLegacySessionFacts` |
| 新网关 + 旧 control-api（TelemetrySiteScope.configuration_scope_id） | 已修复 | 旧授权里没有 configuration_scope_id，scoped 授权校验失败，原来遥测连接全部会被拒绝。现在只要没有任何站点带 scope，就按 legacy 校验（要求每个站点都属于节点所有者），并回显 scoped_records=false。只要有站点带 scope，缺 scope 时仍然拒绝。 | `agent-gateway.TestScopedTelemetryFallsBackToUnscopedForReleasedControl` |
| 旧网关 + 新 control-api | 兼容 | 旧网关不会发送新字段，新 control-api 按缺省值处理；新增的 configuration_scope_id 对旧网关来说是未知字段，会被忽略。 | — |
| 限制 | — | 新 control-api 发出的 DeploymentCommand 如果 required_capabilities 里有旧网关不认识的能力名，旧网关会拒绝这条命令（失败关闭）。只有 Helm 先升级 control-api、并且发布用了新功能时才会出现；原生安装包不会遇到。 | — |

## 4. 数据库迁移与主控回滚

把 1.0.34 迁移后的 schema 交给 1.0.33 二进制运行，各迁移的结论如下：

| 迁移 | 内容 | 1.0.33 二进制能否在其后运行 | 依据 / 处理 |
|---|---|---|---|
| 284 node_purge | 新增 node_purged_ids；外键改为 CASCADE；保护触发器拆分 DELETE | 能 | 旧代码不会 DELETE 这些父表 |
| 285 site_supply_binding | 新增 4 张表和 1 个视图 | 能 | 只新增 |
| 286 cname_market_target | 新增可空列 target_cname，CHECK 换成等价约束 | 能 | — |
| 287 tenant_node_carriage | node_group_scope_id NOT NULL 且无默认值；唯一索引改名 | 已修复（CNAME 写入）；限制（冲突映射） | CNAME 默认值迁移（297）补了 BEFORE INSERT 默认值。旧 securitybinding 原来按索引名映射 409，索引改名后会变成 500 |
| 288 node_scope_config_state | configuration_scope_id NOT NULL，主键改为 (node, scope) | **不能**（结构性） | 旧 edgedeployment/edgepublish 会写 NULL 占位行 |
| 289 agent_queue | 新增状态 agent_queued/started | 数据库里出现新状态之前能 | 新版写入这些状态后，旧的严格白名单会失败 |
| 290 node_presence_scope_identities | 只新增表 | 能 | — |
| 291 multi_tenant_node_gate | 删除 node_config_state(node_id) 唯一索引和每节点单活部署索引 | **不能**（结构性） | 旧代码的 ON CONFLICT (node_id) 会报 42P10 |
| 292 | 只新增索引 | 能 | — |
| 293 l4_tls_passthrough | 新列有默认值；索引改名 | 能；限制 | 旧 l4forward 原来端口冲突返回 409，现在会变成 500 |
| 297 cname_target_scope_default（新增） | 补 287 的默认值 | — | down 只删除触发器 |

改号说明：CNAME 默认值迁移按集成分支头号（296 market_buyer）+1 编为 297，前置检查要求 296 的校验和。如果 M9 先合入并占用 297，本迁移改为 298，需要同步修改以下位置：两个 SQL 文件名，文件里的号码（head 校验、`migration_id`、函数和触发器后缀、ERRCODE `P29x0/P29x1`），前置检查中的上一号迁移 ID 及其 up/down 校验和，`cname_target_scope_default_297_contract_test.go` 的文件名、测试名和两个 SHA-256，以及 integration 测试中的 `version` 常量。

启动校验：control-api 1.0.33 的 serve 不检查 schema 版本，所以会带着上表的问题照常运行；执行 `migrate` 时会因为 "applied migration 284 has no matching embedded migration" 退出。license-service 遇到更高版本的 schema 会以 ErrSchemaAhead 拒绝启动。

回滚策略：
- runner 自动回滚（升级失败）：升级前先 pg_dump 并校验；回滚时先停 control-api，再 pg_restore，然后核对账本，不执行 down。代价是迁移和健康检查期间新版写入的数据会丢失。这条路径对 288/291 也安全。
- 手动回滚 1.0.34→1.0.33：runner 要求目标版本包含当前版本的全部迁移，所以会拒绝这个计划。只能二选一：还原升级前的 dump（会丢失升级后写入的数据），或者用 1.0.34 二进制逐个 migrate down。287/288/289/291/293 的 down 遇到新语义的数据时会拒绝执行，并提示从备份还原；285 的 down 会 DROP 市场绑定表，284 的 down 会丢 node_purged_ids。
- **结论**：主控一旦跨过 288/291，回滚就必须还原数据库，只换回二进制会让核心写入路径出错。待拍板的选项：① 在发布说明里写明这一点；② 把 288/291 拆成扩展和收缩两步（多租户共享节点推迟一个版本）；③ control-api serve 增加和 license-service 一样的 ErrSchemaAhead 检查，让旧二进制直接拒绝启动，而不是带病运行。
- market-service：只有 up 迁移，服务启动时自动执行；install-market.sh 回滚只换二进制，迁移要靠备份恢复。

测试：`migrations.TestOldReleaseWritersOnCurrentSchema`（逐条重放 1.0.33 的写入 SQL；CNAME 用例修复前报 23502；node_config_state 用例把 42P10 固定为已知的不兼容边界）、`TestCNAMETargetScopeDefaultMigration`。

## 5. control-api ↔ license-service

旧 license 包括 9150da49（1.0.33），以及 68 实际部署的 c37b9994，也就是 schema 63。

| 方向 | 结论 | 说明 | 测试 |
|---|---|---|---|
| 新 license + 旧主控（租约） | 已修复 | 1.0.34 在租约里新增了配额码 `market.offers.count`。1.0.33 的 `entitlement.Lease.Validate` 遇到不认识的配额码，会拒绝整份租约，entitlement 同步会一直停到重启。现在 issueLease 按安装最后一次上报的 control_version 过滤配额码（`licensing/lease_control_compat.go`）；版本未知或比要求的旧时，不下发新增的码。 | `licensing` 中的 lease_control_compat 集成测试，以 1.0.33 的配额码表作为对照 |
| 旧 license + 新主控（规则目录） | 已修复 | 065 之前的授权端下发的 CC 过滤器不带 params，HEAD 的 ExpandCCRuleGroup 会直接拒绝。现在按过滤器类型补上 065 之前的默认值；如果带了 params，仍然必须合法。 | `securitypolicy.TestExpandCCRuleGroupFollowsCatalogParameters` 及新增用例 |
| CRS 门控（按 control_version） | 兼容 | 旧主控上报的 control_version 低于 EngineCatalogControlVersion 时，不会拿到 CRS 目录。 | — |
| 升级授权、平台策略、插件目录、密钥托管 | 兼容 | 子审计逐个接口核对过，未发现严格解码，也没有新的必填字段。 | — |
| 限制 | — | license-service 遇到比自己新的 schema 时，会以 ErrSchemaAhead 拒绝启动，所以授权端回滚也要还原数据库。68 现在是 schema 63，跑的不是 1.0.33 的授权端，需要先确认部署来源。 | — |

## 6. control-api ↔ market-service（M4 的 benchmark 和能力 34 除外）

旧 market 取 5c5dacfd / d9dbeb32（85 机部署的版本，两者服务代码相同；85 上的二进制没有通过 SSH 核对）。

| 方向 | 结论 | 说明 | 测试 |
|---|---|---|---|
| 旧主控 1.0.33 + 新 market | 兼容（无交互） | 1.0.33 里没有市场客户端，market 也不会主动调用 control-api。 | — |
| 新主控 + 旧 market | 兼容 | 旧 market 解码时拒绝未知字段，所以把新版发出的每个请求体都和旧结构逐字段比对过，字段完全一致；benchmark 字段是 omitempty。control-api 解析响应用的是 json.Unmarshal，能容忍未知字段。 | — |
| marketproto grant / envelope（以后新增字段） | 已修复 | 原来 Verify/Inspect 严格解码，market 只要加一个字段，1.0.34 叶子就会丢掉所有 grant。现在 v1 容忍未知字段；签名覆盖的是原始字节，验签不受影响；叶子必须执行的新字段要通过升 schema 来表达。 | `grant.TestVerifyToleratesUnknownFieldsOfV1`、`envelope.TestInspectOpenTolerateUnknownHeaderFields`（修复前都失败） |
| siteconf | 限制 | cache、access、rate_limit 块内部是严格解码。以后扩展这些块之前，要先补能力协商，或者改成返回 unsupported_* 阻断项。 | — |

## 7. market-service ↔ license-service（M2 契约，尚未合入）

| 方向 | 结论 | 说明 |
|---|---|---|
| 新 market + 旧 license（/service/v1） | 限制 | 旧 license 没有 /service/v1。旧版的 404 和 M6 规定的“客户不存在 404”无法区分，在新版这一侧修不干净。在 license 升级到 M2 之前，**不要设置 MARKET_LICENSE_SERVICE_URL**（不设置时返回 503，按正常方式降级）。建议 M6 把“没有认证记录”改为返回 200 加 none/none，并给 license 加一个能力探测接口。 |
| license → market 回调（payments/payouts） | 兼容；限制 | 目前字段一致。market 侧是严格解码，契约里写的也是 additionalProperties:false，这和“接收方容忍未知字段”的原则冲突。因为涉及资金记账，没有放宽，需要拍板。license 以后加字段之前，必须先探测 market 的能力。 |
| M2 合入约束 | — | /service/v1 的 decode 也是严格模式，market 要根据 license 的能力决定是否发送新字段。旧 market 没有 service 监听时，目录同步应当按“暂不支持”重试，不能判定为失败。 |

## 8. 新主控（control-api + 网关）→ 旧 edge-agent 的配置和命令

| 功能 | 结论 | 说明 | 测试 |
|---|---|---|---|
| 1.0.33 存下的 CC 挑战策略（没有 6 个 PoW 字段） | 已修复 | 原来 HEAD 校验不通过，该 scope 下所有站点发布都返回 503，和节点版本无关。现在按 1.0.33 的规则编译，输出逐字节一致。这个形态现在也是“兼容挑战”，允许写入（见下条）。 | `securitypublication.TestStoredEdge133ChallengePolicyCompilesToEdge133Bytes`（1.0.33 金样本）、`TestCompatibleChallengeIsWritableAndCompilesForEdge133` |
| 新建的 PoW 挑战 | 已修复（r135-compat2） | 只有含 PoW 的策略才要求 CC 3（新 agent 声明 CC 3）。**默认按目标节点能力决定**：从系统规则目录导入 CC 规则时（`GET /v1/security-policies/catalog-rules?kind=cc[&scope_id=]`），服务该 scope 的节点（自有节点、当前承载节点、线路组节点）最新会话全部声明 CC v3 才带 PoW；否则生成兼容挑战（1.0.33 形态，无 PoW/页面有效期/网段绑定/密钥轮换，5秒盾固定 5 s），响应 `challenge_compatibility` 列出不支持的节点，编辑器提示“部分节点版本不支持 PoW，已使用兼容挑战，升级节点后可开启”，规则列表与编辑器给“兼容挑战（未启用 PoW）”标记；兼容形态允许写入（去掉了原来的写入限制）。**显式开启 PoW 的策略不静默降级**：发布到 CC v2 节点仍返回 422 `node_capability_unavailable`，写明节点、版本、缺少的功能；发布面板提供“对不支持的节点使用兼容挑战”（`compatible_challenge`），勾选且确有目标节点不支持时，本次发布对**全部目标节点**使用兼容挑战变体（不是按节点混发：一次发布只有一个 config version，canonical 文档对所有接收方逐字节相同，见下条限制），存储的策略仍带 PoW；发布结果 `compatible_challenge.node_ids` 列出原因节点，审计记录 `compatible_challenge_requested/applied/node_ids`。之后同一 scope 的每次发布按发布时钉住的摘要继续编译兼容变体（`securitypolicy.CompileBoundRuntimeSnapshot`），节点升级后不勾选再发布一次即恢复 PoW。 | `securitypolicy.TestCatalogRulesWithoutProofOfWorkAreCompatibleAndPublishable`、`TestCompileBoundRuntimeSnapshotFindsThePublishedVariant`；`edgepublish.TestCatalogCCRuleForMixedFleetPublishesTo133Node`、`TestProofOfWorkChallengeRequiresCCV3AndRefuses133Node`；集成 `securityactivation.TestProofOfWorkActivationToA133NodeNeedsTheExplicitCompatibleChallenge`（1.0.33+1.0.34 混合目标：不勾选 422 且不落库；勾选后钉住兼容变体、CC v2、审计、幂等冲突）、`edgepublish.TestPublishedCompatibleChallengeKeepsCompilingFromTheStoredPolicy`（修复前报 validate security runtime digest）；`securitypublication.TestCompatibleChallengeIsWritableAndCompilesForEdge133`；web `CompatibleChallenge.test.tsx`；e2e `run.sh` 阶段 cc |
| 限制（PoW 按节点混发） | — | “旧节点下发 v2、新节点下发 PoW”在同一次发布里做不到：一次发布一个 config version，v1 只有一个签名 artifact，v2 虽按接收方加密但要求 canonical 文档逐字节相同（`edgedeployment/validate.go`）；旧 agent 对 runtime.json/compiled.json 严格解码、release 目录有未知文件即拒，没有旁路可以只让新节点读到 PoW。显式选项因此是“整次发布用兼容挑战”。按节点混发需要把一次发布拆成多个 config version，另开任务。 | — |
| CRS 托管 WAF（32） | 已修复（提示） | 只有用户主动选择时才会用到，属于合理拒绝。现在在发布前给出可读的拒绝信息，不再等到节点那边报错。 | `edgepublish.TestManagedWAFAndSharedL4RefuseOnly133Nodes` |
| L4 TLS 透传、共享端口（v4）和附加监听（v3） | 已修复 | 门控原来读的是注册时的能力快照，原地升级到 1.0.34 的节点会被当成 v3 误拒。现在优先使用最新会话上报的能力。不使用这些功能时，产物字节不变。 | 集成测试 `TestL4TLSPassthroughPublicationNeedsL4V4`（两类节点） |
| 多租户（33，部署路径已于 1.0.35 删除）、市场拨测 oneof 19 | 兼容 | 只在协商出对应能力后才发送。旧 agent 收到未知 oneof 时会断开连接，所以必须保证不发给它，而网关已经保证了这一点。 | — |
| URL auth 产物的 activation.configuration_scope_id | 限制 | 新 control-api 总会写这个字段，旧 agent 会严格拒绝；而新 agent 又要求它非空，也没有能力位可以区分两者。目前没有生产调用方，接入生产之前必须先加能力门控。 | — |
| 反向缺口：1.0.34 agent 遇到 1.0.33 存下的旧形态挑战 | 已修复（r135-compat2） | 原来新 agent 的 ccv2.CompileSource 要求 PoW 字段，precheck 失败；engine.lua 的 validate_challenge 也拒绝，CC 运行时在 init 就起不来。现在 ccv2 识别旧形态（6 个字段全 0）按 1.0.33 规则和默认值编译，序列化不带新字段，与 1.0.33 主控/新主控 compileEdge133CCV2Challenge 逐字节一致；engine.lua 对 5 个新字段全缺省的挑战按 1.0.33 规则校验并按旧语义执行（无 PoW、页面 120 s、凭证绑定精确地址、5秒盾/无感验证带种子计算答案、密钥 30 天轮换）。无需数据迁移。同一改动也让新节点接受新主控给混合机群生成的兼容挑战。 | `ccv2.TestCompileSourceAcceptsChallengeStoredBy133`、`TestEdge133ChallengeKeepsItsOwnRules`（修复前失败）；`edge/openresty/ccv2/edge133_challenge_test.sh`（真实 OpenResty：旧形态挑战页、过早/错误答案拒绝、正确答案放行；1.0.34 挑战仍强制 PoW；修复前 init 报 invalid or duplicate policy rule）；e2e 阶段 cc（1.0.33 主控产物 → 新 agent，修复前 invalid CC v2 source） |

## 9. 节点安装包与升级 runner

| 场景 | 结论 | 说明 | 测试 |
|---|---|---|---|
| 旧主控的 install-node.sh 安装新 agent 包 | 兼容 | 旧主控只会下发旧脚本，新包可以装上。新 agent 读取旧配置时，缺少的新段（waf_engine、multi_tenant_runtime、market_probe）按旧行为处理。1.0.35 删除了节点插件段与 multi_tenant_runtime 段，带这些段的配置会被严格解码拒绝；`dynamic_routing.enabled` 必须为 true（兼容基线 1.0.35）。 | — |
| 节点从 1.0.33 原地升级到 1.0.34，以及再回滚 | 升级兼容；回滚已修复（见下条） | install.sh 会先用新二进制对旧配置执行 --check-config；agent 运行期间不改写配置；旧 agent 不读取新增的目录。回滚前 1.0.34 下发过 L4 v2 部署时，原来 1.0.33 起不来（下条）。 | — |
| 新主控的 install-node.sh 安装旧包（主控升级时不会刷新 edge-agent/latest） | 已修复 | 原来无条件写入 waf_engine，1.0.33 agent 读到后报 `unknown field "waf_engine"`，安装中断。现在按签名包版本判断，≥1.0.34 才写入。 | `TestNodeInstallerWritesWAFEngineOnlyForAgentsThatDecodeIt`（覆盖 1.0.29/1.0.33/1.0.34 等 8 个版本，可以用真实的旧二进制验证） |
| 新主控 runner 遇到旧节点 | 兼容 | Preflight 不检查节点版本。 | — |
| 新主控下发 plan/grant 给旧 agent 的 updater | 兼容 | 生成端和 updater 自 1.0.29 以来都没有改动。 | — |
| 节点从 1.0.34 回滚到 1.0.33，回滚前 1.0.34 下发过 L4 v2 部署 | 已修复（r135-compat2） | 实测范围比原来写的大：**任何** 1.0.34 写入的 L4 v2 版本，nginx.conf 都多一行 Geo preload（`geoPreloadDirectiveV2`），1.0.33 启动时 `newDiskStore`→`validateActiveRecord` 逐字节比对失败，报 corrupt L4 runtime state，整个 agent 起不来（不只是下一次 L4 部署失败）；用了 v4 的版本 runtime.json 还带 tls_passthrough/server_names/site_sockets 等字段，严格解码直接拒绝。**节点侧**：`l4runtime.PrepareLegacyRelease` 持 L4 apply 锁，L4 正在切换时拒绝；不含 1.0.34 功能的版本把 nginx.conf 改成 1.0.33 的渲染（只去掉 preload 行，1.0.34 也接受），重新封存；生效版本用了 1.0.34 功能时切到最近一个不含这些功能的已存版本；没有这样的版本时拒绝并写明功能，状态不动。1.0.34 updater 在激活 <1.0.34 的版本之前调用它（降级计划 Prepare 前与 Activate 前、健康检查失败后的自动回滚前）；被拒时降级计划失败（`L4_STATE_INCOMPATIBLE`，已 Prepare 的事务先 Abort），自动回滚不执行、保持当前版本并告警。手工回滚用 `edge-agent prepare-l4-rollback [--check]`（停 agent → 执行 → 装旧包；输出一行 JSON，不兼容/忙退出码 3）。**控制面**：`GET /v1/nodes/{id}/configuration-scopes` 新增 `capability_regressions`（各 scope 最近一次 healthy 部署需要的门控能力高于节点最新会话声明的），节点详情“承载的租户”面板顶部告警并给出处置。 | `l4runtime.TestPrepareLegacyRelease*`（含 tls_passthrough+server_names 生效状态，用拷贝自 9150da49 的 1.0.33 存储类型严格解码）；`updater.TestDowngradePlanRefusedBeforeInstaller…`、`TestAutomaticRollbackKeepsRunningVersion…`、`TestAutomaticRollbackPreparesStateFirst`、`TestV2InstallerRunsHookAtPrepareAndBeforeActivation`；cmd `TestL4LegacyReleaseHookOnlyPreparesForOlderAgents`、`TestPrepareL4RollbackCommand`；`nodepresence.TestCapabilityRegressionAfterAgentRollback` 与集成 `TestNodeConfigurationScopesShowsEveryTenantOnASharedNode`；web `NodeConfigurationScopesPanel.test.tsx`；e2e 阶段 l4-rollback（基线自己的 l4runtime：准备前 v3/v4 均拒绝，准备后均能启动并加载） |
| 限制（回滚路径覆盖） | — | 安装包脚本自身在安装失败时的回滚（root helper 内部，不经过 updater）不调用准备步骤；那条路径发生在新版本生效之前，L4 状态仍是旧版写的，不受影响。只回滚 OpenResty 或手工替换二进制、不经 updater 时，需先手工执行 `edge-agent prepare-l4-rollback`。回退到旧的已存版本只改 active.json/current，正在运行的 OpenResty 不重载，直到旧 agent 启动恢复；准备后若最终没有切换版本，下一次部署会按控制面配置重新生效。 | — |

## 10. 跨版本端到端验收

`tests/version-skew-e2e/run.sh`：从签名基线中用 git archive 取出旧网关和旧 agent，再通过 `go test -overlay` 往两棵树里注入 harness，不改动任何一棵树。每种组合都跑生产代码的 Connect 服务和 gatewayclient，并使用这一侧代码自身的生产能力集，要求最终 EDGE_UPGRADE 处于已启用状态。

| 基线 | 旧网关+旧 agent | 旧网关+新 agent | 新网关+旧 agent | 新网关+新 agent |
|---|---|---|---|---|
| 1.0.33（9150da49） | PASS | 修复前 FAIL，修复后 PASS | PASS | PASS |
| 1.0.29（f074efdf） | PASS | PASS | PASS | PASS |

阶段 cc（r135-compat2）：两边的 control-api 各自从系统目录编译同一条 CC 规则（5秒盾）得到 agent 收到的产物，两边的 agent 各自跑 release precheck（`ccv2.CompileSource` 逐字节 + `DecodeCCV2Policy`）。release 要求的 CC 版本 ≤ agent 声明时必须接受；高于声明时 agent 必须拒绝（控制面在下发前 422）。

| 产物 | 要求 | 新 agent（CC 3） | 1.0.33 agent（CC 2） |
|---|---|---|---|
| 1.0.33 主控：目录规则 | CC 2 | 修复前拒绝（invalid CC v2 source），修复后接受 | 接受 |
| 新主控：混合机群默认（兼容挑战） | CC 2 | 接受 | 接受 |
| 新主控：全 1.0.34 机群默认（PoW） | CC 3 | 接受 | 控制面拒绝下发（agent 确实跑不了） |
| 新主控：显式兼容挑战发布 | CC 2 | 接受 | 接受 |

阶段 l4-rollback（r135-compat2）：新代码写出 L4 状态（只用 v3；TLS 透传 + server_names 生效且有旧 v3 版本），准备前后各一份，用基线的 l4runtime 按 agent 启动方式打开（`NewDeploymentManager` 后 `loadActiveConfig`）：准备前两份都报 corrupt（复现），准备后都能启动并加载生效版本。

用法：`tests/version-skew-e2e/run.sh`，或 `SKEW_BASE_REF=f074efdf tests/version-skew-e2e/run.sh`；`SKEW_PAIRS="old-new"` 只跑指定组合；`SKEW_STAGES="cc l4-rollback"` 只跑指定阶段（默认 `sessions l4-rollback cc`）。
