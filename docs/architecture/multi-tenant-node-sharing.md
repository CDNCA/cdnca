# 多租户共用节点方案

> 已于 1.0.35 删除：动态路由（site_runtime 9）为节点唯一模式，1.0.35 为初始基线；本文涉及的 节点端多份共存（`multi_tenant_runtime`、单 scope 部署、composed runtime）与 `siteruntimev2`；多租户共用节点改由动态路由按站点对象承载 已删除，以下保留原文作历史记录。

状态：**已定案，2026-10-15 用户确认采用方案 (b)「节点端多份共存」**，第 0、1 期一起做，不顺延。租户配置出错时，停在该租户上次成功的版本并通知它，同一节点上的其他租户不受影响。迁移号：第 0 期 287，第 1 期 288 起（退款不需要迁移）。

## 1. 结论先说

- **问题不只在市场。** 系统给每个用户各建一个租户 scope（`identity/user_store.go:142`），节点却建在 platform scope，而且很多环节都要求“节点和站点在同一个 scope”或“一个节点只属于一个租户”。所以只要有第二个用户把站点放到同一批平台节点上，就会出问题。线上 73 现在 0 个租户、0 个站点，还没触发。
- **有一处只有一个租户也会坏：** 证书和验证密钥（secret rollout）要求 `nodes.scope_id` 必须等于租户 scope，没有 platform 例外。所以租户站点的证书根本发不到平台节点上（第 2.2 节第 3 个测试）。
- **采用方案 (b)「节点端多份共存」**，分两期：第 0 期先修“平台节点承载租户资源”的那些外键和校验，单租户现在就需要；第 1 期让节点按（节点，租户）分别部署、回滚和上报，再在节点上拼成一份 nginx 配置。理由见第 6 节。
- 方案 (a)「控制面按节点组汇总」工作量小，最初推荐的是它。但它要在平台汇总层把按租户的语义重新拆回去，长期越来越难改；租户多了还会碰到体积上限，最后还是要走到按租户传输。用户按长期考虑改选了 (b)。

## 2. 现状

### 2.1 卡点清单

| 环节 | 代码 / 迁移 | 现在的规则 | 后果 |
|---|---|---|---|
| 配置认领 | `edgepublish/target.go` validateEligibleNodes 100-149、claimEligibleNodes 151-207；`edgedeployment/store.go` 约 414 行 | `node_config_state` 以 node_id 为主键，只存一个 `configuration_scope_id`，第一个发布的租户独占节点 | 第二个租户发布到同一节点被拒（测试 2） |
| 证书 / 验证密钥 | `edgedeployment/secret_rollout.go` lockSecretRolloutNode 1259 起 | `nodes.scope_id` 必须等于租户 scope，没有 platform 例外 | 租户证书发不到任何平台节点，单租户也一样（测试 3） |
| 清缓存 | `cachecontrol/operation.go:83`；迁移 034 外键 `cache_operation_nodes (scope_id,node_id)→nodes(scope_id,id)`；`loadOperation` 约 300 行 | 节点必须在租户 scope | 平台节点上没法清缓存（测试 1） |
| ACL / CC 激活 | `securitybinding/store.go:343`；迁移 031 外键 `security_policy_publication_targets (tenant_scope_id,node_id)→nodes(scope_id,id)`，以及“每个节点只能有一个未结束的发布”的唯一索引（031:131） | 节点必须在租户 scope；一个节点同一时间只能有一个安全发布 | 平台节点上没法激活；多个租户还会互相排队 |
| CNAME 分配 | `cnameallocation/store.go:337-382` | `line_group.tenant_scope_id = subscription.tenant_scope_id` | 引用平台节点组的租户站点拿不到解析目标 |
| 目标快照 / 节点组 | 迁移 074、173、241：`edge_target_snapshot_nodes`、`node_line_endpoints` 等的外键是 `(tenant_scope_id,node_id)→nodes(scope_id,id)`；`topology_snapshot.go:508` | 平台节点只能进 platform scope 的分组 | 租户不能用快照指向平台节点组，只能用显式 node_ids |
| 其他带租户 scope 的节点外键 | 063 `acme_http01_overlay_targets`、111 `firewall_command_outbox`、127 `cc_coordination_*`、139 `l4_*_drain_*`、158 `ja4_block_edge_receipt_queue_158` | 同样要求节点在租户 scope | 同类问题，修复方法相同 |
| 部署通道 | 046 `node_deployments_one_active_per_node_idx`；proto `DeploymentCommand.configuration_scope_id` 单值（types.proto:399） | 一个节点同一时间只有一个进行中的部署，命令只带一个 scope | 方案 (b) 必须改，方案 (a) 不用改 |
| 节点端 | `deployment/storage.go` 只有一个 `current` 和一个 `activation.lock`；site runtime v2 文档只有一个 `configuration_scope_id`，`gatewayclient/site_runtime.go:59` 校验它必须等于命令里的 scope；`siteruntimev2/compiler.go:502` 用计划的 scope 当证书的 TenantScopeID；`cachetask`、`urlauth`、遥测清单（`edgepublish/site_capture_policy.go:117`）都只认一个租户 | 节点同一时间只跑一个租户的配置 | 两种方案都要改，(b) 改得多得多 |

已经满足、不用改的：
- 域名在所有租户之间唯一（迁移 148 的触发器），不会出现两个租户抢同一个 `server_name`。
- L4 转发按协议加端口全局唯一（007）。
- 节点证书、节点流量策略、隔离、监控覆盖（036、181、182、279）按节点自己的 scope 走，本来就对。
- 节点监控按节点下发，跟租户无关（节点插件已在 1.0.35 删除，ADR 0007 §4.6）。

还缺一个检查：同一个节点、同一个 HTTP 端口上，一个租户用明文、另一个租户用 TLS，nginx 无法同时监听。现在只在单个租户内部检查。两种方案都要在控制面加上跨租户检查。

### 2.2 复现测试（都按现状通过，即证实了缺陷）

1. `services/control-api/internal/cachecontrol/platform_node_scope_integration_test.go`：平台节点上租户清缓存返回 ErrNotFound，外键也会拒绝写入。目标行为的测试先 Skip。
2. `services/control-api/internal/edgepublish/multi_tenant_platform_node_integration_test.go`：第二个租户发布到已被认领的平台节点被拒，而且不会部分认领；发到空闲节点可以。
3. `services/control-api/internal/edgedeployment/platform_node_secret_rollout_integration_test.go`：租户证书发到平台节点返回 ErrConfigurationScopeConflict，一个产物都不生成；同一请求发到租户自己 scope 的节点可以。

## 3. 方案 (a)：控制面按节点组汇总

**做法**：configuration scope 改为 platform。按节点组（平台 line group）各出一份汇总配置，里面是所有指向这个节点组的租户站点和 L4。节点同一时间仍然只跑一份配置。

- **发布与版本控制**：每个租户的 `edge_configuration_scopes.source_revision` 照旧推进。汇总发布额外记录两样东西：每个租户各自的 source_revision，以及每个租户片段的摘要。某个租户有变更时，只重新汇总它用到的节点组。autopublish 原来按租户入队，改为按节点组入队，并加一个合并窗口，把短时间内的多个变更合成一次发布。
- **授权与计费**：仍然按租户逐个检查 entitlement。未授权或欠费的租户直接从汇总里剔除（等于下线），不影响其他租户。
- **文档**：site runtime 文档升一个版本（能力 SITE_RUNTIME api_version 5），每个站点带上 `tenant_id` / `tenant_scope_id`，L4 的 `L4StreamRuntimeV2` 本来就有 TenantID。`siteruntimev2/compiler.go:502` 改为按站点的租户取证书。遥测清单、`cachetask` 清单、`urlauth` 绑定也都改为按站点的租户。
- **租户隔离**：
  1. 控制面汇总之前，先对每个租户片段单独校验（复用 edgepublish 现有的 v2 构建和校验），再做跨租户冲突检查（同端口明文和 TLS 混用等）。没通过的租户停在它上一次成功的片段，并给这个租户报错，不影响其他租户。
  2. 节点预检（`nginx -t`）失败时，节点照旧整份回滚到上一版。控制面把本次有变更的租户片段退回上一个成功的版本，重新发布。一次汇总只含一个租户的变更时能精确定位；合并了多个变更时用二分法找出是哪个租户。
  3. 所有租户共用一个 nginx master，运行时崩溃会影响整个节点。这是两种方案都有的剩余风险，(b) 也一样。
- **证书与密钥**：secret rollout 的 configuration scope 改为 platform，鉴权仍按证书所属的租户（certificatepublish 现在就是按租户授权）。节点端 certstore 本来就按（租户 scope、站点、版本）存，不用改。
- **协议与节点端**：部署命令、ActiveConfigIdentity、部署状态机、`activation.lock`、`current` 链接都不变。节点端要改的只有：解析新版文档；编译器、cachetask、urlauth、遥测改为按站点的租户。
- **能力门控**：节点声明 SITE_RUNTIME v5 后才收汇总版；没声明的节点继续走现在的单租户发布。
- **迁移（3 个）**：287 是第 0 期的外键修改（见 6.1）；288 新建汇总发布表（汇总发布、各租户的 source_revision、片段摘要、节点组到节点的对应）；289 新建承载关系表 `node_site_carriage`，记录每个节点当前承载哪些租户的哪些站点，供清缓存和激活时挑节点。
- **兼容**：现有的单租户发布（租户 scope 认领节点）继续能用。节点升级到 v5 后由平台汇总接管：第一次汇总发布时，把 `node_config_state.configuration_scope_id` 从租户 scope 改为 platform，一次性完成并记审计。线上 0 个租户，没有存量要迁移。
- **代价**：任何一个租户变更，都要给整个节点组重发整份汇总、整份 reload。租户多了以后文档会变大（上限 16MB，`site_runtime_v2.go:36`）；节点上的部署是串行的，所以需要合并窗口。第 2 期改为按片段传输来缓解。
- **工作量**：第 1 期约 5–7 人周（粗估）。

## 4. 方案 (b)：节点端多份共存

**做法**：保留按租户发布、按租户的 configuration scope。节点同时持有多个租户各自的当前版本，各自部署、各自回滚，最后在节点上拼成一份 nginx.conf。

- **控制面**：
  - `node_config_state` 主键改为（node_id, configuration_scope_id）。
  - edgestatus 的 `updateRunningConfig`、edgedeployment 的认领和部署都改为按（节点、scope）。
  - `node_deployments` 从“每个节点只有一个进行中的部署”改为“每个节点每个 scope 一个”。
  - 证书、清缓存、安全发布的外键同第 0 期。
- **协议**：Hello、Heartbeat、DeploymentStatus 里的 current/previous identity 改为按 scope 的列表（新字段，加能力门控）；DeploymentCommand 现有的 scope 字段可以直接用；agent-gateway 的 `validation.go` 跟着改。
- **节点端**：
  - deployment storage 改为每个 scope 各有一组 current/previous、pointers 和回滚记录；`activation.lock` 仍然全局串行。
  - 新增一个组合器，把各 scope 的计划拼成一份 nginx.conf，拼的时候做端口明文/TLS 冲突检查。
  - 某个 scope 的新版本预检失败时，只回滚这个 scope，其他 scope 保持不动。
  - site runtime、cachetask、urlauth、遥测、challenge、cachefreshness、firewall、l4runtime 等模块里的“当前租户”状态，都要改成按 scope 的集合；`agents/edge-agent/internal` 下引用 scope/tenant 的包约有 20 个。
- **隔离**：最好。发布、回滚、审计、授权都按租户进行，一个租户的坏版本只回滚它自己。
- **迁移（约 5 个）**：287 第 0 期外键；288 `node_config_state` 改主键并核对相关外键（引用 configuration_scope_id 的迁移有 20 个）；289 `node_deployments` 唯一性改为按 scope；290 状态上报和身份表改为按 scope；291 `node_site_carriage`。
- **兼容**：旧节点只能承载一个 scope，控制面要区分新旧节点；新旧版本混跑的那段时间最复杂。
- **风险**：要改的是节点部署状态机、身份上报和回滚，正是最核心、最难测的路径；改动面最大，对节点升级顺序也最敏感。
- **工作量**：约 10–13 人周（粗估）。

## 5. 对比

| | (a) 控制面汇总 | (b) 节点端共存 |
|---|---|---|
| 节点端状态机 | 不变 | 重写（按 scope 部署、回滚、身份上报） |
| 协议 | 只改文档版本（能力 v5） | Hello/Heartbeat/DeploymentStatus 的 identity 改为列表 |
| 节点端模块 | 编译器 + cachetask/urlauth/遥测按站点取租户 | 约 20 个包改为按 scope |
| 迁移 | 3 个（287–289） | 约 5 个（287–291） |
| 坏配置的隔离 | 控制面预校验 + 停在上次成功片段 + 节点失败后按租户回退 | 节点上只回滚出问题的租户 |
| 单个租户变更的成本 | 整个节点组重发、整份 reload（第 2 期可缓解） | 只发这个租户的那一份 |
| 审计 / 授权边界 | 汇总发布记录每个租户的版本；鉴权仍按租户 | 天然按租户 |
| 升级顺序要求 | control-api → 网关 → 节点 → 打开汇总开关 | 同左，但新旧节点要长期分开处理 |
| 主要风险 | 规模变大后文档体积和 reload 频率 | 节点核心路径大改 |
| 粗估工作量 | 第 1 期 5–7 人周 | 10–13 人周 |

两种方案共用一个 nginx master，运行时都会互相影响；区别只在于“发布时出错”能隔离到什么程度。

**节点上的数据量和租户之间的信息隔离，两种方案一样。** 节点要服务某个租户的站点，就必须持有这个站点的配置、证书和回源地址。(a) 是放进一份汇总文档，(b) 是分成多份各自保存，节点上的总量相同，能接触到的数据也相同。两种方案都只把节点组里实际承载的站点发给这个节点，不会把平台上所有租户都塞进来。租户之间互相看不到，靠的是这几条，跟选哪个方案无关：
- 控制面和 API 层按租户鉴权：租户只能读写自己的站点、日志和清缓存任务。
- 节点对外：未知 Host 和按 IP 访问一律回 421（拨测分支 9937cc52 的默认 server），不会被路由到别的租户的站点。
- 缓存命名空间按（租户、站点、配置版本）隔开（`edgeconfig.CacheNamespaceID`）。遥测按站点归属到对应租户；方案 (a) 下改为按站点取租户。
- 产物按节点各自的接收公钥加密（HPKE），证书私钥只发给承载这个站点的节点。

节点本身被攻破的话，它承载的所有租户的数据都会暴露，这在两种方案下都一样。真正的差别在第 3、4 节：运维复杂度、节点端改动的风险，以及单个租户变更时要重发多少数据。

## 6. 定案：方案 (b)

理由（按长期考虑）：
- 系统里的版本号、权限、计费、autopublish、审计、安全策略的金丝雀发布，全都以租户为单位。(b) 原样保留这些，(a) 要在汇总层重新拆回租户，功能越加越难改。
- 用户选定的出错处理是“停在上次成功的版本、只影响该租户”。(b) 天然按租户各自回滚；(a) 合并了多个变更时要二分查找。
- (b) 每次只下发变化的那个租户；(a) 每次重发整份汇总，长期会碰到 16MB 上限。
- (b) 最大的风险原本是新旧节点混跑；现在测试机整体重装、没有存量节点，这一条基本不存在。

第 3 节方案 (a) 的描述保留，作为对照。

### 6.1 第 0 期（两种方案都要做，单租户现在就需要）：迁移 287

- **证书与密钥**：secret rollout 允许平台节点承载租户的证书和密钥，条件是该节点在这个租户某个站点引用的节点组里（`lockSecretRolloutNode` 去掉 `nodes.scope_id` 必须等于租户 scope 的要求，改为检查承载关系）。
- **外键**：`cache_operation_nodes`、`security_policy_publication_targets`、`acme_http01_overlay_targets`、`firewall_command_outbox`、`cc_coordination_*`、`l4_*_drain_*`、`ja4_block_edge_receipt_queue_158` 的节点外键改为直接引用 `nodes(id)`；节点属于哪个租户，改用承载关系校验，校验写在 Go 代码里，再加一层触发器兜底。
- **安全发布**：“每个节点只能有一个未结束的发布”改为“每个节点每个租户一个”，不同租户不再互相排队。
- **CNAME**：允许租户站点引用平台节点组（`cnameallocation/store.go` 的 join 改为认 platform 节点组）。
- **跨租户冲突**：加上同一节点、同一端口明文与 TLS 混用的检查。
- **承载关系**：第 0 期先用“节点在租户站点引用的节点组的服务端点里”判断，不依赖发布模型；第 1 期改用 `node_site_carriage`。
- **测试**：三个复现测试改写为目标行为。

### 6.2 第 1 期：按（节点，租户）部署（迁移 288 起）+ 节点多租户组合 + 能力门控

- **能力**：新增 `CAPABILITY_NAME_MULTI_TENANT_RUNTIME = 33`（30 作废 reserved（原节点插件，1.0.35 删除），31/32 已被 MARKET_PROBE / WAF CRS 占用）。节点声明了这个能力，控制面才允许第二个租户认领它；没声明的节点仍按“一个节点一个租户”处理。
- **控制面**：
  - `node_config_state` 改为每个（node_id, configuration_scope_id）一行；`node_deployments` 的唯一性改为每个（节点，scope）只有一个进行中的部署。
  - edgepublish 的认领、edgedeployment 的部署和回滚、edgestatus 的运行状态，都按（节点，scope）处理。
  - 新增按（节点，scope）的“上次成功版本”，节点上某个租户的新版本失败时，只回滚这个租户。
  - `node_site_carriage`（视图或表）：从各租户的当前版本得出“节点当前承载哪些站点”，供清缓存、激活、状态查询使用。第 0 期的承载函数改成基于它。
- **协议**：Hello、Heartbeat、DeploymentStatus 新增按 scope 的身份列表 `repeated ScopedConfigIdentity`。旧的单值字段保留，只在单租户节点上使用。DeploymentCommand 现有的 `configuration_scope_id` 必填。网关 `validation.go` 按能力校验。
- **节点端**：
  - deployment storage 改为每个 scope 各自一组 `current` / `previous`、pointers 和回滚记录；`activation.lock` 仍然全局串行。
  - site runtime 的运行时适配器改为按 scope 保存当前计划；新增组合器，把各 scope 的计划拼成一份 nginx.conf。组合时做跨租户的端口明文/TLS 冲突检查，并给各 scope 生成互不冲突的 upstream / zone 名称。
  - 某个 scope 的新版本失败（预检或健康检查）时，只回滚这个 scope 的指针，其他 scope 保持当前版本，再重新组合。
  - cachetask、urlauth、遥测、challenge、cachefreshness、firewall action、L4 等模块里的“当前租户”状态，都改成按 scope 的集合。
- **测试重点**：组合器做快照测试，并在 openresty 上跑 `nginx -t`；多 scope 回滚只影响出问题的租户；身份上报和网关校验做往返测试。

#### 6.2.1 控制面落地（迁移 288–291）

| 迁移 | 内容 |
|---|---|
| 288 | `node_config_state` 主键改为（node, scope），去掉 NULL 占位行；`node_deployments` 新增 `configuration_scope_id`，随 rollout 自动填写，写入后不可修改。隔离改为节点级：只绑定节点和它的属主 scope。 |
| 289 | 部署状态新增 `agent_queued` 和 `started`。所有配置命令都带 `configuration_scope_id`，包括 ROLLBACK 和证书。SUPERSEDED 不映射：控制面每个（节点，scope）同时只有一个进行中的部署，不会出现被替换的情况。 |
| 290 | 新表 `node_presence_scope_identities`：按心跳里的 `scoped_config_identities`，每个（节点，scope）记录 current、previous 和最近一次应用结果。 |
| 291 | 打开门控。删除过渡索引 `node_config_state_single_scope_288_idx`。部署新增 `queued_per_scope`：节点声明能力 33 时写 true，这类部署每个（节点，scope）只能有一个进行中；其他部署仍是每个节点一个。对账门控和流量同步触发器改为按（节点，scope）判断。 |

- **能力来源**：取 `node_session_capabilities` 里该节点最新一次会话的快照，必须同时声明 MULTI_TENANT_RUNTIME v1 和 ACTIVE_CONFIG_IDENTITY v1（`edgedeployment.NodeServesSeveralScopes`）。数据库读不了能力快照，所以“只有能力 33 的节点可以出现第二个 scope”这条规则只在认领路径里检查：`validateEligibleNodes`、`createNodeDeployment`、证书下发。
- **组合约束**：端口能不能共用，规则只写在 `edgeconfig.FindPortConflicts` 一处。同一租户内和跨租户用同一套规则。用到它的地方有三个：控制面保存时、控制面发布时（`edgepublish.validateCrossScopeComposition`），以及节点组合器（由 mtnode 接入）。发布前，会把新快照和目标节点上其他租户的配置逐一比较；其他租户的配置包括当前版本和还没结束的 apply。只有下面几种情况会拒绝发布（`ErrCrossScopeConflict`，HTTP 409 `node_scope_conflict`）：
  - 相同域名，不区分大小写；
  - 相同站点；
  - 普通 TCP/UDP 的 L4 用了同一协议、同一端口；
  - 普通 TCP 的 L4 和另一租户的明文网站用了同一端口，两者无法区分；
  - 普通 UDP 的 L4 和另一租户 TLS 网站的 HTTP/3 用了同一端口，也无法区分；
  - 同一 TCP 端口上，两个 TLS 使用方（TLS L4 透传，或 TLS 网站）声明了同一个名字：可能是两个 L4 的 `server_names` 重复，也可能是 L4 的 SNI 和对方 TLS 网站的域名重复。名字按完全相同比较：通配和通配相同算冲突；`*.a.com` 和 `x.a.com` 可以共存，节点端精确名优先。

  下面这些情况是正常业务，必须允许，由节点组合：
  - 同一端口一个租户明文、另一个 TLS；
  - 多个租户都有 L4（端口不同，或 TCP/UDP 同号）；
  - 多个租户都有 CC v2；
  - TLS 网站和普通 TCP 的 L4 同端口，用 `ssl_preread` 判断是否为 TLS 来分流；
  - 多个 TLS L4 透传（`tls_passthrough` + `server_names`；`server_names` 可以是精确名，也可以是只在最左一级通配的 `*.example.com`）在同一端口按 SNI 分流。这个端口还可以同时给 TLS 网站、明文网站用，以及最多一条普通 TCP 的 L4 用。非 TLS 的连接交给普通 TCP 那条；SNI 匹配不上的连接直接关闭。

  以下发布要求 agent 声明 `tcp`/`udp` 能力 v4：用了 TLS 透传的；L4 和自己的网站用同一端口的；两条 L4 用同一个 socket 的。旧 agent 会在能力检查这一步拒收。

  错误原因只写节点和违反的规则，不写对方租户。
- **遥测授权**：每条站点绑定都带发布该配置版本的 `configuration_scope_id`。节点有多个 scope 时，授权快照的顶层 tenant 留空，站点绑定包含节点上所有 scope 的站点，每条带各自的 tenant 和 scope；仍按（站点，配置版本）排序，总数上限不变。控制面转换时要求每个 scope 只对应一个 tenant。网关的按 scope 会话（scoped_records）逐条按记录的 scope 取 tenant 校验；旧式会话需要顶层 tenant，在这类节点上仍然拒绝遥测。
- **租户之间的故障隔离**：
  - 多 scope 节点（只允许 platform 节点，授权时会再检查一次）上，如果某个 scope 的配置版本读不出来、是平台自身的 scope 没有租户，或者放不进站点上限，就只把这个 scope 从遥测授权里剔除。节点照常连接，其他 scope 不受影响。被剔除的 scope 会记一条告警日志，管理端“承载的租户”里显示“遥测已隔离”及原因（`telemetry_excluded`：`invalid_config_version` / `platform_scope` / `telemetry_site_limit`）。
  - 每个 scope 各自最多读 `MaxTelemetrySiteScopes` 个版本。站点总数超出上限时，按站点数从少到多纳入 scope，放不下的整个剔除。
  - 发布时做跨租户比较，遇到别的租户的配置读不出来就跳过并记日志，不阻止本次发布，节点的组合预检仍是最后一道关。
  - 单 scope 节点保持原来的 fail-closed：一旦出现异常，整个授权直接失败。
- **两种配置格式的遥测**：遥测授权同时认 config-source/v1 和 site-runtime/v2 两种快照，同一站点走哪种格式发布，得到的绑定都一样。其他 schema 一律拒绝，并在日志里写明原因。
  - v2 的 canonical 文档不带站点的套餐归属，这个信息只放在按节点加密的 telemetry manifest 里。因此 v2 发布时，在同一个事务里把每个站点的套餐写进 `config_version_telemetry_site_bindings`（迁移 295，只增不改）。写入用的数据和 manifest 是同一份 packageSubscriptions，恢复中的站点也包括在内。
  - 迁移 295 之前就发布了的 v2 版本，按 114 加上文档里的 `package_limits` 尽量补齐套餐。补不齐的站点不带套餐，记一条告警，不让节点授权失败。
  - 只要表里还有绑定，就不允许回滚 295。
- **流量策略**（已知缺口）：`node_traffic_sync_tasks` 用策略的 scope（节点属主）去重新应用“该 scope 的当前配置”。平台节点被租户认领后，属主 scope 下没有配置，所以同步任务会报 `ErrConfigUnavailable`，不会再写入错误的 scope。要改成按每个被认领的 scope 各下一个同步任务，涉及流量策略模型，另行处理。

## 7. 清缓存修复在两种方案下怎么做

原计划：放宽外键，再校验节点确实承载这个站点。两种方案下都成立，区别只是“承载”从哪里判断。

- **(a)**：
  - 迁移 287 把外键改为 `nodes(id)`；`CreateOperation` 改为检查节点当前承载这个站点（第 0 期查节点组，第 1 期查 `node_site_carriage`）。
  - `Claim` / `readyNodes` 原来要求 `config.configuration_scope_id = 租户 scope`，改为“节点当前配置里包含这个站点”。
  - 节点端 `cachetask/active_release.go:253` 原来要求 manifest.TenantID 等于租户，改为“manifest 里这个站点属于这个租户”，随 v5 一起改。
- **(b)**：
  - 外键同上；`Claim` 改为节点在这个租户 scope 下有 node_config_state 行，且 current 不为空。
  - 节点端 cachetask 按 scope 找对应的 manifest。

## 8. 定案方案 (b) 下：叶子下发、叶子清缓存、叶子 ACL/CC 激活

（下面条目里的“汇总发布”在 (b) 下读作“该叶子租户自己的发布”：叶子租户用 autopublish 显式列出节点组里的节点 ID，第 1 期之后多个叶子租户可以共用同一批平台节点。）

- **叶子下发**：
  - marketsupply 现在就在 mkt-<hash> 租户里建站点，并引用平台节点组（卖家报价的池）。第 0 期修好 CNAME 后，叶子站点就能拿到解析目标。
  - 第 1 期汇总发布会自动把它带上，叶子租户不需要自己的 autopublish 策略。这样就补上了现在“Commit 返回 OK、但站点实际没下发”的缺口。
  - `OpStatus` 加上承载信息，例如“已在 N 个节点生效”。
- **叶子清缓存**：
  - `OpPurge` 以租户 owner 身份调用 `cachecontrol.CreateOperation`，NodeIDs 取 `node_site_carriage` 里承载这个站点、而且在线的节点。
  - 每次最多 16 个目标，多出来的拆成多个任务。
  - 结果通过 `OpStatus` 回报，或者新增一个查询清缓存任务的操作。
- **叶子 ACL/CC**：
  - Commit 时在叶子租户里创建或更新 securitypolicy（leafacl 分支已有映射：`accessFields` / `rateLimitFields`），绑定到站点。
  - 然后调用 `securityactivation.Start`，TargetNodeIDs 取承载节点，CanarySize 为 1。
  - 去掉 `activation_pending` 阻断项，改为在 `OpStatus` 里回报激活进度。
- **拨测**：不受影响（节点本地开关，节点仍在 platform scope）。

## 9. 需要用户确认

1. 选 (a) 还是 (b)。**用户 2026-10-15 先选了 (a)，随后按长期考虑改选 (b)，以 (b) 为准。**
2. 第 0 期要不要先上：**第 0、1 期一起做，每完成一个能合并的阶段就合。**
3. 排期：**不顺延、不分版本，全部合入后出一个版本，在空白机器上全新安装验收。**
4. 出错处理：**A，停在该租户上次成功的版本并通知它。**
