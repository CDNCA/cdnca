# ADR 0007：插件平台总体架构（SaaS + 插件化）

- 状态：已接受（含全部待决问题与换主控规则）；本文只定架构与任务边界，不含实现。
- 日期：2026-10-17
- 依据版本：4a2f8a36（control-api 迁移头 343、license 079、market 026、能力号最大 38）。
- 修订：ADR 0002“文档与插件扩展契约”一节（第三方只经进程外 OpenAPI/Webhook/事件）在本文 §3 的范围内被细化，不被推翻：第三方代码仍不进入任何核心进程和边缘请求路径。
- 相关：ADR 0004（签名者吊销 checkpoint）、0005（原生制品签名）、0006（节点市场）、0008（聚合边缘，本文配套）、0009（边缘运行时动态路由，`security.mounts` 接口）；任务拆解见 [plugin-platform-tasks.md](plugin-platform-tasks.md)。
- 约定：“未核实”= 本仓库代码与文档里没找到依据，也没有实测。兼容基线 1.0.35（测试阶段无商用数据），本文所有新结构不为 1.0.34 及更早做兼容。

## 1. 决策摘要

1. **核心做小，按授权“装了就有、不装就没有”**。核心 = 租户/身份/RBAC、站点与节点模型、发布与能力协商、WAF/CC/ACL/挑战**引擎**、计费账本、审计。其余功能都是插件，分四档（§3）：A 官方内置模块、B 官方签名制品（数据包/规则包/引擎扩展）、C 第三方插件（进程外服务 / 声明式规则包 / 主题包）、D 主题与界面扩展包。
2. **授权只有一个开关源，购买只有一个入口**：所有插件（官方与第三方）都在主控内嵌的插件市场上架与购买（已定（10-17 用户），§8.5）。购买生成按安装绑定的市场许可证（`market_licenses.installation_id`），授权端据此写 `plugin_market_entitlements`（license 068/075）。官方 A/B 档再由授权端折算进该安装的租约功能码 `module.<id>` / `pack.<id>`（`libs/entitlement/lease.go:95`），主控仍只用 `CheckFeature` 判断；套餐自带的模块直接写进租约。C/D 档第三方插件走安装授权链（不变）。
3. **一条制品通道**：授权端签名制品 → 主控按授权和引用按需同步（LKG）→ 主控按节点签名的“节点制品集”下发 → 节点回执。CRS 规则文本、系统规则目录、IP 库、WAF 引擎扩展、节点插件开关、第三方规则包全部走它（§4）。现有 6 条各自为政的链路按 §4.6 保留/改造/删除。
4. **规则引擎在核心、规则内容是包**。规则包分 system / developer / user 三层，命名空间 + 优先级 + 冲突检测在主控发布时完成，结果写进 ADR 0009 的 `security.mounts`（§5）。所有规则包与插件**“下载”与“启用”分开**：主控选择下载，启用/禁用由管理员管，冲突靠禁用一方解决而不是删除（§5.4）。
5. **规则内容保护只做“防复制、防随手查看”**，不承诺防节点 root（§6）。CRS 本体是 Apache-2.0，不加密；只加密自研和付费规则。
6. **主题走声明式**：主题令牌 + 品牌槽位 + 布局槽位 + 受限模板，主控渲染、静态产物下发；不让主题包带脚本（§7）。第三方插件自带页面走沙箱 iframe（只做 C 档，§8.3）。
7. **Provider 插件接口统一**：支付、DNS、短信/通知、第三方 CDN、备案查询各定一个 provider 协议；官方实现编进核心、按授权开关；第三方以 C1 进程外 HTTPS 服务实现同一协议，**第三方 CDN 除外：只由官方提供**（已定（10-17 用户））。插件只上报事实，状态机、入账、幂等、对账在主控（§8.2）。
8. **开发者平台复用 market-service**：开发者 = `market_sellers`；审核 worker、市场签目录、授权端同步目录、安装授权、托管结算全部沿用（§8）。清单 `entrypoint.type` 从仅 `external_https` 扩到 `rule_pack`、`theme`、`provider`。
9. **聚合边缘是 A 档官方内置模块**（ADR 0008）：调度、拨测、切换和全部 `cdn_provider` 适配器都只由官方提供，不开放给开发者（已定（10-17 用户））。

## 2. 现状核对（集成头 4a2f8a36）

| 项 | 现状 | 依据 |
|---|---|---|
| 授权租约 | 扁平 `features[]{code}` + `quotas[]{code,limit}`，各最多 256 项；功能码不限名单，配额码有白名单 | `libs/entitlement/lease.go:84-112,42,47-62,134-160` |
| 主控按功能拒绝 | `entitlementguard.Guard.CheckFeature`，非测试调用方 8 处（`packages.manage`、`builtin.node_monitoring`、`extensions.webhooks` 等）；无插件/规则包类功能码 | `services/control-api/internal/entitlementguard/guard.go:120-139`、`model.go:14-22` |
| 系统规则目录 | `cdnca.security-rule-catalog/v1`，授权端**在线租约 key** 按安装签名（envelope 带 `installation_id`），按**客户**定向（all/include/exclude），不看授权功能；主控每分钟同步 | `libs/entitlement/rulecatalog/catalog.go:28`、`envelope.go:15-52`；`services/license-service/internal/licensing/security_rule_catalog.go:231`、`security_rule_catalog_delivery.go:105-141`；`services/control-api/internal/securityrulecatalog/syncer.go:47-48` |
| CRS 规则文本 | 作为目录条目 `waf_set:crs_rules` 下发（rules.json 约 205 KiB），但文件摘要钉在 edgeconfig 二进制内嵌 manifest；改文本必须配套新主控二进制 | `libs/entitlement/rulecatalog/crs_bundle.go:20`、`libs/edgeconfig/crs.go:49,63` |
| CRS 引擎扩展 | libmodsecurity 模块，agent 写死版本 `3.0.17-1.0.4-1`，从授权端下载服务器直接拉，平台发布密钥签 `signatures.json`；不看授权 | `agents/edge-agent/cmd/edge-agent/waf_engine.go:25,79-132`；`agents/edge-agent/internal/wafengine/artifact.go:56-58` |
| IP 情报库 | 授权端在线 key 签发布信封；主控 `ipintelsync` 同步 LKG（已接线 `main.go:6068-6089`）；**主控→节点 `ipinteldist` 无生产调用方，agent `internal/ipintel` 无人 import，agent 不声明 IP_INTEL**（runbook N2） | `docs/architecture/ip-intel-artifact.md:101-117,162-222`；`docs/runbooks/release-1.0.35.md:32` |
| 节点插件 | 只有能力开关、无代码；唯一能力 `edge.health_beacon`；主控边缘发布 key 按节点签 bundle，NATS 下发，能力 30；`NODE_PLUGIN_PUBLICATION_ENABLED` 默认关 | `libs/edgeconfig/nodeplugin/bundle.go:1-48`；`services/control-api/cmd/control-api/plugin_installation_runtime.go:26-57` |
| 签名者信任 | 离线根签 checkpoint 与 edge signer trust，能力 38 推送 | ADR 0004 |
| 节点侧制品部署 | `edgedeployment.CreateNodeArtifactRolloutTx` 已实现（为 IP 库写），不碰 `node_config_state`，按 scope 排队 | `services/control-api/internal/edgedeployment/store.go:247-253` |
| 节点制品加密 | HPKE X25519 + AES-256-GCM 按节点封装已用于机密 rollout | `services/control-api/internal/edgedeployment/secret_rollout.go:1094,1150`；迁移 019 `node_artifact_encryption_keys` |
| 第三方插件 v1 | 清单只接受 `external_https`；授权端有目录、发布者、清单验签、安装授权链、mTLS 激活事实；主控有 Webhook 控制与投递 | `docs/developer/plugin-integration.md:10,92`；`docs/plugins/distribution-audit.md:9-16` |
| 事件总线 | 生产只投递 `io.cdnca.webhook.v1.test`；扩展点目录 6 个事件、9 个权限全部 `reserved`；通用领域事件 producer 未接 | `docs/developer/plugin-integration.md:134`；`api/schemas/marketplace/v1/extension-catalog.json` |
| 插件市场 | market-service 插件包（命名空间、发布者 key、版本、审核 worker、下架/吊销）、托管结算；市场作为目录 origin 进授权端 | `services/market-service/internal/plugin/`、`internal/review/`；`docs/architecture/marketplace-buildout.md:154-175` |
| 品牌资产 | 只有平台级三槽位 `favicon/logo/login_ad`，`scope.kind='platform'` 才能改 | `services/control-api/internal/brandasset/model.go:15-24`、`service.go:122` |
| 错误页 | 只接受无属性的静态 HTML 标签白名单（无 style/img/script） | `services/control-api/internal/errorpagecontrol/validate.go:76-115` |
| 前端扩展 | 无插件 UI 扩展点；菜单为集中静态表 + 权限码；antd 主题令牌写死在 `main.tsx:54-75`；web 的 CSP 用 nonce + `strict-dynamic` 承载平台“全站 JS 代码”，运营后台 `script-src 'self'` | `apps/web/src/routes/navigation.ts:439-476`；`apps/web/nginx.conf:30-72`；`apps/operator-console/nginx.conf:47` |
| Provider 现状 | 支付两套（`libs/payment.Provider` + `paymentchannel` 迁移 298，与 `rechargepaymentprovider`）；DNS 6 家适配器只有 DNSPod 支持分线路；通知 `notificationruntime.ProviderTransport`；备案 `icpquery` | `libs/payment/provider.go:85-92`；`services/control-api/internal/dnsproviderremote/model.go:53-62`；`notificationruntime/model.go:120` |

## 3. 插件分档与边界

| 档 | 是什么 | 跑在哪 | 谁签名 | 授权开关 | 计费 | 吊销/回退 |
|---|---|---|---|---|---|---|
| **A 官方内置模块** | 编进主控/agent 二进制的功能模块：聚合边缘、IP 库更新、安全分析、高级 CC、各 provider 的官方实现等 | 主控进程、agent 进程（可进控制面与边缘请求路径） | 随原生发布包（ADR 0005 制品密钥） | 租约功能码 `module.<id>`；`CheckFeature` + 菜单 + 能力门控三处同源 | 套餐自带（授权端 `portal_license_plans`）或在插件市场按安装购买（§8.5） | 授权撤销即关；关闭语义每个模块必须定义“停新增、存量保持/摘除” |
| **B 官方签名制品** | B1 数据包（IP 库、蜘蛛名单、云厂商段）；B2 系统规则包（CRS 档位、自研检测、CC 规则组）；B3 引擎扩展（libmodsecurity 等原生模块） | 节点（数据/规则由核心引擎解释；B3 由 nginx 加载） | 授权端（B1/B2 在线 key，B3 平台发布密钥） | 包目录条目声明 `requires_feature`；主控只同步有授权的包 | 包级功能码 `pack.<id>`，可按版本/按年 | 新目录不含即停用；节点保留 LKG 直到主控下发不含该包的集合；B3 走签名者吊销（能力 38） |
| **C 第三方插件** | C1 进程外 HTTPS 服务（provider（不含 cdn）、自动化、导出）；C2 声明式规则包（developer 层）；C3 带页面的插件（沙箱 iframe） | C1 开发者自己的服务器；C2 节点引擎解释（无代码）；C3 用户浏览器沙箱 | 发布者 key 签清单 + 市场签目录（现链路） | 安装授权链 + 付费投影 `plugin_market_entitlements` | 市场 escrow 结算、平台抽成 | 市场下架 → 授权端停用 → 主控撤身份/停投递/下次发布摘包 |
| **D 主题与界面扩展** | 主题令牌、品牌/布局槽位、受限模板、错误页模板 | 主控渲染成静态产物；浏览器只加载 CSS 与图片 | 官方主题随发布包；第三方主题走 C 档链路 | 官方：`module.theme.<id>`；第三方：安装授权 | 同 A 或 C | 切回默认主题即回退，主题产物带版本 |

边界（硬约束）：

- （修订注记：[ADR 0017](0017-third-party-node-plugins.md) 第三方节点插件已暂缓（节点负担大，需要时再做），本条边界不变。）
- **第三方代码不进入控制面和边缘请求路径**。C2 规则包是数据，由核心引擎按白名单动作解释，等价于用户在页面上配的规则；不支持任意 Lua、WASM、nginx 指令。将来要开放可执行扩展（如 WASM 过滤器）必须另立 ADR，证明沙箱、CPU/内存上限、超时、崩溃隔离与签名。
- **会改调度与下发的只能是 A 档**：聚合边缘的调度与切换、节点插件能力、多供给切换、IP 库下发（`cdn_provider` 适配器也只由官方提供）。第三方插件对调度只有建议权（C1 可通过 OpenAPI 读写允许的资源，经同一套 RBAC 与审计）。
- **开放面尽量大，但都在边界内**（用户 23:05“尽量开放开发者权限，重新评估只能独立 HTTPS 的边界”）：结论是保留“后端=进程外”这一条，新增三种不执行代码的开放面——C2 规则包、D 主题包、C3 沙箱页面。后端仍需进程外的理由：控制面持有租约私钥、节点签名 key、DNS/支付凭据，进程内插件一旦失控影响全部客户，且 Go 没有可靠的进程内沙箱。
- 节点插件（能力 30）改为 A 档专用的“官方节点能力开关”，不再挂在第三方安装授权上（§4.6）。

### 3.1 授权功能码命名

- `module.<id>`（A 档）、`pack.<id>`（B 档包族，如 `pack.crs`、`pack.ipintel.base`）、`theme.<id>`（官方主题）。现有码（`sites.manage`、`market.*`、`extensions.webhooks` 等）保持，不改名。
- 租约上限 256 个功能码（`lease.go:42`）。按“包族”而不是“每个版本”占功能码，预计够用；超过时把包授权移到独立签名文档（未做，§11 不需要现在拍板）。
- 主控三处同源判断：API 入口 `CheckFeature`、前端菜单（新接口 `GET /v1/modules` 返回已授权模块，菜单项加 `requiredModule`，与现有 `requiredPermission` 并列）、发布门控（未授权包不进节点制品集）。
- 租约功能码的来源有两个：套餐（`portal_license_plans`）与插件市场购买（`plugin_market_entitlements` 中 `status=active` 的官方条目，按 `plugin_id` → 功能码映射）。授权端在购买生效、续费、到期、改绑时重签该安装的租约；主控通过现有租约续期拉到新租约（购买后多久生效取决于续期触发方式，未核实是否已有“授权端变更即通知主控刷新”，PA-27 补）。

## 4. 统一制品通道

### 4.1 链路

```
授权端                         主控                                     节点
 制品目录（签名）  ──resolve──▶  artifactsync：按授权+引用过滤          ──▶ 节点制品集 v1（主控边缘发布 key 签）
 制品字节（按摘要）◀──fetch───   LKG 存储（按摘要，不可变）                  对象库 <state>/objects/sha256/...（ADR 0009 §8.2）
                                artifactset：按节点生成集合 + 封装密钥  ◀── 回执：每制品 applied/rejected + 当前集合摘要
```

- **授权端只有一个目录接口**：`POST /installation/v1/artifact-catalog:resolve`（安装私钥证明，同现有规则目录/IP 库协议），返回该安装可见的条目；`POST /installation/v1/artifacts:fetch` 按 `sha256` 取字节。现有两对接口（`security-rule-catalog`、`ip-intel-releases/artifacts`）删除。
- **目录条目**（`cdnca.artifact-catalog/v1`）：`artifact_id`（`<kind>/<name>`）、`kind`（`ruleset`、`crs_profile`、`ipintel`、`dataset`、`engine_module`、`node_capability`）、`version`、`revision`、`sha256`、`size`、`media_type`、`requires_feature`、`requires_capability{name,min_version}`、`encryption`（无 / `install_wrapped`，§6）、`license_spdx`、`supersedes`。目录本身按安装签名（envelope 沿用 `rulecatalog.Envelope` 字段：`installation_id`、`scope_revision`、`supersedes`、`valid_from/expires_at`）。
- **按授权过滤**在授权端做（只返回租约里有 `requires_feature` 的条目，免费条目 `requires_feature` 为空）；主控再用本地租约复核一次（防授权端与主控租约短暂不一致时下发越权包）。
- **主控选择下载**（用户第 3 条“主控需要哪个就下哪个”、01:05“下载与启用分开”）：目录全量同步；字节只在管理员点“下载”，或条目标 `resident=true`（如 IP 基础库，默认随核心下载）时 fetch。下载只进主控 LKG，不进任何节点；进节点制品集的只有**已启用且被挂载**的项（§5.4）。LKG：目录与字节都只接受更高 revision；任何校验失败保留上一份。

### 4.2 签名链（复用，不新增根）

| 层 | 签名者 | 节点是否验 | 依据 |
|---|---|---|---|
| 目录 envelope | 授权端在线租约 key（`signing_keys` active） | 否（主控用 `entitlementguard.TrustStore` 验） | 同规则目录 `security_rule_catalog_delivery.go:116-124`、IP 库 `ip-intel-artifact.md:115` |
| 引擎扩展（B3）字节 | 平台发布密钥（离线），多签 `signatures.json` | **是**，用 `artifact_trust_file` | `wafengine/artifact.go:56-58`；理由：原生代码，恶意主控不能伪造 |
| 节点制品集 | 主控边缘发布 key | 是（现有部署验签同一信任） | `nodeplugin/bundle.go:4-6` 同模式 |
| 签名者吊销 | 离线根 checkpoint / edge signer trust | 是（能力 38） | ADR 0004 |

数据与规则包（B1/B2/C2）在节点只验主控签名的制品集 + 摘要链，不重复验授权端签名（与 `ip-intel-artifact.md:125` 的结论一致：节点不持有租约信任，信任主控转发）。B3 例外，必须带平台发布签名，因为它是会被 nginx 加载的原生代码。

### 4.3 节点制品集

- 文档 `cdnca.edge.artifact-set/v1`：`node_id`、`revision`（单调）、`items[]{artifact_id, version, sha256, size, media_type, encryption, wrapped_key?}`、`issued_at`、`key_id`、`signature`。完整期望集合，缺席即卸载（同节点插件 bundle 语义 `nodeplugin/bundle.go:61`）。
- 字节进 ADR 0009 的内容寻址对象库；站点对象的 `security.mounts`、`resolved_sha256` 只引用摘要。一个包被 N 个站点挂载，节点只存一份。
- 传输：沿用 `CreateNodeArtifactRolloutTx`（不碰 `node_config_state`、按 scope 排队、不阻塞站点发布）+ `edgestatus` 的 `node_artifact` 域（`ip-intel-artifact.md:194-222` 已设计并评审过读者影响）。不再为每类制品各开 NATS 流。
- 传输实现（PA-01）：两类平台 scope 节点侧部署，迁移 368 的触发器保证这两种 media type 只在平台 scope、一份配置只含一个制品。
  - 对象部署（`application/vnd.cdnca.edge.artifact-segment;version=1`）：条目内容（首期 zstd 压缩）切成段，每段 sha256 一份所有节点共享的配置（`node_artifact_segments`）；描述符 sha256 即对象地址，节点验主控签名与摘要后写入对象库，HEALTHY 不带回执。
  - 集合部署（`application/vnd.cdnca.edge.artifact-set+json;version=1`）：每节点每 revision 一份配置（`node_artifact_sets`），只含签名的集合文档，条目按摘要引用段。
  - 上限（`libs/edgeconfig/artifactset`）：每段 ≤ 4 MiB，每条目 ≤ 8 段（压缩后 ≤ 32 MiB）、解压后 ≤ 64 MiB，每集合 ≤ 32 条目、文档 ≤ 64 KiB。
  - 顺序（主控 `internal/artifactsetdist`）：每节点同一时刻只有一个节点侧部署在途；先逐个补节点缺的对象，全部 healthy 后再发集合。集合被拒或失败后等 RetryAfter（默认 30 分钟），先重发该集合的全部段（覆盖节点上缺失或被改的对象）再发集合。节点只在所有段齐全、校验通过且各安装器预检通过时整体切换，否则回执 rejected/pending 并保留上一份。
  - 回执随集合部署终态走 `DeploymentStatus.artifact_set_receipt`（字段 13，不占 Connect oneof）；`edgestatus` 校验回执与已部署集合逐项对应后写 `node_artifact_set_receipts`，applied 时替换 `node_artifact_applied_items`（§4.5 门控读它）。
  - 对象库与 ADR 0009 §8.2 同一路径 `<state>/objects/sha256/<2>/<2>/<64>`（agent `internal/objectstore`，`<state>` 为 deployment_root）。站点对象（g8c）与本通道共用对象库，但传输不同：站点对象经 `FetchSiteObjects` RPC 拉取，不走部署通道。不再被任何集合引用的段暂不回收（待做）。
- 节点预检：解密（若有）→ 摘要 → 按 `media_type` 交给对应安装器预编译（规则包编译、IP 库 `Open`、引擎模块 `nginx -t`）→ 原子切换 → 回执。失败保留 LKG，回执带每制品结果。
- 能力协商：新增能力 `ARTIFACT_SET` v1（能力号 39）。各内容自己的能力版本保留（`IP_INTEL` v2、`WAF_CRS_MODULE`、`CC` vN），目录条目的 `requires_capability` 与 `edgepublish.validateFeatureCapabilityTargets`（`feature_capabilities.go:175`）同一套门控：节点不具备就拒绝发布并列出节点，能力到位后自动重新发布（g11-syspub 入口）。
- 回执：`cdnca.edge.artifact-set-receipt/v1`（集合 revision、集合摘要、每制品 `applied|rejected|pending` + 原因码），写主控每节点视图表；主控汇总（不含字节）按需上报授权端，用于“哪些安装在用哪个版本”。

### 4.4 IP 情报库：A / B 对比与决定

用户想法“核心带基础库，更新走插件联动 dnspup 收费”，要求对比 A（授权端统一拉）与 B（主控插件、用户自填 dnspup Key 直拉）。

| | A 授权端统一拉 | B 主控插件直拉 |
|---|---|---|
| 谁付 dnspup | 平台一个账号，平台转售（`pack.ipintel`） | 每个客户自己的 dnspup Key，dnspup 直接收费 |
| 构建 `.ipi` | 授权端（已有：license 078/079，`ip-intel-artifact.md:166-188`） | 主控本地（要把 `ParseDnspupSnapshot`/构建器从 license 移到 `libs/entitlement/ipintel`） |
| 签名 | 授权端在线 key，节点信任主控转发 | 主控边缘发布 key（节点本来就信） |
| 授权端是否在链路 | 是 | 否 |
| dnspup 负载 | 一个客户 | N 个客户各拉全量（dnspup 侧按 release 缓存，每实例最多生成一次） |
| 已有代码 | 授权端发布/拉取、主控同步已合入 | 需新增主控插件 + 构建器下沉 |

**已定（10-17 用户）：两者并存**——基础库由授权端用平台自己的 dnspup 客户 Key **只拉取一次**（目录条目 `ipintel/base`，免费、`resident=true`，所有节点都有），**以后不再刷新**；之后的更新全部走官方插件 `module.ipintel.dnspup`：用户在主控填自己的 dnspup Key，dnspup 直接向用户收费，拉取间隔与时间由用户在插件里设置，主控本地构建，作为 `ipintel/local` 进同一个节点制品集。节点同一时间只用一份：取两者中 `data_updated_at` 较新的；插件失败或 Key 失效时回落基础库。授权端现有定时拉取（license 079 `LICENSE_IP_INTEL_PULL_INTERVAL` 默认 6h）改为“首次成功后停止，仅运营手动触发”。

### 4.5 发布门控

- 只有**生效启用**（§5.4 继承计算后）的项参与发布计算与门控；已下载未启用的项不影响任何发布。站点/策略引用某包或某能力时，发布前检查：目标节点的**当前已应用集合**含该制品（同 `feature_capabilities.go:174-200` 现有 IP 库门控的语义，改读回执表）且能力满足；否则 422 并列出节点，就绪后自动重新发布。
- 未授权（主控本地租约没有 `requires_feature`）的包：发布拒绝 `entitlement_feature_denied`；授权过期后存量节点集合在下一次集合生成时去掉该包，引用它的站点进入“待重新发布”并在页面提示（不静默改站点规则）。

### 4.6 现有代码：保留 / 改造 / 删除

| 现有 | 处理 | 说明 |
|---|---|---|
| `libs/entitlement/rulecatalog` 条目体（`CCRuleGroupBody`、`WAFRuleSetBody` 等，`catalog.go:80-130`）、`report.go`（自定义规则上报） | 保留 | 成为 `ruleset` 包的内容格式；上报方向不变 |
| `rulecatalog` envelope/resolve/ack 协议、license `security_rule_catalog_delivery.go`、control `internal/securityrulecatalog` 同步器 | 改造 | 并入 artifact-catalog；按客户定向改为按 `requires_feature`，保留灰度（`ServedRevision`） |
| `edgeautopublish.RuleCatalogPublisher`（CRS 文本变更自动重发布） | 保留 | 触发条件改为“包摘要变化” |
| `libs/edgeconfig/crs/manifest.json` 内嵌摘要钉死 | 删除 | 改为由目录签名 + 包摘要保证；CRS 升级不再需要新主控二进制 |
| agent `wafengine`（写死版本 `waf_engine.go:25`、直连授权端下载服务器 `:121-126`） | 改造 | 版本与字节来自节点制品集；`signatures.json` 平台签名校验保留 |
| license IP 库发布/拉取（078/079）、`libs/entitlement/ipintel` 格式与 `Verify/VerifyArtifact` | 保留 | 作为 `ipintel/base` 的生产者 |
| license `ip-intel-releases:resolve`/`artifacts:fetch`、control `internal/ipintelsync` | 改造 | 并入 artifact-catalog / artifactsync（LKG 逻辑原样复用） |
| control `internal/ipinteldist`（无调用方） | 删除 | 由节点制品集分发器取代；其 rollout 写法（`CreateNodeArtifactRolloutTx`）保留 |
| agent `internal/ipintel` 安装器（无人 import） | 保留并接线 | 作为 `ipintel` media type 的安装器；agent 在库就绪后声明 `IP_INTEL` v2 |
| 节点插件：`libs/edgeconfig/nodeplugin`、control `nodepluginpublication`、gateway/agent 节点插件流、能力 30、ConnectResponse 18 / ConnectRequest 15 | 删除 | “官方节点能力开关”改为 `node_capability` 制品项，由 `module.*` 授权驱动；第三方安装授权不再能开节点能力 |
| edge signer trust（能力 38、ConnectResponse 21） | 保留，独立 | 信任根不能依赖它要保护的通道 |
| `wafsubscription`（平台订阅第三方规则 URL） | 已改造（PA-25） | 平台只配置订阅 URL；租户订阅得到本租户 `user/<租户>/waf-sub-<订阅>` 规则包（已下载、不启用），规则变化 → 每个订阅租户的包新版本，已发布网站挂载旧版本即“待发布”；原 `@system/<订阅>` 副本直接下发路径已删除 |
| 错误页、挑战、证书、回源鉴权等站点级发布 | 不进本通道 | 属站点对象（ADR 0009 §8.3） |

## 5. 规则包

### 5.1 格式

`cdnca.rule-pack/v1`：`pack_id`（命名空间 `system/<name>`、`dev/<seller-namespace>/<name>`、`user/<scope_id>/<name>`）、`version`（semver）、`layer`（system/developer/user）、`engine`（`waf_v2`、`cc_v2`、`acl`、`challenge`、`modsecurity`）、`engine_min_version`、`params_schema`（JSON Schema 子集：数字范围、枚举、布尔、规则 ID 列表）、`exports`（可被排除的规则 ID）、`rules`（复用 `rulecatalog` 条目体与 edgeconfig 规则模型，不新造 DSL）、`defaults`。

- 引擎只执行白名单动作（放行/拦截/挑战/计分/打标/限速）；规则体经主控与节点**同一个编译器**校验（主控发布时编译一次得到 `resolved_sha256`，节点预检再编译一次，结果必须一致）。
- 开发者写的规则包与系统包同格式、同编译器，只是 `layer=developer`，审核 worker 增加“能否编译 + 正则回溯/规则数/每请求代价预算”pass（§8.1）。

### 5.2 分层、优先级与冲突检测（在主控发布时完成）

- 执行顺序 = `(layer_rank, priority, pack_id, rule_id)`；`layer_rank` 默认 user < developer < system（用户放行规则先于系统拦截，符合“用户例外优先”）；同层内 `priority` 0–1000，由挂载时选择。
- 冲突检测**只计生效启用的项**（拒绝发布，不静默；拒绝信息列出冲突双方及各自在哪一层被启用，并给出“在某层禁用其中一方”的操作入口，不提供删除）：同一 `pack_id` 重复挂载；同引擎同条件出现相反终结动作且无显式优先级；引用不存在的 `exports`；参数超出 `params_schema`；`engine_min_version` 高于目标节点能力。告警（不拒绝）：被更高优先级规则完全遮蔽的规则。
- 结果写入站点对象 `security.mounts`（ADR 0009 §8.4：`[{layer, pack_id, version, sha256, engine, params}]` + `resolved_sha256`），页面展示最终顺序；节点不裁决。

### 5.3 CRS

- 用户 00:15 已定（ADR 0009 §9 Q3）：CRS 站点调参 = **有限个节点级档位** + 站点级排除。档位即 `system/crs-<level>` 规则包（规则集 × paranoia × 异常阈值），节点级加载，换版本要 reload；站点只选档位并在 `params.exclusions` 里列 `exports` 中的规则 ID，请求期用 `ctl:ruleRemoveById` 生效（ADR 0009 标注该机制未核实，需 PoC）。
- “按授权收费”针对档位包、调优排除集与更新服务，不针对 CRS 文本本身（§6.3）。

### 5.4 下载与启用分开（适用于全部插件类型）

| 状态 | 含义 | 谁决定 |
|---|---|---|
| 可用 | 出现在主控的制品目录里（授权允许） | 授权端 + 租约 |
| 已下载 | 字节进主控 LKG；不进任何节点、不影响任何发布 | 主控平台管理员；`resident=true` 的条目默认已下载 |
| 启用 | 参与发布计算；被挂载时进节点制品集 | 各层管理员（下表） |

- **粒度**：包级 + 规则级。规则级启用/禁用按包的 `exports` 列出的规则 ID；未导出的规则只能随包整体开关。
- **继承**：平台 → 租户 → 站点，每层每项三态 `继承 / 启用 / 禁用`，下层覆盖上层，只影响本层及以下（与 quickblock-site 的三态一致）。平台层由平台管理员设，租户层由租户管理员设（仅限平台层允许租户调整的项），站点层由站点所属用户设（同样受上层“允许下层调整”约束）。
- **冲突**：只计继承计算后**生效启用**的项（§5.2）；解决方式是在某一层禁用其中一方，系统不自动删除、不自动改优先级。
- **删除**：删除本地字节是单独操作，只有在所有层都没有启用该项时才允许。
- **更新**：新版本同样“先下载、后启用”。默认值：`system` 层安全包（CRS 档位、自研检测）与 `resident` 数据包为“自动下载并自动启用新版本”（保持 crs-republish 现有的目录更新自动重新发布语义）；developer / user 层包默认“自动下载、手动启用新版本”；每个包可改。
- **同一模型用于** provider 插件与主题：官方 provider 编进核心，“下载”恒为已下载，只有启用/禁用（按授权）；第三方 C1 插件的“下载”= 安装授权确认，“启用”= 现有安装授权 `enabled/disabled`；主题包下载后由平台管理员启用一个（首期只有平台层，§7.3）。
- 数据：主控新增“本地制品”表（artifact_id、version、sha256、下载状态、来源）与“启用覆盖”表（层级、层级对象 ID、artifact_id、可选 rule_id、三态、是否允许下层调整、操作者与时间）；发布时由同一个解析函数算出每站点生效集合，主控与页面共用该函数的结果。

## 6. 规则包内容保护（已定（10-17 用户）：接受“防复制、防随手看、可追溯，不防节点 root”；CRS 不加密）

### 6.1 方案

- 加密包（`encryption=install_wrapped`）：授权端每个包版本生成内容密钥 CEK，AES-256-GCM 加密包体；CEK 用该安装的 X25519 公钥 HPKE 封装后放进该安装的目录条目。安装 X25519 公钥在激活时登记（**新增**：现在安装身份私钥是 Ed25519，`services/control-api/internal/entitlementsync/client.go:148`；不做 Ed25519→X25519 转换复用，单独生成一把加密 key）。
- 主控解封 CEK 后**不解密包体**：为每个节点用节点 HPKE key 重新封装 CEK（复用 `node_artifact_encryption_keys` 与 `secret_rollout.go` 的 HPKE X25519 实现），节点在内存里解密、编译。Lua 引擎包不落明文盘；ModSecurity 包需要文件，写到 `0600`、仅 nginx 用户可读的 tmpfs 路径。
- 页面与 API 对加密包只展示元数据和 `params_schema`，客户只能调参数（用户第 3 条“客户只能调基础参数”）。
- 每个安装的包体带不可见水印（安装 ID 的 HMAC 写入无执行影响的规则元数据字段），泄露后可追溯来源。

### 6.2 能防什么、不能防什么

| 能防 | 不能防 |
|---|---|
| 从主控数据库、备份、页面、API 导出明文 | 节点 root 读内存/tmpfs（节点终究要明文执行） |
| 包文件在安装之间复制使用（CEK 按安装封装，别的安装解不开） | 主控 root 读取安装 X25519 私钥后自行解密 |
| 授权到期后的**新版本**继续获取 | 已在节点上运行的旧版本被人为保留（只能靠授权条款和水印追责） |
| 中间人、下载服务器被拖库 | 根据拦截行为黑盒还原规则 |

结论：这是“防复制、防随手看、可追溯”，不是 DRM。商业保护最终靠授权协议与水印；技术上不承诺防节点 root。

### 6.3 CRS 许可

OWASP CRS 是 Apache-2.0：允许商用、修改、再分发，要求保留 LICENSE/NOTICE、标明修改。CRS 档位包 `encryption=none`、`license_spdx=Apache-2.0`，包内随附 LICENSE 与 NOTICE；对公开文本加密既无保护意义（上游免费可得）也增加合规解释成本。加密只用于自研检测、付费调优排除集和第三方付费规则。

## 7. 主题与界面扩展（D 档）

### 7.1 选型：声明式主题，不用沙箱 iframe 承载主题

| | 声明式（令牌 + 槽位 + 受限模板） | 沙箱 iframe |
|---|---|---|
| 能改什么 | 颜色、字体、圆角、密度、图片、登录页/首页布局变体、页头页脚、错误页 | 任意页面，但只能在框里 |
| 是否需要脚本 | 否 | 是（框内） |
| 与现有 CSP | 不改：web `script-src 'self' 'nonce' 'strict-dynamic'`，运营后台 `script-src 'self'`（`apps/web/nginx.conf:72`、`apps/operator-console/nginx.conf:47`） | 需要按安装动态放开 `frame-src`，主题要覆盖整个外壳时做不到 |
| 一致性 | 所有页面统一换肤，升级不破 | 外壳与框内两套样式 |

**选声明式**：主题的目标是“整个界面换皮”，iframe 只能包住局部，且主题不需要逻辑。沙箱 iframe 只用于第三方插件自带页面（§8.3），不是主题机制。

### 7.2 主题包 `cdnca.theme/v1`

- `tokens`：白名单令牌，对应 antd `ConfigProvider.theme.token` 的子集（`colorPrimary`、`colorLink`、`colorText`、`colorBgLayout`、`borderRadius`、`fontFamily`、`fontSize`、`controlHeight` 等，现写死在 `apps/web/src/main.tsx:54-75`）与现有 CSS 变量（`styles.css` 的 `--setting-*`、`--sidebar-width` 等）；每个令牌有类型（颜色/长度/字体栈），超出范围拒绝。
- `brand_slots`：在 `brandasset` 现有 `favicon/logo/login_ad`（`brandasset/model.go:20-22`）上增加 `logo_dark`、`login_background`、`app_icon`；媒体校验沿用 brandasset。
- `layout_slots`：枚举变体，如 `login.layout ∈ {centered, split, background}`、`shell.sidebar ∈ {light, dark}`、`header.links[≤8]{label_i18n, https_url}`、`footer.text_i18n`、`user_home.blocks[]`（预置区块的选择与顺序）。
- `templates`：只用于错误页与通知邮件。无逻辑模板（Mustache 风格：变量插值、条件、循环，全部自动转义，无 partial 外链）；渲染结果仍须通过错误页静态校验。现有校验不允许任何属性（`errorpagecontrol/validate.go:98-104`），扩展为：允许 `class`（取值限主题声明的类名）和一个由主控根据令牌生成的 `<style>`，禁止 `url()`、`@import`、外部资源。

### 7.3 渲染与作用范围

- 主控把主题渲染成 `theme.<sha>.css` + `theme.<sha>.json`（令牌），同源静态服务；SPA 启动时读 JSON 作为 ConfigProvider 数据传入，**主题不执行代码**。
- 作用范围：apps/web 的管理端与用户前台（同一 SPA，按 `scope_kind` 区分角色，`apps/web/src/auth/session.ts:184-187`）、节点错误页默认模板（主题渲染成静态 HTML，作为错误页系统默认值，仍走现有错误页发布链路）、品牌资产。不包括 operator-console、license-portal、seller-portal（平台自己的界面）。
- 首期主题按平台（主控）生效，与 brandasset 现在只允许 `scope.kind='platform'`（`brandasset/service.go:122`）一致；按代理商/租户白标放到 1.0.37+（市场 P3 白标项，`docs/marketplace/09-phases.md:46`）。
- 平台“全站 JS 代码”（`systemsettings` `GlobalJS`，nginx 以 nonce 放行）是主控所有者自己的代码，**不属于主题包**，第三方主题不能设置它。

## 8. 开发者平台

### 8.1 开发、审核、签名、上架

- 身份：开发者 = `market_sellers`（与授权端客户一对一）；命名空间、发布者 key 由市场管理并登记到授权端（`docs/architecture/marketplace-buildout.md:7-10,154-175`，已合入）。
- 清单 `entrypoint.type` 扩为：`external_https`（现有）、`rule_pack`、`theme`、`ui_page`（C3），以及 provider 声明 `provides: [{kind: payment|dns|sms|notify|cdn|icp, protocol_version}]`。`rule_pack`/`theme` 包体随版本上传、按 sha256 列在清单里，发布者签清单即覆盖包体（与 buildout §2.3“每平台包分别签名”的做法一致）。
- 审核 worker（`services/market-service/internal/review/`）新增 pass：规则包编译 + 代价预算；主题 schema + 资源扫描 + 对比度检查（可选）；`ui_page` origin 必须 https、无重定向。
- 签名与上架：发布者签清单 → 市场签目录快照 → 授权端 `SyncPluginCatalog` → 清单验证 → 安装授权（现有链路不变）。规则包与主题的字节随后进 §4 的制品目录（`kind=ruleset|theme`，`requires_feature` 为空，改由安装授权投影过滤）。
- 分成：第三方插件在市场 escrow 结算（`docs/marketplace/09-phases.md:80`），抽成由授权端管理员配置；官方条目也在同一市场上架（发布者 = 平台），收入归平台，不抽成（§8.5）。

### 8.2 Provider 插件接口（支付、DNS、短信/通知、第三方 CDN、备案）

用户 23:20：这几类统一为插件接口；官方实现签名内置、按授权开关，开发者可上架；插件只报事实，主控状态机入账、幂等、对账。

| kind | 协议（主控侧唯一接口） | 官方实现（A 档，编进核心） | 第三方（C1，HTTPS 实现同一协议） |
|---|---|---|---|
| payment | `libs/payment.Provider`（`CreateCheckout`/`VerifyCallback`/`CreateCompensation`/`Reconcile`，`provider.go:85-92`）+ 可选 Cancellation/Payout | alipay、wechat、epay、codepay、crypto（`libs/payment/` 子包） | 主控把回调原文转给插件验签；插件返回的事实必须由主控再调 `Reconcile` 主动查询确认才入账 |
| dns | `dnsproviderremote` 适配器契约 + `ProviderCapability` 矩阵（`model.go:41-62`） | 现有 6 家 | 安装时跑契约测试（增删改查、线路、权重、TXT）后才可选 |
| sms / notify | `notificationruntime.ProviderTransport`（`model.go:120`） | 现有通道 | 同协议 |
| cdn | ADR 0008 `cdn_provider`（§3） | Cloudflare（先）、EdgeOne / ESA / CloudFront（后，ADR 0008 §10 P2–P4） | **不开放**，只由官方做适配器插件发放（已定（10-17 用户）） |
| icp | `icpquery` | 天行、ALAPI、自定义 HTTP | 同协议 |

- 支付合并：`rechargepaymentprovider`（`alipay.go`/`wechat.go`/`strict.go`）与 `paymentchannel`（迁移 298，`libs/payment` 之上）两套并存（`cmd/control-api/recharge_payment_runtime.go`、`payment_channel_runtime.go`）。合并为一套：`paymentchannel` + `libs/payment.Provider` 保留，`rechargepaymentprovider` 删除，充值订单状态机改用 `paymentchannel` 渠道。不做数据迁移（无商用数据）。
- 第三方支付是高风险权限：安装需二次确认，插件只能对自己这次安装创建的结账单报“已支付”，金额、商户号、订单号由主控逐字段比对（`provider.go:87-88` 现有约定）。

### 8.3 带页面的插件（C3 `ui_page`）

- 在 apps/web 的固定挂载点（插件中心页内、站点详情的“扩展”页签）用 `<iframe sandbox="allow-scripts allow-forms">`（不给 `allow-same-origin`）加载开发者 https origin 的页面。
- 宿主只通过 `postMessage` 白名单消息传上下文（租户、站点 ID、语言、主题令牌）；框内页面调开发者自己的后端，后端用插件工作负载身份调 OpenAPI。浏览器里不传用户会话、不传 token。
- web 的 CSP `frame-src` 现为静态 map（`apps/web/nginx.conf:41-43`）；改为由主控按已启用安装返回允许的 origin（照 `global_js_hosts` 的 auth_request 做法，`nginx.conf:53-56,123`）。

### 8.4 事件总线补齐路线

进展（PA-20/PA-24）：通用 outbox 已落地（迁移 367，删除 187/189 的部署专用表）；6 个业务事件均已 `available`（迁移 367、368，产生点为各业务事实表上的同事务触发器）；订阅按站点过滤与按时间重放/补发已落地（迁移 369），契约见 `docs/developer/plugin-integration.md` 第 8.1、8.2 节。路线：

1. control-api 通用领域事件 outbox producer（与业务写同事务），复用 `pluginwebhookruntime` 的 JetStream、退避、死信与 v2 签名；
2. 按顺序把事件改为 `available`（每个都带 schema、权限、契约测试、顺序与幂等说明）：`deployment.status_changed` → `site.updated` → `certificate.status_changed` → `node.status_changed` → `usage.threshold_reached` → `security.incident_detected`；
3. 订阅过滤（按站点/事件类型）、补发与按时间回放；
4. 入站写能力只经 OpenAPI + 工作负载身份 + 权限，不新增“事件回写”通道。

### 8.5 主控内嵌插件市场（已定（10-17 用户））

**范围**：所有插件（官方 A/B/D 档与第三方 C 档）统一在插件市场上架；主控里的插件市场页（现有 `apps/web/src/pages/plugin-market/PluginStorePage.tsx`，路由 `/sys/plugin-store`，`navigation.ts:331`）直接内嵌浏览和购买，不跳转到外部站点。

**卡片**：
- 发布者角标：`官方`（发布者是平台卖方）/ `认证开发者` / `第三方`。现 `market_plugins` 没有发布者类型字段（`services/market-service/migrations/018_plugin_market.up.sql:54-73`），需新增 `publisher_kind`，由卖方身份派生，开发者不能自填。
- 价格：免费 / 一次性 / 订阅（按月、按年），以及试用天数，取自现有价格计划（`018_plugin_market.up.sql:121-136`，`kind IN ('free','one_time','subscription')` + `interval`）。
- 状态按钮：`购买` → `下载` → `启用/禁用`（下载与启用分开，§5.4）。
- 插件类型枚举要换成本文的分档：现 `kind IN ('edge_script','waf_rule_pack','control_extension','dns_provider','exporter')`（`018:54-55`）中 `edge_script` 与新边界冲突（第三方不进边缘请求路径），改为 `module`、`rule_pack`、`dataset`、`engine_module`、`theme`、`provider`、`external_service`、`ui_page`，其中 `module`、`dataset`、`engine_module` 和 `provider` 里的 `cdn` 只允许官方发布者使用。

**身份链**（浏览器不接触任何市场或授权端凭据）：

```
浏览器 ──主控会话（现有登录）──▶ control-api /v1/admin/market/*
control-api ──安装客户端证书 mTLS──▶ market-service（marketclient，client.go:79-109）
market-service ──服务身份──▶ license-service（许可证投影、租约重签）
```

- 买方身份 = 该安装所属授权端客户（`market_licenses.buyer_customer_id`）+ 安装（`installation_id`，来自 mTLS 证书，`018_plugin_market.up.sql:166-168`）。用户在主控的登录密码、授权端门户账号都不经过主控转发给市场。
- 购买需要主控管理员权限（现 `plugin_installations.manage`；建议单列 `marketplace.purchase`）与 `Idempotency-Key`（`apps/web/src/api/market.ts:285,312` 已带）。

**支付**：
1. 优先用该客户在市场的预付余额扣款（托管账户 `buyer_prepaid`，`services/market-service/internal/order/money.go:48`），整个过程在页内完成。
2. 余额不足时，在页内弹窗显示收银二维码（支付宝当面付、微信 Native）；只有渠道只支持网页收银台时才新开窗口，付款后 `ReturnURL`（`order/order.go:175,209`）回到本页。哪些渠道能出二维码未核实。
3. 页面轮询订单（现 `OrderTracker`，`PluginStorePage.tsx:51-56`）；结算成功后市场签发许可证并推送投影到授权端，页面切换为“下载”。官方条目由授权端重签租约；第三方条目生成待确认安装授权，沿用 pluginconfirm 的“已购买，待你确认”。

**买一次、绑一个主控**：
- 许可证按 (买方客户, `plugin_id`, `installation_id`) 唯一。同一安装之后再登录、重装前端、主控重启都直接显示“下载”，不需要重新购买。
- **换主控规则（已定（10-17 用户，02:25））**：
  - 每份购买只绑定一个主控（安装）；有几个主控就买几份。同一客户的另一个主控（另一个 `installation_id`）没有授权。
  - 可以在授权端（license-portal）解绑后改绑到新主控。改绑后原主控上的该插件随即失效停用：授权端在同一事务里把原安装的投影置为 `ended`、重签原安装的租约去掉对应功能码，并通知原主控立即刷新；原主控把该插件置为“授权失效”（已下载字节保留但不能启用，已启用的从下一次节点制品集中去掉，§9）。新安装接着用剩余有效期。
  - 原主控离线、收不到通知时，在下一次成功续租或现租约到期时停用；“随即”以主控在线为前提（通知机制由 PA-27 补，现有续期触发方式未核实）。
  - 改绑频率限制是**可配置项**：授权端管理员可调，**默认每条许可证每月 1 次**。这是建议的默认值，不是用户的硬性要求；运营可对单条许可证人工放行。
- 主控一键迁移（G10）之后安装 ID 是否保持不变未核实。如果会变，迁移流程要自动走一次改绑（建议不计入频率限制）。

## 9. 吊销、停用与回退（汇总）

- 授权撤销/到期：A 档关闭新增、按模块定义处理存量；已下载的 B/C2 包标“授权失效”、不能再启用，已启用的从下一次节点制品集中去掉（主控本地字节保留，续费后可直接再启用），引用站点标“待重新发布”；C1 撤工作负载身份、停投递；D 回默认主题。
- 市场下架/安全公告：授权端对已有安装授权 `enabled→disabled`（现有，buildout §2.3），主控同上处理。
- 签名 key 泄露：B3 与节点制品集走 ADR 0004 签名者吊销；目录 key 走授权端 key 轮换（主控 TrustStore 窗口）。
- 节点侧回退：对象库保留“当前代 + 上一代”（ADR 0009 §8.2）；任一制品预检失败整集合不切换。
- 紧急开关：运营端可对单个 `artifact_id` 下“全局撤回”，目录下一 revision 不含它，主控收到后立即生成新集合（不等站点重新发布）。

## 10. 后果

- 删除：节点插件（能力 30 及两条 proto oneof、`nodepluginpublication`、`nodeplugin` 包）、`ipinteldist`、CRS 内嵌摘要、规则目录与 IP 库各自的 resolve 协议、`rechargepaymentprovider`。能力 30 号作废不复用。
- 新增：artifact-catalog（授权端）、artifactsync + artifactset（主控）、对象库安装器与回执（agent）、能力 `ARTIFACT_SET`、安装 X25519 key、主题渲染、`GET /v1/modules`、领域事件 producer。
- 不变：第三方插件安装授权链、市场审核与结算、Webhook v2、签名者吊销、ADR 0009 站点对象格式。
- 风险：统一通道是 IP 库、CRS、规则包的共同单点，回归面大；用 §4.3 的“整集合原子切换 + LKG”与每类安装器独立预检控制。

## 11. 用户决定与待拍板

原 5 个问题与 ADR 0008 的 3 个问题均已定；换主控规则写在 §8.5。
