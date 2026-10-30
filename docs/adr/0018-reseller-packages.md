# ADR 0018：代理商自建套餐（RS）

- 状态：已拍板（Q1 改为预付批发价，其余按推荐；见 §8）；RS-01 已实现（迁移 480）。进 1.0.35。
- 兼容基线：1.0.35（PATROL A4：不考虑向前兼容，不迁移旧数据，测试机上线时全部重装）。
- 编号说明：派单写 0015，但 `0015-market-direct-seller-payments.md` 已占用（现有最大 0017），本 ADR 用 0018。
- 需求："线路组「授权给下级」——1.0.35 本版就做「代理商自建套餐」，让线路组授权真正生效"（取代此前"代理自建套餐属后续"的安排）。语义依据（A/B/C 由套餐所有者设置；平台/顶级代理建线路组标等级、决定授权哪些给下级；中间代理只能在上级授权的线路组里挑并可继续授权下级；最下级同样；站长不能改 A/B/C）。
- 代码核对基于集成头 `773f63db6`。路径前缀：主控 `services/control-api/`，前端 `apps/web/src/`。

## 1. 问题

用户在「线路分组 → 线路组等级与授权」看到「授权给下级」，问下级是谁。核实结果：

- 授权表 `node_line_group_grants`（`migrations/460_attack_escalation.up.sql:42-63`）是 scope 授权树，可再授权（`may_regrant`），撤销递归（`internal/escalate/store.go:161-198`）。
- 授权唯一的用途是 `UsableLineGroups`（`internal/escalate/store.go:208-227`）与 460 的守卫 `scope_may_use_line_group_460`（`460:66-73`、`460:138-150`）：**在自己的套餐里**把它选作 B/C。
- 但只有平台能建套餐（§2.2），租户拿到授权后没有自己的套餐可配，这个功能实际不起作用。
- 前端从 `GET /v1/admin/tenant-scopes` 列出**全部租户**作为"下级"（`pages/node-scheduling/EscalateLineGroupsPanel.tsx:206-213`），普通客户也能被选中，造成"授权给客户"的误解。

本 ADR 定义"代理商"、让代理商能建自己的套餐卖给自己名下的客户，从而让线路组授权真正生效。

## 2. 现状（逐段核对）

### 2.1 账号、scope、权限码

| 项 | 现状 | 位置 |
|---|---|---|
| scope | 只有 `platform`（全局唯一）与 `tenant` 两种，**没有父子关系列** | `migrations/001_identity.up.sql:11-24` |
| 租户 | `tenants` 一行对应一个 tenant scope（`UNIQUE (tenant_id)`） | `001:1-9`、`001:20` |
| 成员 | `memberships(scope_id,user_id)`；租户成员/子账号/邀请共享同一 scope 的站点、余额、套餐 | `001:42-48`；`internal/identity/tenant_members.go:109`；`internal/httpapi/tenant_members.go:60-276` |
| 开户 | 平台管理员建用户 = 同一事务建 tenant + tenant scope + 用户 + owner 角色；自助注册同样 | `internal/identity/user_store.go:118-170`；`internal/accountregistration/postgres.go:205-215` |
| 用户管理入口 | `requireUserManager` 要求 platform scope；`GET /v1/admin/tenant-scopes` 同样 | `internal/httpapi/identity_users.go:655-659`；`internal/httpapi/tenant_scopes.go:9-12` |
| 跨 scope 授权 | iamlock：tenant 凭据只能作用于自己的 scope；platform 凭据可指向任意 scope | `internal/iamlock/authorizer.go:116` |
| 平台专属权限 | `packages.manage`、`package_subscriptions.*`、`billing.adjustments.manage`、`nodes.*` 等被排除出租户自定义角色 | `migrations/042_custom_rbac.up.sql:259-264` |
| 线路权限 | `node_scheduling.read/manage` 属租户 owner（也给平台） | `migrations/033_node_scheduling.up.sql:1-33` |

### 2.2 套餐体系与"谁能建套餐"

| 项 | 现状 | 位置 |
|---|---|---|
| 套餐（catalog） | `package_products` **没有所有者列**；名称全局唯一；`package_product_versions` 只追加 | `migrations/009_package_catalog.up.sql:26-71` |
| 建套餐权限 | `packages.manage` 只给 `platform_owner` | `009:1-8` |
| Go 层门 | `NewSessionActor` 拒绝非 platform；`validActor` 同样 | `internal/packagecatalog/authorization.go:40-48,51-55`；`service.go:203-205` |
| 上架门 | 090 上架守卫要求 actor scope 为 platform 且持 `packages.manage`，否则 `P9002` | `migrations/090_package_offer_publication.up.sql:766-783` |
| 资源校验 | 地区、主/备线路组（`purpose='general'`、属**平台 scope**）、CNAME 域名（平台系统设置的 CNAME 区）都按平台 scope 校验 | `internal/packagecatalog/resources.go:36-63,101-139,145-150` |
| spec | 主线路 `node_group_id`、备用 `backup_node_group_id`、限额、价格（月/季/年）、CNAME、购买策略；spec 键集有 090 严格守卫 | `internal/packagecatalog/model.go:48-112`；460 注释 `460:24-28` |
| 租户可见目录 | `listPublishedPackageCatalogSQL`：所有已上架且分组可见的套餐对**所有租户**可见，不区分所有者 | `internal/packagecommercehttp/reader.go:44-92` |
| 订阅 | `package_subscriptions.tenant_scope_id` + 产品快照（含线路组） | `migrations/028_package_subscriptions.up.sql:28-62` |
| 订单 | `package_orders`（purchase/renew/upgrade/downgrade/traffic_package_purchase），`created_by_scope_id` 记录下单方 | `migrations/051_package_commerce.up.sql:1-45` |
| 加购包 | `package_addon_products` 无所有者；管理只认 platform | `migrations/263_package_addon_management.up.sql:20-32`；`internal/packageaddon/store.go:126` |
| 流量包 | 快照有 `audience`/`owner_tenant_scope_id`（指"给哪个租户专属"，不是卖方）；管理只认 platform | `migrations/032_traffic_packages.up.sql:1-12`；`internal/trafficpackage/authorization.go:51` |
| 攻击升级策略 | `escalate_package_policies.owner_scope_id` = 写入者 scope；只有所有者能改；路由 `platformOnly(packages.manage)` | `460:105-136`；`internal/escalate/store.go:297-353`（`:321`）；`internal/escalatehttp/routes.go:65-67` |
| 授权功能码 | 下单时 `CheckFeature("packages.manage")`；配额 `packages.count` | `internal/packagecommerce/checkout.go:427-436`；`libs/entitlement/lease.go:34` |

### 2.3 计费链

| 项 | 现状 | 位置 |
|---|---|---|
| 账户 | `billing_accounts.kind`：`tenant_liability`（每个 tenant scope 一个，`id=scope_id`，不能为负）与 `platform_clearing`（平台一个） | `migrations/008_billing_ledger.up.sql:11-46` |
| 下单扣费 | `postLedger`：租户账户 ↔ `platform_clearing` 双边记账，余额减冻结不足拒绝 | `internal/packagecommerce/ledger.go:19-100,129-160` |
| 下单授权 | 租户自己下单要 `package_subscriptions.manage`（只能本 scope）；平台代下单要 `billing.adjustments.manage` | `internal/packagecommerce/store.go:70-80`；`authorization.go:18-21` |
| 充值 | 充值入账 `platform_clearing → tenant_liability`；支付通道只有平台能配 | `internal/billing/recharge_store.go:453-458`；`internal/paymentchannel/http.go:88` |
| 佣金/分账 | 主控内**没有**；只存在于节点市场 market-service（抽成规则、预付抽成） | `services/market-service/internal/commission/`；ADR 0012 §21 |

结论：主控账本只有"平台 ↔ 租户"两极，没有"代理商收入"这一边。

### 2.4 线路组、节点归属

| 项 | 现状 | 位置 |
|---|---|---|
| 节点 | `nodes.scope_id` 为所有者；注册/生命周期 `requireNodePermission` 只认 platform | `migrations/002_nodes.up.sql:1-18`；`internal/httpapi/nodes_lifecycle.go:90`、`node_registration.go:76` |
| 线路组 | `node_line_groups.tenant_scope_id`（233 起允许 platform scope），`purpose` 为 `general`/`market_supply` | `migrations/033_node_scheduling.up.sql:59-91`；`233_...:80-81`；`427_market_supply_line_groups.up.sql:26-36` |
| 端点→节点 | `node_line_endpoints(tenant_scope_id,node_id)` 外键到 `nodes(scope_id,id)`：线路组只能装**同 scope** 的节点 | `033:133-165`；`284_node_purge.up.sql:244-245` |
| 下发 | 站点下发节点 = 站点自身线路组 + 订阅快照主/备线路组 + 升级路由线路组，节点须属站点 scope 或平台 | `internal/edgeautopublish/system.go:248-292`（`:277-288`） |
| 等级 | `node_line_group_tiers`：线路组所在 scope 标 normal/high_defense/unlimited | `460:30-40` |

结论：今天实际可用的节点都是平台节点（租户不能注册节点），线路组也基本是平台的。代理商"授权来的线路组"在下发路径上已能生效：快照里的线路组 ID 不看站点 scope（`system.go:277-279`），节点是平台节点即通过（`:288`）。

### 2.5 已有的"代理/子账号/父子"概念

| 关键词 | 结果 | 位置 |
|---|---|---|
| `reseller`/`parent_scope`/`sub_tenant` | 主控 schema **没有**任何父子 scope 列 | `rg` 迁移目录仅命中注释 |
| 子账号/成员 | 是同一 tenant scope 内的多用户，不是下级客户 | §2.1 |
| 白标 373 | 注释提到"a tenant (an agent/reseller included)"：租户可选主题、绑定登录域名 `theme_tenant_domains`，错误页按租户 | `migrations/373_theme_tenant_whitelabel.up.sql:23-34,65-71`；`internal/themescope/themescope.go:76-135` |
| 市场 438 downstream | 指节点市场的**另一台主控**作为转售者，跨主控 | `migrations/438_market_downstream_attacked.up.sql:25-31` |
| 工单 | `tickets.tenant_scope_id`，员工侧只通知 platform 成员 | `migrations/302_tickets.up.sql:43-60`；`internal/tickets/notify.go:82-91` |
| 审计 | `audit_events.scope_id` 按 scope 存 | `migrations/001_identity.up.sql:123-129` |

结论：主控内没有代理商模型，要新建。白标 373 与工单、审计按 tenant scope 组织，可直接复用到代理商 scope。

## 3. "代理商"的定义：候选

### (a) 主控内代理商：tenant scope + 父子关系

代理商是一个 tenant scope，平台给它开通"代理商"身份；代理商名下的客户是**独立的子租户**（各自 tenant scope），子租户行上记 `parent_scope_id = 代理商 scope`。同一台主控、同一批节点。

子租户 vs 代理商成员的取舍：

- 成员方案：客户只是代理商 scope 里的一个用户。站点、余额、套餐全在代理商 scope 下，客户之间互相可见（成员共享 scope 资源，§2.1），无法分别计费、分别限额，**不可行**。
- 子租户方案：每个客户一个 tenant scope，站点、余额、订阅、审计、工单天然隔离，现有租户侧代码全部照用。**采用**。

### (b) 市场代理商：订阅了平台节点的另一台主控（ADR 0006/0012）

代理商 = 另一台授权主控，通过节点市场订阅供给后在**自己的主控**里建套餐卖给自己的客户。这条链路已经存在：订阅方主控本身就是平台 scope，`packages.manage` 照常可用，可加价再上架（ADR 0012 §17.1）。

区别：(b) 是跨主控、跨授权、资金在主控之间直结或托管，配置经市场中继落到叶子主控（ADR 0006"流量不走代理链，只有账走代理链"）；(a) 是同一主控内的多级客户，资金在同一账本里。(b) 不需要线路组授权（它买的是供给，不是线路组），所以**不能解决用户问的问题**。

### 3.1 影响对比

| 维度 | (a) 主控内代理商 | (b) 市场代理商 |
|---|---|---|
| 账号体系 | tenant 加 `parent_scope_id`、代理商身份；代理商能给下级开户 | 无变化（各自主控） |
| 计费 | 主控账本加"代理商"一边：客户付给代理商，平台按批发价从代理商预付余额扣 | 市场已有（5 分钟扣费、抽成、预付） |
| 站点归属 | 站点属客户 scope；代理商只读 | 站点在订阅方主控；叶子主控只见受限用户 |
| 线路组/节点授权 | **直接用 460 授权树**：平台授权给代理商，代理商建套餐选用 | 不用；买的是供给线路组（`purpose='market_supply'`） |
| 攻击升级 B/C | 代理商套餐配 B/C，`owner_scope_id = 代理商 scope`，460 守卫原样生效 | 订阅方主控是平台，自己配 |
| 白标 | 373 已按 tenant 支持；客户应继承代理商主题与登录域名 | 各自主控自己的主题 |
| 工单 | 客户工单需代理商可见可回复（今天只有平台员工） | 已有市场工单（ADR 0012 §18.3） |
| 审计 | 代理商对客户的操作写在客户 scope，actor 为代理商用户；平台全可见 | 各自主控 |

## 4. 决策：采用 (a)，(b) 维持现状

代理商 = 同一主控里被平台开通"代理商"身份的租户。下级客户 = `parent_scope_id` 指向代理商的子租户。1.0.35 只做**一级代理**（平台 → 代理商 → 客户）；授权树仍允许多级（460 原样），但代理商的客户不能再当代理商（见 Q2）。

### 4.1 代理商能做什么（MVP）

1. **建套餐**：名称、描述、分组、价格（月/季/年）、限额（流量、带宽、连接、域名、端口、站点数等，同平台套餐 spec，`model.go:48-112`）、购买策略。
   - A 主线路 `node_group_id`、备用 `backup_node_group_id`：只能从 `UsableLineGroups(代理商)` 里选（平台授权来的，`purpose='general'`）。
   - B/C：同 460，B 只能高防、C 只能无限防（`460:138-150` 原样）。
   - 地区、CNAME 域名：用平台的地区目录与平台 CNAME 区（`resources.go:101-150`），不新增代理商 CNAME 区（见 §7 不做）。
2. **上架/下架**自己的套餐；只有自己名下的客户能看到、能买。
3. **给下级开户**：建子租户（tenant + scope + owner 用户，`parent_scope_id = 代理商 scope`），复用 `CreateManagedUser` 的事务（`user_store.go:118-170`），由代理商发起。
4. **给下级下单/续费**：对自己客户的订阅 purchase/renew/upgrade（费用见 §5）。
5. **查看下级**：客户列表、订阅、订单、用量（`/v1/package-usage` 同口径）、账单；只读站点列表。
6. **线路组再授权**：1.0.35 不开放（一级代理，Q2）；`may_regrant` 在授权弹窗里隐藏，库表保留。

### 4.2 不能做什么

- 不能注册节点、不能建线路组（节点注册只认平台，`nodes_lifecycle.go:90` 不变）；不能改线路组等级。
- 不能用未授权的线路组；授权撤销后不能再选。
- 不能看/改平台直客或其他代理商的客户；不能改客户站点配置（只读，除非 Q4 允许"切换"）。
- 不能配支付通道、不能直接改客户余额（调账仍是平台 `billing.adjustments.manage`）。
- 不能管加购包、流量包产品（仍平台专属，`packageaddon/store.go:126`、`trafficpackage/authorization.go:51`）；代理商客户能否买平台加购包见 Q3。
- 客户不能直接拿到线路组授权：授权对象只能是代理商（§6）。

### 4.3 平台如何管理代理商

- 开通：平台在「用户管理 → 编辑用户」把类型改为"代理商"（写 `reseller_profiles`，授予代理商权限码），可停用。平台手动开通，1.0.35 不做申请/审核流程。
- 参数（每个代理商）：批发价表（§5）、预付余额提醒线、可开客户数上限。
- 停用代理商：收回 `reseller.*` 权限码，禁止新建套餐、新开户、新下单；已售订阅照常到期（与 ADR 0012 U3"不停供"精神一致）；停用期间客户不能续费代理商套餐。
- 平台可见：全部代理商、其客户、套餐、订单、批发扣款流水；平台照常能操作任何客户（平台凭据可指向任意 scope，`iamlock/authorizer.go:116`）。

## 5. 计费：代理商预付批发价（Q1 已拍板）

平台给线路组或套餐定**批发价**，代理商**先充值**（预付），每售出一单按批发价从代理商预付余额扣款；**售价由代理商自定**，平台不参与客户与代理商之间的定价。

```text
批发价：平台维护批发价表 wholesale_price_list（每个代理商指定一张，默认 standard），
        按 (价表, 线路组 或 平台套餐模板, 周期) 定价，单位分。
        单的批发成本 W = 该代理商套餐引用资源的批发价之和 × 周期数（主线路组必计；备用/B/C 是否计价由价表决定）。

客户自助购买代理商套餐（售价 P 由代理商定，周期 n）
  客户余额 -P  →  代理商余额 +P              （operation reseller_sale）
  代理商预付余额 -W  →  platform_clearing +W  （operation reseller_wholesale）
  代理商预付余额不足 W → 整单拒绝，三方余额不变（不透支）

代理商代客户下单（客户线下付钱给代理商）
  只记 reseller_wholesale：代理商预付余额 -W；客户余额不动
```

- 预付余额：代理商的 `tenant_liability` 账户或独立预付账户，由 RS-03 定；`reseller_profiles.prepaid_account_id` 记录它（RS-01 已留字段，未定前为空）。代理商充值走平台现有充值/支付通道（`paymentchannel/http.go:88` 不变）。
- 低余额提醒：`reseller_profiles.low_balance_minor`（分，0 = 不提醒），扣款后低于此值发通知（RS-03）。
- 用现有账本：加 `reseller_sale`、`reseller_wholesale` 两类操作（`ledger.go:19-100` 现在只有租户 ↔ 平台），同一事务、同一订单 ID；退款/降级按原单金额反向（客户退 P、代理商退回 W）。
- `package_orders` 加 `seller_scope_id`（套餐所有者）、`wholesale_minor`，`funding_source` 加 `reseller`（`051:1-45`）。
- 代理商提现：线下结算，平台走现有调账审批（迁移 100 的 `billing_adjustment_requests`）扣代理商余额。不做在线提现。
- 售价 0 不影响平台收入：平台按批发价 W 收，与售价无关（取代原推荐 a 的"每月最低成本"）。

## 6. 线路组授权的语义与页面

- 授权 = 平台把自己的线路组授权给**代理商 scope**；代理商建套餐时可选为 A/备用/B/C。客户只能通过买套餐使用，不能被授权。
- DB 守卫（迁移 480，占位）：`node_line_group_grants` 插入时 grantee 必须是有效代理商 scope（P4801）；`may_regrant` 必须 false（P4802，Q2）；grantor 只能是线路组所有者且所有者是平台（P4803）。Go 层同样拒绝（`ErrRegrantUnsupported`/`ErrGranteeNotReseller`/`ErrGrantDenied`）。
- 撤销（Q5 b）：同一事务内把代理商引用该线路组的在售套餐（spec 主/备，或 `escalate_package_policies` B/C）自动下架、清掉对应 B/C 并在代理商 scope 写审计 `package.escalate_policy.grant_revoked`，响应 `{revoked, withdrawn_products, cleared_policies}`；已售订阅快照不变、到期为止（同 U3"不停供"精神），到期后不能续费该套餐。哪些套餐"引用"由 DB 函数 `reseller_products_using_line_group_480` 决定（RS-01 只认 B/C，RS-02 补 spec 主/备）。
- 新接口 `GET /v1/escalate/grantees?search=`：平台返回有效代理商列表；代理商返回空（一级）。前端改用它，不再用 `GET /v1/admin/tenant-scopes`（`EscalateLineGroupsPanel.tsx:206-213`）。
- 页面文案（`i18n/escalateLineGroups.ts:14,19,32,38`）：
  - 标题保留「线路组等级与授权」；按钮「授权给下级」改「授权给代理商」；列名「下级」改「代理商」。
  - 说明改为："给自己的线路组标等级：套餐的 B 级只能选「高防」，C 级只能选「无限防」。授权给代理商后，代理商在自己的套餐里可以把它选作主线路或 B/C 升级线路；代理商的客户只能通过购买套餐使用，不能直接授权给客户。"
  - 没有代理商时：弹窗显示"还没有代理商。先在用户管理里把用户类型设为代理商"，并给链接。
  - 「可再授权」复选框 1.0.35 隐藏。

## 7. 数据模型与改动点

迁移号占位（开工时集成头 `478_security_activation_rule_pack_waits`，479 预留给 cname-exhaust；RS-01 用 480，本地放 `479_placeholder_cname_exhaust` 占位保持连号，合入时删除占位并统一改号）。RS-02/RS-03 依次取下一个号。

| 迁移 | 内容 |
|---|---|
| 480 `reseller_core`（RS-01，已实现） | `reseller_profiles(scope_id PK → access_scopes tenant, status active/suspended, customer_limit, wholesale_price_list, prepaid_account_id → billing_accounts, low_balance_minor, currency, revision, created/updated/suspended_at)`；`tenants.parent_scope_id`（只能指向有效代理商、不能指向自己、代理商自己必须为 NULL = 一级）；权限码 `reseller.packages.manage`、`reseller.customers.manage`、`reseller.customers.read`（租户侧只给有效代理商的 tenant_owner，开通授予、停用收回；平台 platform_owner 也持有）；`node_line_group_grants` 守卫（grantee 有效代理商、`may_regrant=false`、grantor=平台所有者）；`reseller_products_using_line_group_480` 撤销联动查找函数 |
| RS-02 `reseller_packages`（下一个号） | `package_products` 加 `owner_scope_id uuid NOT NULL`（平台 scope 或代理商 scope；A4 不回填，新装即带）；名称唯一索引改为 `(owner_scope_id, lower(name))`；`package_groups` 同样加 `owner_scope_id`；090 上架守卫 `P9002` 放宽为"platform 持 `packages.manage`，或代理商 scope 持 `reseller.packages.manage` 且 `product.owner_scope_id = actor scope`"；主/备线路组校验改为 `scope_may_use_line_group_460(owner_scope_id, …)`；`CREATE OR REPLACE reseller_products_using_line_group_480` 补 spec 主/备 |
| RS-03 `reseller_billing`（再下一个号） | 批发价表 `reseller_wholesale_prices(price_list, line_group 或 套餐模板, cycle, price_minor)`；`billing_transactions.operation` 加 `reseller_sale`、`reseller_wholesale`；`package_orders` 加 `seller_scope_id`（套餐所有者）、`wholesale_minor`，`funding_source` 加 `reseller`；`reseller_profiles.prepaid_account_id` 落值；`escalate_package_policies.owner_scope_id` 必须等于 `package_products.owner_scope_id`（新守卫） |

Go 改动点（每项对应 §8 一个任务）：

- `packagecatalog`：`NewSessionActor`/`validActor`/`Authorize` 允许代理商（`authorization.go:40-55`、`service.go:203-205`）；`ListResourceOptions`/`validateProductResources` 按 `owner_scope_id` 取可用线路组（`resources.go:36-139`），地区与 CNAME 仍取平台；`packages.count` 配额按所有者计（`store.go:691`）。
- `packagecommercehttp`：租户目录 `listPublishedPackageCatalogSQL` 加 `owner_scope_id = COALESCE(tenant.parent_scope_id, 平台)`（`reader.go:44-92`）——直客只见平台套餐，代理商客户只见所属代理商套餐（Q3）。
- `packagecommerce`：`checkout` 校验"产品所有者 = 客户的上级"；`postLedger` 拆三方（客户 → 代理商 → 平台），代理商预付余额不足批发价 W 整单拒绝；新增 `authorizeResellerActor`：代理商对自己客户下单（`store.go:70-80`、`ledger.go:19-100`）。
- `identity`：代理商建/列/停用自己的客户（复用 `CreateManagedUser` 事务，`user_store.go:118-170`），`ListTenantScopes` 加 `parent_scope_id` 过滤；平台用户编辑加"代理商"类型（用户类型语义同处）。
- `escalate`/`escalatehttp`：`/v1/escalate/grantees`；`PutPolicy` 路由放开给代理商（`routes.go:65-67` 现 `platformOnly`）；`RevokeGrant`（`store.go:163-198`）同事务下架引用套餐并清 B/C。
- 白标：代理商客户未选主题时继承代理商主题（`themescope.LoadTenant`，`themescope.go:76-106`）；代理商客户的登录域名用代理商绑定的 `theme_tenant_domains`。
- 工单：代理商可见/回复自己客户的工单（`tickets` 员工侧通知加代理商 scope，`notify.go:82-91`），平台仍全可见。
- 审计：代理商对客户的操作在客户 scope 记一条、代理商 scope 记一条（payload 带对方 scope），平台审计页可按代理商筛选。

不做（1.0.35）：多级代理（代理商的客户再当代理商）、代理商自有节点/线路组、代理商 CNAME 区、代理商支付通道与在线提现、代理商自建加购包/流量包、代理商申请审核流程。

## 8. 需要用户拍板（最多 6 个）

已定"中间代理只能在授权范围挑、站长不能改 A/B/C"；节点市场（跨主控）的决定不适用本 ADR，以下不重复问。

| # | 问题 | 选项 | 推荐与理由 |
|---|---|---|---|
| Q1 | 代理商怎么给平台付钱 | a 平台代收、按单抽成 + 每月最低成本；b 代理商预付批发价（平台给线路组/套餐定批发价，卖出时按批发价扣）；c 只收固定年费，不抽成 | **用户选 b**：代理商先充值，每售出一单按批发价扣代理商余额，售价代理商自定。§5 按 b 写 |
| Q2 | 代理商层级 | a 1.0.35 只做一级（平台 → 代理商 → 客户），授权弹窗不给"可再授权"；b 多级（代理商的客户也能当代理商，沿 460 授权树） | **a**。多级要递归计费、递归可见性、递归撤销引用检查，测试面成倍；460 表结构保留，以后放开只需改守卫 |
| Q3 | 代理商客户能买什么 | a 只能买所属代理商的套餐（平台套餐、加购包、流量包都看不到）；b 也能买平台套餐与加购包/流量包 | **a**（加购包/流量包除外：仍可买平台的，钱进平台）。只看代理商套餐，代理商才有"自己的客户"；加购包/流量包产品现在只能平台建（§2.2），本版不开放给代理商建 |
| Q4 | 代理商能不能"切换"登录到自己的客户 | a 能（同平台「切换」规则：点了就登录、写审计、可随时退出）；b 不能，只读查看 | **a**。代理商要替客户排障；复用 impersonation 现有链路，只放宽"actor 是 target 的上级" |
| Q5 | 撤销授权时代理商还有在售套餐用着该线路组 | a 拒绝撤销并列出套餐，先下架再撤；b 允许撤销，自动下架相关套餐，已售订阅到期为止；c 允许撤销且已售订阅立即改线 | **b**。平台不该被代理商卡住；已售订阅不受影响符合 U3"不停供"精神。c 会打断客户服务 |
| Q6 | 平台直接注册的用户能否被转给代理商（设置 `parent_scope_id`） | a 能，平台在用户编辑里选"所属代理商"，客户原有订阅保留到期；b 不能，只能代理商新开 | **a**。代理商带来已有客户是常见场景；原订阅保留不涉及资金迁移 |

拍板结果：Q1 b（预付批发价，§5）；Q2 a（一级，后端拒绝 `may_regrant=true`，前端由 RS-06 隐藏）；Q3 a；Q4 a；Q5 b（撤销自动下架、清 B/C，已售到期）；Q6 a。

## 9. 任务拆分

迁移号：RS-01 用 480（479 预留 cname-exhaust），RS-02、RS-03 依次取下一个号，合入时统一改号；前端只做编译级自检与相关 vitest，PG 集成与三端复测由合并批次统一跑。

| 任务 | 范围 | 涉及 | 迁移 | 依赖 | 验收 |
|---|---|---|---|---|---|
| RS-01 core | 代理商身份、父子租户、权限码、授权守卫 | 迁移 480；`identity`（`reseller_profiles` 读写、平台编辑用户类型、`ListTenantScopes` 按 parent 过滤）；`escalate`（grantee 只能代理商、`may_regrant=false`、撤销联动下架） | 480 | 无 | PG 用例：普通租户作 grantee 被拒（新 ERRCODE）；代理商作 grantee 通过；代理商 `parent_scope_id` 非空被拒；撤销后引用套餐变已下架、B/C 清空且审计有记录 |
| RS-02 catalog | 代理商建/改/删/上架套餐与分组 | 迁移 480；`packagecatalog`（actor、资源选项、线路组按 owner 校验、`packages.count` 按 owner）；090 守卫放宽 | 480 | RS-01 | 代理商只能选授权线路组（未授权 → 400）；两个代理商可用同名套餐；代理商改不了平台套餐（403）；平台套餐流程回归不变 |
| RS-03 billing | 预付批发价三方记账、代理商代下单、目录按上级过滤 | 迁移（RS-03 号）；`packagecommerce`（checkout 所有者校验、`postLedger` 三方、`authorizeResellerActor`）；`packagecommercehttp/reader.go` 目录过滤 | RS-03 号 | RS-01、RS-02 | 客户买代理商套餐：客户 -P、代理商 +P-W、平台 +W，金额与 `wholesale_minor` 一致；代理商预付余额不足 W 整单拒绝且三方余额不变；代下单只扣代理商 W；直客看不到代理商套餐，代理商客户看不到平台套餐；退款按原比例反向 |
| RS-04 escalate | 代理商套餐配 A/B/C | `escalatehttp/routes.go` 放开 PutPolicy/GetPolicy 给代理商；RS-03 迁移的守卫 policy owner = product owner | 与 RS-03 同号 | RS-02 | 代理商给自己套餐配授权来的高防组为 B 成功；配未授权组 P4604；配别人套餐 403；客户站点受攻击按代理商策略升级（合并批次 e2e） |
| RS-05 reseller-web | 代理商控制台 | `apps/web`：套餐管理（复用 `pages/package-basic`、`PackageBasicPage.tsx`，线路组下拉来自 `/v1/escalate/line-groups`）、我的客户（开户/停用/切换，复用 `UserListPage.tsx` 组件）、客户订单与用量（复用 `AccountOrdersPage.tsx`、`PackageMonitorPage.tsx`）、代理商收支流水；菜单按 `reseller.*` 权限显示 | 无 | RS-01–RS-03 接口定稿 | vitest：无 `reseller.*` 权限时菜单不出现；线路组下拉只含授权组；开户表单提交字段正确 |
| RS-06 admin-web | 平台侧 | 用户编辑加"代理商"类型与参数（批发价表、预付余额提醒线、客户上限；接口 `PUT /v1/admin/resellers/{scope_id}`）、"所属代理商"（Q6，`PUT /v1/admin/tenant-scopes/{scope_id}/parent`）；授权弹窗改 `/v1/escalate/grantees` 与 §6 文案、隐藏「可再授权」；订单列表加卖方列 | 无 | RS-01 接口 | vitest：授权弹窗下拉只列代理商、无代理商时显示引导；文案与 §6 一致 |
| RS-07 whitelabel-tickets | 主题继承、工单代理商可见、切换 | `themescope.LoadTenant` 父级回退；`tickets` 代理商可见/回复/通知；`impersonation` 允许上级代理商（Q4） | 482 占位（工单可见性若需表改） | RS-01 | 代理商客户未选主题时登录页/错误页显示代理商主题；客户工单代理商可见，别家代理商不可见；代理商切换到别家客户被拒 |
| RS-08 acceptance | 真实复测脚本与 runbook | 复测脚本；`docs/runbooks/release-1.0.35.md` 补"开通代理商"一节 | 无 | 全部 | 见 §10 |

可并行：RS-01 先行（约半天）；之后 RS-02、RS-06、RS-07 并行；RS-03、RS-04 在 RS-02 后并行；RS-05 在 RS-02/03 接口定稿后开工；RS-08 最后。

## 10. 真实复测步骤（RS-08，测试机全新安装后）

1. 平台管理员建平台线路组 G1（普通）、G2（标高防），节点各 1 台。
2. 平台给 G1 定月批发价 20 元。建用户 `agent1`，类型改"代理商"，批发价表 standard；给 `agent1` 充值 100 元（预付）。授权弹窗只能选到 `agent1`（普通用户不出现）；把 G1、G2 授权给 `agent1`。
3. 用 `agent1` 登录：建套餐 P1，A=G1、B=G2，月价 100 元，上架。线路组下拉只出现 G1、G2。
4. `agent1` 开客户 `cust1`。平台给 `cust1` 充值 100 元。
5. `cust1` 登录：套餐列表只有 P1（看不到平台套餐）；购买 P1 一个月。核对：`cust1` 余额 0，`agent1` 收入 +100、预付余额 100 → 80（扣批发价 20），平台收入 +20；订单卖方为 `agent1`、`wholesale_minor`=2000。再把 `agent1` 预付余额调到 10 元，`cust1` 续费被拒且三方余额不变。
6. `cust1` 建站（cdnca-t 前缀测试域名），确认自动下发到 G1 节点、CNAME 正常。
7. 对站点压测超过 B 阈值，确认升级到 G2（`escalate_site_states.applied_level = B`），回落后自动回切。
8. 平台撤销 G2 对 `agent1` 的授权：P1 的 B 被清空并有审计，`cust1` 现有订阅不受影响；`agent1` 再建套餐时下拉只剩 G1。
9. 平台直客 `direct1` 看不到 P1；`agent1` 看不到 `direct1`。
10. 测完删除测试 DNS 记录。

## 11. 被否决的方案

- 下级 = 代理商 scope 里的成员：成员共享站点、余额、套餐，无法分别计费与隔离（§3 (a)）。
- 下级 = 节点市场订阅方主控（§3 (b)）：跨主控，不用线路组授权，解决不了用户问的问题；市场转售链继续按 ADR 0012。
- 让任意租户都能建套餐（不设代理商身份）：普通客户会看到无意义的套餐管理入口，授权对象仍无法筛选，与用户问题"授权给客户不应该分完就有"相反。
- 代理商自带节点与线路组：需要放开节点注册给租户与跨 scope 端点（`284_node_purge.up.sql:244-245` 外键），安全面大，不进本版。
