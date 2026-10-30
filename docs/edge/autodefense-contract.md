# 智能自动防御契约（AD-00，冻结）

- 依据：ADR 0010 `docs/adr/0010-auto-defense.md`与已定决策（Q1–Q10，Q3 改为不设默认上限、人工按项锁定）。
- 代码：`libs/edgeconfig/autodefense`（Go 类型、规范化、校验、签名与编解码），`proto/agent/v1/types.proto`。
- 冻结：本文与上述代码是 AD-01..AD-17 的共同契约。字段、取值、单位、签名域改动都算契约变更，需改本文、改测试；新增特征/维度/字段同样是契约变更。

## 1. 编号与载体

| 项 | 值 | ADR |
|---|---|---|
| 能力 | `CAPABILITY_NAME_AUTO_DEFENSE = 42`，`autodefense.APIVersion = 1`；节点不声明则不启用自动防御 | §8.2 |
| 下行 | `ConnectResponse.auto_defense_command = 26`，消息 `AutoDefenseCommand{event, node_id, revision, snapshot_json, snapshot_sha256}` | §8.2 |
| 回执 | `ConnectRequest.auto_defense_receipt = 23`，消息 `AutoDefenseReceipt{event, node_id, command_event_id, revision, snapshot_sha256, applied, sites, signatures, mitigations, error_code}` | §8.2 |
| 回执错误码 | `untrusted_signature`、`invalid_snapshot`、`wrong_node`、`stale_revision`、`incomplete_parts`、`runtime_unavailable`、`not_supported` | §10.2 第 5 条 |
| JetStream | 下行 `AUTODEFENSE_COMMANDS` / `cdnca.agent.autodefense.commands.<node>`；回执 `AUTODEFENSE_RECEIPTS` / `cdnca.agent.autodefense.receipts.<node>`，消费者 `control_api_autodefense_receipts`；上行 `AUTODEFENSE_REPORTS` / `cdnca.security.autodefense.v1.<node>` | §8.1、§8.2 |
| IP 级封禁 | 主控判定的单地址 L3/L4 仍走 ge-waf S5 封禁名单（ConnectResponse 25 / ConnectRequest 22，`source=autodefense`），本契约不重复定义 | §8.2 |

封禁名单用 ConnectResponse 25 / ConnectRequest 22，本契约用 26/23 与能力 42。

## 2. 快照、分片与签名

- 模式名 `cdnca.autodefense/v1`；签名域 `Domain = "cdnca.autodefense/v1\n"`；算法只有 `ed25519`，用边缘发布 key（与 S5、sched302 同一套信任）。
- 签名内容 = `Domain` + 去掉 `signature` 的规范 JSON；线上字节 = 带 `signature`（小写 hex）的规范 JSON。`snapshot_sha256` = 线上字节的 SHA-256。
- 规范：所有列表按键升序（站点 `site_id`；端口组 `id`；白名单 `cidr`/`ja4`；登录接口 `path_template, method`；模块 `name`；项 `field`；签名 `id`、条件 `dim, value`；处置 `kind, target`；槽 `slot`；带/分布 `feature`；份额 `value`），`Canonical()` 负责排序，`Decode` 要求重编码逐字节相等、拒绝未知字段与尾随数据。
- 全量替换：一个 revision 就是节点要持有的全部状态；revision 按节点单调增长；空站点列表 = 节点停用自动防御（未授权时主控下发空快照，ADR §9.1）。
- 分片：单片线上字节 ≤ `MaxPartBytes`（896 KiB，保证载体在 agent/网关默认 1 MiB 命令上限内），一个 revision 至多 64 片。每片 `part/parts`，都带相同 `node_id/revision/issued_at/auto_mitigation`，各自签名；`platform_allow`、`port_groups`、`prior`、`waf_budget` 只在第 1 片；站点跨片不重复且整体升序。节点 `Open` 每片后 `Assemble`，片不全回 `incomplete_parts`、保留旧快照。`Split` 为主控提供最少分片。
- 整数一律 ≤ 2^50（Lua 双精度可精确表示）；时间为 Unix 秒。

## 3. 字段与 ADR 对应

### 3.1 快照头

| 字段 | 含义 | ADR |
|---|---|---|
| `auto_mitigation` | `module.autodefense.auto` 已授权；false 时任何站点不得有处置条目、覆盖层不生效 | §9.1、Q1/Q2 |
| `attack_fragments` | 平台设置“向官方贡献规则情报”开启（ADR 0011 Q1：默认开、平台管理员可关）；每个分片重复且一致；false（省略）时 `waf_evidence` 不得带 `fragments` | ADR 0011 §4.4 |
| `platform_allow` | 节点自身、平台服务、拨测网段（永不处置） | §7.2 第 2、4 条 |
| `waf_budget` | 自动排除预算（waf-exclcap2，可选，缺省按默认）：`latency_us` 100..5000（默认 500，单请求因本站自动排除最多多花的时间）、`memory_percent` 1..50（默认 5，节点全部自动排除最多占节点内存比例）；节点每站生效 k = min(下发, ⌊latency / 实测单条代价⌋)，超内存预算按站点流量从低到高裁尾 | 系统设置 → WAF 自适应 |
| `port_groups[]` | 四层端口组：`id`、`protocol`(tcp/udp)、`ports[]`（不重叠区间）、`baseline`、`module`（l4 覆盖层） | §4.3（节点×端口组）、§7A.4 |
| `prior` | 全局先验文件（所有站共用一份，只在第 1 片）：`version`、`classes[]`（`class` slug、`max_request_milli` 量级上界升序、最后一档 0=无上界、`bands[]` 按 `metric` 升序 `{metric,p50,mad}`，×1000，指标名 = 节点基线行 `PriorMetrics`）。节点从未学过的站点从先验起步（先验带宽 ×3、只挑战/限速）；主控内置四档 `small`/`medium`/`large`/`huge`（≤1、≤20、≤200 rps、无上界），配置了 ClickHouse 时每小时按 `access_hourly_facts_v1` 近 7 天各档站点小时值的中位数/MAD 细化（请求率、字节率、4xx/404/5xx、缓存命中；延迟与回源错误保持内置值），内容不变不升版本；空快照不带 | §4.3 第 1 条 |

### 3.2 站点 `sites[]`

| 字段 | 含义 | ADR |
|---|---|---|
| `mode` | `learning` / `observe` / `protect`；关闭的站点不在快照里；非 protect 不得有处置条目 | §9.3、Q5 |
| `sensitivity` | `low/medium/high` → 基线带 k = 8/6/4 | §4.3 |
| `max_level` | 处置上限，作为覆盖层项 `site.max_level`：未锁定 = 自动，可到 L5（不设默认上限）；锁定 = 人工档位，直到人工再选“自动” | §7.1、Q3 |
| `observe_until` | 一键解除后“仅观察”到期时刻，期间覆盖层与处置不生效 | §7.4 |
| `cross_site` | 同租户跨站点联防开关 | §8.3 |
| `prior_class` | 该站从未学过时起步用的先验档（`prior.classes[].class`），主控按近 7 天平均请求率选；省略或节点不认识时取第一档 | §4.3 第 1 条 |
| `circuit` | `closed` / `open` + `reason`（`agent_fault`/`baseline_stale`/`false_positive_limit`/`whole_site_mitigated`/`delivery_failure`）、`since`、`manual_resume`（24h 内二次熔断需人工） | §10.2、Q6 |
| `baseline` | 见 3.3 | §4.3、§4.4 |
| `whitelist.networks[]` | 站长白名单网段，`source` = user / admin_login（7 天）/ release（解除并加白），`until`=0 永久 | §7.2 第 3 条、§7.4 |
| `whitelist.ja4[]` | 站点 JA4 白名单（挑战通过率 ≥ 50% 加 7 天），每站 ≤ 64 | §7A.6 |
| `login[]` | 登录类接口 `method`、`path_template`、`source`(auto/user) | §5.2 撞库、Q10 |
| `modules[]` | 站点级模块覆盖层 cc/waf/scan/bot，见第 4 节 | §7A |
| `signatures[]` | 见 3.4 | §6 |
| `mitigations[]` | 见 3.5 | §7.1 |
| `releases[]` | 单条解除（可缺省，≤ 256，按 kind、target 升序，每目标一条）：`kind`（ip/cidr/ja4，不收 site）、`target`（同 3.5 规范）、`at`（解除时刻 Unix 秒）。主控保留 24 小时（不超过最长单条处置）。节点收到即删掉该目标在 `at` 及以前判定的本地处置（cidr 覆盖其中逐 IP 条目；ja4 删 JA4 挑战名单条目），并删除自己写入的内核封禁与 XDP 条目（不动内核限速封禁等其他来源）；之后的新判定照常（重新受攻击会再处置），同一解除重复下发不再生效一次。站点一键解除仍用 `observe_until` | §7.4 单条解除（SEC-CONTROL-RECOVERY-01） |
| `waf_adapt` | 自适应 WAF，见 3.6；缺省 = 站点无自适应（非动态路由托管 WAF 站点或 waf 模块未开） | ADR 0011 §3.10 |

已核验蜘蛛（§7.2 第 1 条）与用户放行规则（第 5 条）不需要条目，节点处置门永远先判它们（用户放行 = 站点自绑 ACL/WAF 策略或 user 层规则包里命中的 allow 规则，段默认动作与开发者/系统层不算；规则解释器在改写阶段置 `ngx.ctx.cdnca_user_allow`）。

### 3.3 基线 `baseline`

节点自治：基线只在节点本地学习与存储，主控不计算、不下发。主控快照里站点与端口组的 `baseline` 一律为零值（`Baseline.Omitted()`，JSON 为全零字段、无 `slots`），校验接受；零值即 `can_ban=false`，因此主控快照的处置条目最高 L2（L3 及以上由节点本地判定执行）。部分填写的 `baseline` 仍按下表校验并拒绝。下表保留为节点本地基线行与测试用的格式。

| 字段 | 含义 | ADR |
|---|---|---|
| `version` / `generated_at` | 每次计算或回滚都是新版本 | §4.3 防投毒第 6 条 |
| `maturity` | `prior` / `hour` / `day` / `week`（168 槽）；`prior` 不得 `can_ban` | §4.3 冷启动 |
| `can_ban` | 达到最低样本（请求 ≥ 1000 且独立 IP ≥ 20）；false 时处置条目不得 ≥ L3 | §4.3 第 3 条 |
| `share_permille` | 本节点该站点请求份额（‰） | §4.4 |
| `absolute_request_milli` | 硬上限（rps×1000），0 = 无 | §5.1 |
| `slots[]` | 当前槽 + 下一槽（≤ 2 个），`slot` = 星期×24+小时（0–167） | §4.4 |
| `bands[]` | `feature`、`p50`、`mad`、`p99`、`samples`，千分单位；节点算带 `[p50−k·1.4826·MAD, max(p99, p50+k·1.4826·MAD)]` | §4.3 |
| `distributions[]` | 分布型特征 top-K 份额（‰，和 ≤ 1000，余量为尾部），JSD 参照 | §4.2 |

特征表（冻结，见 `features.go`）：站点数值特征 `SiteFeatures`（请求率、字节率、独立 IP/24、每 IP p50/p99、4xx/404/5xx/超时比、缓存命中、p95/p99 耗时、熵、CV、会话深度、静态占比、无 Referer/Cookie、IDC/新 IP 占比、挑战通过率、每 IP 404 p99），四层 `PortGroupFeatures`（新建连接、SYN、SYN cookie 发送/失败、队列溢出、UDP 包/字节、异形包、INVALID、空连接、单 IP 并发/新建 p99、握手完成率、来源 /24 熵），分布 `SiteDistributions`（asn/country/header_order/ja4/path_template/status/ua_family）与 `PortGroupDistributions`（packet_length）。

### 3.4 签名 `signatures[]`

| 字段 | 含义 | ADR |
|---|---|---|
| `conditions[]` | 1–3 个 `dim=value`（AND），每维至多一个；维度与取值规范见 `Dimensions()`/`ValidCondition` | §6.1 候选特征、项集长度 ≤ 3 |
| `id` | 规范条件 `dim=value` 以 `\n` 连接后 SHA-256 前 16 hex | §6.2（主控撤回/节点计数共用身份） |
| `stage` | `shadow` / `challenge` / `block` / `standby`；standby 带 `resume`（复发恢复到的阶段）和 `expires_at`（15 分钟） | §6.2 |
| `cooldown_until` | 回退后冷却 10 分钟 | §6.2 回退 |
| `cover_permille`、`fpr_ppm`、`lift_milli`、`attack_samples`、`normal_samples` | 覆盖率、正常命中率、提升度、样本数 | §6.1 输出 |
| `origin` / `origin_node_id` | `node`（带节点）或 `control` | §6.1 节点与主控并行 |
| `reason` | 原因串（≤ 512 字节、单行） | §6.1、§5.2 |

维度：ja4、ua_hash、ua_family、path_template、query_names_hash、header_order_hash、missing_header（accept/accept_language/referer/cookie）、http_version、method、asn、cidr（IPv4 /24、IPv6 /48）、country、ip_tag、status、bytes_bucket（log2 分档 0–40）、interval_cv_bucket（lt0.1/mid/ge0.3）、unique_path_ratio_bucket（lt0.05/mid/ge0.3）、static_ratio_bucket（none/some）、challenge_passed（0/1）。签名到 D6 规则 IR 的编译归 AD-03（IR 缺 header_order_hash、path_template 等条件类型时回报 D6）。

### 3.5 处置表 `mitigations[]`

| 字段 | 含义 | ADR |
|---|---|---|
| `level` | 1 挑战 / 2 限速 / 3 临时封禁 / 4 内核封禁 / 5 XDP；0 观察不入表；不得超过站点 `max_level` 生效值 | §7.1、Q3 |
| `kind` / `target` | `ip`（规范地址）、`cidr`（IPv4 ≥ /24、IPv6 ≥ /48）、`ja4`（只到 L2）、`site`（`*`，只 L1：严重态/保护源站全站挑战） | §7.1、§5.1 |
| `rate_milli` | 仅 L2 且必填：每目标 rps×1000 | §7.1 L2 |
| `scope` | `site`（本站判定）/ `tenant`（租户联防，最高 L2） | §7.1 末条、§8.3 |
| `since` / `until` | 单条时长 ≤ 24 小时 | §7.1 默认时长 |
| `offences` | 复犯次数（时长翻倍） | §7.1 L3 |
| `score` / `reason` | 个体分（0–100）与原因串 | §5.2 |

联防（AD-10）：主控评估节点上报的 candidate（每节点一条 sighting），合格签名以 `origin=control`、`stage=challenge` 下发给本站未挖到它的节点，并在 ≥2 站出现时下发给本租户开启 `cross_site` 的其他站；撤回以同 ID `stage=shadow` 下发给本站所有节点（快照签名优先于节点自挖同 ID 副本，shadow 即停止处置）。租户联防条目 `scope=tenant`、L2、`rate_milli=5000`，只在 `protect` + `auto_mitigation` + 站点上限 ≥ L2 时出现。站点单 IP L3/L4 另经封禁名单（ConnectResponse 25）`source=autodefense` 同步到本站所有节点。

XDP（L5）只占位（Q9）：契约各处都接受 5，节点在没有 XDP 时按 L4 执行（`NodeLevel`），并在状态上报里如实报执行级别。平台级情报（只加分，Q7）的类型 `Intel` 已定义，1.0.35 快照不携带（ADR §9.1 跨主控情报列为后续）；WAF 侧的加分通道是请求上下文 `c3` 的 `p=` 段（ADR 0011 RI-02，见 3.6 末），情报条目如何到节点不在本契约。

### 3.6 自适应 WAF `waf_adapt`（ADR 0011 RI-02）

代码 `wafadapt.go`。参数一律用 ModSecurity 的叫法：位置 `loc` = `args`（query、表单、JSON 叶子统一，审计记录只给 `ARGS:<名>`）/ `cookie` / `header`；JSON 叶子名为 `json.<路径>`（PoC-1）；名字匹配 `edgeconfig.WAFParamNamePattern` `^[A-Za-z0-9_.\[\]-]{1,64}$`，大小写敏感，字符集外的名字不能逐参数排除（只能走站点×规则 `x=`）。参数键 `WAFParamKey` = 16 hex：高 8 位为路径模板 CRC-32（IEEE，同 Lua `ngx.crc32_long`；站点级为 0），低 8 位为 `<loc>:<name>` 的 CRC-32。

| 字段 | 含义 | 上限 |
|---|---|---|
| `grey_challenge` | 站点灰区挑战（继承/开/关由主控解析成布尔）；只有档位包集合 `grey_action=challenge` 的档位才会挑战（严格/极严格） | — |
| `grey_floor` | 站点灰区下限（进上下文 `f=`）：集合总分 ≥ 它才算灰区；0 = 档位原样（总分 > 0）。主控在站点画像成熟时用 `GreyFloorFromP99`（正常请求弱分 p99+1，≥ 1 万正常请求，封顶弱阈值−1）设置，数据由 RI-04 提供；只影响挑战，不影响拦截 | 0–99 |
| `exclusions[]` | 站点×参数×规则排除：`id`（`WAFExclusionID` = SHA-256(`<rule>:<loc>:<name>`) 前 16 hex）、`rule`、`param{loc,name}`、`stage`（`shadow` 只计翻转 / `active` 进该站所在的排除桶 location）、`since`、`until`（跨度 ≤ 90 天；agent 每次 reload 按 `ActiveTargets(now)` 渲染，集合变化即 reload，§3.9）、`rank`（waf-exclcap2：`active` 的排序 1..n 各一次，`shadow` 为 0/省略；节点只渲染自己算出的前 k 个 rank，见 `waf_budget`）；按 (规则, 位置字母, 名字) 升序 | 每站 ≤ 576，其中 `active` ≤ 512（`DynamicWAFMaxTargets`，兜底，不是业务上限）、`shadow` ≤ 64（`MaxWAFAdaptShadow`）；节点总量不设上限，随有生效排除的站点自然增长（实测见下） |
| `typed_params[]` | 确定类型：`key`、`type`（只 `number`/`ident`/`binary`）、`max_len_bucket`（0–7）、`charset`（位图）；按 `key` 升序 | 每站 ≤ 32 |

收紧不在快照里：节点本地覆盖层项 `waf.tighten:<set>`（布尔，set 为不带 `waf_set:` 的集合键），生效即进上下文 `k=`。

升级计分（`k=` 收紧与 `d=repeat`，waf-gap10）：被升级的集合非零弱分按 max(弱分, 强阈值) 计入强分，升级即达拦截线；未升级时按档位包学到的权重计弱分。节点规则号段 `32200 + 集合位置×2`（+0 收紧、+1 重复来源），紧挨对应升级规则之前，依据 ADR 0011 §3.2a。

自动排除按档位分桶（RI-03d 取代 RI-03c 的“每站一个 location + 256 站上限”）：有生效排除的站点按档位、按站点 ID 升序每 `edgeconfig.DynamicWAFBucketSites = 32` 个站一桶，每桶一个命名 location `@cdnca_waf_<档位键>_x<n>`（`DynamicWAFBucketLocation`）。桶规则文件 `RenderDynamicWAFBucket` = `Include` 档位文件 + 每站一条 phase 1 规则：

`SecRule UNIQUE_ID "@beginsWith c3;s=<站点>;" "id:38000+i,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=<规则>;ARGS|REQUEST_COOKIES|REQUEST_HEADERS:<名>,…,skipAfter:CDNCA-XB"`，末尾 `SecMarker "CDNCA-XB"`。

规则号段：`38000–38127` 为桶内每站规则（各桶 location 复用同一段，桶 ≤ 128 站；BATCH 第 18 条 10-20 登记）。

location 规则在节点规则之前执行（ModSecurity-nginx 合并时子 location 在前），所以命中站点后 `ctl` 对本事务后面的 CRS 生效；站点 ID 从事务 ID 读，客户端改不了。Lua 在 `configure managed_waf_buckets`（站点 ID → 桶 location）一次查表定 location，冷站走档位 location，不用为它付任何代价。

为什么不是“全节点钩子树”或“Lua 剔参数”（RI-03d PoC `tests/ruleintel-poc/exclusion-tree`，结果 `result-arm64.txt`）：
- 方案 A：全节点一份钩子树（站点 ID 末两位 16×16 skipAfter）。reload/内存达标（1 万站 1.2 s、+110 MiB），但每请求 +0.3～0.6 ms p50：libmodsecurity 的阶段循环 `RulesSet::evaluate` 对 skipAfter 跳过的规则也要逐条走一遍（marker 判断），所以每个请求仍要过全部钩子规则（O(N)，约 26 ns/条），skipAfter 树省不掉。
- 方案 B：Lua 在进 ModSecurity 前删参数。连接器 `msc_process_uri` 读 `r->unparsed_uri`（客户端原始请求行），`ngx.req.set_uri_args` 改不到它（实测仍拦）；请求头/cookie/表单/JSON 体也是原始数据，要改就得改连接器，而且日志和证据里会看不到原值。不可行。
- 采用方案 C（分桶）：每请求只过本桶 ≤ 32 条站点规则，location 数 = 站点数/32。

实测（RI-03d，真实 OpenResty 1.31.1.1 + libmodsecurity 3.0.17 + CRS 4.30.0，WORKERS=1）：

| 方案 · 有生效排除的站 × 每站条数 | reload | master RSS 增量 | 每请求额外 p50 / p99（对同 WAF 无排除） |
|---|---|---|---|
| 同 WAF 无排除（基线） | 0.3 s | —（42 MiB） | — |
| RI-03c 每站一个 location · 1000 × 32 | 5.0 s | +210 MiB | +182 / +1989 µs |
| RI-03c 每站一个 location · 10000 × 32 | 312 s | +2.1～3.2 GiB | +525～+1416 / +1306～+3659 µs |
| A 全节点钩子树（PoC）· 10000 × 32 | 1.2 s | +108 MiB | +260～+500 µs（随站数线性） |
| **C 分桶 128（采用）· 10000 × 32** | **1.8 s** | **+120 MiB** | **+104 / −70 µs** |
| C 分桶 64 · 10000 × 32 | 2.0 s | +131 MiB | +123 / +475 µs |
| C 分桶 32 · 10000 × 32 | 4.7 s（单轮最高 7.0 s） | +152 MiB | +54 / +341 µs |
| C 分桶 32 · 1000 × 32 | 0.47 s | +16 MiB | −39 / −508 µs |

12 轮配对复测（桶 128，固定 CPU）：额外 p50 中位 −25 µs、95% 区间 [−228, +151] µs，reload 中位 2.3 s、master RSS +120 MiB，见 ADR 0011 §6.5。PoC 数据见 `tests/ruleintel-poc/exclusion-tree/result-arm64.txt`；真实节点路径（agent `dynwaf.Prepare` → 骨架 → Lua → libmodsecurity，`tests/dynroute-waf/run.sh ONLY=scale`）见 `scripts/security/wsa-proto/data/ri03d-scale-1k-10k.txt`。每请求额外 p50 在各轮之间 ±100 µs 的波动范围内（同一轮基线 0.78～1.25 ms）；按规则数算，理论值是本桶平均 64 条 × 约 26 ns ≈ 2 µs。内存增量 = 每条排除约 0.38 KiB（32 万条 +120 MiB），跟总条数成正比。

不设节点总量上限，`dynwaf.Prepare` 不再因站点数拒绝；RI-03c 的 `DynamicWAFMaxSiteLocations`、`node_site_limit` 裁剪接口作废。

给 RI-04 的接口（生成方）：`dynwaf.Input.Targets map[站点 ID][]DynamicWAFTarget` = 该节点上每个有流量站点的 `WAFAdapt.ActiveTargets(now)`（每站 ≤ 256、按 (规则, 位置, 名字) 升序、规则必须是档位包导出的）；空列表等于没有。节点按档位、站点 ID 自行分桶，生成方不管桶。集合变化 = 新 digest = reload；为避免 reload 风暴，`ActiveTargets` 只在排除进入/离开 `active`、或站点上下线时变化（§3.9），不要按请求数排名抖动。

请求上下文 `c3`（`edgeconfig.DynamicWAFContext`，事务 ID，Lua 写、节点规则读）：

`c3;s=<站点>;i=<l|b>;e=<1|0>;g=<0|1>;b=<0|1>;p=<0-100>;d=,…,;f=<0-99>;k=,…,;u=,…,;x=,…,;|<request_id>`

| 段 | 含义 | 上限（条 / 字节含前导逗号） |
|---|---|---|
| `g` / `b` | 有效 WAF 挑战 cookie / 浏览器类请求 | — |
| `p` | 平台情报加分（只加分，不单独成立） | 0–100 |
| `d` | 检测器（`DynamicWAFDetectors` 顺序）+ `shape` + `repeat`（灰区重复来源：TLS 按（站点, 客户端地址, JA4）、无 JA4 按（站点, 客户端地址），60 秒固定窗口内灰区事务 ≥ 20 次，当前或上一窗口达阈值即带；阈值与窗口为常量 `DynamicWAFRepeatThreshold`/`DynamicWAFRepeatWindow`，依据见 ADR 0011 §3.2a，1.0.36 可做成站点级配置） | 8 / 96 |
| `f` | 站点灰区下限（`grey_floor`） | 0–99 |
| `k` | 收紧的集合，升序 | 10 / 340 |
| `u` | 站点禁用的官方 tuning 条目号（1–999999），升序；单独一个 `0` = 站点未挂 `system/crs-tuning`，全部条目不生效（ADR 0011 RI-13，节点按档位分节渲染 `ctl:ruleRemoveTargetById`，见 `RenderDynamicWAFRulesTuned`） | 64 / 450 |
| `x` | 站点×规则排除，升序 | 256 / 1800 |
| 全串 | — | ≤ 4096（PoC-4）；各段上限之和在内，任何段都不丢 |

节点规则用两条 PCRE 解析（`DynamicWAFContextRules`：前一条校验全串并捕获 s/i/e/g/b/p/d/f，后一条捕获 k/u/x），每条捕获 ≤ 9 组；`ParseDynamicWAFContext` 是严格形式（已知名、顺序、条数、字节）。不接受 `c2` 及更早。挑战码 `DynamicWAFChallengeStatus = 599`（PoC-3）。

## 4. 模块自动覆盖层（§7A）

- 模块：站点级 `cc`、`waf`、`scan`、`bot`（`sites[].modules`），节点×端口组级 `l4`（`port_groups[].module`）。模式 `manual` / `auto` / `suggest`（§7A.1）。模块不在快照里 = 按人工值运行。
- 项 `items[]`：`field`、`state`（`auto` / `manual`）、`manual`（人工保存值，或平台默认）、`auto`（覆盖值，可缺省）、`min`/`max`（自动范围）、`locked_by`/`locked_at`（仅 manual，且必填）、`resumed_by`/`resumed_at`（仅 auto，人工最近一次“恢复自动”）、`frozen_until`（1 小时内反向 3 次冻结）。操作者格式 `user:<id>` 或 `plugin:<id>`。
- 生效值：`锁定 ? manual : clamp(auto, min, max)`；覆盖层不生效（模块非 auto、站点非 protect、未授权自动处置、熔断、仅观察期）或无 `auto` 时 = `manual`（`Item.Effective`、`Active`）。`suggest` 只显示 `Suggestion()`，不生效。人工改字段即锁定；锁定期间自动防御不读不改，直到人工再选“自动”。
- 上下限：`min/max` 必须在字段平台范围内；CC 阈值与四层上限 `max ≤ manual`（“上限 = 人工值”），WAF 档位 `min ≥ manual`（“不低于人工档位”）。

字段注册表（冻结，`FieldSpecs()`；枚举值为序号，越大越严，布尔 0/1）：

| 字段 | 类型 | 平台范围 / 默认自动范围 | ADR |
|---|---|---|---|
| `site.max_level` | 枚举 observe..xdp | 0–5 / 0–5 | §7.1、Q3 |
| `cc.per_ip_requests` | 次/窗口，越小越严，max≤人工 | 1–1e6 / 5–1e6 | §7A.2 |
| `cc.challenge` | 枚举 off/js/five_second/pow | 0–3 | §7A.2 |
| `cc.ban_seconds` | 秒 | 600–86400 | §7A.2 |
| `cc.auto_switch_qps` | rps，越小越严 | 1–1e7 | §7A.2（取代 g1-autoswitch 固定阈值） |
| `cc.limit_permille` | 千分比，越小越严，max≤人工 | 100–1000（默认 250–1000） | §7A.2：站点全部 CC 限速规则（任意 count_by 的固定窗口 requests/requests_per_uri、漏桶 rate_per_second/burst）按此比例收紧，只降不升；节点提议 = 受攻击时 ceil(1000×基线 p99×1.5/窗口请求率)，无基线 500，非攻击 1000（ad-bot-cc） |
| `waf.tier` / `waf.crs_tier` | 枚举 log_only/standard/strict/extra_strict，min≥人工 | 0–3 / 1–2（极严格需用户放开） | §7A.3 四档 |
| `waf.auto_block` | 布尔 | 0–1 | §7A.3 |
| `waf.group:<slug>` | 枚举 log/block（每规则组一项） | 0–1 | §7A.3 观察转拦截 |
| `l4.max_conns_per_ip` | 连接，max≤人工 | 4–1e6 | §7A.4 |
| `l4.new_conns_per_second` / `_per_minute` | 速率，max≤人工 | 5–… | §7A.4 |
| `l4.syn_tier` | 枚举 off/syncookies/syncookies_ip_rate/cidr24_rate | 0–3 | §7A.4 |
| `l4.malformed_drop` / `l4.invalid_drop` | 布尔 | 0–1 | §7A.4、ddos-tcpflags |
| `l4.idle_seconds` | 秒，越小越严 | 3–86400 | §7A.4 |
| `scan.not_found_threshold` | 404/60 秒 | 10–200 | §7A.5 |
| `scan.login_failures_per_minute` | 次/分/IP | 5–1e5 | §7A.5 |
| `scan.ban_seconds` | 秒 | 600–86400 | §7A.5 |
| `scan.login_challenge` | 布尔 | 0–1 | §7A.5 |
| `bot.mismatch_challenge` / `bot.fake_crawler_block` | 布尔 | 0–1 | §7A.6 |
| `waf.tighten:<set>` | 布尔（每集合一项，集合须是档位包 `adaptive` 集合） | 0–1 | ADR 0011 §3.5 |
| `bot.scanner` / `bot.headless` / `bot.ai_crawler` / `bot.bad_ua` | 枚举 log/challenge/block | 0–2 | §7A.6：门控按 UA 分类（cdnca_bot.lua，按此顺序取第一个命中类）后执行该类级别；白名单与 CC 已核验可信爬虫豁免；节点提议见 ad-bot-cc（ad-bot-cc） |

调整节奏（收紧立即、放宽每次一档且需 10 分钟、冻结）由 AD-05 执行，契约只携带 `frozen_until` 结果。CRS 档位只能在节点已加载档位内选，否则只给建议（§7A.3），该判断在主控生成 `waf.crs_tier` 的 `max` 时完成。

## 5. 上行上报（§8.1）

`Report{schema="cdnca.autodefense.report/v1", kind, node_id, site_id+tenant_id | port_group, seq, at, revision, <payload>}`，单条 ≤ 256 KiB；幂等键 `node_id + (site_id|port_group) + seq`。`kind` 与载荷一一对应、恰好一个：

| kind | 载荷 | ADR |
|---|---|---|
| `minute` | 分钟对齐；`counts`（原始计数）、`values`（特征千分值，限特征表）、`sketches[]`（名、格式 `<name>/v<n>` 由 AD-01 定义、二进制状态 ≤ 16 KiB）、`top_k[]`（≤ 64 + 尾部）、`dropped` | §4.1 agent 上报 |
| `state` | `from`→`to`（normal/surge/protect_origin/attack/cooldown/circuit_open/baseline_stale）、当前最高级、原因；进入 `circuit_open` 的原因串 `circuit_break(<reason>[,manual_resume])` 由主控镜像为站点 `circuit`（open + reason + manual_resume），节点自行恢复（`circuit_resume(...)`）只关闭非人工熔断；人工熔断由 `POST …/sites/{site_id}/circuit/resume`（需 `module.autodefense.auto`，审计 `security.autodefense.circuit_resume`）关闭，节点在快照 open→closed 时恢复 | §5.1、§7.3、§4.4 |
| `candidate` | 节点挖出的签名，必须 `origin=node`、本节点、`shadow` | §6.1 |
| `verdicts` | 个体判定，只报 L2 及以上，≤ 512 条 | §8.1 |
| `adjust` | 覆盖层自动调整（模块、字段、旧→新、原因），审计 `security.autodefense.module_adjust`；l4 只能在端口组范围。`suggest=true`：覆盖层不生效时（`suggest` 模式，或 `auto` 但未授权 `module.autodefense.auto`）节点算出的建议值，不生效、不审计，主控只展示；`frozen_until`：本次是该字段 1 小时内第 4 次反向调整，节点保持该值到此时（≤1 小时，建议不得带）。主控按目标×项×节点保留最新值（迁移 414 `autodefense_module_values`） | §7A.1 |
| `node_event` | 平台级节点安全事件（F4，AD-08）：不带 `site_id`/`tenant_id`/`port_group`；`source`（ddos/l4guard/autodefense/xdp）、`kind`、`client`（规范地址，可空）、`count`、`duration_seconds`（≤ 24h）、`level`、`reason`；幂等键 `node_id + node + seq`；主控写 ClickHouse `node_security_events_v1`，只给平台管理员 | ge-ddos 遗留 2 |
| `cc_stats` | CC 规则统计（CC 页人工调参与自动防御共用）：节点作用域（不带 `site_id`/`tenant_id`/`port_group`），`cc_stats[]` ≤ 128 行，每行 = 站点×CC 策略(版本)×规则×分钟 自上次上报以来的增量：`matched`/`triggered`/`challenged`/`blocked`/`passed`/`ja4_unavailable`，`rule_id` 空 = 网站级（验证失败封禁），`top_clients`/`top_paths` 各 ≤ 10（触发请求，次数降序）。来源：ccv2 engine.lua 每 worker 计数 → health `/cc-stats` → agent 每 10 秒汇总。幂等键 `node_id + cc_stats + seq`；主控不写回执，按节点是否服务该站点逐行过滤后写 ClickHouse `cc_rule_stats_v1`（行 ID 由 node/seq/index 派生，重投不重复计数），API `/v1/security/cc-stats`、`/v1/admin/security/cc-stats` | cc-metrics |
| `waf_evidence` | 自适应 WAF 小时证据（站点范围，ADR 0011 §4.1）：`hour`（整点、不晚于 `at`）、`pack{pack_id,version}`、`items[]`（≤ 128，按 `key, rule` 升序；`key`、`param{loc,name}`、`type`、`len_bucket`、`charset`、`rule`、`hits`>0、`src`（来源 /24 线性计数位图 16 hex）、`days`（16 天位图，非 0）、`challenged`/`passed`/`failed_src`/`clean`/`attack_after`（≤ hits，`failed_src` ≤ `challenged`）、`stage_hint`（`observe`/`candidate`））、`tighten[]`（≤ 10，`set`、`reason` = `attack_ratio`/`challenge_failed`、`since`）、`limit`（waf-exclcap2，可选：该站下发的生效排除在本节点实际生效情况 `delivered` 1..512、`applied`、`latency_trimmed`、`memory_trimmed`（三者之和 = `delivered`）、`cost_ns` 0..1000000 本机实测单条代价；只有它时也上报）、`exclusions[]`（≤ 576，同快照每站排除上限，`exclusion_id`、`flipped`、`attack_after` ≤ `flipped`、`paused`=节点已暂停请主控撤销）、`fragments[]`（攻击片段，ADR 0011 §4.4，只在快照 `attack_fragments` 开启时出现，出现则非空：≤ 32 条/站/小时，按 `rule_id, location, param_key, fragment, encoding` 升序去重；`rule_id`、`location` = `args`/`body`/`cookie`/`header`/`path`、`param_key`（`WAFFragmentParamKey` 规范化，path/body 为空）、`fragment`（≤ 256 B，节点 agent 用 `libs/entitlement/ruleintel/redact.RedactFragment` 打码后的那段）、`encoding`（`text` / `percent`）、`signal`（`strong` 或检测器名，只允许强信号拦截的请求））、`dropped`；列表与 `limit` 不能同时为空；单条 ≤ 192 KiB（ADR 写 32 KiB；128 项满长名约 60 KiB，32 条全转义片段约 54 KiB，320 条排除结果约 35 KiB，故放宽；满载实测 156 KiB）。片段之外不含参数值、请求体、Cookie 值、IP、UA、路径；片段的打码由主控与授权端用同一库复核（`redact.CleanFragment`），本契约只校验形状 | ADR 0011 §4.1、§4.4 |
| `drift` | 基线漂移待确认（站点范围）：`metrics[]`（升序去重，取自 `BaselineMetrics`：byte_rate/cache_hit/latency_p95/latency_p99/ratio_404/ratio_4xx/ratio_5xx/request_rate/upstream_error/upstream_timeout）、`days`（连续偏离天数阈值，1–255）；节点每个学习日结束时对仍漂移的站点报一次；主控按站点×节点保留最新一条（PG `autodefense_baseline_drifts`），只用于页面提示确认（站点详情 `drifts[]`，`POST …/sites/{site_id}/drifts/confirm` 确认待确认项，审计 `security.autodefense.drift_confirm`；之后上报的指标仍在已确认集合内保持已确认，出现新指标重新待确认），不改节点基线 | §4.3 第 4 条 |

`node_event.kind` 是开放 slug，已知值（主控按这些展示，未知值原样显示）：

| source | kind | reason | 说明 |
|---|---|---|---|
| `ddos` | `empty_connection_ban` | `empty_connections` | 空连接封禁 |
| `ddos` | `rate_ban` | `new_connection_rate` | 内核新建连接速率封禁（agent 每 10 秒差分 nft 封禁集合得出；排除 agent 自己写入的） |
| `l4guard` | `kernel_ban` | `l4_guard_rule` | 四层防护规则内核拉黑 |
| `xdp` | `fallback` | agent `internal/xdp` Reason 码（`verify_failed`/`update_failed`/`attach_failed`…） | XDP 过滤器运行中回落到 nftables（每次回落 1 条，重试失败不再报）；`client` 空、`count`=1、`level`=4；节点同时撤销 XDP_FILTER 能力（会话立即重连发新 hello） |
| `xdp` | `reattached` | 挂载模式 `native`/`generic` | 回落后重新挂载成功（1 条）；`level`=5；XDP_FILTER 随新 hello 恢复 |

每次差分（ddos）或排空（l4guard）超过 256 条时只发前 256 条单报，再加 1 条汇总：`client` 为空、`count` = 超出条数。

## 6. Lua → agent 采集帧（§4.1）

`Frame{schema="cdnca.autodefense.frame/v1", worker, pid, second, revision, sites[]}`，每 worker 每秒经本地 unix 套接字 POST 一次（只对 agent 开放），≤ 8 MiB。每站点：精确计数（请求、2xx/3xx/4xx/404/5xx、缓存命中、上游错误/超时、字节、16 档 log2 微秒耗时直方图）、处置门计数（白名单放行、挑战/通过、限速、拦截、签名命中按 id）、`ips`（规范地址→次数，≤ 4096，溢出计 `overflow`）、`behavior`（前 256 个 IP 的间隔 Welford 量、去重路径、静态、无 Referer/Cookie）、`samples`（蓄水池 ≤ 64 条，字段同签名维度规范，QUIC 下 ja4 为空）、`bot_hits`（可选，Bot 类→次数，类名取 `BotCategories`；门控记录 `bot=true` 即 Bot 模块非手动时才分类计数）、`ja4_challenged`/`ja4_challenge_pass`（可选，JA4→次数，≤ 64 个：ja4 处置条目发出的挑战与通过按 JA4 计，供 agent 算脚本类 JA4 挑战名单的通过率，ADR 0010 §7A.6；通过率 ≥ 50% 且挑战 ≥ 20 次移出名单并加站点 JA4 白名单 7 天）、`params`（可缺省，ADR 0011 §3.6：干净请求抽样 ≤ 64 条，每条 `cidr` + `params[]` ≤ 16 个 `{key, loc, name, type, len_bucket, charset}`，同一样本内参数不重复；值不进帧；RI-05 填）。`samples[].query_names_hash` = 去重排序后的 query 参数名以 `\n` 连接的 SHA-256 前 16 hex（`QueryNamesHash`，无参数为空）。AD-04 与 AD-05 都以 `DecodeFrame` 为准写测试。

传输与门控写入（AD-04 实现，`edge/openresty/dynroute/cdnca_autodefense.lua`）：
- 帧：每 worker 的 1 秒 timer 把已结束的秒以 `POST /autodefense/frame`（HTTP/1.0，`Content-Type: application/json`）发到 collector 套接字，2xx 即成功；超时 200 ms；失败丢弃该帧并退避 10 秒，不排队、不重试。只有 `detail=true` 的站点（越过哨兵）才带 `ips` 与 `samples`；`behavior` 恒为空数组；样本中 asn/country/ua_family/path_template/query_names_hash/header_order_hash 暂空，由 agent 侧按 IP 库与规范化补齐。
- 门控：agent 经控制套接字 `POST /autodefense/gate` 增量写入 `{revision, collector, platform_allow[cidr], sites[{site_id, mode, detail, whitelist{networks,ja4}, signatures[{id, stage, plan}]}], remove_sites[], mitigations[{site_id, kind, target, level, rate_milli, until}], remove_mitigations[{site_id, kind, target}]}`；`plan` 是 D6 规则计划 `cdnca.edge.rule-plan/v1`（签名→IR 由 AD-03 编译），节点以 `evaluate` 非 allow 为命中。处置条目以 `until` 作字典 TTL 自动到期。`GET /autodefense/gate` 返回 revision 与推送/淘汰统计。L1 挑战为模块自带 JS cookie（HMAC 绑定站点+客户端地址+小时）。


## 7. 不在本契约内

- 素描二进制格式（AD-01）、判定与挖掘算法（AD-02/03）、签名→D6 IR 编译（AD-03）、PG/CH 表（AD-08）、页面（AD-1x）。
- S5 封禁名单的 `source=autodefense`、`scope_kind` 扩展（ADR §8.2，由 AD 任务在 S5 控制面合入后补迁移）。
