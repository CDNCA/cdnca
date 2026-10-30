# 动态路由 D7：安全模块按站点对象执行

- 实现：`edge/openresty/dynroute/cdnca_security.lua`（各阶段入口，由骨架入口 `cdnca_dynroute.lua` 调用）、`cdnca_rule_plan.lua`（站点对象规则 → D6 计划）；引擎的对象入口：`ccv2/engine.lua` `configure`/`access_object`、`httppolicy/engine.lua` `access_object`、`firewallaction/engine.lua` `handle_object`、`challenge/engine.lua`（可多实例加载）。agent：`siteindex` 激活器写入并按代保留站点引用对象。
- 依据：[dynroute-contract.md](dynroute-contract.md)（D3 冻结契约）、[site-object-v2.md](site-object-v2.md) §3–§4、ADR 0009 §3.2/§4。v7/v8 编译路径不动（D13 删）。

## 1. 阶段与顺序（与 v7 相同）

| 阶段 | 函数 | 做什么 | v7 对应 |
|---|---|---|---|
| `server_rewrite`（在 `cdnca_site.route()` 之后） | `server_rewrite(site)` | 按公网端口（`proxy_protocol_server_port or server_port`）找 `security.cc` 中含该端口的绑定，`cc.access_object(policy.sha256, read)` | 每个监听一个 `server_rewrite_by_lua { cc.access(entry_id) }` |
| `rewrite` | `rewrite(site)` | `security.rules` → D6 计划（`cdnca_rule_plan.plan`）→ `cdnca_rule_interp` 编译（按站点对象摘要缓存）→ evaluate；block 403、log 记遥测 | 内联 `rewrite_by_lua_block`（`renderWAFBlock`） |
| `access` | `access(site)` | 防火墙动作 → JS 挑战 → HTTP 策略 | `writeRuntimePolicyLocation` |
| `header_filter` | `header_filter(site)` | HTTP 策略响应头/CORS | `httppolicy.header_filter()` |
| `log` | `log(site)` | CC 完成计数（404 统计、自动切换 5xx） | `cc.log()` |

回源签名（D5）在 `access` 中排在本模块之前，高级缓存派发在之后；托管 WAF（ModSecurity）不在本模块（见 §5）。

## 2. 引用对象与缓存

- 站点对象里以摘要引用的对象（CC 策略、HTTP 策略条目、防火墙动作）都经 `cdnca_site.object(digest)` 读取（worker 可读对象目录，校验 SHA-256），不自行打开路径。
- 每个派生物按其来源的摘要缓存在 worker 内（`resty.lrucache`，`configure{cache_items}`，默认 10000；挑战实例 `challenge_items` 默认 1000）：摘要即身份，不需要失效。缓存应按节点热站数配置，与 `cdnca_site` 的 `lru_items` 同档。
- 引用对象缺失、摘要不符、内容非法、属于别的站点：请求 503（失败即拒绝，与 v7 发布文件校验失败同义）。
- agent：激活器的保留/回收统一用 D4 方案（`referencedBy` + `release` 读被删站点对象的引用，只删不再被当前代或上一代引用的）。`siteindex.Object.Referenced` 可选携带引用对象：`Activate` 在任何站点对象可路由前写入；未携带时引用对象必须已在目录（例如网关拉取已写入），否则拒绝激活。

## 3. 各模块语义

- **CC**：条目以策略对象摘要为键；计数/封禁/挑战状态键与 v7 相同（`binding_id:binding_revision:rule_id:client`），并且**一律按租户 scope 前缀隔离**（动态路由所有 scope 共用一个节点字典，等同 v7 组合节点的 `scoped_state`）。所以切换到动态路由时计数与封禁清零（ADR 0009 §6 已列）。遥测变量写 `$cdnca_security_*`（`configure{variables}`）。
- **ACL/WAF 规则**：`cdnca_rule_plan` 是 `edgeconfig.CompileSecurityRulePlan` 的 Lua 版；`libs/edgeconfig/dynroute_rule_plan_integration_test.go` 用 D6 随机生成器（1200 套、17549 条规则，含 header/inspect/ip_intel）逐项比对 Go 与 Lua 的计划。站点对象里规则已按端口合并（site-object-v2 §4），所以一条规则可能没有任何条件（v7 钉的端口被去掉），解释器接受空条件（恒真）。
- **防火墙动作**：`handle_object(digest, read, site_id)`，与 `handle(path)` 共用执行逻辑；策略站点必须是本站。
- **JS 挑战**（init 预加载、下发时 reload，不放宽 worker 可读）：骨架 `Input.Challenges`（`edgeskeleton.ChallengesFromSites`，全部站点绑定的（policy_id, revision）去重排序）渲染进 `configure{challenges}`，master 在 init 里为每个版本加载一个引擎实例（读 `<StateRoot>/challenge/policies/<id>/versions/<20 位版本>.json` 与 root-only 密钥，与 v7 相同）；新下发的版本改变骨架输入 → reload。未加载成功的版本只让绑定它的站点 503（v7 是整份 `nginx -t` 失败）。`crypto`/`ip` 辅助模块只在加载期间绑定到挑战目录的文件（origin auth 另有同名 `crypto`）。
- **HTTP 策略**：站点对象 `http_policy` 引用的是该站在快照中的条目原文；`access_object` 校验与 v7 同一个 `validate_site`。响应头 `X-CDNCA-HTTP-Policy-Version` 报 `http_policy.revision`（v7 报 scope 快照版本；定按站点 revision，已登记 `compare.json` semantic_changes；金标场景二者相同，均为 3）。
- **快速屏蔽站点覆盖**：主控在编译 WAF 绑定时把站点覆盖（继承/开/关）并入规则（`SiteQuickBlockPolicy`），站点对象携带的就是生效结果，节点无额外语义；`TestSiteObjectsV2CarryQuickBlockSiteOverride` 验证三种覆盖进入对象后的规则与 v7 逐条相同。

## 4. 验收

- 金标（`CDNCA_EDGE_GOLDEN_RENDERER=cdnca-dynroute tests/edge-golden/run.sh check cc,js-challenge,http-policy,acl-waf`）：共用渲染器 `goldendyn`（D5a/D5b/D8 同一个）。有监听安全或 HTTP 策略的场景，站点对象由主控生产转换（control-api `cmd/cdnca-site-objects-v2` = `edgepublish.BuildSiteObjectsV2FromBundle`）从 v7 同一份签名发布生成；节点配置就是骨架 `edgeskeleton.Render`，所有阶段经 `cdnca_dynroute` 入口。四个场景 SAME；把本模块四个阶段关掉时 283 处差异（合入前测过）。
- 防火墙动作：`tests/dynroute-security/firewall-action.sh`（同一策略字节，v7 文件路径与对象路径对 IPv4/IPv6 拦截/放行结果相同；摘要不符/他站对象 503）。
- 耗时：`tests/dynroute-security/bench.sh`（§5）。

## 5. 实测：1 万站各带安全策略的每请求额外耗时

每站独立的 CC 策略（固定窗口，不触发）、ACL 3 条 + WAF 3 条规则、HTTP 策略（请求/响应头、重写、跳转）、防火墙动作，共 3 个引用对象/站；另 1 万站无安全作对照；一个 worker，按阶段用 CLOCK_MONOTONIC 计本模块自身耗时。本机 arm64 Docker Desktop，10 vCPU，同时有其他任务（load 19–27），两次运行，耗时只作量级：

| 项 | 第 1 次 | 第 2 次 |
|---|---|---|
| 站点对象 / 引用对象总量 | 36.1 MB / 18.0 MB | 同 |
| 首次激活（写对象 + 索引 + 重建） | 12.8 s | 13.7 s |
| warm 每请求（随机站，2 万次） p50 / mean / p99 | 38 µs / 77 µs / 0.58 ms | 50 µs / 96 µs / 0.63 ms |
| 其中 server_rewrite（CC）p50 | 9.2 µs | 12.6 µs |
| 其中 rewrite（规则）p50 | 4.8 µs | 5.7 µs |
| 其中 access（防火墙+HTTP 策略）p50 | 19.8 µs | 26.4 µs |
| cold：每站首个请求（建 CC 条目、编译规则、解析策略） p50 / p99 | 217 µs / 1.7 ms | 273 µs / 3.7 ms |
| 端到端：有/无安全两端口 p50 差 | 噪声内（±200 µs 两个方向） | 同 |

结论：每请求额外开销在几十微秒量级，与站点数无关（按摘要的 worker 缓存命中）；首个请求的冷开销是一次性的、毫秒以内，缓存容量需覆盖热站集（超出时退化为每次冷读）。

## 6. 骨架接入（已做）

- 入口 `cdnca_dynroute.lua`：`server_rewrite` 选站 → TLS → CC；`rewrite` 规则；`access` 防火墙动作 → JS 挑战 → HTTP 策略 → 回源选路 → 缓存派发；`header_filter`/`log` 各接一处。缓存变体（`ngx.exec` 进命名 location 时 `rewrite`/`access` 再跑）不重复执行安全阶段（`ngx.req.is_internal()`）。
- 骨架：`lua_shared_dict cdnca_cc_state 64m / cdnca_challenge_state 16m / cdnca_firewall_action 16m`；`lua_package_path` 加 `<lua>/security/?.lua`；`configure{challenge_root, challenge_lua, challenges}`；6 个 `$cdnca_security_*` 变量声明；`Input.HealthPort` 渲染回环健康 server（`/healthz`、CC 自动切换状态与 ge-ddos 内核封禁队列 `/healthz/cc-kernel-bans`、ge-waf S5 封禁名单 `/healthz/security-bans`（`cdnca_banlist`，字典 `cdnca_security_bans`；封禁名单是运行态，不进站点对象））；`variables_hash_max_size 2048 / bucket_size 128`（各模块变量已超默认哈希）。
- 合入时补齐的 ge-origin 回源语义（动态路由原缺，金标 forwarding/l2-fallback 暴露）：`X-Forwarded-For`/`X-Real-IP`/`X-Forwarded-Proto` 由 `cdnca_origin` 写 `$cdnca_origin_xff/real_ip/proto`（只在 origin 池、非缓存预热；换池时 `recreate_request` 重建）；`Location`/`Refresh` 指向源站地址时改写为访客 Host（`cdnca_origin.header_filter`）。受信代理链由站点对象 `origin.trusted_proxy_cidrs` 决定（D5a）。
- `resty.ipmatcher` 原生缺失（定为产品缺陷，已修）：`edge/openresty/vendor/lua-resty-ipmatcher`（v0.6.1 钉值同容器镜像，sha 1c40f52b…）经 `/source-contract/vendor/` 进两份镜像（容器镜像不再联网下载、改用同一文件并校验钉值），原生包 `runtime/openresty/lualib/resty/ipmatcher.lua` 为必需数据成员（0444），验收的 build inputs 记录它。反证：`IPMATCHER=none tests/dynroute-security/firewall-action.sh` 在修复后原生镜像 RESULT ok，在修复前镜像 RESULT fail（全部 503）。

## 7. 遗留与待定

1. 托管 WAF（ModSecurity）由 D11 负责。
2. ge-waf（WAF v2 动作、观察模式、自动封禁、新检查点字段）合入后需：edgesite RulePolicy 加 `mode`/`auto_block` 并放行 challenge/ban 与 `action_config`；`cdnca_rule_plan.lua` 的 inspect JSON 加 `filters`/`body_overflow`、生成段 `action`（`TestDynrouteRulePlanMatchesGo` 会报不一致）；`cdnca_waf.gate/act` 遥测变量名可配；骨架加 `cdnca_waf_state`。
3. 受信代理（`origin.trusted_proxy_cidrs`）站点对象字段未有，动态路由一律以对端为客户端。
