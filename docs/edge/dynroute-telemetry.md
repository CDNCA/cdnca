# 动态路由遥测与日志（D12）

- 状态：D12 实现（10-18）。依赖 [dynroute-contract.md](dynroute-contract.md)（D3 冻结契约 §1 `$cdnca_site_*`），**不改该契约**。
- 实现：`libs/edgeconfig/dynroute_telemetry.go`（日志格式、access_log 指令、变量表）、`edge/openresty/dynroute/cdnca_telemetry.lua`（log/body_filter 阶段）、`agents/edge-agent/internal/dyntelemetry`（归属表、行还原、共享源解析、error.log 过滤）、`eventspool.TailConfig.Resolve`（共享源按行绑定身份）、`siteindex.Activator.Prepare`（激活前登记归属）、`edgeskeleton.Input.Telemetry`。
- 验收：`tests/dynroute-telemetry/run.sh`（真实 OpenResty 1.31.1.1，`--rm --network none`，2 worker）。

## 1. 目标与边界

v7 每个监听一个 server，身份写死在 server 级 `set $cdnca_site_id …`，日志路径 `shared/telemetry/<cv>/<site>/<port>/{access,security}.jsonl` 本身就是身份（agent 按路径绑定 `TrustedIdentity`，行内身份只做核对）。共享 server 下一个端口上万个站点，不能再一站一文件，也不能信任行内字段。D12 做法：

1. 节点只写**两个节点级文件**，行 = **v7 行原样** + 归属对象 `cdnca`；
2. agent 按归属对象读站点对象复核，把行**还原成该站的 v7 行**与同样的 `TrustedIdentity`，交给既有事件 spool；网关、ClickHouse、主控**完全不变**（同一 v7 格式、同一校验）。

## 2. 节点侧

### 2.1 文件

`<shared>/telemetry/dynroute/access.jsonl`、`security.jsonl`（`edgeconfig.DynamicRoutingTelemetryPaths`；`<shared>` = 骨架 `Paths.SharedRoot`）。权限、轮转同 v7（agent 预建 0600，tailer 跟踪轮转/截断）。

### 2.2 行格式

`cdnca_access_json` / `cdnca_security_json` 由 v7 的 `telemetryAccessJSON` / `telemetrySecurityJSON` **同一常量**派生（`dynamicRoutingLine`），字段、顺序、变量与 v7 相同，只有两处差别：

| 差别 | v7 | 动态路由 | 理由 |
|---|---|---|---|
| `client_ip` | `$remote_addr` | 受信代理链结果（见下） | 已定 |
| 末尾追加 | — | `"cdnca":{"generation":$cdnca_site_generation,"scope":"$cdnca_site_scope","digest":"$cdnca_site_digest","port":$cdnca_site_port}` | 归属；agent 还原时删除 |
| 安全行 `listen_port` | `$server_port` | `$cdnca_site_port` | 共享 server 的 `$server_port` 是套接字端口，mux 内部 unix 套接字上为空；选中的公网端口才是 v7 语义 |

`config_version_id` 节点写空串（发布身份不在请求路径上），由 agent 填。

第三处差别：`client_ip` 按站点受信代理链取值（`$cdnca_telemetry_client_ip` ← `cdnca_origin.client_ip()`）：对端在站点 `origin.trusted_proxy_cidrs` 内且 `X-Real-IP` 是合法地址时取它，否则取对端（`$remote_addr`，含 PROXY protocol 源）——即发给源站的 X-Real-IP。v7 一律记对端；无受信代理的站点两者相同（金标 access-logs 不受影响）。采集事件同样替换。采集站点用 v7 同一段采集 Lua（`telemetryCaptureLogBody`，标记 `cdnca:capture-begin/end` 之间，`TestDynamicRoutingCaptureLuaIsV7` 保证逐字节相同，唯一替换是上面的 `listen_port`），产出的 JSON 再由 Lua 追加同一个归属对象。

### 2.3 变量

`log()` 在 `$cdnca_site_state == "ok"` 且站点对象有 `telemetry` 时写：`$cdnca_tenant_id ← $cdnca_site_tenant`、`$cdnca_site_id ← $cdnca_site_id`、`$cdnca_config_version_id ← ""`、`$cdnca_node_id ← ""`、`$cdnca_ja4_log ← $cdnca_ja4 或 ""`，以及 v7 server 级默认值（`$cdnca_security_emit 0`、`$cdnca_security_block_page 0` 等，模块未写过才填）；最后 `$cdnca_telemetry ← plain | capture`。四条 `access_log … if=` 按 `$cdnca_telemetry`（与 `$cdnca_security_emit`）选格式，**一个请求最多一条访问行 + 一条安全行**。安全事件变量（`$cdnca_security_*`、`$cdnca_security_block_page`）仍由 CC（server_rewrite）与 D6 解释器（rewrite）按 v7 名写，D12 不改它们。变量声明表 `edgeconfig.DynamicRoutingTelemetryVariables`（不含 `cdnca_site_*`，契约 §1 第 4 条）。

### 2.3a 聚合安全行（sec-log-agg）

CC 挑战页与 429 不逐条记：引擎设 `$cdnca_security_aggregate=1`（不设 emit），`log()` 在共享字典 `cdnca_security_agg`（8m）按（分钟, 站点, 客户端 IP, 类型, 规则, 动作）计数，每键首个请求存一行（plain 安全行字段，采集字段为 null，`count` 在 `cdnca` 归属对象前）。worker 0 每 5 秒把已结束分钟的行经本机 `unix:<state>/run/secagg/flush.sock` 交给 flush server，该 server 用 `cdnca_security_capture_json` 写进 master 打开的 `security.jsonl`。创建临时封禁仍逐条 emit。`run/secagg` 由 agent 建为 0710、worker 组（nginx 把 unix 监听设为 0666，访问控制靠目录）；能进入该目录的本机进程可注入行，agent `Normalize` 仍按站点对象复核归属（scope/租户/站点/端口/Host）。`count` 经事件池、网关、主控入库为 CH `security_events.event_count`（CH 迁移 025，缺省 1），日志查询返回 `count`，攻击汇总按 `sum(event_count)`。

### 2.4 归属规则（写进契约的部分）

| 请求 | 是否记日志 | 归属 |
|---|---|---|
| `$cdnca_site_state = ok`，站点有 `telemetry` | 记 | 选中的站点（按 Host 选站，SNI≠Host 时按 Host，BATCH-PLUGIN 第 12 条） |
| `ok`，站点无 `telemetry`（scope 无遥测） | 不记 | — |
| `unknown`（端口上无此 Host，含 IP/空 Host/`[::1]`，421） | **不记** | 与 v7 默认 server（`access_log off` + `return 421`）一致；不归属给任何租户 |
| `unknown` 而被节点级 location 服务（健康、ACME overlay、市场探测、基准对象） | **不记** | 同上：v7 默认 server 服务这些路径时不记 |
| `not_ready`（索引未就绪/对象缺失，503） | **不记** | 选站前就结束，没有可信站点；计入节点健康而非租户 |
| 内部跳转、`error_page`、`ngx.exec` 后 | 记一次 | 选站只做一次（契约 §1 第 2 条），归属不变 |
| 代切换中途的请求 | 记 | 选站时读到的代 g（`generation` 字段），agent 按 g 查发布版本 |

## 3. agent 侧

### 3.1 归属表 `dyntelemetry.Registry`

(代, scope) → config version 的分段表：`Register(first, last, scopes)` 表示 first..last 这些代里各 scope 服务的发布版本（`scopes` 是整个节点；缺席即已离开）。`siteindex.Activator.Prepare` 在**第一次 stage 或重建之前**调用它，所以任何代被服务前已能归属；分片激活登记一个代区间；回滚到旧代按旧段解析；未用代区间（激活失败后重试同一 first）可覆盖。只保留最近 64 代（`Window`），持久化为私有文件（原子重写），agent 重启后仍能还原积压行。

### 3.2 行还原 `dyntelemetry.Normalize`

拆出归属对象（严格：未知字段、重复键、代 0、非小写摘要都拒绝）→ 查归属表 → 按摘要从 worker 可读对象目录读站点对象（SHA-256 校验 + `edgesite.Decode`）→ 核对：站点有 telemetry、`scope`/`tenant_id`/`site_id` 是该对象的、`config_version_id` 为空、站点服务该端口、`host` 是站点名字之一（精确或通配规则）、安全行 `listen_port` = 归属端口 → 填 `config_version_id`、删归属对象 → `TrustedIdentity{ListenPort, TenantID, SiteID, ConfigVersionID, CapturePolicyRevision, CapturePolicyDigest}` 与采集策略（同 v7 清单转换，0 取默认上限）。之后走 `eventspool.ParseSourceLineBound`，与 v7 tailer 完全相同。

不信任行内任何身份：伪造的租户、站点、scope、摘要、端口、Host 都与站点对象不符而被隔离（`TestNormalizeRefusesWhatTheSiteObjectDoesNotConfirm` 13 种）。

### 3.3 共享源 `TailConfig.Resolve`

一个 tailer 读一个节点级文件，每行由 `Resolver.Resolve` 绑定身份。代或对象暂不可得（`ErrUnattributed`）→ `ErrLineNotReady`，tail **停在该行**（保序、不丢），下一轮重读；超过宽限 30 s 才隔离（只在 agent 丢失归属表等异常时出现）。批次在追加前按站点维度稳定排序，事件 spool 的发布仍是一站一批（`samePublicationDimension`）。

### 3.4 节点 error.log

`dyntelemetry.ErrorLog` 增量读 `<shared>/error.log`，只过滤 D2 定的 `quic reuseport` reload 噪声：`[emerg] <pid>#<tid>: close() socket <IPv4|[IPv6]>:<port> failed (9: Bad file descriptor)`（行尾精确匹配，样本来自真实 OpenResty，`testdata/reuseport-reload-noise.log`）。errno 不是 9、级别不是 emerg、带 `client:` 后缀的都照常报；其余 alert/crit/emerg 全部返回。上报方式：走心跳，只报计数（噪声数、严重行数、丢弃数）与最近 N 条严重行摘要，不进访问日志流；接线在 D13，本任务只留 `ErrorLog.Read() → ErrorLogSummary{Severe, Noise, Lines}` 与 `Dropped` 接口。

## 4. 与 v7 金标的关系

D0 `access-logs` 场景（主域名、通配子域、POST、源站 404、WAF 拦截 + 安全事件）在共享 server 下经 agent 还原后与 v7 金标**逐字段相同**（掩码同金标），无语义变化，`compare.json` 不需要登记。金标渲染器整体接入（`edgegolden.Renderer`）需要 D5 回源与 D7 安全，本任务的验收程序直接读场景事实与金标文件比对。

## 5. 给 ge-analytics / ge-ddos 的字段需求

站点对象不需要新增字段：遥测身份全部来自站点对象已有的 `tenant_id`/`site_id`/`configuration_scope_id`/`hosts`/`listeners`/`telemetry`。对接要点：

| 需求方 | 新日志字段 | 动态路由侧要求 |
|---|---|---|
| ge-analytics 带宽按传输时长分摊（CH 019 `duration_us`） | `duration_us` = `$request_time` 微秒（或起止时间） | 加进 `telemetryAccessJSON` 常量即两种运行时同时生效；字段由 nginx 变量求值，与站点无关 |
| ge-analytics 省份/浏览器/OS/UV | 省份：节点 IP 库查表（G3-c）或 CH 侧；UA：日志带 `user_agent` 后 CH 侧解析；UV：CH `uniq(client_ip)` | `user_agent`、`province` 若节点写，同样加进 v7 常量；节点查表在 `log()` 里写 `$cdnca_*` 变量（与 JA4 同模式），不进站点对象 |
| ge-ddos 安全事件 country/carrier 填充 | `country_code`、carrier 编码进安全行 | 节点只写 IP 库编码（国家码 + carrier 标签位），主控按 `ipintel` 目录映射成运营商名称，与 ge-analytics 已合入的“主控入库时查 IP 库补全”一致；节点不加名称字段，站点对象不加字段 |

ge-analytics 已合入的 `duration_us`、`client_browser`、`client_os`（访问行）与 `cache_status` 等字段都是 http 级 map，动态路由经共用常量与 `renderTelemetryMaps` 自动带上（合入集成 fc9c6d9b 后验收仍 0 差异）。

规则：**新字段一律加在 `telemetry.go` 的两个常量**（v7 与动态路由共用），需要 Lua 计算的变量在 `cdnca_telemetry.log()` 写并登记到 `DynamicRoutingTelemetryVariables`；不得在动态路由格式里单独加字段，`TestDynamicRoutingLinesAreV7Lines` 会失败。

## 6. 实测（本机 arm64 Docker Desktop，load 5–11，耗时只作量级）

| 项 | 结果 |
|---|---|
| 金标 access-logs | 6/6 行逐字段一致 |
| 1 万站（8 scope / 4 租户，双端口，主域名/别名/通配）激活 | 1.1–1.2 s |
| 混合流量 60,200 请求、32 并发、中途 2 次代切换 | 48,111 条应记请求 **100% 归属正确**（错 0、漏 0、重 0、无法归属 0、多余 0）；未知 Host 6,060 与节点路径 6,029 请求 0 行；行按代分布 1:24023 / 2:18795 / 3:11271 |
| 采集站点 | 允许头采集、Authorization 脱敏、前缀外不采；采集身份 = 站点对象；真实 tailer 进 spool 3/3 |
| quic reuseport 两次 reload（2 worker × IPv4/IPv6） | 8 条 EBADF 噪声全部过滤，其他 alert/crit/emerg 0 |
