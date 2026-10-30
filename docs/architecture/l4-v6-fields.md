# L4 v2 流在 1.0.35 新增字段约定（G4 / G5）

1.0.35 的四层新特性都加在 `libs/edgeconfig/l4_v2.go` 的 `L4StreamRuntimeV2`（及 agent 侧 `l4runtime.StreamRuntimeSpecV2` / `ListenerV2`）上。节点 agent 严格解码（`DisallowUnknownFields`），所以：

- 新字段一律 `omitempty`（指针或零值省略），不用时签名产物逐字节不变；
- 每个字段由一个能力版本门控（`edgepublish.l4StreamCapabilityVersion` + `gatedFeature`），目标节点不具备时发布前直接拒绝，不做降级；
- tcp/udp 能力版本单调：声明 vN 的 agent 认识 v≤N 的全部字段。G4 组内串行，按下表顺序占号；
- 字段在结构体里的位置固定（JSON 输出顺序即结构体顺序），各子任务只在自己的位置插入，不挪动别人的字段。

| 子任务 | 字段（JSON） | 位置 | 形状 | 门控 |
| --- | --- | --- | --- | --- |
| G4-a #3 单 IP 新建连接速率 | `new_conn_rate` | 流级，`server_names` 之后第 1 个 | `*L4NewConnRateV2{rate_per_second, burst, ban_seconds}` | tcp/udp **v6** |
| G4-b #6 会话日志 | `session_log` | 流级，`new_conn_rate` 之后 | 由 G4-b 定（建议 `*bool` 或小对象）；实时连接不走流字段，用能力名 37 `L4_LIVE_CONNECTIONS` | tcp/udp **v7** |
| G4-c #4 端口范围 / 跟随端口回源 | `port_end`（监听，`listener` 与 `additional_listeners[]` 各自可带，表示 `port..port_end`）；`follow_port`（`endpoint` 内，`bool`） | `L4ListenerV2` / `L4AdditionalListenerV2` 的 `port` 之后；`L4EndpointV2` 的 `port` 之后 | `int` / `bool`，均 `omitempty` | tcp/udp **v9** |
| G4-d #8 四层防护规则 | `guard_rules` | 流级，`session_log` 之后 | `[]L4GuardRuleV2`，最多 64 条（见下文 #8） | tcp/udp **v10**（geo 条件另需 IP_INTEL v2） |
| stream-be 源站列表 / 定源 / IPv6 | `endpoint.origins`、`endpoint.balance`、`listen_ipv6` | `origins`/`balance` 在 `L4EndpointV2` 的 `follow_port` 之后；`listen_ipv6` 流级，`subscription_limits` 之后、`toa` 之前 | `[]L4OriginV2{address,weight 1..100,down}` 最多 64 个，只收 IP、至少一个上线，`address` 等于第一个；`balance` 只取 `ip_hash`（省略为按权重轮循） | tcp/udp **v11** |
| G5 TOA | `toa` | 流级，`guard_rules` 之后（最后） | `bool`，与 PROXY protocol 入站/出站都互斥 | tcp **v8**（字段解码）+ 能力名 36 `L4_TOA` v1（节点探测通过） |

说明：

- G4 若调整合入顺序，能力版本按实际合入顺序顺延，但字段名与位置不变。
- tcp v8 已由 G5 `toa` 按合入顺序占用（g4b 用了 v7），G4-c/G4-d 顺延到 v9 起，以合入时定号为准。
- `new_conn_rate` 的拉黑（`ban_seconds`）记在 L4 OpenResty 的 `lua_shared_dict l4_v2_rate` 里，键 `ban:<stream_id>:<client>`；#8 的 `ban` 动作复用同一个字典和键格式，升级为内核级拉黑也由 #8 接入。
- 节点侧计数的客户端地址与地域判定一致：`cdnca_l4_geo.enforce` 第三个返回值（PROXY 协议入站且来自可信代理时为真实客户端地址，否则为 `remote_addr`）。#8 的 IP 条件应复用它。

## #3 `new_conn_rate`（tcp/udp v6）

- `rate_per_second` 1–100000：每个客户端 IP 每秒可新建的连接数（UDP 按新会话计，`proxy_responses 1` 下每个请求数据报是一个会话）。
- `burst` 0–100000：在速率之外允许瞬时多出的连接数。令牌桶容量 = `rate_per_second + burst`，按 `rate_per_second`/秒回填。
- `ban_seconds` 0–86400：0 只拒绝超限连接；>0 时超限后该 IP 对本流的新连接在这段时间内一律拒绝（节点本地、按流）。
- 计数按“流 + 客户端 IP”，同一条流的多个监听端口共享额度；节点上各 worker 共享字典。
- 控制端：`l4_forwards.max_new_connections_per_client_per_second`（0 = 不限）、`new_connection_burst`、`new_connection_ban_seconds`（迁移 299 占位；0 时后两者必须为 0，v1 流不可设）。API 同名字段，发布意图 `runtime_spec.new_conn_rate` 仅在限速时出现。
- 节点：有限速流时 stream{} 声明 `lua_shared_dict l4_v2_rate 16m`；preread 在 `cdnca_l4_geo.enforce` 通过后调用 `limit_new_connections(stream_id, client, rate, burst, ban_seconds)`。字典键 `rate:<stream_id>:<client>`（令牌桶）与 `ban:<stream_id>:<client>`（拉黑）。参数非法或字典缺失时拒绝连接（fail closed）。各 worker 的读改写不加锁，并发时可能多放行少量连接。
- 门控：带 `new_conn_rate` 的流要求 tcp/udp v6；目标节点会话能力低于 v6 时发布前 422 `node_capability_unavailable`，错误里列出所有不满足的节点。拉黑目前只在节点本地字典，未接入 nftables（由 #8 接入）。

## #6 `session_log`（tcp/udp v7）与实时连接（能力 37）

- 字段：流级 `session_log: bool`（`new_conn_rate` 之后，omitempty）。未开启时规范 JSON 与节点 nginx.conf 逐字节不变。
- 节点（开启的流）：日志格式 `l4_session_v2`（v1 + `client`、`remote_addr`/`remote_port`、`proxy_protocol_port`、`upstream_addr`、`upstream_connect_time`、`end_reason`），被 Geo/新建速率拒绝的会话照常出一行。`end_reason`：Lua 写入 `geo_blocked`/`rate_limited`/`banned`/`bad_request`/`config_error`/`killed`，其余由 agent 按 `$status` 推出（200 `closed`、400 `bad_request`、403 `forbidden`、502 `upstream_failed`、503 `conn_limited`、其它 `internal_error`）。nginx 的空闲超时与对端关闭同为 200，不区分。
- 链路：l4.jsonl → eventspool `Envelope.L4Log` → `L4SessionEventV1.session_log`（`L4SessionLogV1`）→ 网关校验 → NATS `L4_SESSIONS_INGEST_V1`。地址只在该子消息里传，facts 表仍不含地址。
- 实时连接：只登记 TCP（v2 UDP 每个请求数据报一个会话）。preread 通过后按内核四元组 `<本地址>|<本端口>|<对端址>|<对端端口>` 写 `lua_shared_dict l4_v2_live 64m`（LRU），log 阶段按 `pid:connection` 令牌删除；agent 经 `/var/lib/cdnca-edge/shared/l4ctl/control.sock`（目录 0700 归 agent）`get`/`kill`/`stats`。断开方案：pidfd_getfd + shutdown（Docker Desktop linuxkit 内核未开 `CONFIG_INET_DIAG_DESTROY`，不用 SOCK_DESTROY）。

## #4 `port_end` / `follow_port`（tcp/udp v9）

- 字段：`listener.port_end`、`additional_listeners[].port_end`（`port` 之后，omitempty）：该监听为 `port..port_end`，`port_end > port`，最多 1000 个端口（`edgeconfig.L4PortRangeMax`），不得覆盖 80/443/18080/18443（`L4RangeProtectedPorts`）。`endpoint.follow_port`（`port` 之后，omitempty）：回源端口取客户端连入的端口，此时 `endpoint.port` 必须等于主监听 `port`。都不用时规范 JSON 与 nginx.conf 逐字节不变。
- 共享规则：范围是独占套接字，不能 TLS 透传（不按 SNI 拆分），与同协议任何声明（网站、其他四层、范围）重叠即冲突；`PortClaim.PortEnd` + `FindPortConflicts` 按区间比较，`PortConflict.Overlap()` 给出重叠端口段。
- 节点：`listen 0.0.0.0:起-止[ udp];`；follow_port 的 upstream 是占位 `server 0.0.0.1:1;` + `balancer_by_lua_block`，地址取 agent 按 L4 DNS 策略解析出的地址集（内联在 nginx.conf，IPv6 加方括号），端口取 `$server_port`（分发器后为 `$proxy_protocol_server_port`），首次按连接号挑地址，失败依次重试其余地址。遥测目录按范围起始端口，日志行 `server_port` 记实际端口。预检逐端口探测；实时连接把范围展开成端口集（超过 4096 个端口时不下发 inet_diag 过滤，改在 agent 内按端口过滤）。
- 控制端：`l4_forwards.listen_port_end`、`upstream_follow_port`，`l4_forward_listeners.port_end`（迁移 331）；套餐 `stream_ports` 按端口数计。
- 门控：带范围或 follow_port 的流要求 tcp/udp v9；旧节点 422 `node_capability_unavailable` 并列出全部节点。

## #8 `guard_rules`（tcp/udp v10）

- 字段：流级 `guard_rules`（`session_log` 之后、`toa` 之前，omitempty，最多 64 条），`edgeconfig.L4GuardRuleV2`：`id`（uuid）、`action`（`drop` / `ban` / `allow`）、条件（至少一个，全部满足才命中）：`first_packet{match: prefix_hex|contains|regex, value}`、`server_names`（仅 TLS 透传流，按 ssl_preread 读到的 SNI）、`client_ip{cidrs, negate}`（每条 ≤1024、整流 ≤4096 段）、`geo`（`[]WAFIPIntel`，≤4 个，节点 `cdnca_iplib` 查表）；`ban` 另有 `ban_seconds`（1–86400）、`threshold`（1–10000，1 = 首次命中即拉黑）、`window_seconds`（threshold>1 时 1–3600）。不用时规范 JSON 与 nginx.conf 逐字节不变。
- 语义：按顺序判定，第一条命中的规则生效。`drop` 断开；`ban` 断开并按“规则 + 客户端”计数，窗口内达到阈值后该客户端对本流的新连接 `ban_seconds` 内一律拒绝；`allow` 结束防护规则判定（地域策略、新建速率照常）。客户端同地域判定（可信代理 PROXY 协议时为真实地址）。
- 首包：TCP 在 preread 里用 `MSG_PEEK|MSG_DONTWAIT` 轮询套接字，最多等 2.5 s（带首包规则的 server 设 `preread_timeout 3s`），取首段数据的前 512 字节；客户端一直不发（服务端先说话的协议，如 SSH/MySQL/SMTP）等满后视为不命中并照常转发，不会被误杀，但首连会多等 2.5 s。UDP 取第一个数据报（不消费）。正则在节点用 PCRE（`lua_regex_match_limit` 限制回溯），控制端按 RE2 校验，拒绝 `\C`/`\p`/`\P`。
- 节点：规则编译进 config.json 的 `listeners[].guard`（`cdnca_l4_geo` 校验，非法候选走 LKG）；preread 顺序 `enforce → guard → limit_new_connections → session_track`。拉黑复用 `l4_v2_rate` 字典 `ban:<stream>:<client>`（与 #3 同一把锁），计数 `hit:<stream>:<rule>:<client>`。
- SNI 条件：独占透传端口本来就 ssl_preread；共享端口（分发器后的 unix 套接字）上只有带 SNI 条件的流在自己的 server 里再开 ssl_preread（PROXY 头后仍是 ClientHello）。独占透传端口的 SNI map 变量名 54 字节，stream 默认 variables_hash_bucket_size 64 放不下（nginx 拒绝启动，此前无真进程用例覆盖），有这类套接字时声明 variables_hash_bucket_size 128。
- 内核级拉黑：客户端就是套接字对端（非 PROXY 协议转来）且套接字只属于本流（非分发器/透传共享端口）时，Lua 把拉黑写入 `kban` 队列；agent 经控制套接字 `bans` 取走，按流合并为防火墙 scope（`policy_kind=l4_guard`、`policy_id=<stream>`，条目为本流各监听的 协议+端口段 + 客户端 /32|/128 + `expires_at`），走 `firewall.Manager` 写入与网站侧同一张 nftables 表 `inet cdnca_firewall`，到期由既有 firewallExpiry 清理（按分钟，内核条目最多比字典拉黑晚约 1 分钟解除）。每流最多 4096 条，超出时保留最晚到期的。节点没有 nft 时只有字典拉黑。
- 门控：带 `guard_rules` 的流要求 tcp/udp v10；含 `geo` 条件另要求 IP_INTEL v2，并经 `validateFeatureCapabilityTargets` 要求目标节点已加载验签库（未就绪拒绝发布，库就绪后自动发布）。旧节点 422 `node_capability_unavailable` 列出全部节点。

## stream-be 源站列表 / 定源 / IPv6（tcp/udp v11）
- `endpoint.origins`：多个 IP 源站共用 `endpoint.port`，节点渲染 `server <ip>:<port> [weight=N] [down];`，`proxy_next_upstream_tries` 只数上线的源站。下线源站仍写进 upstream（`down`），使 `ip_hash` 的映射在上线后不变。域名源站只支持单个（`endpoint.host`）。
- `endpoint.balance=ip_hash`：`hash $remote_addr consistent;`。省略为 nginx 默认按权重轮循。
- `listen_ipv6`：流独占的套接字在 `0.0.0.0` 之外再 `listen [::]:<port> ipv6only=on`；走共享端口分派器的套接字不受影响（分派器自身只听 IPv4）。
- 门控：任一项出现即要求 tcp/udp v11，旧节点 422 `node_capability_unavailable`。

## l4-decouple 转发不属于网站（tcp/udp v12）
- 已定"四层转发与 HTTP 网站完全解耦"：转发归属 = 租户作用域 + 套餐订阅，线路/CNAME 自带或跟随套餐（控制端迁移 506 删 `l4_forwards.site_id`）。
- 运行时 JSON 顶层与 `geo` 都去掉 `site_id`。节点内部把流 ID 放在原 site 槽（`ListenerV2.SiteID`、遥测文件目录、会话信封与 NATS 主题第 6 段、DNS 状态键），每条转发自成一个分区；proto、NATS 主题形状、ClickHouse 列不变，`site_id` 列对四层行即转发 ID。
- 门控：每条 v2 流都要求 tcp/udp v12（不再按功能分档，1.0.35 基线）；v11 及更早节点 422 `node_capability_unavailable`。
