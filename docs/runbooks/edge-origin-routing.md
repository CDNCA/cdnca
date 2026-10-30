# 条件回源、重试与 L2 直回源

状态：已完成隔离的数据面纵向切片和真实 OpenResty 验收，尚未接入正式 site bundle、control API、Agent Gateway、管理员 UI 或节点灰度任务。当前实现不能单独把对照矩阵中的 SITE-05 至 SITE-08 标为完整交付。

实现位置：

- `agents/edge-agent/internal/originroute`：严格策略解析、规范化、匹配、重试/L2/自适应状态模型、确定性编译、不可变发布和 OpenResty runtime。
- `edge/openresty/originroute/engine.lua`：请求路径条件匹配、动态 peer 选择、有限重试、L2 熔断、可选 Peak EWMA/P2C 和入口源地址选择。
- `scripts/edge-origin-route-smoke.sh`：固定 OpenResty 1.27.1.2 的隔离容器验收。

## 兼容目标与证据边界

| 条目 | 公开基线 | 本切片证据 | 未完成边界 |
| --- | --- | --- | --- |
| SITE-05 条件回源 | `update-log` master v5.7.7 | 路径、节点区域和客户端 CIDR 使用 AND 组合；区域/CIDR 列表内部使用 OR；优先级、路径具体度、冲突和默认池有 Go 测试，真实 OpenResty 验证条件及优先级命中 | 未接网站编辑 API/UI 和签名站点制品 |
| SITE-06 源超时切换 | `update-log` master v5.8.8 | 真实连接拒绝、读超时、502/503/504、GET/HEAD 切换、POST/请求体不重放、尝试次数和总预算有自动化证据 | 未接站点级配置、指标和告警 |
| SITE-07 L2 失败直回源 | `update-log` master v5.8.8 | 真实 L2 失败后直源、开路、单探针半开、连续成功恢复、伪造 hop 隔离和运行时 hop 生成有自动化证据 | 未接 NODE-03 拓扑和 L2 mTLS 身份；v1 不支持 L2 到 L2 |
| SITE-08 入口 IP 回源 | `update-log` master v5.6.2/v5.8.5 | 发布前确认 IPv4/IPv6 地址属于本机，真实 OpenResty 验证每个目标地址族使用对应 `proxy_bind` | 仅在隔离节点 loopback 双栈验证；真实 NAT、多网卡、策略路由和故障节点验收未完成 |
| enhancement 自适应源选择 | 非基线替代项 | 默认关闭；shadow 保持原加权选择，active 才启用加权 P2C、Peak EWMA、慢启动、异常摘除和单探针恢复；真实 OpenResty 覆盖冷启动、状态过期/丢失、容量压力、时钟逆跳、摘除上限、全部异常和旧策略逐字节兼容 | 未接控制面高级模式、指标、告警或生产流量灰度；不能仅凭隔离 benchmark 默认开启 |

本切片没有使用外部实例推断字段语义。兼容依据只来自对照矩阵已记录的 `update-log` 条目；安全、确定性发布和熔断属于增强实现。

## 策略契约

schema 固定为 `cdnca.edge.origin-route/v1`。未知 schema、未知 JSON 字段、任意对象深度的重复 JSON key、尾随 JSON、空/超大策略一律拒绝。主要对象如下：

| 对象 | 关键字段与边界 |
| --- | --- |
| policy | 正 revision、稳定 version ID、1-16 listeners、1-64 pools、0-256 routes |
| node | token ID、规范小写区域、`l1` 或 `l2` |
| listener | 唯一 ID、IP literal 监听地址、非零端口、可选 IPv4/IPv6 ingress source |
| pool | 唯一 ID、`origin` 或 `l2`、1-32 endpoints |
| endpoint | 唯一 ID、IP literal、非零端口、1-100 权重；L2 必须指向非本机 node ID |
| route | -1000 至 1000 优先级、路径前缀、区域、规范 CIDR、目标池和可选直源 fallback |
| retry | 仅 `GET`/`HEAD`、1-8 次总尝试、10ms-60s 连接/读取超时、最大 120s 总预算 |
| l2 | 1-10 次失败/恢复阈值、100ms-60s 探测间隔、1-8 hop 上限 |
| adaptive | 可省略的版本 1 专家策略；`off` 规范化为省略，`shadow` 只观测，`active` 才改变选择；样本、freshness、EWMA、探索、慢启动和异常摘除均有硬边界 |

v1 endpoint 只接受 IP literal。真实 OpenResty 验证表明 `ngx.balancer.set_current_peer` 对主机名返回 `no host allowed`；请求阶段 DNS 查询会引入阻塞 I/O、TTL 漂移和不可重复发布，因此不能静默接受。现有 `siteconfig` 仍支持普通 DNS 源。正式合并条件路由前，控制面必须提供版本化解析结果、TTL/健康更新和签名绑定，或发布新的 schema；不能在 Lua 请求路径临时解析。

所有输入在写盘前完成规范化：listeners、pools、endpoints、routes、methods、regions 和 CIDRs 都按稳定规则排序。规范 JSON 与生成的 Nginx 配置共同进入 SHA-256 digest；相同语义输入得到逐字节相同制品。

## 路由排序

routes 按以下顺序比较，首个完全匹配者获胜：

1. `priority` 降序。
2. 更长的 `path_prefix` 优先。
3. 显式节点区域条件优先。
4. 更长的客户端 CIDR 前缀优先。
5. route ID 字典序只作为确定性尾排序。

相同 priority、路径、区域集合和 CIDR 集合的两条 route 直接返回 `ErrConflict`，不能依赖 ID 决定业务结果。路径按 segment 边界匹配；`/api` 匹配 `/api` 和 `/api/x`，不匹配 `/apix`。同一 route 的路径、区域和 CIDR 条件使用 AND；多个区域或 CIDR 使用 OR。未命中 route 时使用 `default_pool_id`。

L2 pool 在 L1 策略中必须显式配置不同的 origin fallback。L2 节点不能再路由到 L2，本机也不能作为自己的 L2 endpoint。拓扑级循环仍需 NODE-03 控制面校验；本切片只保证单节点策略不会自指，并通过禁止 L2 到 L2 消除 v1 的多跳路径。

## 重试安全

可切换故障仅包括：

- 连接错误或连接超时。
- 读取超时。
- HTTP 502、503、504。

重试同时受 `max_attempts` 和 `total_budget_ms` 限制。每次 balancer 进入前重新计算剩余预算，连接/发送/读取 timeout 不得超过剩余值；Nginx 的 `proxy_next_upstream_tries` 和 `proxy_next_upstream_timeout` 提供第二层上限。

只有策略显式允许、没有 `Content-Length > 0`、没有 `Transfer-Encoding` 且尚未开始下游响应的 GET/HEAD 可以切换。POST、带 body 的 GET、流式 body 和已开始响应的请求不重放；L2 失败时也不能为了“直回源”突破这一规则。启用 `non_idempotent` 是禁止项。

endpoint 权重只决定请求的首选 peer，后续尝试按规范 endpoint 顺序遍历且同一请求不重复相同 endpoint，避免权重环造成失败放大。

## 自适应源选择

`adaptive` 是增强能力，不替代原加权基线。字段缺失或显式 `mode=off` 都规范化为 nil，规范 JSON、Nginx 配置和制品 digest 与增强前逐字节相同。`shadow` 采集同样的有界遥测并计算候选，但实际请求仍使用原加权序列；`active` 才使用自适应序列。推荐先在 shadow 观察原因码、尾延迟、失败率和资源占用，再通过版本化策略灰度 active；关闭后立即恢复基线行为。

版本 1 的默认候选参数及可接受边界如下。默认值不是服务端隐式补齐值，控制面启用增强时必须显式生成完整对象：

| 参数 | 默认候选 | 边界 |
| --- | ---: | ---: |
| `minimum_samples` | 4 | 2-1000 |
| `sample_freshness_ms` | 30000 | 100-300000 |
| `peak_ewma_half_life_ms` | 10000 | 100-60000 |
| `exploration_percent` | 2 | 1-10 |
| `slow_start.initial_weight_percent` | 10 | 1-100 |
| `slow_start.ramp_ms` | 30000 | 100-300000 |
| `slow_start.hard_timeout_ms` | 120000 | `ramp_ms` 至 600000 |
| `outlier.minimum_samples` | 8 | `minimum_samples` 至 1000 |
| `outlier.consecutive_failures` | 3 | 1-20 |
| `outlier.failure_ratio_percent` | 50 | 1-100 |
| `outlier.max_ejection_percent` | 50 | 1-99，严格按 `floor(endpoint_count*percent/100)` 计算并始终至少保留一个 endpoint |
| `outlier.base_ejection_ms` | 1000 | 100-60000 |
| `outlier.max_ejection_ms` | 60000 | `base_ejection_ms` 至 600000 |
| `outlier.recovery_probe_interval_ms` | 1000 | 100-60000 |

每次成功或可切换失败都会更新 endpoint 的采样数、in-flight、连续失败、失败 EWMA、延迟 EWMA 和 Peak EWMA。设距上次观测为 `dt`、半衰期为 `H`，峰值按 `peak=max(latency, previous_peak*exp(-ln(2)*dt/H))` 衰减；普通 EWMA 使用有界样本系数。选择时按当前有效权重独立抽样两次，允许两次命中同一候选；先选择失败 EWMA 较低者，失败 EWMA 相等时再比较 `max(ewma, peak)*(inflight+1)/effective_weight`，分数较低者获胜。这样快速返回 502 的 endpoint 不会仅凭低延迟压过健康源，高容量 endpoint 也不会因为“必须抽到两个不同候选”而丢失权重语义。最多 10% 的确定性探索仍按当前有效权重选择，用于避免低流量 endpoint 永久饥饿；同一请求的重试安全和总预算不变。

新状态达到 `minimum_samples` 前使用原加权序列。进入自适应后，endpoint 从 `initial_weight_percent` 随 `ramp_ms` 线性恢复到配置权重；恢复探针成功会重新进入慢启动。连续失败或失败 EWMA 达到阈值后，摘除时间按次数指数退避并受 `max_ejection_ms` 限制。pool 级锁内严格向下取整计算 `max_ejection_percent`，不能把全部 endpoint 同时摘除；例如 3 个 endpoint、1% 的上限为 0，因此不会摘除任何 endpoint。

摘除到期后，只有候选真正进入 balancer 尝试时才申请恢复探针；仅构造序列或后来被其他候选抢先成功不会占用 lease。shared-dict 原子 fenced publication 只允许一个恢复探针，其他请求继续避开该 endpoint。L2 熔断和 adaptive 探针 token 都绑定本次实际候选，任何 peer、timeout 或 request rebuild 的早期失败都会释放本候选已经取得的 token 并撤销 in-flight。`recovery_probe_interval_ms` 只控制两次探针的最小间隔；另一个不可配置的 owner lease 覆盖完整 `total_budget_ms` 再加 1 秒清理余量，不能用较短的探针间隔代替请求期租约。lease 使用独立 fence generation 与 owner slot；admission、replacement 和 release 共用 exact revision/key 的 100ms mutation lock，迟到 writer 只能改写自己的旧 generation。release 写入 generation 专属 marker，使该 owner 在逻辑上立即失效，不物理删除 replacement 的 fence。pool 逐出锁使用 500ms crash-recovery TTL，发布 endpoint 状态前再次核对 owner generation，因此旧 owner 恢复后不能覆盖 replacement，也不能突破精确摘除上限。锁忙、写入失败或 shared-dict 淘汰均降级到 baseline。worker 崩溃时不由其他请求猜测释放 probe lease；有 TTL 的 mutation lock、probe lease 和逐出锁分别到期恢复。

以下情况立即使用原加权序列，不尝试猜测：任一 endpoint 样本不足或过期、状态缺失/损坏、shared dict 不存在或余量不足、强制淘汰、锁/写入失败、时钟逆跳。packed 状态必须是 10 个有限数值字段；样本数、连续失败和逐出次数必须为有界整数，失败率必须在 0 至 1，延迟、时间戳和逐出截止时间也必须落在契约边界内，NaN、Inf、小数计数和未来时间一律按损坏状态降级。若状态或 in-flight 写入在 balance 阶段失败，runtime 会在调用 `set_current_peer` 前重建尚未尝试的真实基线序列；原因码、诊断和实际 peer 保持一致，当前请求也不再继续写 adaptive 遥测。pool 逐出锁内先重读其他 endpoint，再把本 endpoint 的精确逐出状态写入 shared dict，最后按 owner token 解锁；不能先解锁后发布半完成状态。自适应状态使用独立的 `cdnca_originroute_adaptive_state` 2 MiB shared dict，key 包含策略 version ID、revision、pool 和 endpoint；即使更高 revision 复用 version ID 也不会继承旧遥测。packed 状态和锁均有 TTL，不与 L2 熔断状态共用容量。时钟逆跳会让当前 worker 进入至少 1 秒冷却；后续合法 revision reload 使用新状态命名空间，不能继承未来时间戳。

## L2 熔断与 hop

每个策略 version ID、精确 revision 和 L2 pool 在 `cdnca_originroute_state` shared dict 中维护独立状态：

- closed：累计连续失败，达到阈值后 open。
- open：探测间隔内直接选择 origin fallback，不访问 L2。
- half-open：间隔到期后用原子 `add` 只放行一个探针；失败重新 open，连续成功达到恢复阈值后 closed。

默认兼容值由控制面显式生成：10 秒探测、连续 3 次失败、连续 3 次成功；schema 允许在边界内覆盖。version ID 和精确 revision 都进入 shared-dict key；更高 revision 即使复用 version ID，也不会继承旧熔断计数。guard、失败、恢复、开路和探针 key 都有 TTL；普通状态 TTL 为探测间隔的 10 倍，并限制在 1 至 300 秒，旧 revision 状态会自动回收。

`probe_interval_ms` 只决定 open 状态何时允许下一次 half-open 尝试，不是探针 owner lease。原子 `add` 写入的 lease value 绑定 worker PID、连接、请求和时间，TTL 固定覆盖 `total_budget_ms + 1s`；因此探针请求仍在预算内执行时，较短的 probe interval 不能放入第二个探针。admission、replacement 和 release 与 adaptive 探针复用相同的 100ms mutation-lock 协议；release 只写入精确 owner 的逻辑释放 marker，不物理删除共享 lease key。锁竞争、shared-dict 错误或强制淘汰均 fail closed，不放入第二个探针；普通请求和迟到的旧 owner 不能影响 replacement token。worker 崩溃时不猜测解锁，只等待 mutation lock 与 probe lease 各自 TTL 到期。

v1 完全忽略客户端传入的 `X-CDNCA-Origin-Hop`，不把公共 HTTP header 作为拓扑信任事实。L1 runtime 为每个实际候选生成 hop：L2 为 `1`，直源为 `0`。Nginx 在首次连接前已经生成 upstream request buffer；L2 失败后切换到直源时，runtime 必须在 balancer 阶段更新变量并调用 `ngx.balancer.recreate_request()`，否则最终直源仍会收到首次 L2 的 `1`。只有候选类型改变时才重建，重建失败则中止请求，不能发送错误拓扑标记。真实烟测分别验证连接失败、读取超时和 HTTP 502 后的最终直源收到 `0`，L2 成功收到 `1`，初始直源收到 `0`，且客户端伪造 `255` 不影响运行时结果。由于 v1 禁止 L2 到 L2，`max_hops` 只保留为契约兼容边界，不参与入站 header 判定。未来若支持可信多跳，必须发布新 schema，并使用认证 peer CIDR 或 mTLS 节点身份携带 hop，不能恢复读取公共 header。

每次允许 L2 前，runtime 会清理过期状态并保留至少 16 KiB shared-dict 空间。`set`、`incr`、`expire` 和半开探针 `add` 的错误都会检查；`no memory` 只在清理过期项后重试一次，任何强制淘汰都视为状态不可用。状态不可用时 worker 进入 1 至 10 秒冷却并产生 `circuit_state_unavailable`，请求跳过所有 L2 候选并选择显式直源 fallback，不能在无法可靠记录熔断状态时继续访问 L2。有效 L1 策略在发布前就强制要求 L2 配置直源 fallback；运行时若仍无可选池则返回 502。真实烟测使用 64 KiB shared dict 验证容量压力时不触达 L2、压力过期后恢复，以及两个策略版本的状态在 TTL 后清零。

## 入口源地址

发布器在预检前通过 `AddressInspector` 枚举本机接口，确认所有配置的 IPv4/IPv6 ingress source 实际存在。任一地址缺失或接口检查失败时不写 current、不 reload。Lua 根据每次选中的 endpoint 地址族设置 `$cdnca_origin_bind`，所以重试从 IPv4 切到 IPv6 时使用对应源地址。

策略启用 source bind 时，所有目标仍必须是 IP literal 且每个目标地址族必须有对应 source。v1 的 pool 是全局集合，因此检查是保守的全 listener/全 pool 检查，不推断某个 listener 永远不会到达某个 pool。

入口源地址指本机 socket 可绑定地址，不等于 NAT 后公网地址。生产验收必须分别验证：

- 多网卡节点的地址归属、路由表和反向路径过滤。
- SNAT 后对端实际观察到的地址及 NAT 映射稳定性。
- IPv4/IPv6 分流、备用地址顺序和地址撤销后的发布拒绝。
- reload 前后长连接和新连接是否使用预期地址。

## 发布与回滚

磁盘布局：

```text
<state-root>/                         0700
  .apply.lock                         0600
  apply-journal.json                  0600，仅发布中的候选
  current -> versions/<digest>
  lkg -> versions/<digest>
  staging/                            0700
  versions/
    <digest>/                         0500
      policy.json                     0400
      nginx.conf                      0400
  shared/                             0700
    originroute.pid
    originroute-error.log
    client-body-temp/                 0700
    proxy-temp/ fastcgi-temp/ ...     0700
```

流程：严格解析和本机地址校验，确定性编译，然后同时取得进程内 mutex 和 `<state-root>/.apply.lock` 跨进程排他锁。持锁后先把任何未验证的 current 对账回 LKG，再完成 staging 文件 fsync、原子 rename、release 降权为只读和真实 `openresty -t`。切换 current 前原子写入并 fsync `apply-journal.json`，随后启动/reload、执行版本健康探针，只有验证通过才推进 LKG 并删除 journal。revision 必须单调递增；同 revision 不同 digest 返回冲突，同 digest 重投只重新检查健康。

OpenResty 临时目录全部位于 shared，禁止污染不可变 release。release 读取器要求精确两个普通 `0400` 文件，且两个文件的 hard-link count 都必须为 1，再重新编译核对 digest；额外文件、模式变化、symlink、hardlink 或内容篡改都会阻断复用/回滚。

首次启动只有在 master 至少产生一个可识别的 OpenResty worker 后才进入健康检查。reload 前记录旧 worker PID 集合；发出 reload 后必须同时看到新 PID 的 worker ready，并确认全部旧 PID 已退出，才允许版本健康探针推进 LKG。旧 worker 即使还能返回旧版本健康响应，也不能让 candidate 提前通过。reload 或健康失败时，发布器用独立 10 秒恢复 context 重载旧 release 并执行同一 generation drain 门禁，再确认旧版本健康。第一次 Apply 没有旧版本时，先 graceful stop 新 master，识别 Linux zombie 为已退出，清除 PID 和 current 后才返回原始失败。只删除 symlink 不算恢复成功。

Publisher 构造和每次 Apply 都在跨进程锁内执行 current/LKG/journal 对账。若进程在 current 切换后、LKG 推进前退出，下一实例会把 current 回滚到已验证 LKG；若没有 LKG，则停止未验证 runtime 并移除 current。损坏、不安全或与 LKG 不一致的 journal 会 fail closed。release GC 尚未实现，正式 systemd 接线仍须加入指标和告警。

## 可观测与排障

生成配置提供有界变量：

- `$cdnca_origin_route`：命中 route ID 或 `default`。
- `$cdnca_origin_event`：`selected`、`retry`、`direct_fallback`、`circuit_open`、`circuit_state_unavailable`、`budget_exhausted` 或 `attempts_exhausted`。
- `$cdnca_origin_hop`：runtime 为最终实际 upstream 候选生成的 hop 值；L2 为 `1`，直源为 `0`，跨类型重试会重建 upstream request header，与客户端入站 header 无关。
- `$cdnca_origin_reason`：active 的 `p2c_ewma_selected`、`slow_start_active`、`endpoint_ejected`、`ejection_cap_reached`、`telemetry_stale_fallback`、`single_candidate_fallback` 或 shadow 的 `baseline_weighted_selected`。
- `$cdnca_origin_shadow_reason`：shadow 计算结果；active/off 为空。
- `$cdnca_origin_diagnostic`：最多 160 字节的有界摘要，例如 `p=primary;c=origin-a;n=3;e=0;explore=0;s=1`，只含有界 pool/candidate token 和聚合状态，不包含主机、IP、URL 或请求标识。

当前独立配置关闭 access log，只把 OpenResty notice/error 写到 `<state-root>/shared/originroute-error.log`。正式 site bundle 必须把上述有界字段接入统一结构化访问日志、Prometheus 计数和 trace/task ID；不能记录请求 body、凭据或完整高基数 URL。

排障顺序：

1. 确认 current/lkg 指向合法 digest，release 只有两个预期文件。
2. 运行 `openresty -t -p <release>/ -c nginx.conf`。
3. 检查错误日志中的 connect/read timeout、peer setup 和 reload 结果。
4. 确认 ingress source 仍存在于本机接口，目标 IP 地址族有对应 source。
5. 检查 route/event/hop、adaptive reason/diagnostic 和策略版本；出现 `circuit_state_unavailable` 或 `telemetry_stale_fallback` 时分别检查对应 shared dict 容量、时钟和错误日志，不能把状态失败误判为条件未命中。
6. 失败版本不能手工覆盖 current；修正策略后发布更高 revision，或通过受审计回滚流程恢复 LKG。

## 验证

```sh
cd agents/edge-agent
GOWORK=off go test -count=1 ./internal/originroute/...
GOWORK=off go test -race -count=1 ./internal/originroute/...
GOWORK=off go vet ./internal/originroute/...
cd ../..
shellcheck scripts/edge-origin-route-smoke.sh
./scripts/edge-origin-route-smoke.sh
```

真实 smoke 使用唯一命名、任务自有的镜像/容器和临时目录，容器禁用外部网络。它启动 IPv4/IPv6 直源、连接拒绝源、快/中/慢源和可切换 L2，运行真实 OpenResty 1.27.1.2，输出单行 `EDGE_ORIGIN_ROUTE_SMOKE_EVIDENCE`。除原有路由、重试、熔断、源地址和发布证据外，脚本精确断言连接失败、读取超时和 HTTP 502 后的最终直源 hop 为 `0`，L2 成功为 `1`，初始直源为 `0`，客户端伪造 `255` 无效；reload 会让旧 worker 持有约 500ms 上游请求，并断言返回时新 worker 存活且旧 generation 已退出；自适应部分还覆盖 off 字节兼容、shadow 等价、P2C、慢启动、探索无饥饿、严格摘除 floor、状态失败前切回基线、恢复探针单 owner、token fencing、成功/失败/中止释放、崩溃租约到期、状态/时钟降级、GET/HEAD 重试和 POST 不重放。另一个双 worker fixture 对 L2 与 adaptive key 各循环 8 次，强制旧 owner 在读到匹配 token 后暂停至 mutation lock 过期，由 replacement 抢占写入，再恢复旧 owner，最终必须保留 replacement 并输出 `probe_release_atomic=true`。脚本验证所有布尔证据和保持版本值后才成功，并只清理本次随机后缀资源。

隔离 loopback 的单次候选 benchmark 使用 96 个 baseline 请求、96 个 adaptive 延迟样本和后续 32 个 steady 请求，并运行 2000 次 Lua 决策循环；曾观察到 baseline/adaptive p95 约 46.6/13.1ms、三端选择约 225/12/3、异常期重试放大约 1.2、12 个状态 key、2 MiB dict 余量约 2.07 MiB。保存完整 baseline 重试序列后，2000 次 baseline/adaptive 决策中位耗时约 4/216ms。该结果只证明当前固定镜像、固定 seed 和人工延迟模型下没有饥饿、状态无界增长或明显尾延迟回归；它不是生产容量结论，也不能证明所有流量分布下优于基线。正式启用前必须用目标节点 CPU、真实连接复用、源数量、并发和失败分布重复压测，并保留一键切回 off 的版本化策略。

## 正式接线前置项

- 将 origin-route 字段合并进签名、版本化 site bundle，固定 protobuf/OpenAPI 契约后再并行改 control API、Agent Gateway 和 UI。
- 由控制面验证 NODE-03 全拓扑无环和 L2 身份；未来可信多跳必须通过新 schema 和认证链路引入，节点不能接受公共 header 作为信任事实。
- 为 DNS 源设计可重复的解析结果/TTL 更新契约，不在请求路径加入 DNS I/O。
- 补 release GC、发布恢复指标和告警。
- 在 control API/UI 的专家模式接入完整 adaptive v1 契约、shadow 对比指标、灰度/暂停/回滚和版本兼容检查；普通用户默认保持 off。
- 在隔离测试节点完成真实 NAT、多网卡、策略路由、地址撤销、长连接和灰度回滚验收。
- 与现有 `siteconfig` 合并时保持其 TLS 信任、Host/SNI、header、上传和五种负载算法能力；本切片不能替换或削弱这些基线。
