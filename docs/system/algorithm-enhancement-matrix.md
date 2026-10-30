# 调度、回源、缓存与安全算法增强矩阵

状态：设计与实施门禁，2026-07-24。本文记录当前可验证基线、候选增强、验证方法和回退边界；不表示候选算法已经接入生产链路，也不改变功能完成度判定。

## 1. 范围与证据边界

本文只覆盖四个领域：节点/区域调度、源站负载与故障切换、缓存、WAF/CC。证据标签沿用项目约定：

- `baseline-implemented`：仓库中已有实现和自动化证据，但仍可能只是隔离内核。
- `observed`、`help-doc`、`update-log`、`customer-instance-observed`：只说明参考行为或操作体验，不证明目标系统内部算法。
- `enhancement-candidate`：待基准、容量测试和故障注入证明的候选，不得描述为更优或已完成。
- `integration-unknown`：缺少可解析的正式运行路径或真实端到端证据；静态类型、测试夹具和独立 smoke 均不能把它提升为已接线。

当前证据边界：

| 领域 | 已有可验证基线 | 仍未闭环 |
| --- | --- | --- |
| 节点/区域调度 | `nodescheduler` 已实现 region/carrier 最具体匹配、最小 priority 主集合、有序备用、确定性权重选择、10 秒探测和连续 3 次失败/恢复默认值，并具备不可变 revision、CAS、幂等和审计 | HTTP/UI、DNS provider、Agent 探针 transport、Edge 发布和端到端 DNS 收敛证据 |
| 源站负载与故障切换 | `siteconfig` 支持轮询、`ip_hash`、`url_hash`、最少连接和随机；`originroute` 支持权重首选、GET/HEAD 有界重试、L2 熔断、直源 fallback、不可变发布和 LKG | `originroute` 尚未进入正式 site bundle、control API、Agent Gateway 和 UI；没有正式 telemetry 输入 |
| 缓存 | `cachecontrol` 有不可变 TTL/跟随源站/覆盖策略与刷新预热任务事实；`cachetask` 有真实 purge/prewarm executor；`rangecache` 有静态 TTL、容量/inactive、revalidate 和相同 slice 的 cache lock | control API 到 Gateway/Edge 的完整链路、通用对象 admission、站点级 SWR 和通用 request coalescing |
| WAF/CC | WAF 已有有序 `allow/log/block` 与 `continue/stop`；CC 已有节点本地 fixed window、leaky bucket、allowlist、可信代理、429/临时封禁和 LKG | 控制面、Gateway、正式 site bundle、UI、跨节点计数、挑战闭环、自适应阈值和安全事件闭环 |

仓库内证据入口：

- 节点调度：[node-scheduling.md](../runbooks/node-scheduling.md)、[control-node.md](../help-workflows/control-node.md)。
- 回源：[edge-origin-routing.md](../runbooks/edge-origin-routing.md)、[site-acceleration.md](../help-workflows/site-acceleration.md)。
- 缓存：[cache-control-plane.md](../runbooks/cache-control-plane.md)、[cache-control-http-api.md](../runbooks/cache-control-http-api.md)、[edge-cache-task.md](../runbooks/edge-cache-task.md)、[edge-range-cache.md](../runbooks/edge-range-cache.md)、[cache-refresh.md](../help-workflows/cache-refresh.md)。
- WAF/CC：[waf-rule-engine.md](../runbooks/waf-rule-engine.md)、[edge-cc-engine.md](../runbooks/edge-cc-engine.md)、[security-waf-cc.md](../ui-audit/security-waf-cc.md)、[waf-cc.md](../help-workflows/waf-cc.md)。
- `customer-instance-observed` 只补充刷新/预热的 JobId/TaskId、历史和重新提交体验：[customer-user-experience.md](../ui-audit/customer-user-experience.md)。它不证明缓存、调度或限流算法。

## 2. 所有增强的统一门禁

算法增强不得替代或隐藏基线。每个增强必须同时满足：

1. **可关闭**：关闭后恢复同版本的基线行为和配置语义，不要求授权中心、控制面或遥测在线。
2. **可解释**：输出稳定 reason code、关键输入摘要、候选/命中结果、状态年龄、回退状态和策略版本；用户可见说明由 i18n 资源渲染。
3. **可复现**：固定时钟、随机种子、请求序列、拓扑和故障脚本；记录二进制、配置、数据集和运行环境摘要。
4. **可比较**：同机、同流量、同故障下与当前 baseline 做 A/B；至少测吞吐、p50/p95/p99/p99.9、错误率、CPU、内存、状态基数、恢复时间和公平性。
5. **可回滚**：shadow 后才能 canary；canary 必须限定节点组/站点/租户、并发量和时长；异常自动停止推进并原子恢复 LKG。
6. **无新在线依赖**：已有边缘流量不能因控制面、Redis、NATS、ClickHouse、授权中心或 telemetry 不可用而停止。
7. **有安全上限**：状态量、采样年龄、ejection 数、stale 时长、等待者数量、窗口大小和自适应阈值均有硬上限。
8. **不泄露高基数数据**：IP、URL 和租户对象 ID 不进入 Prometheus label；原始样本只进入受权限、脱敏和 TTL 控制的事件存储。

每项 benchmark 在执行前冻结目标指标和不可回归预算。只有目标指标在重复运行中稳定改善，且错误率、受保护尾延迟、资源上限、公平性和恢复时间均未越过预先声明的预算，候选才可从 shadow 进入 canary。一次成功或理论复杂度不能作为启用依据。

## 3. 节点与区域调度

### 3.1 基线与候选矩阵

`nodescheduler` 当前选择顺序是：健康且启用 -> region/carrier 最具体匹配 -> 最小 priority -> 同 priority 内确定性权重；更大 priority 仅作有序备用。该行为是兼容基线和所有增强的最终回退。

| 模式 | 适用条件与状态量 | 时间/空间复杂度 | 尾延迟、误判、饥饿与抖动 | 失效模式与 baseline 回退 |
| --- | --- | --- | --- | --- |
| 确定性加权选择（baseline） | 静态容量已知；每个 endpoint 保存 priority、weight、health | 计划排序 `O(N log N)`；单次加权选择 `O(N)`；空间 `O(N)` | 不感知实时延迟；错误权重可持续压热点；低权重可能长期少量命中；健康切换时集合突变 | 无健康 endpoint 时停止新发布并保留 LKG；其他增强异常时回到此模式 |
| 加权 rendezvous 子集 | DNS/Edge 只需稳定选择少量 endpoint；状态为 endpoint 权重和稳定 key，无请求历史 | 每个 key `O(N)`；空间 `O(N)` | 节点增删时重映射小于简单取模；不感知排队/延迟；低权重 endpoint 可能近似饥饿；大规模健康切换仍会抖动 | hash/schema 不支持、集合过大或分布偏斜时回到完整有序基线集合 |
| 拓扑多样性约束 | endpoint 有可信 failure-domain 标签且至少两个可用域；状态为 region/zone/rack 标签和每域容量 | 排序/约束选择 `O(N log N)`；空间 `O(N)` | 可降低同域故障相关性；错误/缺失标签会制造虚假隔离；小集群可能牺牲容量或让低权重域饥饿；域进出会抖动 | 标签缺失、容量不足或约束不可满足时明确记录 `topology_constraint_unsatisfied`，回到 region/carrier+priority 基线，不静默选空集合 |
| 遥测感知分数 | 只用于控制面计划、样本量和时间同步达标；状态为有界 EWMA、错误率、样本数和 freshness | 更新 `O(1)`/样本；计划 `O(N log N)`；空间 `O(N)` | 可能降低慢节点尾延迟，但采样偏差会误降权；低流量节点易冷启动饥饿；延迟噪声会引发频繁改计划 | 样本不足、过期、时钟异常或 collector 不可用时记录原因并回到静态权重；不得让每个边缘请求查询控制面 |

### 3.2 默认与专家模式

- 默认继续使用当前 region/carrier、priority、weight 和 10 秒/3 次健康阈值，不自动启用遥测分数。
- 拓扑多样性仅在标签完整且预检证明仍有足够容量时启用；UI 必须显示选择来源、被排除域和回退原因。
- 遥测增强先只生成 shadow plan，与实际 plan 对比重映射率、健康误切率、容量偏差和预测尾延迟；默认不发布。
- 专家参数只开放样本最小值、最大样本年龄、分数权重、最大重映射比例和最短保持时间，并受服务端硬边界约束。

必备 reason code：`baseline_weighted_selected`、`telemetry_insufficient`、`telemetry_stale`、`topology_constraint_unsatisfied`、`remap_budget_exceeded`、`no_healthy_endpoint`。

## 4. 源站负载与故障切换

### 4.1 算法矩阵

| 算法 | 适用条件与状态量 | 时间/空间复杂度 | 尾延迟、误判、饥饿与抖动 | 失效模式与 baseline 回退 |
| --- | --- | --- | --- | --- |
| Weighted Round Robin（WRR） | 容量差异可由静态权重表达；保存平滑 WRR current weight 或等价状态 | 选择 `O(N)`；空间 `O(N)` | 可预测且易解释，但不感知请求成本和排队；权重错误会持续增加慢端尾延迟；低权重可能少量命中 | 状态重启可从静态权重重建；作为动态算法的首选回退 |
| Least Connections | 长连接或请求时长差异显著；保存每 endpoint 活跃连接数 | 朴素选择 `O(N)`；空间 `O(N)` | 通常避免向繁忙端继续加连接，但连接数不等于工作量；计数延迟会误选；慢长连接可能让 endpoint 长期少用；连接完成会引起分数跳变 | 计数缺失、溢出或跨 worker 不一致时回 WRR；不得用控制面陈旧连接数驱动请求路径 |
| Random | endpoint 近似同质、池较大；只需 RNG 和静态候选 | 选择 `O(1)`；空间 `O(1)`（不含候选表） | 平均分散但短窗口可堆叠到同一端，p99 波动较大；无确定性亲和；不会系统性饥饿但小样本不公平 | RNG/候选异常时回确定性 WRR；测试必须固定 seed |
| `ip_hash` / `url_hash` | 需要客户端或对象亲和；保存稳定 endpoint 顺序/哈希结构 | 构建 `O(N)`；常规查找约 `O(1)`；空间 `O(N)` | 可提高局部性，但热点 IP/URL 会形成热点；不感知排队；节点变更可能大幅重映射；小权重节点可被 key 分布饿死 | endpoint 不健康时按既定备用选择；hash 输入缺失时回 WRR，不能随意换 key |
| P2C + Peak EWMA | 池至少两个健康端、请求级低成本遥测可信；每 endpoint 保存 peak EWMA、并发和样本 freshness | 每次采样/选择 `O(1)`；空间 `O(N)` | 两次随机选择可降低尾延迟且避免全表扫描；冷启动/陈旧样本会误判；持续低分端可能饥饿；噪声与突发可抖动 | 样本不足/过期、时钟回退、状态不可用或只剩一端时回 WRR；必须保留小比例受限探索 |
| Slow Start | endpoint 新增、恢复或刚 reload；保存恢复时间、ramp 进度和有效权重 | 更新 `O(1)`；选择复杂度继承基础算法；空间 `O(N)` | 避免冷端瞬时过载；ramp 过慢会浪费容量并造成饥饿；频繁 flap 会反复降权 | 时钟异常或状态丢失时使用保守起始权重并设硬超时，最终回静态配置权重 |
| Outlier Ejection | 池有足够冗余且能按 endpoint 统计连续错误/成功率；保存窗口、ejection 次数和到期时间 | 每次结果 `O(1)`，周期扫描 `O(N)`；空间 `O(N)` | 可隔离局部故障并改善尾延迟；低样本、上游 4xx 或共同依赖故障会误摘除；无 cap 会全摘除或饿死端点；反复进出会抖动 | 严格限制最大摘除比例、最长时长和最小样本；全部异常时保留至少一个 baseline 候选并依赖现有有界重试/LKG |
| Maglev | 大规模稳定池、需要跨 worker 的低重映射亲和；保存大小为 `M` 的 lookup table | 构建典型为 `O(M + collision probes)`、朴素最坏 `O(MN)`；查找 `O(1)`；空间 `O(M)` | 查找稳定且节点变更重映射有限，但不感知延迟；表大小/权重离散会产生偏斜；错误健康视图导致 worker 间不一致 | 表构建失败、内存超限或成员视图不一致时回 `ip_hash`/`url_hash` 或 WRR；不能在请求路径重建表 |

### 4.2 建议默认组合

- 默认保留 `siteconfig` 已验证的 WRR、`ip_hash`、`url_hash`、least-conn 和 random；独立 `originroute` 在正式合并前继续使用当前确定性权重首选和有界重试，不能把它描述为已经采用 WRR。
- `P2C+Peak EWMA` 仅在健康 endpoint >= 2、每端样本达到下限且样本未过期时启用。分数应同时受并发、延迟上限和固定权重约束。
- 新增/恢复 endpoint 先进入 slow-start；outlier ejection 设置最大摘除比例、指数退避上限和恢复探针。slow-start 与 ejection 不能绕过现有 GET/HEAD 重试安全边界。
- Maglev 只作为需要稳定亲和的大池专家模式，不替代基线 hash，也不用于按延迟选择。

必备 reason code：`p2c_ewma_selected`、`slow_start_active`、`endpoint_ejected`、`ejection_cap_reached`、`telemetry_stale_fallback`、`single_candidate_fallback`、`baseline_wrr_selected`。

## 5. 缓存

### 5.1 算法矩阵

| 算法 | 适用条件与状态量 | 时间/空间复杂度 | 尾延迟、误判、饥饿与抖动 | 失效模式与 baseline 回退 |
| --- | --- | --- | --- | --- |
| Static TTL + LRU（baseline） | 遵守源站头或显式 TTL；保存对象 metadata、大小、过期时间和 LRU 顺序 | 命中/更新通常 `O(1)`；空间 `O(C)` | 易解释；冷 miss 承担完整源延迟；一击大对象可污染缓存；热点对象不会饥饿但集中到期会抖动/击穿 | 磁盘满、metadata 损坏或策略无效时 bypass/回源并保留 LKG；不得返回不完整对象 |
| TinyLFU + SLRU admission | 容量受限、请求呈 Zipf/scan 混合；保存有界频率 sketch、window/probation/protected segment | admission/访问摊销 `O(1)`；空间 `O(C + sketch)` | 可减少一次性对象污染，但 sketch 冲突会误拒绝；新热点在升温前可能饥饿；周期 aging 会造成阈值抖动 | sketch 丢失时冷启动且先 shadow；分配失败或收益不达标时关闭 admission，恢复现有 TTL/LRU |
| Request Coalescing | 相同完整 cache key 的并发 miss；保存每 key 的 leader、等待者、deadline 和结果状态 | 加入/完成 `O(1)`；空间 `O(K + waiters)` | 降低源站放大，但 follower 尾延迟受 leader 限制；错误 cache key 会跨请求合并；慢 leader 可让等待者饥饿；超时同时释放会形成二次峰值 | leader 崩溃/超时、等待者超限或状态不可用时有界散开回源；可服务的 stale 优先于无限等待 |
| Stale-While-Revalidate（SWR） | 仅公开、可缓存、可重验证对象；保存 fresh/stale hard deadline、validator 和单次 refresh 状态 | 命中 `O(1)`；空间 `O(C + active refresh)` | stale 命中可压低尾延迟，但会返回有界旧内容；分类错误会泄露私有响应；持续 refresh 失败可能长期陈旧；集中进入 stale 窗口会抖动 | `private/no-store/Authorization/Cookie/Set-Cookie` 一律禁用；超过 hard stale cap 或校验失败回到 RFC 9111 严格 freshness/同步回源 |

### 5.2 默认与专家模式

- 默认遵守 RFC 9111 和源站缓存头；现有 `follow_origin`/显式 override 行为保持不变。
- 通用 coalescing 必须使用完整的租户、站点、scheme、host、port、方法、规范路径、精确 query、Vary 和 representation identity；不能只按 URL 合并。
- SWR 默认关闭。开启时只允许 GET/HEAD 的公开响应，并设置独立 soft TTL、hard stale cap、refresh timeout、最大等待者和失败退避。
- TinyLFU/SLRU 第一阶段只记录 `would_admit/would_reject`，用对象/字节命中率、源请求放大、淘汰 churn 和 CPU/内存与 LRU 比较；不能在 shadow 阶段改变缓存内容。
- 专家参数不得放开私有对象例外，也不得覆盖磁盘、对象、等待者或 stale hard cap。

必备 reason code：`cache_fresh_hit`、`cache_miss`、`coalesced_follower`、`coalesce_timeout_fallback`、`stale_served_revalidate`、`stale_hard_limit_reached`、`admission_shadow_reject`、`cache_private_bypass`。

## 6. WAF/CC 与自适应阈值

### 6.1 算法矩阵

| 算法 | 适用条件与状态量 | 时间/空间复杂度 | 尾延迟、误判、饥饿与抖动 | 失效模式与 baseline 回退 |
| --- | --- | --- | --- | --- |
| Fixed Window（baseline） | 简单站点/IP/path 计数；保存窗口编号和计数 | 请求 `O(1)`；空间 `O(K)` | 低开销，但窗口边界可形成近 2 倍突发；阈值不合适会误杀/漏放；新窗口瞬间清零产生抖动 | 节点状态不可用时沿用现有 action 级 fail-open/fail-closed 规则；自适应关闭时回该静态阈值 |
| Token / Leaky Bucket（baseline 含 leaky） | 允许受控 burst 或需要平滑输出；保存 token/水位和更新时间 | 请求 `O(1)`；空间 `O(K)` | 比 fixed window 平滑；时钟/浮点误差会误判；低 refill 可能让持续客户端饥饿；配置变化会突变 | 时钟回退、锁失败、状态被逐出时按现有安全动作回退；配置版本隔离状态，禁止跨版本复用错误水位 |
| Sliding Window | 需要更准确表达最近 `T` 秒；保存事件队列或固定 buckets | 精确队列 `O(log E)`/请求且空间 `O(E)`；分桶近似 `O(1)` 且空间 `O(KB)` | 边界误差低于 fixed window；分桶仍有近似误判，精确模式高基数成本大；旧事件清理延迟会误拒；bucket 轮转可抖动 | 状态/内存超过上限时不自动扩大；记录降级并回 fixed window 或 leaky bucket |
| GCRA | 需要精确平均速率和受控 burst；每 key 保存 theoretical arrival time | 请求/空间每 key `O(1)` | 决策平滑且适合分布式原子更新；时钟偏差或非原子多副本会误判；大 debt 可让客户端较久饥饿 | 单节点先实现；需要跨节点时必须有明确一致性/降级契约。状态不可用时回静态 fixed/leaky，不把 Redis 变成边缘硬依赖 |
| Median + MAD | 流量有足够同周期历史且需抗离群点；保存有界基线窗口、分群键和样本质量 | 精确窗口约 `O(W log W)`，空间 `O(W)`；近似实现须另证误差 | 对单个尖峰稳健，但稀疏站点/活动发布会被误判；攻击可污染长期基线；样本不足会使阈值饥饿或剧烈跳动 | 只在 shadow 生成建议；样本不足、季节性不匹配、漂移或污染时回人工静态阈值 |
| EWMA 自适应阈值 | 平稳或缓慢变化且需快速更新；每分群键保存均值/偏差、样本数和更新时间 | 每样本 `O(1)`；空间 `O(K)` | 响应快但对 alpha 敏感；攻击可训练基线，突发活动会误杀；冷启动和正反馈会抖动 | 加最小样本、上下限、变化速率限制、hysteresis、最短保持和人工冻结；异常即回静态阈值 |

### 6.2 默认、shadow 与人工接管

- 现有 fixed window/leaky bucket 和显式管理员阈值继续作为默认、可审计 baseline。
- GCRA 可先作为静态限流器候选，不依赖自适应阈值；跨节点一致性不是首批范围。
- Median+MAD 与 EWMA 只在 shadow 计算 `suggested_threshold`。没有人工确认或通过独立 canary 门禁时，不得改变 WAF/CC action、自动封禁或挑战结果。
- 自适应分群必须有最低流量和最大基数；默认以租户/站点/规则为边界，IP/URL 不进入长期模型或指标 label。
- 自动模式未来启用时必须同时具备阈值下限/上限、单周期最大变化、进入/退出 hysteresis、最短保持时间、攻击污染保护、人工冻结和一键恢复静态值。
- 自适应建议不能绕过 allowlist、可信代理、规则 `continue/stop`、套餐上限或安全动作资源预算。

必备 reason code：`static_limit_applied`、`gcra_limit_applied`、`adaptive_shadow_only`、`adaptive_insufficient_samples`、`adaptive_baseline_stale`、`adaptive_change_capped`、`manual_threshold_frozen`、`limiter_state_unavailable`。

## 7. 基准、容量与故障注入矩阵

每个候选必须使用生产代码路径或固定版本的真实 OpenResty，而不是只测纯函数：

| 领域 | 可重复负载 | 容量边界 | 必做故障 |
| --- | --- | --- | --- |
| 节点调度 | 均匀、区域偏斜、carrier 缺失、权重悬殊、节点 churn | 1/16/128/512 endpoint，计划频率和并发 CAS | probe 延迟/乱序/丢失、旧 revision、整区故障、遥测过期、时钟偏差 |
| 源站负载 | 等时延、双峰延迟、长连接、热点 key、不同权重、混合对象大小 | 1/2/8/32 endpoint，请求并发、worker 数、状态内存 | 慢端、连接拒绝、超时、502/503/504、flap、恢复冷启动、状态丢失、全部异常 |
| 缓存 | uniform、Zipf、scan、flash crowd、热点大对象、Range/完整对象混合 | 对象数、字节数、磁盘满、高基数 key、等待者上限 | 源慢/断、leader 崩溃、校验器变化、截断响应、metadata 损坏、reload、私有响应 |
| WAF/CC | 稳态、合法 burst、活动突发、低慢攻击、分布式攻击、基线漂移 | 活跃 key、规则数、窗口/bucket 数、shared dict 满、worker 数 | 时钟跳变、状态逐出/锁失败、Redis/NATS/CH 不可用、策略倒退、攻击训练、节点重启 |

除通用指标外，各领域必须额外记录：

- 调度/回源：选择分布、weighted fairness、endpoint starvation、重映射率、ejection 率、重试放大和恢复时间。
- 缓存：对象/字节命中率、源站请求/字节放大、admission 误判、coalescing 等待时间、stale 年龄和 revalidate 成功率。
- WAF/CC：真实正/负样本的误杀率/漏放率、阈值变化、挑战/429 比例、状态逐出、规则决策开销和人工回退时间。

固定 clock 之外还要运行真实 wall clock 测试，验证 monotonic time、NTP 跳变和进程重启。统计结果必须包含重复次数、置信区间或明确的离散度，不用单次平均值掩盖尾部。

## 8. 首批三个纵向切片

优先级是实施顺序，不代表缺陷等级。三个切片可并行开发，因为文件所有权互不重叠；共享 runtime 只能在三项各自冻结契约后由一个 integrator 接入。

### P0：Origin `P2C+Peak EWMA + slow-start + bounded outlier ejection`

- **目标**：在 `originroute` 隔离数据面内加入显式模式；telemetry 充足时执行 P2C+EWMA，新增/恢复端执行 slow-start，局部失败执行有摘除比例上限的 outlier ejection；任一前提不满足立即回当前确定性权重首选。未来与 `siteconfig` 合并时，再按站点显式配置回退到 WRR 或其他既有 baseline。
- **所有权**：`agents/edge-agent/internal/originroute`、`edge/openresty/originroute`、任务专属 origin smoke/benchmark 和对应 origin runbook。不得修改 `siteconfig`、control API、Gateway、主程序或 canonical OpenAPI。
- **契约**：固定计时来源、EWMA 更新公式、冷启动分数、样本 freshness、探索下限、ejection cap、退避、恢复探针及上述 reason code。
- **验收**：固定 seed benchmark 覆盖同质/异质/慢端/错误/flap/全部异常；真实 OpenResty smoke 证明 GET/HEAD 重试边界、POST 不重放、L2 fallback、LKG 和关闭增强后的逐请求兼容结果。

### P1：Cache `bounded SWR + general request coalescing`

- **目标**：把现有 range slice cache lock 扩展为完整 cache identity 的通用合并，并为严格公开、可重验证对象加入 bounded SWR；不在本切片启用 TinyLFU 写路径。
- **所有权**：`agents/edge-agent/internal/rangecache`、`edge/openresty/range`、任务专属 range/cache smoke/benchmark 和对应 range runbook。不得修改 `cachecontrol`、`cachetask`、control API、Gateway、主程序或 canonical OpenAPI。
- **契约**：完整 key、leader/follower 生命周期、等待者/超时上限、soft/hard deadline、refresh 单赢家、错误缓存禁止项，以及 `Authorization/Cookie/private/no-store/Set-Cookie/Vary` 边界。
- **验收**：真实 OpenResty 并发 cold miss 证明源站放大受限；leader 超时/退出、源断、磁盘满、reload 和集中 stale 均有有界退路；逐字节 Range/206、If-Range、私有响应隔离和关闭增强后的 baseline 全部回归。

### P2：CC `GCRA + Median/MAD and EWMA shadow adaptive`

- **目标**：在现有节点本地 CC 内加入静态 GCRA 候选，并旁路计算 MAD/EWMA 建议值；第一阶段 shadow 绝不改变 allow/log/429/temporary-ban 结果。
- **所有权**：`agents/edge-agent/internal/cc`、`edge/openresty/cc`、任务专属 CC smoke/benchmark 和对应 CC runbook。不得修改 WAF、control API、Gateway、主程序、站点 bundle 或 canonical OpenAPI。
- **契约**：GCRA 时间单位/原子状态、burst 语义、模型分群和 TTL、最小样本、上下限、hysteresis、变化速率、人工冻结、shadow comparison event 和 reason code。
- **验收**：固定时钟覆盖窗口边界、并发单赢家、时钟回退和状态逐出；真实 OpenResty 覆盖合法 burst、低慢攻击、活动突发、攻击训练和 shared dict 满；断言 shadow 开关前后实际 action 逐请求一致。

### 共享 integrator 的后置所有权

三个切片冻结版本化 schema、事件和回退语义后，单独派一个 integrator 独占以下共享路径：正式 site bundle、Agent Gateway/protobuf、`cmd`/runtime 注册、control API 路由、canonical OpenAPI、Web UI/i18n 和跨域运行手册。integrator 必须完成租户/RBAC/entitlement/审计、签名制品、灰度/暂停/回滚、指标告警和桌面/移动真实浏览器验收；不得把独立 benchmark/smoke 当成平台闭环。

## 9. 权威资料

以下资料访问日期均为 2026-07-24；它们用于定义候选和测试假设，不是本项目性能结论：

- NGINX upstream：<https://nginx.org/en/docs/http/ngx_http_upstream_module.html>
- Envoy 负载均衡：<https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers>
- Envoy outlier detection：<https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/outlier>
- Maglev 论文：<https://www.usenix.org/conference/nsdi16/technical-sessions/presentation/eisenbud>
- Linkerd Peak EWMA：<https://linkerd.io/2016/03/16/beyond-round-robin-load-balancing-for-latency/>
- Finagle load balancing：<https://twitter.github.io/finagle/guide/Clients.html#load-balancing>
- HTTP caching（RFC 9111）：<https://www.rfc-editor.org/rfc/rfc9111.html>
- stale controls（RFC 5861）：<https://www.rfc-editor.org/rfc/rfc5861.html>
- TinyLFU：<https://arxiv.org/abs/1512.00727>
- Caffeine eviction/admission：<https://raw.githubusercontent.com/wiki/ben-manes/caffeine/Eviction.md>
- NGINX proxy cache：<https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- Single Rate Three Color Marker（RFC 2697）：<https://www.rfc-editor.org/rfc/rfc2697.html>
- Envoy local rate limit：<https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/local_rate_limit_filter>
- redis-cell / GCRA：<https://github.com/brandur/redis-cell>
- NIST EWMA：<https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc324.htm>
- OWASP Denial of Service guidance：<https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html>
- HTTP 429（RFC 6585）：<https://www.rfc-editor.org/rfc/rfc6585.html>

## 10. GitNexus 与完成声明

本次只读查询使用的 GitNexus 索引日期为 2026-07-23，状态为 `HEAD=unknown`（1868 files、48009 symbols、300 processes）。对四个领域的概念查询只命中定义，没有返回可用于证明正式接线的 execution process；`BuildPlan`、`RecordProbe`、`Match`、`CompileJSON`、`Evaluate` 和 `PublishPolicy` 的 symbol context 均返回 `not found`。因此这些路径的流程影响与接线证据统一标记为 `UNKNOWN`，不能解释为低风险或无影响。

本文完成只表示算法候选、默认值、风险、回退和验证门禁已形成可派工规格。只有各切片实现、独立复审、共享 runtime 集成、契约/迁移/UI/i18n/文档同步、真实浏览器或真实 OpenResty/节点验收，以及持续对照矩阵更新全部通过后，才可声明对应增强完成。
