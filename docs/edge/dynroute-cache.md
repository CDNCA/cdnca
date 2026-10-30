# 动态路由缓存（D8）

- 实现：`libs/edgeconfig/edgecache`（zone 池、站点计划、键、骨架片段，Go 规范）、`edge/openresty/dynroute/cdnca_cache.lua`（请求期）、`agents/edge-agent/internal/dyncache`（清除、清空代际、预热、软配额）、原生补丁 24（`proxy_cache_valid` 接受变量）。
- 依据：ADR 0009 §4 缓存行、“站点缓存容量为软配额”、补丁 24（清空全部缓存放节点状态）、ge-cache 修正语义 A–I。
- 验收：`tests/dynroute-cache/run.sh`（功能 + 策略扩展 45 项 + 1 万站；`ONLY=functional|extensions|scale`）；金标 `CDNCA_EDGE_GOLDEN_RENDERER=cdnca-dynroute tests/edge-golden/run.sh check cache,cache-ge`（0 缺陷）。

## 1. 节点骨架

| 片段 | 内容 |
|---|---|
| zone 池 | `edgecache.PlanPool(节点预算)`：≤64 GiB 4 个、≤1 TiB 16 个、更大 64 个 zone（2 的幂，每 zone ≥64 MiB）；`max_size` = 预算/zone 数（**唯一硬上限**）；keys_zone = 节点 keys 预算/zone 数，未给时按 32 KiB/对象 × 8000 键/MiB 估算，1–256 MiB；`min_free`；inactive = max(1h, 最长规则 TTL；有 stale_if_error 的站点 ≥24h) |
| 站点 → zone | `ZoneIndex(key_prefix)` = key_prefix 前 8 位十六进制 & (zone 数−1)：只随池大小变化 |
| 共享字典 | `cdnca_cache_purge`：每站清空代际（键 = key_prefix）、`loaded`、预热令牌 |
| map | `$cdnca_cache_valid`：按 `$upstream_status`（重试取最后一个）从站点状态表 ` 200=60 404=0 any=60 ` 取 TTL，无则 any，再无则空（补丁 24：不缓存）；`$cdnca_cache_expires` 同法取浏览器过期；命中头与原因 |
| 命名变体 | `@cdnca_cache_<override\|follow>[_stale\|_stalebg][_s<KiB>]`（2×3×6=36 个）+ `@cdnca_cache_bypass`：只放配置期才能定的差异——`proxy_ignore_headers`（override）、`proxy_cache_use_stale error timeout updating http_500..504` + `proxy_cache_background_update`（stale_if_error/background_update）、`slice <N>`（分片）；每个变体都有 `proxy_cache_lock`（5s）、`proxy_cache_revalidate`、`proxy_force_ranges on`（v7 每个缓存 location 同）；其余全是变量 |
| 分片尺寸 | nginx `slice` 只接常量：变体固定 256 KiB / 1 / 4 / 16 / 64 MiB（控制台可选的全部尺寸）；策略 `slice_bytes`（64 KiB 倍数）取不大于它的最大一档（`edgecache.SliceVariantBytes`），只影响回源按多大分片取，客户端字节相同；分片对象键尾加 `|slice=$slice_range`，206 与 200 同 TTL |

## 2. 请求期（access 末尾）

1. 站点无缓存计划：不缓存，`Range` 原样转发，不出 `X-CDN-Cache`（v7 同）。
2. 绕过原因（`X-CDN-Cache-Reason`）名与先后次序同 v7（`SiteRuntimeCacheV2HTTPMaps`）：`method`、`authorization`、`cookie`（只对未被任何缓存规则点名的请求；命中规则的请求忽略请求 Cookie，ge-cache C）、`upgrade`、`no_cache_rule`（有规则而无一命中，或命中的规则对所有状态都不缓存）；动态路由独有 `key`、`purge_state`（agent 尚未同步清空代际：重启后不会把清过的对象读回来）、`disabled`。响应侧：`set_cookie`、`origin_no_store`（private/no-store/no-cache）、`object_size`。
3. 绕过的请求：未被规则点名的进 `@cdnca_cache_bypass`（range 站点，转发 Range）或留在 location /；其余进本站变体但 zone 为空（不读不存，Accept-Ranges 与 v7 一致）。
4. 可缓存：键 = `key_prefix|generation|清空代际|host 或 domain|port|策略键`，`ngx.exec` 进 `Plan.Variant()`。所有缓存站点由缓存对象切 Range（206/多段/416，v7 `proxy_force_ranges`）；site.range 只决定绕过请求是否转发 Range。缓存请求永不向源站发客户端 Range（分片变体只发对齐分片 Range）。
5. 对象大小上下限：header_filter 的 cache_status 槽在填充（MISS/EXPIRED）时按 Content-Length 或 Content-Range 总长判断，越界置 `$cdnca_cache_size_bypass`（`proxy_no_cache`，nginx 在 send_header 之后才求值），显示 BYPASS/object_size；有上限而长度未知时不存（v7 `cacheSizeFilterLua`）。站点响应规则（dynroute-filters.md §2.1）替换的回源响应置 `$cdnca_cache_rule_bypass`（同为 `proxy_no_cache`），显示 BYPASS/response_rule。
6. TTL：规则候选集（命中的全部规则序号）→ 决策表，与 v7 `cachePolicyPlan` 同语义（每个状态取第一个点名它或不点名状态的候选；schema 2 的 `no_cache` 动作不缓存）。Lua 与 Go 计划（含变体、分片、大小上下限）在真实 OpenResty 上逐站比对（`PLAN-LUA-EQUALS-GO-*`、`EXT-PLAN-LUA-EQUALS-GO-*`）。
7. `X-CDN-Cache`：HIT / MISS / EXPIRED / STALE / UPDATING / REVALIDATED / BYPASS（v7 同，EXPIRED 单列）。只在站点对象 `cache_status_header` 为 true（响应头显示缓存状态，攻击升级 B 级及以上编译为 false）或 agent 预热请求时输出，`X-CDN-Cache-Reason` 同。

### 2.1 按规则设置（CACHE_RULE_MATCH v2）

规则字段 `edgeconfig.CacheRuleExtras`；请求的**决定规则**是候选集中序号最小的规则，其设置作用于整个请求，未设置的继承全站策略。

| 字段 | 界面文案 | 节点行为 |
|---|---|---|
| `path_exact` | 单个路径（首页 = `/`） | `$uri` 全等；作为独立路径类参与候选集枚举，不占 8 条条件规则上限 |
| `ignore_query` | 忽略 URL 参数 | 键走投影形式，查询摘要按 `ignore`；agent 清缓存按投影键匹配路径 |
| `slice_bytes` | 分片回源 | 路由用该规则的分片变体（0 = 不分片）；绕过时走同变体的不分片版 |
| `force_cache` | 强制 CDN 缓存 | true 走 override 变体（忽略源站 Cache-Control/Expires/X-Accel-Expires），false 走 follow；源站 private/no-store/no-cache、Set-Cookie 照旧不存 |
| `ignore_vary` | 忽略 Vary | `_nv` 变体：`proxy_ignore_headers Vary` |
| `no_cache[]` | 不缓存条件 | source（uri/path/client_ip/scheme/args/host/header+name）上正则命中即不读不写，`X-CDN-Cache-Reason: no_cache_condition` |

变体名 `@cdnca_cache_<override|follow>[_stale|_stalebg][_nv][_s<KiB>][_f]`，`edgecache.Route.Variant` 与 Lua `route.variant` 一致（`tests/dynroute-cache` ONLY=ruleextras 比对）。

## 3. 清除、预热、软配额（agent，`internal/dyncache`）

- 只读本站 zone，只删 KEY 以本站 key_prefix 开头且文件名 = md5(KEY) 的文件：清 A 不会碰 B（同 zone 同路径实测）。
- URL：普通键按 md5(当前代键) 直接定位（不扫目录）；投影键（查询/vary 摘要）按路径清全部变体；分片站点（`Site.Sliced`）扫本站 zone，清该 URL 全部分片。目录：路径段前缀。
- 整站清空：清空代际 +1，先写 agent 文件再经控制套接字 `POST /cache/generations` 推给节点（立即生效、不走发布），再后台删本站旧代对象。节点启动后 agent `Sync` 全量推送；推送前不缓存。
- 预热：agent 经回环访问共享 server 公网端口，带令牌头 `X-Cdnca-Cache-Task`（令牌经控制套接字下发，只认回环来源）；响应回显站点 ID 与缓存键，第二次同键 HIT 才算成功。
- 软配额：按站点汇总字节，超过 `policy.disk_quota_bytes` 的站点按访问时间从旧到新删到 90%；其他站点不动。

## 4. 与 v7 的有意差异（compare.json semantic_changes，renderer cdnca-dynroute）

- 去掉 `X-CDNCA-Config-Version` 响应头（共享 server 无每次发布的配置版本）。
- 原因名与 v7 相同；只有 `key`/`purge_state`/`disabled` 为动态路由独有。
- 缓存键不含 config_version_id（发布不换键空间）。
