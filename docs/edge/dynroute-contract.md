# 动态路由跨阶段契约（D3 冻结）

- 状态：**冻结**。D2 骨架与 D4–D12 依赖本文；改动本文 = 改契约，须同时改所有依赖方。
- 依据：ADR 0009 §3.2/§3.3/§8.2、[0009-poc-results.md](../adr/0009-poc-results.md) §1/§2、[site-object-v2.md](site-object-v2.md)（站点对象 `cdnca.edge.site/v2`，`libs/edgeconfig/edgesite`）、BATCH-PLUGIN 第 11（命名 cdnca）、12（SNI/Host 不一致不回 421，按 Host 选站）条。
- 实现：Lua `edge/openresty/dynroute/cdnca_site.lua`（请求期查表）、`cdnca_site_admin.lua`（控制套接字）；Go `agents/edge-agent/internal/siteindex`（索引文件、变更集、激活/回滚/健康）。本文与实现不一致时以本文为准修实现。

## 1. 站点上下文：`ngx.var.cdnca_site_*`

站点上下文只放 `ngx.var`，不放 `ngx.ctx`（缓存派发 `ngx.exec` 进命名 location 会清空 `ngx.ctx`，ADR 0009 §3.2）。变量由**选站**（§2）唯一写入，其他阶段只读。

| 变量 | 值 | 写入时机 |
|---|---|---|
| `$cdnca_site_id` | 站点 UUID（`Site.SiteID`）；未选中为空串 | `server_rewrite` 选站 |
| `$cdnca_site_revision` | 十进制 `Site.Revision` | 同上 |
| `$cdnca_site_digest` | 站点对象 64 位小写十六进制摘要（对象库键） | 同上 |
| `$cdnca_site_tenant` | `Site.TenantID` | 同上 |
| `$cdnca_site_scope` | `Site.ConfigurationScopeID` | 同上 |
| `$cdnca_site_host` | 命中的索引名：精确名或 `*.x`（不是请求 Host） | 同上 |
| `$cdnca_site_port` | 公网端口（十进制，见 §2.1） | 同上 |
| `$cdnca_site_generation` | 选站时生效的索引代（十进制） | 同上 |
| `$cdnca_site_max_body` | 上传上限，`client_max_body_size` 用（原生补丁 23），总是正的十进制字节数，见 §1.2 | 同上 |
| `$cdnca_site_state` | `ok` / `unknown`（端口上无此 Host）/ `not_ready`（本端口索引未就绪或站点对象读不出） | 同上 |

1. 七个身份变量（id/revision/digest/tenant/scope/host/port）同时写入、同一代；`$cdnca_site_state != "ok"` 时它们都是空串。
2. 一个请求只选一次站。`ngx.exec`、内部跳转、子请求、`error_page` 后变量保留（nginx 变量随请求，不随 location），**任何阶段不得再次选站或改写这些变量**。之后的阶段用 `require("cdnca_site").current()` 取站点对象（§3），它按 `$cdnca_site_digest` 取，不再查索引，所以同一请求在代切换中途也看到同一站点。
3. D2 骨架在**不会执行的 location** 里用 `set` 声明这些变量（nginx 变量须在配置期声明；PoC §5：不能在 server 级 `set`，它在 SERVER_REWRITE 阶段跑，会覆盖 Lua 写的值）。声明片段见 §6.2。
4. 其他任务需要的站点级变量（缓存 zone、回源 SNI、WAF 事务 ID 等）由各自任务声明为 `$cdnca_<模块>_*`，在 `$cdnca_site_*` 之后由各自模块写，不得复用 `cdnca_site_` 前缀；声明方式同本节第 3 条（各任务把自己的 `set` 行交给 D2 并入 §6.2 的声明 location）。

### 1.1 选站失败时的响应

| `$cdnca_site_state` | 响应 | 说明 |
|---|---|---|
| `not_ready` | **503**，`Retry-After: 1`，`Cache-Control: no-store`，体 `cdnca: site index not ready\n` | 冷启动/重建中、该端口未被激活过、或站点对象缺失/损坏。PoC §1 第 3 条：未就绪绝不回 421 |
| `unknown` | **421**，nginx 默认 421 页（`ngx.exit(421)`，与 v7 默认 server 的 `return 421` 逐字节相同；明文与 TLS 端口相同）；节点发布了全局 `unknown_site` 页时按该页状态（403/404/410/421）回页（`edgeskeleton.Input.UnknownSite`） | 索引已就绪而端口上无此 Host（含 IP Host、空 Host）；与 v7 默认 server 相同（`default_server.go`）。**SNI 与 Host 不一致不触发 421**：按 Host 选站（BATCH-PLUGIN 第 12 条），SNI 只用于证书（D4） |
| `ok` | 继续流水线 | |

节点级 location（健康、ACME overlay、市场探测、基准对象）由骨架在选站之前截走**仅当**选站结果为 `unknown`（ADR 0009 §3.3：路由先于探测路径）；`ok` 的请求走站点，`not_ready` 一律 503（D2 实现顺序见 §6.1）。

### 1.2 `$cdnca_site_max_body`

十进制字节数（补丁 23 用 `ngx_parse_offset` 解析，纯数字即字节）。`Site.Limits.MaxBodyBytes > 0` 时为该值；为 0 时取节点系统值 `configure{ system_max_body = <字节数> }`（D2 从节点系统配置写进 `init_by_lua`）；`not_ready`/`unknown` 时为 `1`（请求已被拒绝，只为保证变量合法）。补丁 23 下空值或 0 回 500，所以本变量**永不为空或 0**（骨架声明默认值 `1`）。D11（套餐限额与上传）若要改写，须保持“总是正数”。

## 2. 选站算法（`cdnca_site.route()`）

在 `server_rewrite_by_lua` 的**第一行**调用（CC 等同阶段模块在它之后）：

```lua
server_rewrite_by_lua_block { require("cdnca_site").route() }
```

`route()` 写 §1 的变量；`not_ready` 时直接 `ngx.exit(503)`（带上表的头）；`unknown` 时**不退出**，由骨架决定（节点级 location 匹配则服务，否则 `cdnca_site.reject_unknown()` 回 421）；`ok` 时返回站点对象（Lua 表，见 §3）。

### 2.1 键

- 公网端口：`ngx.var.proxy_protocol_server_port or ngx.var.server_port`（与 CC/WAF 一致，mux 内部 unix 套接字上 `$server_port` 为空）。
- 名字：`ngx.var.host`。nginx 已把它小写、去掉端口、去掉一个尾点（`ngx_http_validate_host`）；无 Host 时是 `server_name`（骨架写 `server_name _;`，不会命中任何站点名）。IPv6 字面量 `[::1]` 不是合法站点名，必然 `unknown`。
- 索引键 = `edgesite.IndexKey(port, name)` = `md5("<port>\0<name>")` 16 字节原始字节（不是十六进制）。

### 2.2 顺序

1. 精确：键(port, host)。
2. 通配：依次去掉最左一个标签得到余下部分 r；r 含点时查键(port, `*.` + r)，r 不含点即停止。于是 `x.y.a.com` 依次查 `*.y.a.com`、`*.a.com`（最长通配优先）；`a.com` 去掉一个标签后余下 `com` 不含点，不做任何通配探测，所以 `*.a.com` 不匹配 `a.com`。与 nginx `server_name` 语义一致，由金标 `host-routing` 场景校验。
3. 命中后取站点对象并**复核**：对象的 `hosts.primary`/`hosts.aliases` 含命中名、`listeners[].port` 含该端口；复核失败按未命中继续下一级（md5 碰撞不会串站，site-object-v2.md §6）。

### 2.3 就绪

就绪是**按端口**的：端口 `p` 就绪 ⇔ 代指针所指的代 g ≥ 1 且 `ports:<g>` 含 `p`（§4.2）。冷启动重建中所有端口不就绪；一个新端口在第一次含它的代提交前不就绪（骨架可能先于索引 reload 出新端口）。不就绪端口上任何 Host 都是 `not_ready`（503），不是 `unknown`。

## 3. Lua API（`cdnca_site`，D4–D12 只用这些）

| 函数 | 阶段 | 语义 |
|---|---|---|
| `configure(opts)` | `init_by_lua` | `{ objects_root, index_root, system_max_body, lru_items }`；D2 写死路径（§6.2）。只调一次。`objects_root` 布局同 objectstore（`sha256/<2>/<2>/<64>`），必须 worker 可读（§5.5） |
| `init_worker()` | `init_worker_by_lua` | 起冷启动检查 timer（§5.3） |
| `route()` | `server_rewrite`，第一行 | §2 |
| `reject_unknown()` | `server_rewrite` | `unknown` 时回 421 并结束请求 |
| `current()` | 选站之后任意请求阶段（含 `balancer_by_lua`、`header_filter`、`body_filter`、`log`） | 返回本请求站点对象（Lua 表，`cjson` 解码的 `cdnca.edge.site/v2`，**只读**，worker 内按摘要缓存共享，不得修改）；`$cdnca_site_state ~= "ok"` 时返回 `nil` |
| `lookup(port, host)` | 任意（含 `ssl_client_hello_by_lua`、`ssl_certificate_by_lua`） | 不写变量；返回 `site, state, matched_name`；state 同 §1。D4 用 SNI 调用它判断“握手是否有站点”和取证书版本 |
| `object(digest)` | 任意 | 按摘要从对象库读并校验 SHA-256，worker LRU 缓存；返回原始字节。D5–D12 读站点引用的对象（CC 策略、错误页资源等）用它，**不得自行打开对象库路径** |
| `site(digest)` | 任意 | 按摘要取解码后的站点对象（同 `current()` 的缓存） |
| `generation()` | 任意 | 当前生效代（数字），未就绪为 `0` |
| `ready(port)` | 任意 | 端口是否就绪 |

约束：

- 站点对象表只读。需要派生结构（编译后的规则、解析后的证书）的模块按 `$cdnca_site_digest`（或被引用对象的摘要）自建 worker 级缓存；摘要不变即命中，无需失效。
- `ssl_*` 阶段没有 `ngx.var` 请求变量可写，D4 只用 `lookup`，`route()` 仍在 `server_rewrite` 重新按 Host 选站（会话恢复跳过证书回调，PoC §2 第 2 条：站点存在性要在 client hello 里查）。
- 任何模块不得写 `cdnca_site_*` 共享字典（§4），只有 `cdnca_site_admin` 写。

## 4. 共享字典与代

骨架声明（尺寸由节点规模档位决定：`键数 × 128 B × 1.25 + 65536 × 256 B`，后一项是一次变更集的过渡值余量；PoC §1）：

```nginx
lua_shared_dict cdnca_site_index   <size>;   # 索引：键 → 站点摘要（或过渡值）
lua_shared_dict cdnca_site_state   8m;       # 代指针、端口表、过渡键列表、重建状态、worker 心跳
lua_shared_dict cdnca_site_lock    1m;       # resty.lock
```

### 4.1 `cdnca_site_index`

- 键：16 字节 md5 原始字节（§2.1）。
- 值有两种，按长度区分：
  - **稳定值**：正好 32 字节 = 站点对象 SHA-256 原始字节（128 B 槽）。
  - **过渡值**（只在最近一次变更集改过的键上）：`0x01 ‖ gen u64 大端 ‖ flags u8 ‖ [new 32 B] ‖ [old 32 B]`，长 10/42/74 字节，永不为 32。flags bit0 = 有新值，bit1 = 有旧值。读取者用**本请求读到的当前代 g** 解析：`g ≥ gen` 取新值，否则取旧值；取到“无”即该键不存在。
- 只用 `safe_set`/`safe_add`/`delete`；任何 `no memory` 让本次 stage 失败（§4.3）。

### 4.2 `cdnca_site_state` 键

| 键 | 值 |
|---|---|
| `gen` | 当前生效代（整数）；0 = 从未提交 / 冷启动未完成 |
| `max_gen` | 用过的最大代号；新代号必须大于它（回滚后不复用代号） |
| `prev_gen` | 上一代（可回滚目标）；无则缺失 |
| `ports:<gen>` | 第 gen 代的端口表：`,` 分隔升序端口，前后各一个逗号（`,80,443,`）；就绪判断 = 子串 `,<p>,`。只保留当前代、上一代、进行中 stage 的三份 |
| `tags` | 当前存在过渡值的键：`<gen>:` + 连续的 16 字节键 |
| `stage` | 进行中的 stage 的代号；commit/abort 后删除 |
| `rebuild` | 重建状态 JSON：`{gen, done, total, started, finished, error}` |
| `worker:<pid>` | worker 心跳：已观察到的 gen，TTL 10 s |

### 4.3 代与原子切换

一次激活 = 一个**变更集**（§5.2：要设置/删除的键 + 新端口表 + 新代号 N）：

1. **stage N**（持锁）：先**收敛**上一批过渡值（按当前 gen 解析后写回稳定值或删除，清空 `tags`；这一步不改变任何读者看到的结果）；再对变更集每个键写过渡值 `{N, 新值, 当前稳定值}`，写 `ports:N`、`tags = N:<键…>`、`stage = N`。当前 gen < N，所以所有读者仍看到旧值，**stage 期间对外零变化**。任一 `no memory` → 收敛（等于撤销），返回 507。
2. **commit N**：`prev_gen = gen`、`max_gen = N`，最后写 `gen = N`。单键写是原子的：此刻起每个新请求读到 g = N，变更集内所有键**同时**切到新值。删除 `stage`。
3. **rollback N**（当前 gen = N 且 `tags` 属于 N）：写 `gen = prev_gen`。同样一次写、立即生效、整代同时切回；随后收敛过渡值（按新的 gen 写回旧值）。只能回滚一代；收敛之后（下一次 stage 开始时）就不能再回滚到更早的代，agent 对“不能单步回滚”的情形（分片激活、已收敛）用上一代索引文件算出到它的变更集，作为新代**向前激活**回去（不经重建、无 503 窗口）。
4. 读者一致性：`route()` 在一次选站中只读一次 gen，所有探测（精确 + 各级通配）与端口就绪都用同一个 g，所以一个请求看到的是某一整代。唯一例外：选站进行中恰好另一次 stage 开始收敛，读者可能看到收敛后的新值——只发生在“一个请求的几微秒内连续两次激活”，且命中后仍按站点对象 `hosts` 复核，不会串站。
5. 并发：stage/commit/abort/rollback/rebuild 都在 `resty.lock`（`cdnca_site_lock`，键 `admin`）内。

旧值、新值指向的站点对象都必须在对象目录里（§5.5）：agent 在 stage 前放好新代对象，并保留上一代的对象直到下一次 commit 之后。

### 4.4 大变更集与分片

单次变更集上限 `65536` 条（请求体 ≤ 3.2 MiB；过渡值余量按此计）。Go 侧把更大的变更拆成多个按顺序提交的代（每片一个代、各自原子），回滚只能回到最后一片之前；整体回滚到分片前用索引文件全量激活。冷启动、索引丢失、尺寸变化走 §5.3 重建。

## 5. 文件与控制通道

### 5.1 整代索引文件（agent 写，Lua 冷启动读）

路径：`<index_root>/gen-<gen>.idx`，`<index_root>/current` 是文本文件，内容 `gen-<gen>.idx\n`（原子 rename 更新）。agent 保留当前与上一代两个文件。格式（全部大端）：

```
magic   "CDNCAIX1"                       8 B
gen     u64                              8 B
count   u32  索引条目数                  4 B
nports  u16  端口数                      2 B
ports   nports × u16（升序）
entries count × (key 16 B ‖ digest 32 B)，按 key 字节序升序，key 唯一
trailer SHA-256(前面所有字节)            32 B
```

每条 48 B，100 万条约 46 MiB。Lua 读取时先校验 magic、长度、升序与 trailer，失败则整代拒绝（不就绪，健康报错）。

### 5.2 变更集（agent → Lua，经控制套接字）

```
magic   "CDNCACS1"                       8 B
gen     u64  新代号（> max_gen）          8 B
base    u64  期望的当前 gen（CAS）       8 B
nports  u16  新代端口数 + ports          2 B + nports × u16（升序）
count   u32  条目数（≤ 65536）           4 B
entries count × (op u8 ‖ key 16 B ‖ [digest 32 B 仅 op=1])，按 key 升序，key 唯一
        op 1 = 设置，op 2 = 删除
trailer SHA-256(前面所有字节)            32 B
```

### 5.3 冷启动重建

触发：`init_worker` timer 发现 `gen == 0`（共享字典是新的：节点启动、或尺寸档位变化后 reload）且 `<index_root>/current` 存在；或 agent 调 `POST /rebuild`。重建后 `gen = max_gen =` 文件里的代号。一个 worker 持锁重建（其他 worker 看到 `rebuild` 正在进行即跳过），**每 1000 条 `ngx.sleep(0)` 让出**（PoC §1：同 worker 请求最大卡顿 14–26 ms），写入的都是稳定值，全部写完后写 `ports:<g>`、`max_gen`，最后写 `gen = g`（无过渡值、无 `prev_gen`，不可回滚）。POST /rebuild 先 `flush_all` 再分片 `flush_expired` 清空旧键。重建期间所有端口 `not_ready`（503）。重建失败（文件损坏、`no memory`）记 `rebuild.error`，`gen` 保持 0，健康报告错误，agent 负责修复（重写索引文件或扩容档位）后调用 `rebuild`。

骨架 reload 在共享字典名、尺寸都不变时保留内容（PoC §1），不重建。

### 5.4 控制套接字

骨架提供一个只监听 unix 套接字的 server（不对外）：`listen unix:<state>/run/cdnca-site-admin.sock;`，路径所在目录 0700 属 agent 用户，worker 用户经组可连（D2 按 `lazy_certificate_pool.go` 的组处理）。location 一律 `content_by_lua_block { require("cdnca_site_admin").handle() }`：

| 方法 路径 | 体 | 响应（JSON） |
|---|---|---|
| `POST /stage` | 变更集（§5.2） | 200 `{gen, applied}`；409 base 不符；413 超限；507 `no memory`；400 格式错 |
| `POST /commit?gen=<n>` | — | 200 `{gen}`；409 没有该 stage |
| `POST /abort?gen=<n>` | — | 200；收敛过渡值即撤销 |
| `POST /rollback?gen=<n>` | — | 200 `{gen: prev}`；409 当前不是 n 或已不可回滚 |
| `POST /rebuild` | — | 202；清空索引后从 `current` 文件分片重建（期间全部 503） |
| `GET /probe?port=<p>&host=<h>` | — | 200 `{state, digest, site_id, matched}`：与请求期 `lookup` 相同的判断，不发真实请求 |
| `GET /status` | — | 200 `{gen, prev_gen, max_gen, stage, ports, tags, free_bytes, capacity_bytes, rebuild, workers: {pid: gen}}` |

`stage` 与 `commit` 分开，便于 agent 在 commit 前做额外检查；agent 默认 stage 成功后立即 commit。

### 5.5 worker 可读的对象目录

agent 的对象库（`internal/objectstore`）在动态路由节点上以 `objectstore.OpenShared` 打开（D13-c / F13）：位于 `<state>/objects`，根与 `sha256/` 各级目录 0750、对象 0440，组 = worker 组；`refs/`、`tmp/` 仍 0700 只属 agent。worker 直接读网关客户端存进去的站点对象与被引用对象，不再另存 `site-objects` 副本；激活器的对象目录标为外部（`siteindex.ObjectDir.External`），只核对对象在库、不写不删，回收由对象库按每个 owner 的“当前 + 上一代”做。库里只有**不含机密**的对象：站点对象、被引用对象（site-object-v2.md §3）与节点制品集分段（签名公开制品）；证书私钥在 certstore、回源鉴权凭据走机密对象目录，都不进对象库。非 agent 场景（金标渲染器、各 `cdnca-*-check`）不设 `ObjectsRoot` 时仍用 `<state>/site-objects`，由激活器写入与回收。

### 5.6 健康

某代**健康** ⇔ `status.gen == 该代` 且所有存活 worker 心跳 ≥ 该代（每 worker 每 1 s 写一次）且 `rebuild.error` 为空且 `free_bytes ≥ 20% capacity`（低于即告警扩容，PoC §1 第 2 条）且 agent 对本次变更的站点做本机 Host 探测（经控制套接字 `GET /probe?port=&host=` 返回 `lookup` 结果，不发真实请求）全部选中预期摘要。

## 6. 给 D2 的骨架片段（必须照写）

### 6.1 每个共享 server

```nginx
server {
    listen <addr>:<port> [ssl] [reuseport] ...;
    server_name _;
    server_rewrite_by_lua_block {
        local site = require("cdnca_site").route()
        -- 此处之后才是 CC 等同阶段模块（D5…）
        if not site then
            -- unknown：节点级 location 之外一律 421
            if ngx.var.cdnca_node_location == "" then return require("cdnca_site").reject_unknown() end
        end
    }
    client_max_body_size $cdnca_site_max_body;
    ...
}
```

`$cdnca_node_location` 是 D2 用 `map $uri $cdnca_node_location { default ""; /<探测路径> 1; ~^/\.well-known/acme-challenge/ 1; ... }` 声明的节点级路径标记（ACME overlay 前缀、市场探测、基准对象、健康）。D2 若用别的写法，只要满足“`ok` 走站点、`unknown` 只放行节点级路径、`not_ready` 一律 503”即可。

### 6.2 http 级

```nginx
lua_package_path "<lua_root>/dynroute/?.lua;...;;";
uninitialized_variable_warn off;   # 声明 location 永不执行，变量首次被 Lua 读时不告警
lua_shared_dict cdnca_site_index <size>;
lua_shared_dict cdnca_site_state 4m;
lua_shared_dict cdnca_site_lock 1m;
init_by_lua_block {
    require("cdnca_site").configure({
        objects_root = "<state>/objects", -- §5.5，agent 对象库（共享打开），worker 可读；未设 ObjectsRoot 时 <state>/site-objects
        index_root = "<state>/site-index",
        system_max_body = <字节数>,           -- 节点系统上传上限
    })
}
init_worker_by_lua_block { require("cdnca_site").init_worker() }
server {
    listen unix:<state>/run/cdnca-site-admin.sock;   # §5.4 控制套接字 server
    client_max_body_size 4m;        # 变更集 ≤ 3.2 MiB
    client_body_buffer_size 4m;     # 体留在内存
    access_log off;
    location / { content_by_lua_block { require("cdnca_site_admin").handle() } }
    location = /__cdnca_site_vars {
        internal;
        set $cdnca_site_id "";
        set $cdnca_site_revision "";
        set $cdnca_site_digest "";
        set $cdnca_site_tenant "";
        set $cdnca_site_scope "";
        set $cdnca_site_host "";
        set $cdnca_site_port "";
        set $cdnca_site_generation "";
        set $cdnca_site_max_body "1";
        set $cdnca_site_state "";
    }
}
```

声明 location 放在控制套接字 server 里（nginx 变量是 http 级全局的；`set` 只在该 location 被执行时求值，`internal` 保证它永不执行）。`lua_package_path` 前缀以 D2 实际 Lua 安装路径为准（镜像里是 `/usr/local/share/cdnca/dynroute/`，原生包 `lua/share/cdnca/dynroute/`，brand-rename 统一改名）。

## 7. 不在本契约内

- 证书、client hello 协议收窄（D4）；回源（D?）；缓存键与 zone（D?）。它们从 `current()` / `lookup()` 读站点，按 §1.4 声明自己的变量。
- 多 scope 合成：索引是节点级的（所有 scope 的站点进同一个索引），跨 scope 的（端口, 名字）唯一性由 Go 侧 `edgesite.PortProfiles` 在生成变更集前校验，Lua 不裁决。

## 8. 实现与验收（D3）

- Go：`agents/edge-agent/internal/siteindex`——`Builder`/`Build`（节点级索引，规则同 `edgesite.PortProfiles`，md5 碰撞拒绝）、`MarshalIndex`/`UnmarshalIndex`（§5.1）、`MarshalChangeSet`/`UnmarshalChangeSet`（§5.2）、`Diff`/`ChangeSets`（分片，§4.4；端口只在最后一片移除）、`Files`（`gen-<n>.idx` + `current`，保留两代）、`ObjectDir`（§5.5）、`Activator`（`Activate`：一致时走变更集，否则写索引文件后重建；`Rollback` 单步、`RollbackTo` 向前回滚；`Check`/`WaitHealthy` §5.6）。
- Lua：`edge/openresty/dynroute/cdnca_site.lua`、`cdnca_site_admin.lua`（镜像 `/usr/local/share/cdnca/dynroute/`，原生包 `lua/share/cdnca/dynroute/`）。索引字典与状态字典各存一份纪元，不一致即“索引丢失”：未命中回 503 而非 421，worker timer 触发重建。
- 验收：`tests/dynroute-index/run.sh`（真实 OpenResty 1.31.1.1 节点运行时镜像，`--rm --network none`，2 个 worker）。

功能验收（46 项全过）：按 Host 选站（主域名、别名、一级/两级通配、精确优先于通配、最长通配、`*.x` 不匹配 `x`、大小写、Host 带端口、尾点、按端口隔离）；未知 Host / IP Host / 无 Host / `[::1]` → 421；节点级路径只服务未知 Host，已配置站点同路径走站点；`ngx.exec` 后选站保留；`$cdnca_site_max_body` 生效（站点 2048 B：2048 过、2049 → 413）；首次激活前、站点对象缺失、索引文件损坏时 503；`/probe` 与健康检查；**40 次代切换（含 4 次回滚）期间 16 并发客户端 14–48 万请求零失败**（每次激活最长 0.17–0.46 s）；单步回滚整代恢复（含新端口回到 503）、不能回滚两步、收敛后向前回滚；同尺寸 reload 保留索引、改尺寸 reload 自动冷启动重建；字典满（`no memory`）时拒绝新代并保持旧代可用；对象目录只留当前与上一代对象。

规模实测（`SCALE=1000000 ONLY=scale`；本机 arm64 Docker Desktop，10 vCPU / 8 GiB，机器同时有其他任务，load 13–20，三次运行；耗时只作量级参考，字节数确定）：

| 项 | 10 万站 | 100 万站（三次） |
|---|---|---|
| 索引键（每站 1 名 × 1 端口） | 100,000 | 1,000,000 |
| 整代索引文件 | 4,800,056 B | 48,000,056 B（48 B/条） |
| 共享字典占用 | 12 MiB，130 B/键 | 123 MiB，129 B/键（168m 档） |
| Go 构建索引（排序+查重） | 99 ms | 1.6–4.5 s |
| 编码索引文件 | 10 ms | 30–306 ms |
| 冷启动重建（nginx 内，1000 条/片让出） | 73–133 ms | 2.7–5.0 s |
| 冷启动期间请求 | 只有 503 与 200，无其他状态；最大延迟 3 ms | 只有 503 与 200；最大延迟 13–33 ms |
| 查表（worker 内，站点对象已在 LRU） | p50 1.1 µs，p99 2.8 µs | p50 1.8–4.8 µs，p99 5–59 µs |
| 查表（首次读对象文件并校验 SHA-256） | p50 29 µs，p99 0.39 ms | p50 0.45–0.84 ms，p99 3.9–14.7 ms |
| 未命中（精确 + 3 级通配探测） | p50 1.7 µs，p99 6.7 µs | p50 3.9–5.1 µs，p99 43–99 µs |
| 端到端请求（单客户端顺序，随机站） | p50 134 µs，p99 0.99 ms | p50 0.2–1.1 ms，p99 4.9–12.9 ms |
| 增量 100 站（200 个变更）| 1.65 s | 20–22 s：Go 重建整份新索引 4.1 s + 写 48 MB 文件 0.6 s + **节点 stage/commit 67 ms** + 回收 24 ms；其余是验收程序重新编码 100 万对象（agent 不做） |

结论：100 万键字典 123 MiB、冷启动 3–5 s、查表微秒级，与 PoC §1 外推一致，不需要换索引层。冷读对象的尾延迟（p99 毫秒级）来自每个新站点第一次请求读文件 + SHA-256；worker LRU 默认 10000 站，D2 按节点内存档位配 `lru_items`。

遗留（不在 D3 范围或待定）：
1. 增量激活在 Go 侧仍按“整份新索引 → Diff”计算（100 万站约 4 s）；D2/D8 接站点对象下发时应改为按变更站点直接生成变更集（`Diff` 的输入只需变更站点的新旧条目）。
2. ~~对象在 objectstore 与 `site-objects` 各存一份~~：D13-c 已改为对象库按组可读、去掉副本（§5.5）。
3. 首次激活 100 万站约 9 min，主要是向 `site-objects` 逐个写 100 万个小文件（Docker Desktop 文件系统）；生产磁盘待独立测试机实测。

## 附录 A：响应阶段编排（D9 增补，不改上文条款）

- `header_filter` / `body_filter` 只有一个入口（`cdnca_filters.header_filter()` / `body_filter()`，入口模块调用），槽顺序固定：1 错误页替换 → 2 HTTP 策略（替换页上不执行）→ 3 缓存命中头 → 4 HSTS（只 `$https = on`）→ 5 Alt-Svc。各槽只写自己的头；槽 3–5 的头名（`X-CDN-Cache*`、`Strict-Transport-Security`、`Alt-Svc`）与 `x-cdnca-*` 为保留头，HTTP 策略两端校验拒绝。模块注册：`cdnca_filters.register("http_policy" | "cache_status", fn(site, state))`。
- 错误页替换只作用于 `cdnca_filters.routed()`（`server_rewrite` 最后一行）之后的响应；模块自己出页前调 `cdnca_filters.own_page(kind)`，该响应不被替换。
- 新增模块变量（§1 第 4 条规则）：`$cdnca_filters_routed`、`$cdnca_limits_conn_key`、`$cdnca_limits_rate_key`；新增共享字典 `cdnca_limits_conn`、`cdnca_package_bandwidth`。D10 不改写 `$cdnca_site_max_body`（§1.2）。
- 详细语义、验收与实测：[dynroute-filters.md](dynroute-filters.md)。
