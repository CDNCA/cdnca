# ADR 0017：第三方插件下发到节点

- 状态：暂缓（节点负担大，需要时再做）。未实现，不进 1.0.35；下文为调研结论，恢复时重新评审。
- 兼容基线：1.0.35（不兼容 1.0.34 及更早；新节点能力按能力协商门控，节点不具备直接拒绝发布并列出节点，能力到位后自动重新发布）。
- 用户原话：“第三方插件也要能下发到节点”。
- 修订：ADR 0007 §3 边界“第三方代码不进入控制面和边缘请求路径”在边缘一侧被本文修订（控制面一侧不变），PA-03 删除的节点插件机制不恢复（能力 30 仍 reserved，本文用新号）。
- 代码核对基于集成头 `10c7eecc1`。路径前缀：节点 `agents/edge-agent/`，规则包 `libs/rulepack/`，市场 `services/market-service/`，授权端 `services/license-service/`，主控 `services/control-api/`。
- PoC：`tests/node-plugin-poc/run.sh`（提交 `691a41b0e`），结果见 §6。

## 1. 结论（先看这里）

推荐 **方案 ③′：进程外 WASM 插件宿主**，与 **方案 ①：扩展声明式规则包** 并行。

- 第三方节点代码只以 WASM 字节进入节点，跑在 agent 拉起的独立进程 `cdnca-plugin-host`（Go + wazero，纯 Go、不链 C 运行时）里，不进 nginx worker。nginx 在 `access` 阶段经 unix socket 调宿主拿“决定”（放行/拒绝/加头/打标），宿主不可用时按挂载声明的 `failure_mode`（默认放行）处理。
- 不选 nginx 内的 proxy-wasm（ngx_wasm_module）：上游仍是 prerelease 0.6.0（2025-02），最后一次提交 2025-04，CI 只测 nginx 1.27.4 / OpenResty 1.27.1.1，我们钉的 1.31.1.1 没有任何上游验证；而且 WASM 运行时（wasmtime/V8，C/C++/Rust）链进 worker，运行时自身缺陷或内存耗尽直接打掉 worker。
- 不选 worker 内受限 Lua：PoC 实测 `string.rep` 一类 C 函数绕过指令计数钩子，一个请求让 worker 卡 0.4–2.7 秒并被 OOM 杀（§6.3）。
- 方案 ① 继续是首选开放面：大多数“节点上的第三方逻辑”（匹配 + 白名单动作）用规则包表达零运行时风险。WASM 插件只覆盖规则包表达不了的部分（自定义算法、签名/令牌校验、复杂打分）。

## 2. 现状：开发者规则包已经是“第三方内容下发到节点”

链路（全部已实现，集成头可用）：

| 环节 | 依据 | 做了什么 |
|---|---|---|
| 格式 | `libs/rulepack/pack.go:35-57,113-145` | `cdnca.rule-pack/v1`，`layer=developer`，`pack_id = dev/<发布者>/<名>`（`pack.go:96`） |
| 引擎白名单 | `pack.go:59-74` | `waf_v2`、`cc_v2`、`acl`、`challenge`、`modsecurity`（只限 CRS 选择/调优），`crs_app`；`EngineMaxVersion` 钉版本 |
| 条件 | `libs/edgeconfig/config.go:280-296`、`waf_inspect.go:60-67` | method/path/header/source_cidr/JA4/IP 情报；检测目标 12 种文本 + 6 种数值，运算符 contains/regex/prefix/…/detect，检测器 sqli/xss/ssti/java_deser/php_deser/ssrf/cmd，过滤器 5 种 |
| 动作 | `config.go:57-65`、`waf_action.go:28-29`、`cc_v2.go:89-92` | WAF：allow/block/log/challenge/ban + continue/stop；CC：log/reject_429/temporary_ban/challenge |
| 预算 | `budget.go:27-31,36-41` | 每包 256 规则 / 64 正则 / 4096 单位；每站 1024 / 256 / 16384；CC 128 条；正则 ≤ 512 字节、重复 ≤ 256 |
| 市场审核 | `market-service/internal/review/pass_datapack.go:180-200` | 编译、预算、命名空间必须是发布者、版本一致、规范编码 |
| 授权端封装 | `license-service/internal/licensing/plugin_data_pack.go:98-112` | 同一编译器复核 + 发布门 |
| 主控同步 | `control-api/internal/artifactsync/datapack.go:33-49` | 目录条目 `market_rule_pack`，按摘要验内容 |
| 节点 | `cmd/edge-agent/artifact_set.go:67-71`、`rule_pack_artifacts.go:25-49` | 制品集安装器 `MediaTypeRulePack`，可解封装（`rulepackvault`）后同一编译器复核 |
| 执行 | `edge/openresty/lua/cdnca_rule_interp.lua`（ADR 0009 D6） | 节点解释器，不执行包内任何代码 |
| 转售 | `control-api/internal/marketsupply/supply_plugins.go:60-63,204` | `rule_pack:<id>` 作为供货插件码 |

能做：请求阶段的匹配 + 上述白名单动作；参数化（`params_schema`）；分层优先级与冲突检测（ADR 0007 §5.2）；内容加密防复制（§6）；预算保证每请求代价有界。

不能做：
1. 任何计算：不能做 HMAC/签名/令牌校验、不能算哈希、不能维护自定义状态（CC 计数只有内置维度）。
2. 响应阶段：不能改响应头/体（`pack.go` 没有 header_filter/body_filter 引擎）。
3. 改写请求：不能改 URI/请求头/回源选择（动作集里没有 rewrite/set_header）。
4. 外部调用：不能查第三方服务（这是 C1 进程外服务的范围，但 C1 不在请求路径）。
5. 新检测算法：检测器只有 7 个内置项，第三方不能带自己的检测器。

kind 清单 `libs/marketproto/pluginkind/kinds.json`：`rule_pack` 对第三方开放，`engine_module`（nginx 原生模块）为 `official_only`。能力号：30（NODE_PLUGINS）reserved（`proto/agent/v1/types.proto:42-44`），当前最大号 46。

## 3. 方案对比

| | ① 扩展声明式规则包 | ②a nginx 内 proxy-wasm | ②b worker 内受限 Lua | ③a 进程外原生 sidecar | **③′ 进程外 WASM 宿主（推荐）** |
|---|---|---|---|---|---|
| 第三方交付物 | JSON 数据 | `.wasm`（proxy-wasm ABI） | Lua 源码 | 任意语言原生二进制 | `.wasm`（cdnca ABI，§5.2） |
| 能做什么 | 匹配 + 白名单动作；可加 rewrite/set_header/响应头动作、新检测器（官方实现） | 请求/响应头体全阶段、共享 KV、外呼 | 同 Lua 能力的子集 | 任意（含外呼、磁盘） | 请求阶段决定：放行/拒绝/加头/打标；首期不开放响应体与外呼 |
| 请求路径影响 | 无额外跳；代价受预算约束（`budget.go:27-31`） | 进程内调用，最快 | 进程内，JIT 关闭后慢 | 一次 IPC | 一次 unix socket 往返，PoC p50 +138 µs（§6.1） |
| 崩溃隔离 | 无代码，不需要 | **无**：运行时链进 worker，运行时缺陷/内存耗尽打掉 worker | **无**：PoC 中 C 函数绕过钩子，worker 卡 2 s 并被 OOM 杀（§6.3） | 进程级 | 进程级 + 实例级：PoC 中死循环/trap/超内存只回收实例，`kill -9` 宿主时 nginx worker 不变、5000/5000 放行（§6.2） |
| CPU/内存上限 | 静态预算 | 运行时 fuel/epoch（视运行时）；内存靠线性内存上限，worker 无 cgroup 隔离 | 指令计数钩子（只管 VM 指令），内存无上限 | cgroup + seccomp | 每调用截止时间（`WithCloseOnContextDone`）+ 每实例线性内存上限（`WithMemoryLimitPages`）+ 宿主 cgroup（systemd `MemoryMax/CPUQuota`） |
| OpenResty 1.31.1.1 兼容 | 不涉及 | **未验证**：上游 prerelease 0.6.0（2025-02），CI 只到 OpenResty 1.27.1.1；需新增补丁与 Rust/C 运行时构建链 | 原生支持 | 不涉及 | 不涉及（只用 cosocket，PoC 在 1.31.1.1 跑通） |
| 审核 | 现有编译器 + 预算 pass | 只能扫导入表；行为不可审 | 源码可读但沙箱难证明 | 二进制不可审，供应链风险最大 | 校验导入表只含白名单（WASI 时钟/随机 + cdnca 宿主函数）、导出必须有 `cdnca_alloc/cdnca_on_request`、大小上限；行为由沙箱保证，不靠审核 |
| 签名/吊销/授权 | 现链路 | 同 ③′ | 同 ③′ | 同 ③′ | §5.3–5.5 |
| 复用制品集 | 现成 | 是 | 是 | 是（但要新安装器管进程） | 是：新 media type + 安装器；字节进对象库 |
| 工作量（粗估） | 每加一种动作/引擎 2–5 天（主控编译器 + 节点解释器 + 冲突检测） | 大：新原生补丁 + 运行时交叉编译 + 自行跟上游 | 中，但无法达到隔离要求 | 大：进程管理、seccomp、按插件 cgroup、二进制审核 | 中：宿主约 1–1.5k 行 Go、agent 安装器与 systemd 单元、节点 Lua 调用与发布渲染、审核 pass、SDK 与文档；约 2–3 人周（未细拆） |

取舍理由：

1. 用户要求“第三方插件能下发到节点”，而 ADR 0007 §3 要求可执行扩展“证明沙箱、CPU/内存上限、超时、崩溃隔离与签名”。②a/②b 都把不可信代码放进 nginx worker，崩溃隔离这条在结构上就做不到；②b 已被 PoC 证伪（§6.3）。
2. ③a 能力最大，但第三方原生二进制落到每个节点，审核与供应链风险不可控，和 `engine_module` 只许官方（`kinds.json`）的理由相同。
3. ③′ 把“沙箱”交给 WASM（内存安全、无系统调用、无宿主函数就什么也做不了），把“崩溃隔离”交给进程边界，把“资源上限”交给 wazero + cgroup，三层都由 cdnca 自己的代码控制；运行时是纯 Go（wazero 无 CGO 依赖），与 agent 同一构建链，不碰 OpenResty 版本钉。
4. 代价是每个挂载插件的请求多一次本机 IPC。所以插件只对挂载它的站点/路径生效，不挂载零开销（与规则包挂载同一套 `security.mounts`）。

## 4. 不做的事

- 不恢复 PA-03 删除的节点插件机制（`libs/edgeconfig/nodeplugin`、能力 30）；本文是新通道。
- 不让第三方插件改调度/下发（ADR 0007 §3 第二条不变）。
- 首期不开放：响应体处理、插件外呼网络、插件持久化存储、跨请求共享状态（实例内存可缓存，但实例随时会被回收，不保证）。

## 5. 推荐方案设计（③′ + ①）

### 5.1 链路（复用 ADR 0007 §4 制品通道，不新增通道）

```
开发者 ─上传 .wasm + 清单（发布者 key 签）─▶ 市场审核（新 pass：wasm_plugin）─▶ 授权端目录条目 kind=market_wasm_plugin
主控 artifactsync 按授权同步 → 管理员启用 → 站点 security.mounts 挂载 {layer: developer, plugin_id, version, sha256, phase, failure_mode}
主控 artifactsetdist → 节点制品集 item（media type application/vnd.cdnca.edge.wasm-plugin;version=1）
节点 wasmPluginInstaller 预检（摘要、导入表白名单、wazero 编译）→ 写对象库 → 通知 cdnca-plugin-host 重载 → 回执 applied/rejected
nginx（站点渲染/动态路由）对挂载了插件的请求在 access 阶段调 unix:/run/cdnca/plugin.sock
```

- 新市场 kind `wasm_plugin`（加入 `kinds.json`，第三方可发布），新目录 kind `market_wasm_plugin`（`libs/entitlement/artifactcatalog/catalog.go:28-50` 并列）。
- 制品集上限沿用 `libs/edgeconfig/artifactset/artifactset.go:66-69`（每条目解压后 ≤ 64 MiB、每集合 ≤ 32 条目）。PoC 用 Go 编出的插件 1.6 MiB；首期另设插件上限 8 MiB。每集合 32 条目与规则包、IP 库共用，节点上同时启用的插件数要另设上限（建议 8）。
- 挂载与冲突检测复用 `security.mounts`（ADR 0009 §8.4，`docs/adr/0009-edge-runtime-routing.md:240`）；执行顺序：用户规则 → 开发者规则包 → **WASM 插件** → 系统规则（插件排在开发者层末尾，理由：规则包更便宜，先命中先结束）。

### 5.2 ABI 与能力（首期）

- cdnca 自定 ABI（不是 proxy-wasm）：导出 `cdnca_alloc(u32)->u32`、`cdnca_on_request(ptr,len)->u64`；输入是有界的请求视图（方法、URI、≤ 32 个请求头、客户端 IP、JA4、IP 情报标签、挂载参数），输出一条决定：`allow` / `deny <status>` / `header <name> <value>`（只能加 `x-` 前缀响应头）/ `tag <name>`（进日志与后续规则条件）。宿主拒绝其他输出。
- 不用 proxy-wasm 的原因：它假设插件可直接操作宿主的头/体与外呼，宿主进程外时语义无法保持；自定 ABI 只描述“决定”，与进程外天然对齐，也便于以后由官方加能力（新 ABI 版本 = 新能力版本）。
- 导入白名单：`wasi_snapshot_preview1` 的 `clock_time_get`、`random_get`、`proc_exit`、`fd_write`（只到宿主日志，限速）及其他 WASI 调用的拒绝桩；没有文件系统、环境变量、网络。审核 pass 和节点预检都校验导入表。
- SDK：首期官方提供 Go（`GOOS=wasip1 -buildmode=c-shared`，PoC 已用）与 Rust 模板；TinyGo 未测。

### 5.3 签名与审核

| 层 | 签名者 | 节点验 | 依据 |
|---|---|---|---|
| 插件清单与字节 | 发布者 Ed25519 key | 否（市场验） | `market-service/internal/plugin/manifest.go:181-183` `VerifyManifestSignature` |
| 目录 envelope | 授权端在线 key | 否（主控验） | ADR 0007 §4.2 |
| 节点制品集 | 主控边缘发布 key | 是 | ADR 0007 §4.2、§4.3 |

与 C2 规则包同级：节点信任主控转发，不额外验授权端签名（ADR 0007 §4.2 末段）。不像 B3 那样要平台发布签名，理由：B3 是 nginx 加载的原生代码，WASM 插件的安全性来自沙箱与进程边界，而不是来源；主控本来就能下发任意站点配置，多验一层签名不增加对恶意主控的防护。审核 pass 只做静态校验（导入表、导出、大小、能被 wazero 编译、样例请求冒烟在超时内完成），不承诺审出恶意行为。

### 5.4 资源上限与故障处理

- 进程：`cdnca-plugin-host` 独立 systemd 单元，由 agent 管理（安装/重载/停），独立用户，`RestrictAddressFamilies=AF_UNIX`，`ProtectSystem=strict`，对象库只读；`MemoryMax`、`CPUQuota` 限总量（默认值待定，§8 第 4 点）。注意：agent helper 单元的 `MemoryDenyWriteExecute=yes`（`packaging/systemd/cdnca-edge-agent-helper.service:60`）会挡住 wazero 编译模式的可执行内存，宿主单元不能带这一项，否则只能用解释模式（未实测，推断）。
- 每调用：截止时间（PoC 20 ms）、每实例线性内存（PoC 64 MiB）、每插件实例池（PoC 8 个），池满等待 ≤ 5 ms 后返回 `busy`。
- 熔断：同一插件在某节点 1 分钟内超时/trap 超过阈值，宿主停用该插件并回执 `plugin_degraded`，主控通知租户与发布者；不自动恢复，需管理员在主控重新启用（理由见 §6.2 loop flood：回收重建实例本身很耗 CPU）。
- `failure_mode`（挂载级）：`open`（默认，宿主不可用/超时/熔断时放行并在日志标记）或 `closed`（返回 503）。nginx 侧 cosocket 超时比宿主截止时间多 10 ms。

### 5.5 授权、能力、吊销

- 授权：按安装购买（`plugin_market_entitlements`，ADR 0007 §8.5），未授权不进目录、不进节点制品集。
- 能力：新能力 `WASM_PLUGIN_HOST` v1（能力号未分配，恢复本 ADR 时再分配）。节点在宿主健康时才声明；站点挂载插件而目标节点不具备 → 拒绝发布并列节点；能力到位后自动重新发布（g11-syspub 入口）。ABI 加能力时升能力版本。
- 吊销：市场下架/安全公告 → 授权端停用 → 目录下一 revision 不含 → 主控生成不含该插件的新集合 → 节点安装器删除 → 宿主卸载（PoC：删文件 + 重载后返回 `none`）。紧急全局撤回沿用 ADR 0007 §9。节点 LKG：新版本预检或编译失败保留上一版（PoC：坏文件重载被拒、旧插件继续服务）。

## 6. PoC 结果（`tests/node-plugin-poc`）

环境：本机 Docker Desktop（arm64 VM），镜像 `cdnca-native-runtime:edge-golden`（`nginx -V` = `openresty/1.31.1.1`），单容器 `--rm --network none --cpus 2 --memory 512m`，2 个 nginx worker；宿主以 `nobody` 运行，wazero v1.11.0 编译模式；插件为 Go 1.24 `wasip1` reactor（1,649,530 字节）。压测客户端与 nginx、宿主在同一个 2 CPU 容器里争 CPU，吞吐数字只作相对比较，**不是生产 amd64 数据**。第 4 次运行的原始输出摘录如下（前 3 次用于修脚本：`return` 指令跳过 access 阶段、日志路径权限、socket 残留）。

### 6.1 加载与延迟

| 项 | 结果 |
|---|---|
| 加载（编译 + 8 实例） | 487 ms（其他几次 319–400 ms） |
| 宿主 RSS（加载后） | 103,044 KiB |
| 正常决定 | `x-plugin-seen: 1`、`x-plugin: ok`；`/deny` → 403 |
| 基线（无插件）20000 请求 c=16 | p50 99 µs，p99 1.866 ms，64,635 rps |
| 挂插件 20000 请求 c=16 | p50 237 µs，p99 2.325 ms，25,662 rps；19,983 ok / 17 `unavailable`（cosocket 30 ms 读超时，CPU 争用） |

结论：一次本机 IPC + 一次 WASM 调用 p50 约 +138 µs。吞吐下降包含同容器 CPU 争用（宿主与 nginx、压测器共用 2 CPU），生产上需在真 amd64 节点再测（未做）。

### 6.2 超时、trap、内存上限、崩溃隔离、卸载

| 场景 | 结果 |
|---|---|
| `/loop` 死循环 | 当次 `x-plugin: error`（timeout），下一请求 `ok` |
| 死循环洪水（200 个 /loop，c=4）同时跑正常请求 5000 个 c=16 | 正常请求 4,886 ok / 42 `busy` / 71 `unavailable` / 1 timeout，p50 492 µs、p99 77 ms；洪水本身 110 timeout / 6 busy / 84 unavailable，无一请求失败（全部按故障放行返回 200） |
| `/trap`（panic） | 当次 `error`（trap），下一请求 `ok`；实例被回收重建 |
| `/oom`（无限申请内存） | 当次 `error`，下一请求 `ok`；本机单测 `budget=2s` 时 65 ms 触发 64 MiB 上限 trap，`budget=20ms` 时先撞超时（22 ms） |
| 统计（全部场景后） | calls 25,210，ok 24,950，timeouts 196，traps 1，busy 63，recycled 197 |
| 宿主 RSS（回收 197 次后） | 290,076 KiB（回收的实例内存未及时还给系统，需宿主 cgroup `MemoryMax` 兜底） |
| `kill -9` 宿主 | nginx 两个 worker pid 不变；5000/5000 返回 200（`x-plugin: unavailable`），p50 120 µs |
| 重启宿主 | 恢复 `ok` |
| 坏文件重载 | 拒绝（`compile: invalid magic number`），继续用旧插件（LKG） |
| 删文件重载 | 返回 `none`（卸载）；放回后 `ok` |
| nginx error.log crit/alert/emerg（插件部分） | 0（只有后面 Lua 场景的 2 次 worker 被杀） |

发现：死循环回收很贵（每次重建实例约数十 ms CPU），持续的恶意/缺陷插件会把宿主 CPU 吃满并拖慢其他插件——所以 §5.4 要熔断与宿主 cgroup；插件之间的公平性（每插件独立进程或 CPU 份额）首期不做，§8 第 4 点。

### 6.3 对照：worker 内受限 Lua（方案 ②b）

| 场景 | 结果 |
|---|---|
| 正常插件 | 正常返回 |
| 逃逸（读 `io`/`os`/`require`/`ffi`） | 全部 `nil`，环境白名单有效 |
| `while true do end` | 2–6 ms 后被指令计数钩子停下 |
| `string.rep("x", 400 MiB)`（C 函数） | 钩子无法中断：单次 379 ms–2.7 s；同时的无插件请求 max 2.15 s、1 个 500；**nginx worker 被容器 OOM 杀 2–4 次**（`worker process … exited on signal 9`） |

结论：进程内 Lua 沙箱只能限 VM 指令，不能限 C 函数耗时与内存，一个插件即可让同 worker 的全部站点停顿并重启 worker；不满足 ADR 0007 §3 的崩溃隔离要求。

### 6.4 未验证

- 生产 amd64 节点上的延迟与吞吐、宿主与 nginx 分开 CPU 时的数字。
- systemd 单元下（cgroup `MemoryMax/CPUQuota`、去掉 `MemoryDenyWriteExecute`）的实际行为。
- 与 ADR 0009 动态路由 / 站点对象挂载的接线、发布门控、回执。
- Rust / TinyGo 编出的插件（更小、实例更省内存，推断）。
- 宿主热重载时在途调用的排空（PoC 用 2 秒延迟关闭旧版本）。

## 7. 实现任务（用户选定后再派）

| 编号 | 内容 | 依赖 |
|---|---|---|
| NP-01 | `libs/wasmplugin`：ABI、导入白名单校验、请求视图编码（主控审核与节点预检共用） | — |
| NP-02 | `cdnca-plugin-host`：wazero 宿主（PoC 改产品化：多插件、排空、熔断、指标、日志限速）+ systemd 单元 | NP-01 |
| NP-03 | agent：`wasmPluginInstaller`（制品集 media type）、宿主生命周期、能力声明 `WASM_PLUGIN_HOST` | NP-02、能力号 |
| NP-04 | 市场 kind `wasm_plugin` + 审核 pass + 授权端目录 kind + 主控 artifactsync | NP-01 |
| NP-05 | 主控挂载（`security.mounts` 新项）、发布门控、冲突/预算、`failure_mode` 页面 | NP-03、NP-04 |
| NP-06 | 节点渲染/动态路由 access 阶段调用 + 日志字段（插件结果、耗时、失败原因） | NP-05 |
| NP-07 | SDK 模板（Go、Rust）+ 开发者文档 + 三进程 e2e | NP-01–06 |
| R-xx | 方案 ① 扩展：规则包新增 `set_request_header`/`rewrite`/`add_response_header` 动作 | 独立，可先做 |

## 8. 需要用户选的点

1. **形态**：推荐 ③′ 进程外 WASM 宿主 + ① 扩展规则包并行；备选“只做 ① 扩展规则包、不开放可执行代码”（零运行时风险，但做不了自定义算法）。nginx 内 proxy-wasm 与 worker 内 Lua 不建议（§3、§6.3）。
2. **首期能力范围**：只做请求阶段决定（放行/拒绝/加头/打标）；是否首期就要“改请求头/改写 URI”或“响应阶段改头”（每加一项都是 ABI 能力版本与节点渲染改动）。
3. **故障默认值**：挂载 `failure_mode` 默认放行（推荐，插件故障不影响站点可用性），还是默认拒绝（安全类插件更严格）。
4. **资源默认值与隔离粒度**：宿主总量建议 `MemoryMax=512M`、`CPUQuota=100%`，每调用 20 ms、每实例 64 MiB；是否需要“每插件一个宿主进程”（隔离更好，内存翻倍）——推荐首期单宿主 + 熔断。
5. **节点验签层级**：推荐与规则包同级（节点只验主控制品集签名）；或要求像 B3 那样再带平台发布签名（离线签，每次上架需平台签名，流程更重）。

