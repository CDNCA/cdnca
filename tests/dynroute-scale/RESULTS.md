# D13-d 动态路由规模基准与全量回归结果（2026-10-20）

基线：148f35377 之后（动态路由已是节点唯一模式）。

## 1. 规模基准

工具：`tests/dynroute-scale/run.sh`（`main.go` 经 `go build -overlay` 编进 edge-agent 模块，驱动 `internal/dynroute.Runtime` 与 daemon 同样的 Apply/Recover）。
环境：本机 arm64 Docker Desktop（10 vCPU / 8 GiB），节点运行时镜像 `cdnca-native-runtime:edge-golden`（OpenResty 1.31.1.1），每档一个 `--rm --network none --memory 6g` 容器，2 个 worker；
站点每站 2 个域名（主域名 + www）× 1 端口，10% 带缓存策略；全机同时有其他任务（load 6–13），耗时只作量级参考，字节数确定。
每档跑两次（10 万站：12:15、12:23；1 万站：12:03、12:47），下表取两次范围。原始日志在 `results/`（`*.log` 被 .gitignore 忽略，未提交）。

| 项 | 1 万站 | 10 万站 |
|---|---|---|
| 站点对象 | 911 B/个，8.7 MiB | 913 B/个，87.1 MiB |
| 首次激活（Apply：写骨架+启动+整代重建+健康检查） | 2.4–2.7 s | 23.8–29.2 s |
| 其中索引激活（Activator） | 170–188 ms | 1.8–2.4 s |
| 其中 nginx 内重建（2 万 / 20 万键） | 12–13 ms | 294–419 ms |
| 增量：改 1 站（Apply 总时长） | 1.78–1.96 s | 42.6–50.9 s |
| 　其中索引激活 / 生效后首个请求 | 22 ms / 1–5 ms | 195 ms / 2 ms |
| 增量：改 100 站 | 1.89–1.91 s（激活 46 ms） | 30.4–60.0 s（激活 0.47 s） |
| 增量：加 1 站 / 删 1 站 | 1.6–1.9 s | 32.6–68.9 s |
| 增量是否 reload | 否（master 不变） | 否（master 不变） |
| 加新端口（骨架变更 → reload） | 2.36–2.45 s | 32.2–60.5 s |
| 健康检查 Check：探全部站 / 只探变更站 | 0.81 s / 0.2 ms | **31.6 s / 0.8 ms** |
| reload 次数（整个流程） | 3（1 次启动 + 加端口 + 删端口） | 3（同） |
| agent 重启（New+Recover，OpenResty 不动） | 0.19–0.20 s | 5.6–6.3 s |
| 节点重启（启动+从索引文件重建+Recover） | 0.24–0.27 s | 6.7–7.5 s |
| agent 内存 RSS（首次激活后 / 结束） | 91–99 / 130 MiB（heap_inuse 44–54 MiB） | 763–772 / 1115–1120 MiB（heap_inuse 389–401 MiB） |
| OpenResty 合计 PSS（首次激活后 / 压测后 / 结束） | 104 / 263–266 / 131–138 MiB | 303–308 / 482–515 / 311–315 MiB |
| 　单 worker RSS（首次激活后 / 压测后） | 58–61 / 136–143 MiB | 170–172 / 237–287 MiB |
| 　master RSS | 11.8 MiB | 11.8 MiB |
| 索引共享字典（档位 / 已用） | 4 MiB / 2.48 MiB | 64 MiB / 24.8 MiB（约 130 B/键） |
| 每站首个请求（2000 个随机站） p50 / p99 | 162–169 µs / 0.68–1.10 ms | 226–250 µs / 1.16–1.72 ms |
| 热请求（1 客户端 keepalive，随机站，2 万次） p50 / p99 | 139–147 µs / 0.63–0.75 ms | 197–211 µs / 1.07–1.38 ms |
| 热请求（16 客户端，4 万次） p50 / p99 | 477–569 µs / 5.4–5.8 ms | 0.89–1.43 ms / 5.9–12.9 ms |
| 节点重启后热请求 p50 / p99 | 156–166 µs / 0.65–1.03 ms | 198–240 µs / 0.71–1.12 ms |
| 全部请求状态 | 全 200（未知 Host 421，删站后 421） | 同 |
| 校验项失败 | 0 | 0 |

16 客户端的 max 约 500 ms 两档都出现，是本机 Docker Desktop 下偶发的连接建立抖动（单客户端 max 9–12 ms），未单独定位。

## 2. 与 ADR 0009 目标对比

ADR 0009 没有写数值门槛，§5 规模要求是“测 1k/10k/100k 站的稳态内存、冷启动重建索引耗时、单站增删改从下发到生效的延迟”，§1/§3 的目标是“站点是数据、站点变更不 reload”。对照：

| 目标 | 结果 | 结论 |
|---|---|---|
| 站点增删改不 reload（§1、§3.1） | 1 万/10 万站改/加/删站点都不 reload、master 不变；只有端口变化才 reload | 达成 |
| 冷启动重建索引（PoC §1：10 万条 89–212 ms，100 万外推 ≤2.5 s） | nginx 内重建 20 万键 294–419 ms（每站 2 个域名） | 达成，与 PoC 一致 |
| 字典内存（PoC：128 B/键） | 约 130 B/键 | 达成 |
| 查表/请求延迟（dynroute-contract：10 万站端到端 p50 134 µs、p99 0.99 ms） | 完整请求流水线（含回源）10 万站 p50 197–211 µs、p99 1.07–1.38 ms | 达成（多出的是安全/缓存/回源阶段） |
| 单站增删改从下发到生效的延迟 | 1 万站约 1.8 s；**10 万站 30–69 s**，其中索引激活只占 0.2–0.5 s，其余是健康检查探全部站点（见缺陷 D13d-1） | 1 万站可接受；**10 万站未达成**，原因是产品缺陷 |
| 稳态内存 | 10 万站 OpenResty 约 310 MiB PSS（2 worker），agent 约 0.8–1.1 GiB RSS | 已记录；ADR 无门槛，agent 偏高（见遗留 2） |

## 3. 发现的产品缺陷（未改，按派单只回报）

- **D13d-1 每次 Apply 的健康检查探测全部站点**：`agents/edge-agent/internal/dynroute/apply.go:112` 用 `siteindex.ProbesFor(input.Objects)`，传入的是本次全部站点；`siteindex/activator.go:602` 注释写的是“每个变更站点一个探针”。`Check`（`activator.go:543-575`）对每个探针发一次控制套接字 `/probe`。实测 10 万站一次 Check 31.6 s，只探变更站 0.8 ms。影响：10 万站单站变更下发到 Apply 返回 30–69 s（期间 agent 持有 runtime 锁，后续发布排队）；新配置在激活后约 2 ms 就已经生效，延迟的是回执与下一次发布。修法候选：只探本次变更集（新增/改动的对象）+ 状态检查；整代重建（冷启动、恢复）抽样探测。
- **D13d-2 全新动态路由节点首次发布失败（dynroute 父目录 0750 root:root）**：e2e 暴露，详见 §4。基准与其它套件都自己预建 0755 状态根，所以碰不到它。
- 遗留 2（不算缺陷，供定档）：agent 10 万站 RSS 0.77–1.12 GiB、heap_inuse 约 400 MiB，即每站约 4 KiB 常驻（`Input.Objects` 同时持有 Raw 与解码后的 Site，`runtime.sites` 再存一份）。

## 4. 全量 dynroute 回归与金标

`tests/dynroute-scale/regress.sh`（每个套件串行，日志 `/tmp/d13d-regress/`）。

全机 load 6–13。

| 套件 | 结果 | PASS / FAIL | 结论 |
|---|---|---|---|
| tests/dynroute-agent | rc=0 | 151 / 0 | 通过 |
| tests/dynroute-index | rc=0 | 46 / 0 | 通过（switch 40 次切代 32 万请求 0 失败） |
| tests/dynroute-tls | rc=0 | 100 / 0 | 通过 |
| tests/dynroute-origin | rc=0 | 66 / 0 | 通过 |
| tests/dynroute-origintls | rc=0 | 31 / 0 | 通过 |
| tests/dynroute-originauth | rc=0 | 20 / 0 | 通过 |
| tests/dynroute-cache | rc=0 | 50 / 0 | 通过 |
| tests/dynroute-filters | rc=0 | 145 / 0 | 通过 |
| tests/dynroute-telemetry | rc=0 | 19 / 0 | 通过 |
| tests/dynroute-waf | rc=0 | 21 / 0 | 通过 |
| tests/dynroute-sched302 | rc=0 | 24 / 0 | 通过 |
| tests/dynroute-security/firewall-action.sh | rc=0 | 2 / 0 | 通过 |
| tests/dynroute-security/bench.sh | rc=1 | 首个正确性检查即 503 | **夹具过时**（见下 F1），补字段后结果见 §4.1 |
| tests/dynroute-poc（shdict/quic/origintls/errorpage/modsec） | rc=0 | 175 / 0 | 通过（五项各 failures=0） |
| tests/dynroute-e2e（三进程） | rc=1 | — | **夹具过时 2 处（F2/F3）+ 产品缺陷 D13d-2** |
| 金标 tests/edge-golden check（cdnca-dynroute） | rc=0 | 28 场景：same 21 / different 7 | 0 defects、45 waived，与 d13-c3c（a49b8ed17）一致 |
| tests/dynroute-scale 1 万 / 10 万站 | rc=0 | 各 0 失败（两轮） | 见 §1 |

夹具过时（不在本任务可改范围 agents/ 下，未改；均用 `go build -overlay` 临时补上验证，补丁在 `tests/dynroute-scale/fixture-fixes/`，`git apply` 可用）：

- F1 `agents/edge-agent/internal/siteindex/cmd/cdnca-security-bench/main.go:86-87`：HTTP 策略重定向规则缺 `preserve_path`。ge-access 9815fe4f7 起 `edge/openresty/httppolicy/engine.lua:170-173,318-319` 要求该字段，节点拒对象（error.log `HTTP policy object rejected reason=site_redirects`）→ 503。
- F2 `agents/edge-agent/cmd/edge-agent/dynroute_e2e_test.go:139`：`fileConfig` 没给 `openresty.health_url`。D13-c0 9dcd13eae 起 `assembleDynamicRouting` 要求它带端口（`cmd/edge-agent/dynamic_routing.go:129,187`）→ agent 进程 `openresty.health_url has no valid port`。
- F3 同文件 `:111`：用 `objectstore.Open(<deployment>/…)` 打开对象库。F13 925df1e76 起动态路由节点对象库在 state 根下按组共享（`dynamic_routing.go:84-104` `openObjectStore`），`ObjectDir.External` 只核对对象是否存在（`siteindex/files.go:259-261`）→ `object … is not in the object store`。

产品缺陷 D13d-2（e2e 修完 F2/F3 后暴露，已在容器内复现）：全新动态路由节点第一次发布失败，报 `activate site index: site index rebuild: no current index file`。
daemon 先调 `openObjectStore`（`daemon.go:325`），它的 `os.MkdirAll(state, 0o750)`（`dynamic_routing.go:100`）把 `<deployment 父>/dynroute` 建成 0750 root:root；
后面的 `dynroute.New`（经 `daemon.go:404`）里 `mkdirWorker` 不会去改已经存在的父目录（`internal/dynroute/runtime.go:313-339`，注释写的正是这种情形），所以 nobody worker 进不了 `state/site-index`。
容器内探针：`dynroute` 0750 gid 0，`state`/`shared` 0750 gid 65534。修法候选：`openObjectStore` 用同一套 worker 组建目录逻辑来建 state（父目录也给 worker 组 0750），或者 `dynroute.New` 对 StateRoot/SharedRoot 的父目录也改成组可遍历。

### 4.1 dynroute-security bench（补上 F1 后，1 万站）

`/tmp/d13d-sb/main.go` 等于 `fixture-fixes/security-bench-F1.patch`（另加失败时打印 error.log），1 万站带安全配置 + 1 万站不带，1 个 worker，`--cpuset-cpus 0`：正确性检查全过（200 带 HTTP 策略头、WAF 路径 403、重定向 301、请求头规则 403、不带安全配置的站不受影响），error.log 里 error/alert/crit 0 行。

| 项 | 结果（µs） |
|---|---|
| 安全阶段合计，每站第一次请求（1 万站） | p50 114.8，p99 723.9 |
| 安全阶段合计，热请求（2 万次随机站） | p50 26.5，p99 94.3 |
| 端到端：带安全配置 / 不带（两轮） | p50 103/66、86/80；p99 506/253、422/928 |

## 5. 交接与待决

- D13d-1、D13d-2、F1–F3 已修复/应用，复测见 §6。

## 6. 修复后复测（单轮）

修复：D13d-1 edf14dd0d（`Activation.Probes` 只含本次新增/改动站点，整代重建全量、16 并发；`WaitHealthy` 状态先过再探）；D13d-2 dd6427443（`openObjectStore` 用 `dynroute.MkdirWorker` 建 state 及新建父目录 0750+worker 组）；F1–F3 5907bcc2e。全机 load 高（heavy 队列约 30），耗时只作量级参考。

| 项 | 1 万站（修前 → 修后） | 10 万站（修前 → 修后） |
|---|---|---|
| 增量：改 1 站 Apply | 1.78–1.96 s → **0.56 s**（激活 33 ms） | 42.6–50.9 s → **1.50 s**（激活 0.42 s） |
| 增量：改 100 站 | 1.89–1.91 s → 0.49 s | 30.4–60.0 s → 2.15 s |
| 增量：加 1 站 / 删 1 站 | 1.6–1.9 s → 0.99 / 0.97 s | 32.6–68.9 s → 2.60 / 1.02 s |
| 加新端口 / 删端口（reload） | 2.36–2.45 s → 1.13 / 1.17 s | 32.2–60.5 s → 2.39 / 1.56 s |
| 首次激活（全量探测，16 并发） | 2.4–2.7 s → 1.81 s | 23.8–29.2 s → 29.2 s（激活 4.9 s，含全量探测） |
| Check 探全部站（并发） / 只探变更站 | 0.81 s → 0.48 s / 1.0 ms | 31.6 s → 11.6 s / 2.7 ms |
| 节点重启后首次 Apply | — / 1.0 s | — / 1.58 s |
| reload 次数、校验失败 | 3、0 | 3、0 |

回归（`/tmp/d13fix-regress`，经 heavy.sh 串行）：dynroute-agent 151/0、dynroute-filters failures=0、dynroute-security bench（F1 后）error.log 0 行、dynroute-e2e 三进程全 PASS（全新节点首次发布成功，D13d-2 已修）、金标 28 场景 same 21 / different 7、0 defects、45 waived（与修前一致）。
