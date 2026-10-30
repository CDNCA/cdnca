# 百万网站与降低节点内存：G8-a 基准与第 1 期方案（v6.1.0 #15）

状态：1.0.35 第 1 期（G8-a 基准 + G8-b/G8-c 设计）。代码基线 f7e884ac。
复现：`tests/scale/run.sh control|compile|node <站点数,...>`（见 §6）。

## 1. 结论先行

- **现在挡住规模的不是 1000 站上限，而是一串更低的上限**：全节点 CC v2 监听超过 5 个 `nginx -t` 就失败（注册表内联超 nginx 4096 字节 token 上限）；节点 HTTPS 证书最多 64 个站点；单 scope 实际只能发 666 站（遥测清单 1000 条封顶）；单次发布最多 7 个节点（16 MiB 合计上限）、绝对上限 128 个节点。另有两处会让普通发布直接失败的既有缺陷（多域名站点、带安全策略的 release 证书引用重评）。详见 §2、§10。
- **内存大头是每站的 `server{}`，不是证书**：生产形状每个 server 约 78 KiB（HTTP 与 HTTPS 几乎一样），其中 TLS 相关只有约 27 KiB；一半站点 HTTPS 时约 117 KiB/站，10 万站约 11 GiB 稳态，reload 峰值约 3×。
- **nginx 解析配置的 CPU 随 server 数超线性增长**：生产形状 2000 站 `-t` 6–9 s CPU，5000 站 64 s，启动与 reload 同量级；任何站点的任何变更都整份重做。
- **节点 Go 编译是 O(n²) 但不是主瓶颈**：20 000 站组合 6.4 s CPU，热点是端口冲突两两比较；主控纯计算更便宜（666 站全流程 0.29 s CPU），主控的问题是“体积 × 节点数”和固定上限。
- **第 1 期能交付的**：先修 §7.2 的前置缺陷，再做 G8-b（同站 80/443 合并为一个 server，HTTPS 站内存约 −50%；按 SNI 动态证书：已按 PoC 结论用 nginx 原生变量证书实现为 site runtime v7，每个 HTTPS 站点 server 省约 26 KiB，见 §8）与 G8-c（scope 分片 ≤500 站、只签/传/编变化的片、去掉 666/1000 站与 7/128 节点上限）。第 1 期之后单节点合理规模是万站量级；百万站要靠第 2 期共享 server + Lua 路由（去掉每站 server 和 reload）和第 3 期按线路组按需加载。
- 规划里“证书动态加载是内存下降最大的一块”与实测不符：证书与 SSL_CTX 只占每个 HTTPS server 的约 35%（27/78 KiB），收益大头来自 80/443 合并为一个 server。

## 2. 现状（代码事实）

渲染路径：
- 两套站点文档。`site-runtime/v1`：主控用 `libs/edgeconfig/config.go:314-327` 渲染整份 nginx.conf，证书 PEM 写进 bundle（`config.go:1207-1211`），v1 遇到 HTTPS 站点直接拒绝（`services/control-api/internal/edgepublish/service.go:1046-1047`）。`site-runtime/v2`：主控只发 JSON 文档，节点 `agents/edge-agent/internal/siteruntimev2` 编译 nginx.conf，证书从节点 certstore 解析。
- 发布入口不设 schema 时默认 v1（`edgepublish/service.go:851-852`；`edgepublishhttp/service.go:103`、`edgeautopublish/store.go:461` 都不设）；只有 `packagesoldruntime/runtime.go:126-129` 在 scope 有 TLS 站点时选 v2。（基准时的状态；之后所有入口默认 v2，规则在 `edgepublish.ResolveSiteRuntimeSchema`。）百万网站改造只针对 v2（v1 不能承载 HTTPS），本文数据全部是 v2。
- 节点多租户组合（`cmd/edge-agent/multi_tenant_runtime.go`）只接 v2：`composed_runtime.go:183-185` 拒绝非 site runtime 的 release。

每次变更的节点工作量：
- 每个站点的每个监听一个 `server{}`（`compiler.go:297-375`），每个源站池一个 `upstream{}`（`compiler.go:236-270`），HTTPS 监听逐个写 `ssl_certificate`（`compiler.go:327-334`），全部写进一个 nginx.conf（`compose.go:130-152`）。
- 组合运行时每次 reload：先对每个 scope 单独 `compileNginx`（`runtime_adapter.go:241-247`，单 scope 的产物在组合模式下不用），再整体 `compileComposition`（`composed_runtime.go:209-214`）；然后整份 `nginx -t` 与 reload（`deployment/manager.go:309`）。任何一个站点变更都走这一整套。

硬上限（按先触发的顺序；“监听”= 站点×端口，基准形状 1.5 监听/站）：

| 上限 | 位置 | 基准形状下折合 |
|---|---|---|
| CC v2 注册表内联进 `init_by_lua_block`，nginx 单个配置 token ≤4096 字节 | `libs/edgeconfig/security_fragments.go:60`、`cc_v2.go:287`；每条约 672 字节 | **全节点 ≤5 个 CC 监听**（见 §10 缺陷 1） |
| 节点证书版本引用 Current/Previous 各 ≤64，且 Current 必须都在**同一次**证书激活里 | `certstore/types.go:16`、`validate.go:199-202`、`manager.go:333-336`；组合运行时取全部 scope 的并集 `deployment/multiscope_certificates.go:72` | **全节点 ≤64 个 HTTPS 证书版本** |
| 证书 bundle ≤64 绑定 / 256 域名 / 4 MiB | `certstore/types.go:15-17`、主控 `certificatepublish/producer.go:40-41` | 同上 |
| 遥测身份清单 ≤1000 个监听、≤1 MiB，且每站只能 1 个域名 | `libs/edgeconfig/telemetry.go:96,104`；`edgepublish/site_capture_policy.go:137` | **单 scope ≤666 站**；多域名站点发布失败（§10 缺陷 3） |
| 单文档 ≤1000 站 | `edgepublish/site_runtime_v2.go:856`、节点 `siteruntimev2/validate.go:33` | 1000 站 |
| bundle wire ≤4 MiB | `libs/edgeconfig/bundle.go:22,128`（文件 base64 进 JSON） | 666 站时 2.24 MB，未触发 |
| 单次发布的全部节点产物 ≤16 MiB、≤128 个（每节点一份 HPKE 产物） | `edgedeployment/validate.go:33-35,127-129`，经 `service.go:683-690` 生效 | **666 站时最多 7 个节点** |
| 合成后 CC 注册表 ≤1000 条 | `cc_v2.go:867` | 全节点 ≤1000 个 CC 监听 |
| 组合后安全片段监听 ≤32000 | `security_fragments.go:75-76`（偏移按全部监听计） | **全节点 ≤21333 站**（实测 22000 站编译失败） |
| 单站 ≤100 域名、≤32 监听、≤64 源站池 | `siteruntimev2/validate.go:129,142,210` | — |

结论：v2 现状下，一个节点能承载的站点数先被 CC（5 个监听）、HTTPS 证书（64 张）卡住，其次是单 scope 666 站、单次发布 7 个节点；server 块数量本身要到两万站才撞上 32000 监听。G8-c 去掉“1000 站上限”之前，必须先去掉前面这几个更低的上限，否则 1000 站上限永远不是瓶颈。

## 3. 测量方法

站点形状与主控 `compileSiteRuntimeV2SiteFactWithTopology`（`site_runtime_v2.go:418-466`）输出一致：每站一个 80 端口 HTTP 监听；偶数站另有 443 HTTPS（http1/http2/http3，dual_stack，每站独立 P-256 证书，SAN 覆盖全部域名）；1/3 站点 3 个域名；30% 监听带一条源 IP ACL；1/4 站点 2 个源站；CC v2 默认关闭（原因见 §10 缺陷 1，比例由 `CDNCA_SCALE_CC_PERMILLE` 调）。超过 1000 站时按每 scope 1000 站拆成多个 scope，用组合运行时（多租户节点就是这条路径）编到一份 nginx.conf。

三组测量：
1. 主控（`services/control-api/internal/edgepublish/scale_benchmark_test.go`，本机，无数据库）：`compileSiteRuntimeV2Facts` 取完事实之后的纯计算——规范化校验、遥测清单、bundle、每节点 HPKE 加密签名；二分找出单 scope 实际能发布的最大站点数。数据库读事实那部分未测（见 §5.6）。
2. 节点编译（`agents/edge-agent/internal/siteruntimev2/scale_benchmark_test.go`）：`Evaluate` → 每 scope `compileNginx` → `compileComposition`，与 `ComposedRuntime.compose`（`composed_runtime.go:164-243`）同序。
3. 节点运行（同一测试 + 真实 OpenResty `cdnca-native-runtime:wafdual`，openresty/1.31.1.1，arm64，1 个容器 `--memory 4g/6g`、`worker_processes 2`）：`nginx -t`、启动到健康、master/worker RSS、cgroup 内存、10 个站点的首个 HTTP/HTTPS 请求（新连接，核对证书 CN）、改一个站点后的全量重编译 + `-t` + reload（直到健康检查返回新版本、旧 worker 全部退出）期间的峰值内存。
4. server{} 成本拆分（`tests/scale/server-cost.sh`）：最小配置下分别测 N 个 HTTP server、N 个独立证书 HTTPS server、N 个共用证书 HTTPS server、按 SNI 动态证书两种形态，`worker_processes 1`，并对首/中/末站点做真实 TLS 握手核对。

时间口径：测量期间宿主机（10 核）负载 25–50，容器常常分不到 1 核，墙钟时间被放大且波动大。**结论只用 CPU 时间（getrusage / `/proc/<pid>/stat`）和内存**；墙钟数字仅供参考。

内存口径：master 与 worker 的配置结构是 fork 后写时复制共享的，worker RSS 与 master RSS 大部分是同一批页。`--cap-add SYS_PTRACE` 之前读不到 nobody worker 的 smaps（早期结果里的 PSS 只含 master，已舍弃），之后用 cgroup `memory.current` 与 PSS 交叉核对：稳态真实占用 ≈ master RSS。

## 4. 数据

全部数据 2026-10-17 在本机（Apple M 系列 10 核、Docker Desktop VM 10 核/8 GiB、arm64）测得，宿主机负载 25–50。

### 4.1 主控（单 scope，单域名站点，CPU 秒）

| 站点 | 监听 | 规范化文档 | 遥测清单 | bundle | 节点数 | 全部产物 | 总 CPU | 分配 | 上限 |
|---|---|---|---|---|---|---|---|---|---|
| 300 | 450 | 0.40 MB | 0.37 MB | 1.02 MB | 1 / 10 / 20 | 1.0 / 10.2 / 20.4 MB | 0.15 / 0.18 / 0.21 s | 39–76 MiB | 20 节点超 16 MiB |
| 666 | 999 | 0.86 MB | 0.82 MB | 2.24 MB | 1 / 5 / 10 | 2.2 / 11.2 / 22.4 MB | 0.29 / 0.31 / 0.40 s | 84–123 MiB | 10 节点超 16 MiB |
| 667 | 1001 | — | 失败 | — | — | — | — | — | 遥测清单 1000 条 |
| 1001 | — | 失败 | — | — | — | — | — | — | 1000 站 |

每节点加密签名 ≈0.005–0.01 s CPU。多域名站点（基准形状 1/3 站点 3 个域名）在遥测清单一步全部失败（§10 缺陷 3），表中是单域名副本的数字。

### 4.2 节点 Go 编译（CC 关闭，CPU 秒）

| 站点 | scope | server 块 | nginx.conf | Evaluate | 各 scope compileNginx | 组合 | 分配 | 峰值堆 |
|---|---|---|---|---|---|---|---|---|
| 1 000 | 1 | 1 502 | 1.5 MB | 0.17 | 0.10 | 0.12 | 76 MiB | 22 MiB |
| 5 000 | 5 | 7 502 | 7.4 MB | 0.70 | 0.48 | 1.04 | 379 MiB | 58 MiB |
| 10 000 | 10 | 15 002 | 14.9 MB | 1.14 | 0.82 | 2.53 | 760 MiB | 136 MiB |
| 20 000 | 20 | 30 002 | 29.8 MB | 1.77 | 1.17 | 6.43 | 1.5 GiB | 235 MiB |
| 22 000 | 22 | — | — | 2.08 | 1.43 | 失败 | — | — |

22 000 站失败于第 22 个 scope：组合后安全片段监听偏移超过 32 000（`security_fragments.go:75-76`）。

### 4.3 节点真实 OpenResty（2 worker；“CPU”为进程 CPU 秒，括号内为墙钟）

| 站点（HTTPS） | server 块 | `-t` CPU | 启动 master CPU | master RSS | worker RSS | cgroup | 改 1 站 reload：Go 重编译 + `-t` + master | reload 峰值（进程 RSS 合计） | 首请求 HTTP / HTTPS 中位 |
|---|---|---|---|---|---|---|---|---|---|
| 2 000（0） | 2 002 | 11.5 (37) | 7.95 | 158 MiB | 153 MiB | — | 2.5 + 4.5 + 5.2 | 951 MiB | 66 / — ms |
| 1 000（500） | 1 502 | — (8.4) | — | 122 MiB | 117 MiB | — | — + — + — (15 s) | 739 MiB | 1.4 / 34 ms |
| 2 000（1000） | 3 002 | 6.1 (7.9) | 11.4 | 234 MiB | 229 MiB | — | 2.2 + 16.9 + 19.2 (39 s) | 1.43 GiB | 11 / 28 ms |
| 2 000（1000）+ 哈希调大 | 3 002 | 8.7 (9.8) | 12.5 | 239 MiB | 233 MiB | — | 4.6 + 11.5 + 11.2 (14 s) | 1.45 GiB | 18 / 68 ms |
| 5 000（2500） | 7 502 | 63.9 (79) | 65.5 | 569 MiB | 564 MiB | — | 11.4 + 43.9 + 35.1 (58 s) | 3.5 GiB | 1.5 / 16 ms |

- 每个 server 块的内存（master RSS ÷ server 块）：1k 81 KiB、2k 78 KiB、5k 76 KiB，全 HTTP 2k 79 KiB。
- cgroup 与 PSS 核对见 4.4（最小配置下 master+worker 合计 cgroup ≈ master RSS，写时复制共享）。
- 首请求延迟受宿主机负载影响大（同配置两次相差 2×），只能说明“没有按站点数劣化”；首个 HTTPS 请求比 HTTP 多一次完整握手。
- 5000 站第一次运行时 reload 在 10 分钟窗口内没有切换完成（宿主机负载 45+），第二次（表中）58 s 完成。

### 4.4 server{} 成本拆分（最小配置，1 worker，2000 个 server）

| 形态 | master RSS | worker PSS | cgroup | 每 server |
|---|---|---|---|---|
| 1 个 server（基线） | 2.6 MiB | 2.5 MiB | 5.0 MiB | — |
| 2000 个 HTTP server | 80.2 MiB | 41.3 MiB | 82.7 MiB | ≈39 KiB |
| 2000 个 HTTPS server，独立证书 | 133.4 MiB | 67.8 MiB | 137.7 MiB | ≈67 KiB |
| 2000 个 HTTPS server，共用一张证书 | 118.5 MiB | 60.5 MiB | 123.4 MiB | ≈59 KiB |
| 2000 个 HTTP server + 1 个 HTTPS server 按 SNI 动态证书 | 80.2 MiB | 41.3 MiB | 85.3 MiB | ≈39 KiB |
| 2000 个 HTTPS server 不写证书 + 1 个 default server 动态证书（`nocert`，握手失败） | 80.6 MiB | 41.5 MiB | 83.1 MiB | ≈39 KiB |

动态证书握手核对：`dynamic`（所有站点共用 1 个 443 server）下站点 0/1000/1999 的 TLS 握手成功、SNI 回显正确。**`nocert`（每站 443 server 不写证书、只靠 default server 的 `ssl_certificate_by_lua`）`-t` 通过、内存与 HTTP 相同，但站点 0/1000/1999 的 TLS 握手全部失败**——SNI 选中没有 SSL_CTX 的站点 server 后握手不成立（根因与可行方案见 site-runtime-cert-lazy-load.md，G8-b 已按原生变量证书实现，§8）。`nocertquic`（再加 `listen 443 quic`）`-t` 通过，83.1 MiB。

注意：最小配置里若写 `server_names_hash_max_size 262144`，4000 个 server 时 `-t` CPU 从 17 s 涨到 49 s（`ngx_hash_init` 逐个尝试 size），生成器不要为“消除 could not build optimal server_names_hash 警告”盲目调大这个值；生产配置当前没写（警告无害）。

## 5. 瓶颈分析

按影响从大到小。

### 5.1 server{} 块本身（内存的大头，证书不是）

- 生产形状每个 `server{}`（不论 HTTP 还是 HTTPS）稳态约 75–80 KiB（表 4.3：master RSS ÷ server 块数，1k/2k/5k 一致）。全 HTTP 与一半 HTTPS 的 2000 站对比（表 4.3 第 1、3 行）：多出的 1000 个 HTTPS server 每个约 78 KiB，和 HTTP server 几乎一样。
- 最小配置拆分（表 4.4）：一个只有 `return` 的 server 约 40 KiB；加上独立证书 TLS 再多约 27 KiB（其中 SSL_CTX 约 20 KiB、证书私钥约 7 KiB）。生产 server 比最小 server 多出的约 38 KiB 来自生成的 location、`proxy_*`、ACL 变量、`add_header` 等指令在各模块 loc_conf 里的合并副本。
- 所以 **G8-b（证书动态加载）只去掉每个 HTTPS server 的约 27 KiB（≈35%），不是“内存下降最大的一块”**；它还保留每站一个 443 server。要再省一半，要把同一站点的 80 与 443 合进一个 server（G8-b 一并做，见 §8），真正去掉“每站一个 server”只能靠第 2 期的共享 server + Lua 路由。
- 外推（稳态，按 ≈117 KiB/站：0.5 个 HTTPS + 1 个 HTTP server）：1 万站 ≈1.1 GiB，10 万站 ≈11 GiB，100 万站 ≈112 GiB。reload 时两代配置并存，峰值约 3×（表 4.3：5000 站稳态 0.57 GiB、reload 峰值 RSS 合计 3.5 GiB 的进程视图，master 要同时持有新旧配置并 fork 新 worker）。

### 5.2 nginx 解析配置的 CPU 随 server 数超线性增长

- `nginx -t` CPU：2000 站（3002 个 server）6.1–8.7 s，5000 站（7502 个 server）63.9 s，即 server 数 ×2.5、CPU ×7–10（≈ n^2.2）。启动与 reload 的 master CPU 同量级（5000 站启动 65.5 s、reload 35 s，不含之前的 `-t` 44–64 s）。
- 调大 `server_names_hash_max_size`/`bucket_size`、`variables_hash_max_size` 不改变结果（表 4.3 两次 2000 站对比），超线性不在这两张哈希表。具体是哪个 nginx 阶段（server 名/监听地址合并、各模块 merge）未做火焰图，列为第 2 期前置调查项；对第 1 期的结论是：**按现有每站 server 的形态，节点大于约 5000 站时一次 reload 要分钟级 CPU**，任何站点的任何变更都付这个代价。
- 外推（n^2.2）：1 万站约 5 分钟、2 万站约 25 分钟 `-t` CPU。这本身就否定了“第 1 期在单节点放 10 万站”的可能。

### 5.3 节点 Go 编译：组合阶段 O(n²)，每次全量

- `compileComposition` CPU：1k 0.12 s、5k 1.04 s、10k 2.53 s、20k 6.43 s（表 4.2）。热点是 `edgeconfig.FindPortConflicts`（`libs/edgeconfig/port_claims.go:116-134`）：按端口分组后两两比较，所有网站都在 80/443 上，所以是 n² 次比较（10k 站 pprof 里占组合阶段 75%）。其次是 `validateCertificatePath` 每个域名两次 `EvalSymlinks`（`compiler.go:619-640`）。
- 组合运行时先对每个 scope 单独 `compileNginx` 一遍（`runtime_adapter.go:241`），产物只用于校验，组合时再编一遍：编译工作量 ≈2×。
- 20k 站时 Go 侧分配 1.5 GiB、峰值堆 235 MiB；同一份 nginx.conf 29.8 MB。和 5.2 比，Go 编译不是主要瓶颈，但它是 O(n²) 且每次全量，G8-c 顺手改掉。

### 5.4 下发：单 scope 666 站、单次发布 7 个节点

- 每个节点一份 HPKE 加密产物（`service.go:610-622`），产物内容相同只是收件人不同；666 站的 bundle 2.24 MB（文件 base64 进 JSON，规范化文档 0.86 MB + 遥测清单 0.82 MB），16 MiB 合计上限下最多 7 个节点（表 4.1）；`maxConfigArtifacts=128`（`edgedeployment/validate.go:35`）还意味着 v2 单次发布不能超过 128 个节点，而 HTTP 接口允许 10000（`edgepublishhttp/handler.go:536`、`edgepublish/model.go:47`）。
- 遥测身份清单每个监听一条（`site_capture_policy.go:141-164`），体积和规范化文档相当，且 1000 条封顶：它比“1000 站上限”更早触发。
- 主控纯计算很便宜：666 站从规范化到加密签名合计 0.29 s CPU、84 MiB 分配，每多一个节点 +0.01 s。即使去掉上限，单次 1 万站也只是秒级。主控的问题是“体积 × 节点数”和固定上限，不是 CPU。

### 5.5 证书：节点上最多 64 个 HTTPS 站点（G8-c 已解除，见 §8.3）

- （G8-a 当时）certstore 一次激活 ≤64 个绑定，且新激活必须包含上一次激活的全部站点（`certstore/validate.go:41-42,148-151`），所以节点上生效的证书集只能累加，最多 64 站；部署管理器把 site runtime 引用的证书版本设为 Current 时，要求全部在当前激活里（`manager.go:333-336`），组合运行时取所有 scope 的并集（`multiscope_certificates.go:72`）。`agents/edge-agent/internal/certstore/scale_ceiling_test.go`（`-tags scale`）用真实 certstore 复现：第 65 个站点被拒，只发新站点的激活被拒（stale）。
- 这是“百万网站”在 HTTPS 上最先撞的墙，G8-b 必须一起改（§8）。

### 5.6 Lua 共享字典与 CC

- 共享字典本身是固定大小（CC v2 16 MiB/scope，合成后 `min(16×scope 数, 256)` MiB，`security_fragments.go:57`；防火墙 4 MiB），不随站点线性增长，不是瓶颈。
- CC v2 的注册表却是把全部条目内联进 nginx.conf 的 `init_by_lua_block`，单个配置 token 4096 字节封顶 → 全节点最多 5 个 CC 监听（§10 缺陷 1）。注册表还在每个 worker 的 init 里整体解析，站点多时启动成本线性增长；改为文件或共享字典加载后才能谈规模。

### 5.7 未测/无法在本机测

- 主控数据库侧：`compileSiteRuntimeV2Facts` 读事实要逐站查询 TLS 绑定（`loadSiteRuntimeV2TLSBinding`，`site_runtime_v2.go:580-654`，每个 HTTPS 站一次多表 CTE 查询，N+1）；域名冲突触发器全表 `DISTINCT ON`（§2.8 已列入 G8-d）。需要上万行测试数据，本任务未建，留给 G8-d。
- 1 万站以上的真实 OpenResty：按 5.1/5.2 外推需要 >1.1 GiB 稳态、数分钟 CPU，宿主机（Docker VM 8 GiB、负载 40+）上没跑；规划里“在测试节点跑 1k/5k/10k/50k”这件事仍需要一台独立测试机，用 `tests/scale/run.sh node` 即可复现。
- JS 挑战页 wrk 压测（plan §1 5.8.8）未做，同样需要独立测试机，不宜在本机测 QPS。
- HTTP/3（QUIC）首请求未测（客户端只发 HTTP/1.1 over TLS）。

## 6. 复现

```sh
tests/scale/run.sh control 300,666            # 主控：规范化/遥测/bundle/HPKE，并二分单 scope 上限（CDNCA_SCALE_NODES=1,5,10,20）
tests/scale/run.sh compile 1000,5000,10000,20000,22000   # 节点 Go 编译（本机）
tests/scale/run.sh node 1000,2000,5000       # 节点编译 + 真实 OpenResty（1 个容器，用完即删）
CDNCA_SCALE_HTTPS_PERMILLE=0 tests/scale/run.sh node 2000   # 全 HTTP 对照
tests/scale/server-cost.sh 2000 'empty plain tls tlsone dynamic'   # server{} 成本拆分 + 动态证书握手
tests/scale/server-cost.sh 2000 'nocertquic nocert'               # G8-b 形态：站点 server 不写证书
CDNCA_SCALE_CERTIFICATES=10000 go -C agents/edge-agent test -tags scale -run TestScaleCertificateStore -v ./internal/certstore   # 证书库规模（§8.6）
```

结果写到 `tests/scale/results/*.jsonl`（不入库）。其他开关：`CDNCA_SCALE_IMAGE`、`CDNCA_SCALE_MEMORY`、`CDNCA_SCALE_WORKERS`、`CDNCA_SCALE_CC_PERMILLE`（node 默认 0）、`CDNCA_SCALE_EXTRA_HTTP`（插到 `http {` 后的指令，对比实验用）。规模测试请在独立测试机上跑，本机负载会让墙钟数字失真。

## 7. 第 1 期改造设计（1.0.35）

### 7.1 目标重新定位

数据否定了“第 1 期在单节点上承载 10 万站”：每站一个 server 的形态下内存约 117 KiB/站、`nginx -t` CPU ≈ n^2.2（§5.1–5.2）。第 1 期的可交付目标定为：

1. **去掉比 1000 站更低的那些上限**（CC 5 个、证书 64 张、单 scope 666 站、单次发布 7 个节点/128 个节点），让单节点在 1 万站量级上能正确发布；
2. **把每站常数降下来**：HTTPS 站点内存约 −50%（证书动态加载 + 80/443 合并为一个 server），变更时编译与传输只做变化的分片；
3. **为第 2 期（共享 server + Lua 路由，去掉 reload）铺好数据面**：站点索引按 host 查、证书按 SNI 查、分片清单，这些第 2 期直接复用。

百万网站的总量靠多节点按线路组分摊（第 3 期“按需加载”），不是单节点。

### 7.2 前置修复（不做这几项，G8-b/G8-c 测不出效果）

| 项 | 改法 | 归属 |
|---|---|---|
| CC v2 注册表内联超 4096 字节 | 注册表写到 release 里的文件（如 `security/cc-registry.json`），`init_by_lua_block` 只传路径；校验器 `cc_v2.go:260-300` 同步改；节点 Lua 读文件 | §10 缺陷 1，建议单独小任务，G1（CC v4）组最合适 |
| CC 注册表排序 | `ccV2RegistryForSpec` 先 `sortedCCV2Registry` 再校验 | §10 缺陷 2，同上 |
| 遥测清单单域名、1000 条 | 多域名站点每个域名一条（或清单改按站点、域名列表）；条数上限随分片走（每片 ≤1000 条） | §10 缺陷 3；G8-c |
| `certificate_references.go` 用 site_runtime 3、无 cc/waf 的能力集重评 release | 改用节点本地完整能力集（`daemon.go:323-331` 那份） | §10 缺陷 4，小，任何人可修 |
| 单次发布 16 MiB / 128 个产物 | 每节点产物共用一份 bundle，HPKE 只封装内容密钥（KEM 封装 + 同一密文），或按分片拆多条发布 | G8-c |
| 证书 64 张 | §8 | G8-b |

### 7.3 动态路由 + 共享 server 的取舍

第 1 期**不做**按 Host 的 Lua 路由（第 2 期才做）。理由：`proxy_cache` 键、`error_page`、`limit_conn`、`client_max_body_size`、HTTP 策略 Lua 绑定、ACL 的 geo 变量都是 server/location 级 nginx 指令（`compiler.go:297-375`、`libs/edgeconfig/security_fragments.go:115-140`），改成单 server 要逐项用 Lua 等价实现和测试，plan §2.8 已把它定为 1.0.36。第 1 期只把 TLS 与站点索引改成按 SNI/Host 查，这两块第 2 期原样复用：

- 证书：每个 TLS 套接字一个 default server 持有唯一的 SSL_CTX，原生变量证书 `ssl_certificate $map` 按 SNI 选文件（§8；`ssl_certificate_by_lua` 不可行，见 site-runtime-cert-lazy-load.md §2）。
- 站点索引：每个分片产物带 `sites.index.json`（host → site_id、shard），第 2 期给路由 Lua 用；证书不再需要索引文件（map 由编译器生成）。

## 8. 子任务：G8-b 证书动态加载（site_runtime api_version 7，已实现）

能力：`site_runtime` 7（`edgeconfig.LazyCertificateSiteRuntimeVersion`；v5 强制 HTTPS、v6 缓存/托管 WAF/JS 挑战已占）。这是性能优化，不是功能：主控只在文档有 TLS 监听且全部目标节点声明 v7 时写入 `lazy_certificates`，任一节点低于 v7 就照旧发逐站证书，不拒绝发布（`edgepublish/site_runtime_lazy_certificates.go`）。PoC、根因与实测见 `site-runtime-cert-lazy-load.md`。

### 8.1 渲染（节点 `siteruntimev2/lazy_certificates.go`）

- **不用 `ssl_certificate_by_lua`**：SNI 选中没有 SSL_CTX 的站点 server 后，Lua 回调按站点 server 查 handler 而失败；给站点 server 挂 handler 又要求它有 SSL_CTX（PoC §2）。改用 nginx 原生变量证书：default server 写 `ssl_certificate $cdnca_lazy_cert_<端口>` / `ssl_certificate_key $cdnca_lazy_key_<端口>`，http 级 `map $ssl_server_name … { hostnames; default ""; <域名> <文件>; }`，key 与站点 `server_name` 是同一组字符串，匹配语义（精确 > 通配符）与 server 选择一致。
- 每个端口一对 map；同一端口 IPv4 与 IPv6 对同一域名给出不同证书时按地址族拆成两对（`_ipv4`/`_ipv6`）。同一主机名在不同端口用不同证书天然正确（各端口各自的 map）。多作用域同端口合并成一对 map，`cache_max` 取最大。
- 每个有懒加载监听的 TCP 套接字一个 default server：`listen … ssl default_server`（该套接字有 HTTP/3 时再 `listen … quic default_server`），`ssl_protocols TLSv1.2 TLSv1.3`，`ssl_reject_handshake on`（未知/无 SNI 拒绝），`ssl_certificate_cache max=<cache_max> inactive=10m valid=1h`，`location / { return 421; }`。`map_hash_max_size/bucket_size` 按条目数与最长域名写在 http{} 第一个 map 之前（nginx 在首个 map 定值，之后再写报 duplicate）。
- 懒加载监听 = 文档开启 + 监听 TLS 协议为 nil 或 `TLSv1.2 TLSv1.3`（`edgeconfig.LazyCertificateTLSProfile`）+ 所有地址族的套接字都不被 mux 分发。其余 TLS 站点在同一端口保持逐站 `ssl_certificate`/`ssl_protocols`（SNI 切到它自己的 SSL_CTX），测试覆盖混合端口。
- 80/443 合并为一个 server（原设计的另一半收益）**未做**，留给后续任务。

### 8.2 证书文件与 worker 权限

- 证书库文件是 root 0400，而变量证书在 worker 握手时读文件。G8-c 起懒加载监听的证书与私钥复制进站点运行时的共享证书池 `tls-pool/<site_id>.<certificate_version_id>.crt|.key`（`siteruntimev2/lazy_certificate_pool.go`）：所有 release 共用，池里已有的版本不再复制（原来每次 prepare 把全部懒加载证书私钥读进内存并复制进每个派生 release）；复制时按证书库记录的 sha256 校验；文件 0440，原生 profile 下池目录 root:worker 0710。证书换版本仍是新 release + reload（map 值是带版本的路径），`ssl_certificate_cache` 随 reload 重建。
- worker 可读私钥的取舍维持原结论（不变）。
- `cache_max` 由主控配置：`CDNCA_EDGE_LAZY_CERTIFICATE_CACHE_MAX`（默认 10000，1..1000000；约 4 KiB/张/worker）。

### 8.3 证书存储（`certstore` + 主控 `certificatepublish`，G8-c g8c-certstore）

- 根因：激活是全量快照（新激活必须包含上一次的全部站点），而主控每次只发布一个站点（`publication_adapter.go` `SiteIDs: [command.SiteID]`），所以同一节点上第二个 HTTPS 站点单独发布必然 stale；取消发布只发剩余站点，节点分不清“删除”与“旧快照”。§10 缺陷 6 的猜测成立。
- 改为按站点增量：每条 revision 带 `binding_revision`（`certificate_site_binding_facts` 每站序号），取消发布只发 `removed_sites`（租户 + unbind 序号）；节点按站点排序（低序号 stale、同序号同内容、高序号可换资产），删除留墓碑。主控同时改为发站点全部域名（原来只发 `domains[0]`，多域名站点其余域名在节点解析失败）。
- 存储：`sites/<shard>/<key>/site.json` + 每版本不可变目录，`byversion/` 反向索引，`gc/` 待回收标记；索引变更写 `index-journal.json` 绑定 release，健康后应用。release 只含本命令的绑定，提交后只留 current/lkg/上一版。布局与语义见 `docs/runbooks/edge-certificate-runtime.md`。
- 不再随规模线性的操作：激活只读写命令涉及的站点；解析只读该站 `site.json`（缓存）+ lstat，不扫描 release、不做密码学；引用校验与回收走 `byversion/`，只看掉出引用的版本；重启不重新解析全部证书。
- 上限：节点站点数、命令内 binding 数、引用数均不设条数上限；命令仍受 4 MiB、单站 100 个域名。主控 `maxBindings` 与快照 64 条上限去掉。
- 实测见 §8.6。

### 8.4 实测

- 3 站 PoC 与 1k/2k 最小配置：`site-runtime-cert-lazy-load.md` §4–§5（每个 HTTPS server 66.6 → 39.9 KiB）。
- 产品编译器 + 真实 OpenResty（`TestRealOpenRestyLazyCertificates`）：多 SNI、通配符别名、TLSv1.3-only 站点混在同一端口、未知/无 SNI 拒绝、证书轮换跨 reload 在途请求不断。
- G8-a 工具生产形状（`CDNCA_SCALE_LAZY_CERTS=1 tests/scale/run.sh node`，一半站点 HTTPS、每个 HTTPS 站点 80 与 443 两个 server、2 worker，PSS 为 master+worker 合计）：

| 站点（HTTPS） | 形态 | master RSS | PSS 空闲 | 全部 HTTPS 握手后 PSS | reload 峰值 PSS | `-t` CPU |
|---|---|---|---|---|---|---|
| 1000（500） | 逐站证书 | 123.3 MiB | 127.1 MiB | 146.5 MiB | 269.4 MiB | 0.25 s |
| 1000（500） | 懒加载 | 110.0 MiB | 113.8 MiB | 134.5 MiB | 240.3 MiB | 0.09 s |
| 2000（1000） | 逐站证书 | 234.8 MiB | 238.6 MiB | 275.3 MiB | 516.7 MiB | 0.47 s |
| 2000（1000） | 懒加载 | 208.6 MiB | 212.4 MiB | 251.9 MiB | 459.0 MiB | 0.22 s |

每个 HTTPS 站点省 ≈26.4 KiB（master RSS 两档斜率：逐站 111.5 MiB/1000 站、懒加载 98.6 MiB/1000 站），与拆分测得的“证书 + SSL_CTX ≈27 KiB”一致；全部握手后（缓存全热）仍省 ≈8.5%，reload 峰值省 ≈11%。cgroup 数字含测试进程与证书文件页缓存，不作结论。

### 8.5 风险

- HTTP/3：QUIC 套接字的 default server 已写 `quic default_server`，`-t` 与启动通过，真实 HTTP/3 握手未测（本机无 HTTP/3 客户端）。
- session ticket：共享 SSL_CTX 后 ticket key 在同一端口的懒加载站点间共享（OpenSSL 恢复时校验 SNI），与常见 CDN 做法一致，未显式配置 `ssl_session_tickets`。
- 行为变化：有懒加载的套接字上，未知 SNI / 无 SNI 被拒（alert 112）；原来落到该端口第一个站点。
- 节点在主控编译后降级到 v6：节点按 missing_capability 拒收，`gatedFeature` 提示重新发布；节点升级到 v7 后不会自动重新发布，下一次发布才切到懒加载。

### 8.6 证书库规模实测（G8-c g8c-certstore）

`CDNCA_SCALE_CERTIFICATES=10000 go -C agents/edge-agent test -tags scale -run TestScaleCertificateStore -v ./internal/certstore`（真实 certstore，sidecar 运行时换成空实现；每站一张独立 P-256 证书，1/3 站点 3 个域名，按 500 站一条命令导入）。平台：本机 macOS arm64（APFS，Go 的 fsync 是 F_FULLFSYNC：实测单文件 12.5 ms、单目录 4.7 ms），宿主机同时有其他负载。

| 项目 | 结果 |
|---|---|
| 导入 1 万站（20 条 500 站命令） | 9 min 57 s；第一条 29.0 s、最后一条 28.8 s（每条命令耗时不随已有站点数增长，约 58 ms/站，几乎全是 fsync） |
| 单站激活：空节点 / 1 万站时新站点 / 1 万站时轮换 | 243 ms / 707 ms / 293 ms（707 ms 是读取上一条 500 站 release 的代价，与节点站点数无关） |
| 设置 10002 个 current 引用 | 1.36 s |
| 解析全部站点域名（16668 次） | 热 2.79 s（167 µs/次）、重启后冷 1.72 s（每次 1 次 stat site.json + 3 次 lstat） |
| 重启 + Recover（1 万站） | 122 ms（只验证 current/lkg 两个 release，不重读全部证书） |
| 逐条轮换 100 站 + 回收 100 个旧版本 | 23.0 s + 6.7 s |
| 内存（整个测试进程，含签发 1 万张证书） | 导入后 heap in use 1.8 MiB，进程峰值 RSS 34.0 MiB |
| 磁盘 | 40021 个文件（每站 site.json + 证书 + 私钥 + 持有者标记），内容 21.2 MiB，保留 2 个探测 release |

- 改造前同一测试第 65 个站点即被拒，只发一个站点的激活被拒（stale）。
- Linux ext4/xfs 上 fsync 通常远低于 F_FULLFSYNC，导入与轮换耗时应明显更低，但本机未在 Linux 上测；10 万站未测（按每命令常数外推）。
- 真实 OpenResty（`tests/edge-site/site-runtime-render-smoke.sh`，`cdnca-native-runtime:wafdual`）：`TestRealOpenRestyLazyCertificates` 改用真实 certstore（每站单独一条命令激活）+ 共享证书池，多 SNI、通配符别名、TLSv1.3-only 混合站点、未知/无 SNI 拒绝、证书库激活新版本不触发运行中 OpenResty reload（worker 不变、仍是旧证书）、引用新版本的 release 经 reload 生效且在途请求不断；既有 TestRealOpenResty* 共 22 项全部通过。

## 9. 子任务：G8-c 配置分片增量下发

依赖：控制面部分可与 G8-b 并行；节点组合部分在 G8-b 之后（同改 `compose.go`/`compiler.go` 的命名）。前置：§7.2 缺陷 1–3。迁移：control-api 需要一张分片表，占位 302（守卫指向 `301_line_group_publication_sync_hold`，合入时改号）。

### 9.1 分片

- 每个配置 scope 按 `hash(site_id) mod S` 分片，S 取 2 的幂，使每片 ≤500 站（同时满足 遥测 ≤1000 监听、bundle ≤4 MiB；666 站时 2.24 MB，500 站约 1.7 MB）。S 只在一片超过 500 站时翻倍，翻倍只改写被拆的片（一致性前缀，`hash` 低位）。
- 分片是独立的 v2 文档：在现有文档上加 `shard: {index, count, scope_revision}`；`$.sites` ≤1000 的校验改为每片 ≤500，scope 不设站点上限（`site_runtime_v2.go:856`、`validate.go:33`）。
- scope 级产物 = 分片清单：`{scope_id, scope_revision, shards: [{index, config_version_id, sha256}]}`，签名后下发。清单很小（每片约 100 字节）。

### 9.2 主控（`edgepublish`）

- 新表 `edge_site_runtime_shards(scope_id, shard_index, shard_count, source_revision, config_version_id, canonical_sha256, …)`。发布时按站点事实算每片规范化文档，摘要与上次相同的片不重新签名、不生成产物，只在清单里引用已有版本。
- 每节点产物：只为变化的片生成。顺带解决 16 MiB/128 个上限：产物改为“一份对称加密的 bundle + 每节点 HPKE 封装内容密钥”（或按片拆成多条 config version），总量 ≈ 变化片大小 + 节点数 × 小常数。
- 遥测身份清单、HTTP 策略、防火墙动作、源站路由 bundle 都按片生成（它们今天按 scope 一份，`site_runtime_v2.go:248-304`）。
- 读事实也只读变化片：G8-d 的 apex 索引 + 按片的 `site_id` 范围查询；N+1 的 TLS 绑定查询（`site_runtime_v2.go:580-654`）改为按片一次批量查询。

### 9.3 节点（`deployment` + `siteruntimev2`）

- `deployment` 收清单：缺的片按 config_version_id 拉取并验签，已有的片原地复用；全部就位后整体激活（原子：清单是激活单位，不允许混合不同 `scope_revision` 的片）。回滚 = 激活上一份清单。
- 编译缓存：每片编译产物（server/upstream/geo/安全片段文本 + 端口声明）按片摘要缓存。命名从“全局偏移”（`siteOffset`、`listenerOffset`，`compose.go:84-96`）改为按片的稳定前缀（如 `cdnca_s<scope短哈希>_<片>_<站>_pool_<n>`），片的文本与它在组合里的位置无关，才能原样复用。组合只做拼接 + 节点级单例 + 跨片冲突检查。
- `FindPortConflicts` 改为按 (端口, 协议, 种类) 分桶计数，网站之间同端口同协议不必两两比较（`port_claims.go:116-134`），O(n²)→O(n)。
- 去掉“每 scope 单独 compileNginx 再组合编译”的重复（`runtime_adapter.go:241` 在组合模式下只做校验，或直接用片缓存）。
- 安全片段 32000 监听上限与 CC 合成注册表 1000 条上限（`security_fragments.go:75`、`cc_v2.go:867`）改为每片约束，节点级不封顶。
- nginx 仍整份 `-t` + reload（第 1 期不变），所以**单节点站点数仍受 §5.2 的 nginx CPU 约束**；G8-c 解决的是主控/传输/Go 编译从全量变增量。

### 9.4 预期

- 改一个站点：主控签一片（≤500 站，约 0.2 s CPU、≤1.7 MB），每节点只传这一片；节点 Go 编译从 O(n²) 全量降到一片 + 拼接（1 万站从约 4.5 s CPU 降到 <1 s，数字以复测为准）；nginx `-t`/reload 不变。
- 去掉 666/1000 站与 7/128 节点上限后，单 scope 1 万站可发布；单节点规模由 nginx 内存与 CPU 决定（§5.1–5.2）。

### 9.5 风险

- 原子性：清单激活前所有片都要就位并通过 `-t`；片拉取失败时保留上一份清单，不能部分激活。
- 跨片冲突：域名、站点 ID 唯一性今天在单文档内校验（`validate.go:73-96`），分片后改为主控在清单层校验 + 节点组合时 `CheckCrossScopeConflicts` 扩展到片（`compose_conflicts.go:23-51`，已是 map 实现，O(n)）。
- 兼容：新片格式只发给声明 v5（或 G8-c 的新版本）的节点，旧格式节点直接拒绝发布并列出节点（通用约束）。
- 遥测、计费按 config_version_id 关联站点（`telemetry_v2.go`、套餐监控）：改为按片后，每个站点仍只出现在一个片里，关联键从 scope 版本变成片版本，需要同步改服务端的版本→站点映射。

## 10. 基准中发现的既有缺陷（本任务未修）

> 1–4 已修复：1 注册表超 2048 字节时渲染为 `table.concat` 分块长字符串（真实 OpenResty 50 个 CC 监听通过）；2 `ccV2RegistryForSpec` 先排序再校验；3 遥测清单与服务端名册每监听一条、代表域名取站点第一个域名；4 证书引用按 release 声明的 `required_capabilities` 重评。

1. **CC v2 注册表超过 4096 字节时 `nginx -t` 失败**（高）。注册表整段内联在 `init_by_lua_block`（`libs/edgeconfig/security_fragments.go:60` 组合路径、`:112-113` 单 scope、v1 `config.go:865-911`），每条约 672 字节；nginx 配置解析器单个 token 上限 4096 字节（stock openresty/1.27.1.2 与生产 1.31.1.1 都是 4000 OK / 4096 失败）。生成器层面：5 个 CC 监听时该行 3586 字节、6 个 4251 字节；真实 OpenResty 用基准文档：4 个 CC 监听通过，5 个起报 `Lua code block missing the closing long bracket "]==]", the inlined Lua code may be too long`。影响：一个节点（多租户时所有 scope 合计）带 CC v2 的监听超过 5 个，发布在节点 `-t` 失败。现有 `tests/edge-site/multitenant-compose-smoke.sh ccv2` 只有 2 条，没覆盖。复现：`CDNCA_SCALE_CC_PERMILLE=1000 tests/scale/run.sh node 4,5`。
2. **CC v2 注册表先校验顺序再排序**（中）。`ccV2RegistryForSpec`（`cc_v2.go:639-659`）按站点/监听顺序追加条目后直接 `validateCCV2Registry`，后者要求按 (端口, 域名) 升序（`:886`），排序 `sortedCCV2Registry` 在之后才调用。同一 scope 里站点 ID 序与域名序不一致、或同一站 80 与 443 都挂 CC 时，`renderPlanSecurity` 返回 `invalid site configuration`，整份文档被拒。复现：两个 CC 站点 ID 升序、域名 `zzz.example`/`aaa.example` → 失败，域名对调 → 通过（基准里用临时测试验证过，未提交）。v1 路径同一函数，未单独验证。
3. **v2 发布多域名站点失败**（高，需端到端确认）。`buildSiteRuntimeV2TelemetryManifest` 要求每站恰好 1 个域名（`edgepublish/site_capture_policy.go:137`），而 v2 文档带站点全部域名（`site_runtime_v2.go:400-403`、`site_multi_domain_test.go`）。主控基准里任何带 3 域名站点的文档都在这一步返回 `ErrInvalidInput`；`compileSiteRuntimeV2Facts` 在 `:289-293` 无条件调用它。未连数据库跑完整发布确认。
4. **节点证书引用重评用了过低的能力集**（高，需端到端确认）。`deployment/certificate_references.go:177-186` 用 `site_runtime=3`、无 `cc`/`waf` 的能力集重新 `Evaluate` 已落盘的 v2 文档；带监听安全（ACL/WAF/CC，site_runtime 4）的文档返回 `missing_capability`（基准文档实测 `missing_capability at $.required_capabilities.cc`），`loadCertificateReleaseReferences` 随即报 `ErrCorruptState`，部署走 `CERTIFICATE_REFERENCE_FAILED`（`manager.go:291-299`）。凡配置了证书库的节点（生产都配了，`daemon.go:259,423`）、凡带安全策略的 v2 release 都会撞上。未在真实部署状态机里端到端复现。
5. **v2 单次发布最多 128 个节点、合计 16 MiB**（中）。`edgedeployment/validate.go:34-35,111,127-129`；HTTP 接口允许 10000 个目标（`edgepublishhttp/handler.go:536`）。666 站时 7 个节点即超 16 MiB。
6. **节点 HTTPS 证书最多 64 个站点**（中，设计限制）。**已由 G8-c g8c-certstore 修复**（§8.3、§8.6）：主控确实不按“累积全部站点”构造激活，同节点第二个站点单独发布必然 stale；现改为按站点增量激活。

## 11. 待决定的事

1. §10 缺陷 1–4 的归属与是否进 1.0.35（建议都进：1、2 交 G1 组，3 交 G8-c 或单独小任务，4 任何人可修，各自都是小改动）。缺陷 1、4 修复前，G8-b/G8-c 在带 CC 或安全策略的站点上测不出结果。
2. 能力号：G8-b 已定为 `site_runtime` 7（v5 强制 HTTPS、v6 缓存/托管 WAF/JS 挑战已占）。G8-c 分片格式的版本号待定。
3. G8-b 是否按 b1（渲染 + Lua，沿用 certstore）/ b2（证书库按版本存储、去 64 上限）拆开；b2 动证书状态机，风险最大。
4. （已定，不变）worker 可读私钥文件的安全取舍（§8.2）。
5. 第 1 期目标改为“去掉低上限 + 降常数 + 增量下发，单节点万站量级”，10 万站/节点留给第 2 期——与 plan §2.8 的表述一致，但需要确认对外口径。
6. 1 万站以上的真实 OpenResty 数据与 JS 挑战页压测需要一台独立测试机（`tests/scale/run.sh node`）；本机负载下只测到 5000 站。
7. （已完成）G8-b 证书形态 PoC：Lua 方案不可行，改用原生变量证书，见 site-runtime-cert-lazy-load.md。
