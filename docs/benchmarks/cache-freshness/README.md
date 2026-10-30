# Cache Freshness 隔离基准

本基准比较同一固定 OpenResty 镜像中的两种独立 cache state：

- `baseline`：标准 `proxy_cache`，不启用通用 cache lock 或 stale 服务。
- `enhancement`：完整 cache identity 上启用原生 `proxy_cache_lock`、background update、revalidation 和 5 秒 stale hard window。

它只回答固定本机容器、人工源延迟和单一热点模型下的源站放大、请求延迟与资源观测问题，不是生产容量或默认启用依据。

## 运行

前置条件：Docker、Go、curl、awk 和 ShellCheck。脚本只创建带随机后缀的网络、三个容器、两个独立缓存目录和一个临时目录，退出时精确清理这些资源。

```sh
cd <仓库根目录>
sh -n docs/benchmarks/cache-freshness/run.sh
shellcheck docs/benchmarks/cache-freshness/run.sh
docs/benchmarks/cache-freshness/run.sh
```

固定输入：

| 输入 | 值 |
| --- | ---: |
| OpenResty | `1.27.1.2` |
| 镜像 digest | `sha256:b141c051015a17c8bbf59f19a7d412659b274797c1f62a89ced10bedaee19eb8` |
| distinct cache keys | 8 |
| 每 key 并发 | 32 |
| 每 phase 计时请求 | 256 |
| 人工源延迟 | 200ms |
| fresh TTL | 1s |
| stale prepare wait | 1.3s |
| enhancement stale window | 5s |
| enhancement lock timeout / age | 1s / 5s |

`cold` 为每轮使用新 query 的首次并发请求。`stale` 先为 8 个 key 各发送一次预热请求，等待进入 stale 窗口，再发送每 key 32 并发；所以 stale 的源站计数明确包含 8 个 prepare 请求。baseline 和 enhancement 使用不同 listener、cache state、site/config identity 与 origin path，但共享同一个只读 fixture 进程。

负载生成器使用每轮 barrier，同时记录 HTTP 状态、稳定 reason、响应头完成时延 p50/p95/p99、stale 比例和 coalesced 数；fixture 正文只有一个短行，因此该时延不能外推到大对象完整下载。运行脚本在 workload 期间循环执行 `docker stats --no-stream`，记录容器 CPU 和内存观测峰值；不是运行结束后的单点采样。

## 2026-07-24 本机结果

以下结果来自上述未调整 workload 的一次完整成功运行：

| mode / phase | p50 | p95 | p99 | origin requests | stale ratio | coalesced | timeout fallback | errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline cold | 213.834ms | 228.537ms | 232.991ms | 256 | 0 | 0 | 0 | 0 |
| baseline stale | 214.316ms | 230.716ms | 234.441ms | 264，含 8 prepare | 0 | 0 | 0 | 0 |
| enhancement cold | 507.155ms | 518.033ms | 524.132ms | 8 | 0 | 241 | 0 | 0 |
| enhancement stale | 4.142ms | 9.951ms | 195.583ms | 16，含 8 prepare | 1 | 0 | 0 | 0 |

reason 分布：

- baseline cold/stale：各 256 个 `cache_miss`。
- enhancement cold：8 个 `cache_miss`、241 个 `coalesced_follower`、7 个 `cache_fresh_hit`。
- enhancement stale：256 个 `stale_served_revalidate`。

mode 级资源采样：

| mode | samples | observed peak CPU | observed peak memory |
| --- | ---: | ---: | ---: |
| baseline | 4 | 5.810% | 25.400 MiB |
| enhancement | 4 | 4.090% | 30.510 MiB |

在该模型中，enhancement 把 cold 源请求从 256 降到 8，把 stale phase 的源请求从 264 降到 16；代价是 cold p50/p99 高于 baseline，因为 follower 等待原生 cache lock 和 worker 唤醒。进入 stale 窗口后，请求立即得到有界 stale，p50 明显降低。本轮 stale ratio 为 1；相邻同参数成功运行曾观测到 0.99609375 和 0.87890625，因为 200ms 后台 refresh 完成后，同一 burst 的后段请求可能看到 fresh。脚本不把 stale ratio 固定为 1，也不会为此调 workload。

CPU 样本只有 4/4 个，Docker Desktop 调度、连接建立和 `docker stats` 自身都会引入噪声；这些峰值只能证明本轮没有明显失控，不能据此做节点容量规划。正式 canary 必须在目标节点上用真实对象大小、连接复用、Zipf/scan/flash-crowd 分布、源错误、磁盘压力和不同并发重新测量，并同时观察源请求/字节放大、cold/stale 尾延迟、cache churn、worker CPU/内存与错误率。

## 输出契约

脚本只在所有计时请求均为 200、无 transport error，且 enhancement 的 cold/stale 源请求均严格少于 baseline 时成功。stdout 包含三类单行 JSON：

- `CACHE_FRESHNESS_BENCHMARK_LOAD`：每个 mode/phase 的延迟、状态与 reason。
- `CACHE_FRESHNESS_BENCHMARK_MODE`：mode 级源请求和资源采样峰值。
- `CACHE_FRESHNESS_BENCHMARK_COMPARE`：固定镜像、workload 和两模式源请求总数。

脚本使用宽松但有界的放大断言避免把一次调度抖动误判为算法失败；原始精确计数始终输出，不会为了得到漂亮数字自动重跑或调整参数。
