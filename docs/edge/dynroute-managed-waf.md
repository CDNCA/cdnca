# 动态路由托管 WAF（D11：OWASP CRS 在共享 server 下）

- 实现：`libs/edgeconfig/waf_dynamic.go`（节点规则、档位规则、站点上下文，唯一规范）、`libs/edgeconfig/edgeskeleton`（`Input.ManagedWAF`）、`edge/openresty/dynroute/cdnca_managed_waf.lua`、`agents/edge-agent/internal/dynwaf`（节点文件准备）。与本文不一致时以代码和测试为准。
- 依据：ADR 0009 §9 问题 3 方案 a、[0009-poc-results.md](../adr/0009-poc-results.md) §5、ADR 0007 §5.3（CRS 档位包 `system/crs-<level>`，PA-12）、[dynroute-contract.md](dynroute-contract.md) §1 第 4 条（模块变量 `$cdnca_waf_*`）。
- 依赖的源码事实（libmodsecurity 3.0.17 / ModSecurity-nginx 1.0.4 / ngx_lua 0.10.31rc5）：事务在 location 的 REWRITE 处理器里按该 location 的规则集建（`ngx_http_modsecurity_rewrite.c`）；`SecRequestBodyLimit`/`NoFilesLimit`/`LimitAction`/`ArgumentsLimit`/`JsonDepthLimit`/`PcreMatchLimit` 是规则集属性、按 location 合并（`rules_set_properties.h:501-515`），`ctl` 改不了；`ctl:ruleRemoveById` 运行期压入事务列表（`rule_with_operator.cc:213-228`）；`ngx.exec` 进命名 location 清模块 ctx、从 location rewrite 重跑、变量保留（`ngx_http_core_module.c:2692-2706`），命名 location 不存在回 500（`:2713-2718`）。

## 1. 形态

| 部件 | 内容 | 随什么变（变才 reload） |
|---|---|---|
| 节点规则（http 级 `modsecurity_rules_file`） | 引擎设置、审计日志、站点上下文解析（失败 500）、放行网段关引擎、检查上限模式、请求体解析加固、按规则族分组的排除钩子（每个导出规则一条）、CRS 文本、全部档位包规则集计分 | CRS 文本、节点上的档位包集合 |
| 档位（每个一个命名 location `@cdnca_waf_<key>`） | 档位 = CRS 档位包 + 配置期上限六元组；档位规则文件 = 六个 Sec*Limit + 档位包 paranoia/各集模式与阈值 + 移除档位包不评估的规则（与 v7 每站文件逐行一致，去掉站点部分，`TestDynamicWAFTierMatchesV7SiteFile`） | 站点用到的档位集合 |
| 站点数据（请求期，事务 ID） | `c2;s=<站点>;i=<l\|b>;e=<1\|0>;d=,<检测器>,;x=,<排除>,;\|<request_id>` | 不 reload |

`d=`：节点结构化检测器（`cdnca_waf.detect_args`：sqli/xss/ssti/java_deser/php_deser，按参数值：query、表单、JSON 叶子）命中集合，只对两级评分档位包（严格防护及以上，骨架 `managed_waf_detect`）的站点计算；节点规则 30080+ 把命中加到对应集强分 +5，且只在该档位该集 `weak_threshold>0` 时生效，标准防护判定不变。v7 路径（`renderManagedWAFSite`，每站文件、无 Lua 上下文）不支持检测器强信号（waf-strict-algo 2b）。

`key = <档位包摘要前 16 位>_b<体>_n<无文件体>_<r\|p>_a<参数数>_j<JSON 深度>_p<PCRE>`，Go（`DynamicWAFTier.Key`）与 Lua（`tier_key`）同算法，节点不需要站点→档位映射表。档位包摘要前 16 位在一个节点内重复即拒绝（`ResolveDynamicWAFRelease`）。

## 2. 请求流程

1. `server_rewrite`：选站（D3）、TLS（D4）、CC（D7），与 v7 同在 ModSecurity 之前。
2. `location /`（`set $cdnca_waf_engine 1`，不开 ModSecurity）的 `rewrite_by_lua` 第一步 `cdnca_managed_waf.rewrite(site)`：站点有托管 WAF → 按站点对象摘要缓存的计划写 `$cdnca_waf_txid`（放行网段判定在此，`e=0`）、`$cdnca_waf_pass=tier`、暂存 `ngx.ctx`，`ngx.exec` 进档位 location；无托管 WAF → 不动。
3. 档位 location：ModSecurity 用 `modsecurity_transaction_id $cdnca_waf_txid` 建事务（phase 1：解析上下文、引擎开关、排除）→ `rewrite_by_lua` 再跑（取回 `ngx.ctx`；`client_pass()` 为真，跑规则计划 D6）→ PREACCESS phase 2（请求体）→ `access`（`client_pass()` 为真：防火墙动作/挑战/HTTP 策略/回源/缓存派发；首轮在此结束）。
4. 顺序与 v7 一致：CC → ModSecurity phase 1 → 规则计划 → phase 2 → access（PoC §5 第 5 条；v7 规则计划在 location rewrite、phase 2 在 preaccess）。
5. 缓存可缓存请求从档位 location 再 `ngx.exec` 进缓存变体，事务随请求保留（pool cleanup 找回，响应阶段与审计日志不变）。

## 3. 失败即拒绝

- 上下文缺失/格式错 → 节点规则 30001 回 500；档位 location 不在骨架（站点对象与骨架不一致）→ `ngx.exec` 找不到命名 location 回 500；站点对象托管 WAF 字段读不出 → 500。
- agent 侧 `dynwaf.Prepare` 拒绝：引擎扩展未安装、站点档位包不在节点、排除不在档位包导出、档位超过 256 → `ErrUnavailable`，发布应据此拒绝（不降级）。
- 客户端无法伪造上下文：节点规则只读事务 ID（`UNIQUE_ID`），不读请求头；上下文不送源站。

## 4. 请求体上限档位（与 ge-waf S1 对齐）

ge-waf S1 给自研规则的“请求体超 64KB”：默认只检查前 64KB，`body_overflow: match` 视为命中（`waf_inspect.go`，`cdnca_waf.lua`）。托管 WAF 的同义选项是站点 `request_body_limit_action`：`reject`（超限 403）/`partial`（只检查前 `request_body_limit` 字节），两者都在档位里，同一 server 下不同站点各按自己的档位执行（验收 body-reject / body-partial / body-default）。两套机制独立：自研规则的 64KB 是检查窗口，托管 WAF 的上限是 ModSecurity 缓冲上限。

## 5. 规则包挂载顺序（ADR 0007）

托管 WAF 是 `modsecurity` 引擎的单例包（`rulepack.Resolve` 的 `ConflictEngineSingleton`：一站只挂一个），只能来自 system 层（`rulepack.CRSProfileOf` 要求 `system/crs-*`）。所以 user→developer→system 顺序对它只有一个位置：用户/开发者层的 Lua 规则包段在 D6 规则计划里按 (layer_rank, priority, pack_id) 排列，托管 WAF 的 phase 1/2 分别在规则计划之前/之后，与 v7 相同。站点对象 `security.mounts`（ADR 0009 §8.4）尚未接入节点，接入后 `managed_waf.crs_profile` 应等于 mounts 里唯一的 `modsecurity` 挂载（本任务未改格式）。

## 6. 验收与实测

- 单测：`go -C libs/edgeconfig test -run DynamicWAF .`、`go -C libs/edgeconfig test ./edgeskeleton/`、`go -C agents/edge-agent test ./internal/dynwaf/`。
- 真实 OpenResty：`tests/dynroute-waf/run.sh`（节点运行时镜像 + `scripts/security/modsecurity-runtime.sh` 扩展，`--rm --network none`，2 worker）13/13：9 站 5 档位随机交替 54 请求不串；PL2 专属载荷只在 PL2 站点拦截；70 KiB 体在 64 KiB reject 档 403、partial 档前段无攻击 200（攻击在前段 403）、1 MiB 站整体检查 403；放行网段只对该站该源关引擎；伪造上下文头无效；上下文不送源站；改排除下一请求生效、nginx 进程号不变、WAF 文件目录不变；未知档位站点 500；error.log 无 crit/alert/emerg。
- 金标：`CDNCA_EDGE_GOLDEN_RENDERER=cdnca-dynroute tests/edge-golden/run.sh check managed-waf` → SAME（集成头上为 ERROR，未支持）。
- 每请求额外耗时（`ONLY=scale SCALE=… WORKERS=1`，干净 GET，单客户端顺序，三轮取中位；本机 arm64 Docker Desktop，load 11–26，只作量级）：

| 站点数 | 档位 | 无托管 WAF p50 / p99 | 托管 WAF p50 / p99 | 额外 p50 | master RSS |
|---|---|---|---|---|---|
| 10 | 2 | 60 µs / 365 µs | 707 µs / 1.9 ms | +0.65 ms | 9.0 → 27.5 MB |
| 10 000（每站 0–8 条排除） | 2 | 230 µs / 1.7 ms | 984 µs / 5.1 ms | +0.75 ms | 8.9 → 27.4 MB |

额外耗时与站点数无关（10 站与 1 万站差在噪声内）：来自 ModSecurity 本身（一份 CRS 规则集 + 档位规则）与一次 `ngx.exec`，站点数据只是一个事务 ID 字符串；内存是一份 CRS（约 18 MB），与站点数无关。准备耗时 1 万站 143 ms，节点规则 52,891 B。
