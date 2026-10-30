# 节点 WAF 与 CC/人机验证：开源方案选型

日期：2026-10-15，分支 `task/20261015-r135-secwaf`，基线 b8348499。
数据来源：GitHub REST API（`/repos/<repo>`、`/releases`、`/commits`，2026-10-15 05:00 UTC 查询）与各项目源码。
性能、误报、可复现构建一律以本仓库实测为准，结果写在文末“落地验证”一节，不引用项目宣传数字。

## 结论

| 用途 | 选用 | 版本（锁定 sha256） | 许可证 |
| --- | --- | --- | --- |
| WAF 规则 | OWASP CRS（coreruleset/coreruleset） | v4.30.0 源码包 `a4bb3688…f8550` | Apache-2.0 |
| WAF 引擎 | libmodsecurity v3（owasp-modsecurity/ModSecurity） | v3.0.17 `f283b33d…71a50`（与官方 .sha256 一致） | Apache-2.0 |
| nginx 连接器 | ModSecurity-nginx | v1.0.4 `6bdc7570…13313`（与官方 .sha256 一致） | Apache-2.0 |
| SQLi/XSS 词法检测 | libinjection（libmodsecurity 内置 `@detectSQLi`/`@detectXSS`，CHANGES 记载已更新到 v4.0.0） | 随 libmodsecurity | BSD-3-Clause |
| JSON 请求体解析 | yajl（libmodsecurity 依赖） | 2.1.0 `3fb73364…5ac5a` | ISC |
| XML 请求体解析 | libxml2（libmodsecurity 依赖，仅解析器，无网络/目录/Python） | 2.15.4 `98087fd1…38821`（与 GNOME .sha256sum 一致） | MIT |
| CC 限速计数 | 保留现有实现（与 lua-resty-limit-traffic 的 `resty.limit.count` 同为 shared dict 原子 incr+TTL） | — | — |
| 人机验证 | 自研 Lua 实现，按 Anubis/ALTCHA 的 SHA-256 工作量证明协议加固 | — | 参考的 Anubis、ALTCHA 均为 MIT |

## 自研检测与 OWASP CRS 并存、引擎按需下载（2026-10-16，`task/20261015-r135-wafdual`）

secwaf 原方案用 CRS 覆盖目录规则集，并把 ModSecurity 编进节点原生运行时。现改为：

- 系统规则下两类 WAF 规则集并存：`waf_set:*`（自研检测：签名规则 + `cdnca_waf.lua` 语义检测 SQL 注入/XSS，默认导入）
  与 `waf_set:crs_*`（OWASP CRS，paranoia、异常分阈值、动作可调）。站点/策略可以只选一种，也可以两种都选或都不选。
  两者都开时任一引擎拦截即拦截，命中各自记录：自研检测写 WAF 安全日志，CRS 写 ModSecurity 审计日志（tag `cdnca/<key>`）。
- CRS 规则文本（4.30.0 请求侧 18 个规则文件 + 11 个数据文件）是目录数据 `waf_set:crs_rules`，
  经授权端 → 主控 → 节点签名链路下发；edgeconfig 只把发布用到的文件放进发布包，每个文件按内嵌清单校验 sha256。
- 引擎（libmodsecurity + ModSecurity-nginx `--with-compat`）是独立签名扩展（`edge/openresty/modsecurity/Dockerfile`
  构建，`cmd/waf-engine-package` 打包），放在下载服务器 `downloads/waf-crs-module/<版本>/openresty-<版本>/linux-<arch>/`。
  节点安装包不含引擎，原生运行时输入与签名基线保持不变。
- agent 只在发布带 `security/modsecurity/engine.json` 时下载，依次校验 SHA256SUMS、平台发布密钥签名
  （`signatures.json`，与节点包同一信任根 `artifact_trust_file`）、版本/架构、
  载荷与逐文件摘要，通过后安装到 `<deployment_root>/extensions/waf-crs/versions/<manifest 摘要>`，
  再写门控 `<StateRoot>/waf-engine/<版本>/{load,http,site-<id>}.conf`。nginx.conf 只用 glob `include …[.]conf`
  引用门控，没有门控文件时 include 为空，节点照常启动。
- 任何失败（下载、签名、摘要、版本、带门控 nginx -t、重启）都不写门控：CRS 站点降级为只用自研检测，
  原因放进部署状态检查项 `edge_waf_crs_engine`。加载的模块有变化时 master 必须重启（Stop + 启动）：
  带门控重启失败就改用无门控重启，仍然失败则由部署管理器回滚。
- 能力 `CAPABILITY_NAME_WAF_CRS_MODULE`（32，v1）。授权端对低于 1.0.35 的主控不下发 CRS/参数体，1.0.34 收到的目录不变。

体积（arm64 实测）：引擎扩展载荷 2.3MB，展开 6.7MB。secwaf 方案要把引擎和 CRS 规则打进节点包，压缩后约多 2.5MB；
本方案节点安装包不变（1.0.33 amd64 节点包 83,371,846 字节），只有启用 CRS 的节点才下载这 2.3MB。

## WAF 候选比较

| 项目 | 最近提交 / 最新版本 | 社区 | 与 OpenResty 集成 | 结论 |
| --- | --- | --- | --- | --- |
| coreruleset/coreruleset | 2026-10-13 / v4.30.0（2026-10-02，含 GHSA-575j-qr6p-9763 RCE 绕过修复）；LTS 分支 v4.25.2 同日发布 | 3.3k star | 规则文本，由引擎加载 | **选用**。有 paranoia level 1–4 与 anomaly scoring，官方 go-ftw 回归测试集随源码发布 |
| owasp-modsecurity/ModSecurity | 2026-10-13 / v3.0.17（2026-09-29） | 9.8k star，OWASP 托管 | C++ 库，经官方连接器接入 nginx | **选用**。CRS 的参考引擎；4.25.1 起要求 ≥ v3.0.16 |
| owasp-modsecurity/ModSecurity-nginx | 2026-09-26 / v1.0.4（2025-05-21） | 1.9k star | nginx 模块（静态或 `--with-compat` 动态），REWRITE/PREACCESS/LOG 阶段 | **选用**。v1.0.4 之后 18 个提交，主要是新指令、测试、一个异常配置路径上的内存泄漏（`mcf==NULL` 时才触发），不影响本方案 |
| corazawaf/coraza | 2026-10-14 / v3.8.1 | 3.9k star | Go 库；nginx 只有 `coraza-nginx`（仓库描述 “Experimental Connector”，79 star）或 `coraza-proxy-wasm`（需要 Envoy 等 proxy-wasm 宿主，nginx 不支持） | 不选。nginx 侧没有生产级连接器；要走 sidecar/auth_request 会多一跳 |
| libinjection/libinjection | 2026-10-12 / v4.0.0 | 239 star | C 库 | 不单独接入：libmodsecurity 已内置，CRS 942100/941100 等规则直接使用 |
| p0pr0ck5/lua-resty-waf | 最后提交 2021-10-06，tag v0.11.1 | 1.3k star | 纯 Lua | 不选：停更 5 年，GPL-3.0 |
| ADD-SP/ngx_waf | 2026-09-26 / v6.1.10（2025-01） | 1.6k star | nginx 模块，“兼容 ModSecurity” | 不选：自有规则体系，CRS 兼容度与回归测试无官方保证 |
| chaitin/SafeLine | 2026-09-28 | 22.7k star | 独立网关产品 | 不选：GPL-3.0，不能嵌入节点 |
| jx-sec/jxwaf | 2026-10-05 | 1.2k star | OpenResty | 不选：GPL-2.0 |

### 为什么选 CRS + libmodsecurity 能真正防御

- 检测不是关键字：942 组以 libinjection 词法指纹（`@detectSQLi`）为主，再叠加组装正则；941 组用 `@detectXSS`
  与 HTML 解析类正则；932 组覆盖 Unix/Windows shell 命令、反斜杠/引号逃逸。规则前统一做
  `t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:cmdLine` 等变换，覆盖多重编码。
- 检查范围：ARGS、ARGS_NAMES、REQUEST_COOKIES、REQUEST_HEADERS、REQUEST_FILENAME、XML/JSON 请求体（yajl）、multipart。
- 误报控制：anomaly scoring——单条规则只加分（critical 5 / error 4 / warning 3 / notice 2），
  到达阈值（默认入站 5）才拦截；paranoia level 1 为生产默认，2–4 逐级增加规则、误报也增加。
- 有官方回归测试：每条规则都有 go-ftw YAML 用例（`tests/regression/tests/`），本仓库直接跑官方用例。

## 10 个目录规则集 → CRS 映射

| 目录规则集 | CRS 规则 | 说明 |
| --- | --- | --- |
| waf_set:sqli SQL注入 | REQUEST-942（全部） | libinjection + 正则 |
| waf_set:xss XSS | REQUEST-941（全部，含 941380 AngularJS 客户端模板注入） | |
| waf_set:cmd_injection 命令注入 | REQUEST-932（932180 除外） | Unix/Windows shell、PowerShell |
| waf_set:file_include 文件包含 | REQUEST-930 LFI + REQUEST-931 RFI | 目录穿越、敏感文件、远程 URL 包含 |
| waf_set:file_upload 文件上传 | 920400/920410（上传大小）、922（multipart 攻击）、932180（受限文件名）、933110/933111/933220（PHP 脚本与会话文件上传）、944140（JSP 上传） | 920 其余协议规则不属于任何目录集，见下 |
| waf_set:java_code_injection Java代码注入 | REQUEST-944（944120/944200/944210/944240 与 944140 除外），含 944150/944151/944152 Log4Shell（JNDI） | |
| waf_set:java_deserialization Java反序列化 | 944120、944200、944210、944240 | 序列化魔数、Base64 魔数、危险类 |
| waf_set:php_code_injection PHP代码注入 | REQUEST-933（933170、上传类除外） | |
| waf_set:php_deserialization PHP反序列化 | 933170 Serialized Object Injection | |
| waf_set:ssti SSTI模板注入 | 934200 Server-Side Template Injection、934180 SSTI Attack（PL2） | CRS 4.30 新增的 SSTI 覆盖；Python `__class__` 链等由 934 通用规则与 932 部分覆盖 |

覆盖不到或未纳入目录的：
- 920/921 其余协议规则（请求走私、头注入、范围头滥用等）、911 方法限制、913 扫描器识别、
  934 SSRF/原型污染/Node/Ruby 注入、943 会话固定：这些 CRS 规则存在，但不属于现有 10 个目录集，
  默认不加载。映射写在目录数据里（不是代码），管理员可新增规则集引用这些文件。
- SSTI 只覆盖常见模板语法；无模板引擎上下文的盲 SSTI 无法单靠请求特征判定。
- 反序列化只能识别序列化数据格式与已知危险类，无法判断目标应用是否真的反序列化。
- 响应方向（950–959 数据泄露）需要缓冲响应体，CDN 节点不开启。

## CC/人机验证候选比较

| 项目 | 最近提交 / 版本 | 许可证 | 机制 | 结论 |
| --- | --- | --- | --- | --- |
| TecharoHQ/anubis | 2026-10-12 / v1.28.1 | MIT | 由请求元数据派生 challenge，浏览器 Web Worker 求 SHA-256 前导零（默认难度 5），通过后发 ed25519 签名 JWT Cookie（含 challenge/nonce/response/iat/exp） | 采用其协议思路；它是独立 Go 反向代理，不嵌入 OpenResty |
| altcha-org/altcha | 2026-10-05 / v3.3.0 | MIT | 服务端 HMAC 签名的 salt+难度，客户端求解 SHA-256/PBKDF2/Argon2 | 采用“挑战本身 HMAC 签名、服务端无状态校验”的做法 |
| mCaptcha/mCaptcha | 2025-10-07 | AGPL-3.0 | PoW 验证码服务 | 不选：AGPL，且一年未更新 |
| openresty/lua-resty-limit-traffic | 2026-09-16 | BSD | `resty.limit.count`（固定窗口）、`resty.limit.req`（漏桶）、`resty.limit.conn` | 评估后未替换：现有 `fixed_window`/`leaky_bucket` 与之算法相同（shared dict 原子计数），且已有总量/单 URL/拉黑回归覆盖，替换不改变行为 |

### 现有 challenge/ccv2 的问题（加固前）

| 问题 | 证据（`edge/openresty/ccv2/engine.lua` 基线） |
| --- | --- |
| 5 秒盾/JS 验证可被 curl 直接通过 | 页面里给出 `data-seed="a:b"`，答案是 `(a*b)%9973`；脚本解析即可，等 5 秒提交 |
| 点击/滑块/旋转答案明文在页面里 | `data-id`、目标百分比、`data-base` 角度都直接输出到 HTML |
| 通行 Cookie 绑定精确 IP，HMAC-SHA1 | `pass_material` 用 `peer.text`，移动网络换 IP 即失效；签名用 `ngx.hmac_sha1` |
| 密钥不轮换 | `challenge:secret` 首次生成后一直使用到进程重启 |
| 阈值写死 | `catalogBlockSeconds=360`、`catalogPassSeconds=21600`、`NONCE_TTL=120`、失败窗口默认 60/5 |

### 加固方案

- 所有验证类型先过 SHA-256 工作量证明：服务端签发 `HMAC(挑战)`，内容包括站点、IP 段、UA 摘要、随机盐、难度、过期时间；
  客户端求 `sha256(salt..nonce)` 前导零比特 ≥ 难度。难度（比特）由管理员配置，5 秒盾使用较高难度，交互类使用较低难度。
  curl/脚本要通过必须真算，难度每加 1 位工作量翻倍。
- 交互类（点击/滑块/旋转/验证码）在 PoW 之上保留人机交互；页面不再输出答案（由签名挑战携带）。
- 通行 Cookie：HMAC-SHA256，绑定 IP 段（IPv4/IPv6 前缀长度可配）、UA 摘要、站点、过期时间、密钥编号；
  密钥按可配置周期轮换，仅接受当前与上一周期密钥。
- 限速与计数：保留现有实现（见上表），阈值、周期、拉黑时长全部来自目录与站点规则。
- 所有参数（统计周期、次数阈值、单 URL 阈值、失败次数、拉黑时长、白名单有效期、PoW 难度、IP 段、轮换周期）
  来自目录数据与站点规则，代码里没有默认值。

## 落地验证

全部结果文件在 `tests/security-rule-enforcement/`，命令可重复执行。

### 可复现构建（`edge/openresty/modsecurity/build.sh`）

同一提交、同一固定镜像（openresty 1.27.1.2 alpine-fat arm64）两次独立 `docker run`，产物 133 个文件 sha256 全部一致
（`libmodsecurity.so.3 2f0bebb8…`、`ngx_http_modsecurity_module.so db85fc5c…`、`libxml2.so.16 c3392881…`、
`libyajl.so.2 779ce870…`、CRS 规则文件）。构建不联网（pkg-config 占位、固定 SOURCE_DATE_EPOCH、
`-ffile-prefix-map`、`--build-id=none`、确定性 ar）。原生 amd64 构建（`edge/openresty/native/Dockerfile`）同一配方，
未在本机执行（需 amd64 构建机）。

### CRS 官方回归（`scripts/security/crs-regression.sh`，go-ftw v2.3.0 + CRS 4.30.0 tests/ + nginx-overrides.yaml）

配置与 CRS CI 的 modsec3-nginx 目标相同（paranoia 4、DetectionOnly、info 日志、1 个 worker），
请求体处理器、Unicode 映射与上限取节点目录默认值。

| 组 | 通过/总数 |
| --- | --- |
| 942 SQLi | 1032/1032 |
| 941 XSS | 263/263 |
| 932 RCE | 1089/1089 |
| 930 LFI | 83/83 |
| 931 RFI | 42/42 |
| 944 Java | 1176/1176 |
| 920 协议 | 427/428（920100-4：CONNECT 方法被 nginx 在 WAF 之前处理，与检测无关） |
| 921 / 922 / 933 / 934 | 117/117、47/47、442/442、282/282 |

首轮发现并已修复：未编 libxml2 时 162 个 XML 请求体用例失败；未加载 `unicode.mapping` 时 %uXXXX 全角绕过 4 例失败；
PCRE 匹配上限取 libmodsecurity 推荐值 1000 时 942521 性能用例失败（目录默认值改为 100000，可在目录调整）。

### 节点实测（`scripts/security/rule-enforcement-e2e.sh`，真实编译链产物）

120 项全部通过（`after-crs.txt`）：10 个规则集的攻击请求拦截；误报对照（中文表单、JSON API、正常 XML、PNG 上传、
URL 含 select/union 单词、撇号文本）放行；富文本路径排除 941160/941310 后正常 HTML 放行、`onerror`/`<script>` 仍拦截；
仅记录模式放行并写审计日志；参数个数超限、JSON 解析失败被拒；CC 工作量证明、重放、篡改、换网段、
修改目录参数后行为随之改变。已知设计行为：`admin'#` 在 paranoia 1 不拦、paranoia 2 拦截（WAFP-3）。

### 无头浏览器（`scripts/security/cc-browser-e2e.sh`，Chromium / playwright-core 1.61.1）

10 项全部通过：5秒盾（浏览器自动完成 18 位 PoW 并等满 5 秒）、无感 JS、点击、图形点击、滑块各自通过并拿到 v2 Cookie；
浏览器拿到的 Cookie 换到其它网段使用返回 503。

### 性能（`scripts/security/rule-enforcement-bench.sh`）

同一容器、1 个 worker、8 并发 keep-alive，取 3 轮中位数。测试机为多任务共用的 10 核 arm64 Docker Desktop，
期间负载 17–25，绝对值偏高、只宜看相对差：

| 站点 | GET 正常 | POST 中文表单 | GET 攻击 |
| --- | --- | --- | --- |
| 无安全策略 | 973 req/s，p50 5 ms | 674 req/s | 1286 req/s |
| 10 个规则集 paranoia 1 | 192 req/s，p50 30 ms | 136 req/s | 136 req/s（全部 403） |
| 10 个规则集 paranoia 2 | 154 req/s，p50 37 ms | 143 req/s | 该轮压测端 10 秒超时未出数 |
| 对照：未改动的 CRS PL1（同一构建，裸 nginx） | 303 req/s | — | — |

结论：引擎开销来自 libmodsecurity + CRS 本身（对照组同量级）；PL2 比 PL1 多约 20% 开销。上线前需在独立节点复测。

### 动态路由复测（1.0.35，`tests/dynroute-cc`）

以上三个 v7 脚本已随 v7 渲染器删除（dr-d13-c3e）。同样的覆盖改在动态路由节点上跑：真实编译链 →
生产站点对象转换 → 站点索引激活，OpenResty 1.31.1.1 + ModSecurity 扩展（`tests/dynroute-cc/README.md`）；
CRS 请求目录在 `tests/dynroute-waf` `ONLY=catalog`。

性能 `ONLY=bench`：参数与旧 bench 相同（同一容器、1 worker、8 并发 keep-alive、4000 请求、预热 1 轮后
3 轮按 req/s 取中位数、同样三种请求）。2026-10-20，同一台 10 核 arm64 Docker Desktop，负载 21；
旧列取上表（v7、OpenResty 1.27.1.2、paranoia 2 档位），新列为动态路由，单位 req/s（p50）：

| 站点 | GET 正常 旧 → 新 | POST 中文表单 旧 → 新 | GET 攻击 旧 → 新 |
| --- | --- | --- | --- |
| 无安全策略 | 973（5 ms）→ 14109（0.39 ms） | 674 → 12940 | 1286 → 14621 |
| 10 个 CRS 规则集 PL1 | 192（30 ms）→ 1037（6.6 ms） | 136 → 959 | 136 → 1044（全部 403） |
| 10 个 CRS 规则集 PL2 | 154（37 ms）→ 569（12.3 ms） | 143 → 564 | 未出数 → 675（全部 403） |
| 10 个 CRS 规则集 PL3（新增） | — → 407（16.5 ms） | — → 419 | — → 281（全部 403） |

两次测量机器负载不同、OpenResty 与 CRS 构建也不同，绝对值不可直接比较，只看相对开销：
无策略 / PL1 旧约 5 倍、新约 14 倍；PL1 / PL2 旧 1.25 倍、新 1.8 倍。
即引擎外的请求路径变快很多后，CRS 本身成为主要开销；PL2、PL3 的增量明显高于 v7 时的测量。上线前仍需在独立节点复测。

无头浏览器 `BROWSER=1`（chrome-headless-shell 1228）：12 项全部通过——旧版 10 项加简单滑块、旋转；浏览器的 Cookie 换网段回放 503。
