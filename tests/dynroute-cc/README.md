# tests/dynroute-cc

CC 验证与 WAF 双引擎在动态路由上的回归覆盖（真实 OpenResty，节点运行时镜像 +
ModSecurity 扩展，一个 `--rm --network none` 容器）。取代 dr-d13-c3e 删掉的 v7 脚本
`scripts/security/rule-enforcement-probe.sh`、`rule-enforcement-bench.sh`、
`cc-browser-e2e.sh/.mjs`（CRS 请求目录已迁到 `tests/dynroute-waf` `ONLY=catalog`）。

链路：control-api `TestRuleEnforcementAuditRelease`（真实编译链，签名系统规则目录的每个
CC 规则组 + WAF 引擎组合 + 基准站点）写出 site runtime v2 发布 → control-api
`cmd/cdnca-site-objects-v2`（生产的站点对象转换）→
`agents/edge-agent/internal/edgegolden/goldendyn/cmd/cdnca-cc-check` 经站点索引激活器
把站点对象装进动态路由节点，在容器内发请求。

```sh
sh tests/dynroute-cc/run.sh               # cc,modes,params,rate,engines
ONLY=bench sh tests/dynroute-cc/run.sh    # 性能对比（只测量）
BROWSER=1 sh tests/dynroute-cc/run.sh     # 无头 Chromium 逐页解题
```

| 部分 | 覆盖（旧 probe 用例号） |
| --- | --- |
| cc | 5秒盾 cc_rule:10001：页面/PoW 18 位、未做 PoW、未等满 5 秒、错误 PoW、跨页面盐、通过并跳回、一次性 token、Cookie 放行 20 次、篡改签名、/24 绑定、换网段、换 UA、失败 5 次拉黑（CC-1…CC-10） |
| modes | JS/点击/旋转/简单点击/简单滑块/滑块逐个按页面作答通过，验证码答错被拒，滑块/旋转位置偏离被拒（G1…G4） |
| params | 改目录参数（PoW 20 位、等待 2 秒、失败 2 次、拉黑 30 秒、绑定 /32）行为随之变化；PL2 拦截 admin'#（PARAM-1…6、WAFP-3） |
| rate | 宽松 cc_rule:6：5 秒 300 次 / 单 URL 50 次（RATE-1…4） |
| engines | 自研 / CRS / 两者都开：任一引擎拦截即拦截、正常请求零误报；两者仅记录时放行且各自写日志（安全日志 / ModSecurity 审计日志）；全部 10 个自研规则集 |
| bench | 无策略 / 全部 10 个 CRS 规则集 PL1 / PL2 / PL3，GET 正常、POST 中文表单、GET 攻击；1 worker、8 并发 keep-alive、4000 请求、预热 1 轮后 3 轮按 req/s 取中位数（与旧 bench 同参数） |
| BROWSER=1 | 5秒盾、无感 JS、点击、图形点击、滑块、简单滑块、旋转（旧版 10 项 + 简单滑块/旋转）；浏览器的 Cookie 换网段回放 503 |

变量见 `run.sh` 文件头。
`BROWSER=1` 需要 playwright-core 与对应的 Chromium；包自带的浏览器版本没下载时用
`CHROMIUM=<chrome-headless-shell 路径>` 指定本机已装的。浏览器跑完即关、容器 `--rm`。

`ENG-LOG-SELF` 是 sec-log-fix（2026-10-20）的回归用例：此前 Lua 写 `$cdnca_security_*`、遥测 map 读
`$cdnca_security_emit`，`shared/telemetry/dynroute/security.jsonl` 恒为 0 行；现在全部统一为 `$cdnca_security_*`。
