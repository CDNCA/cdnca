# 安全规则目录：规则名与节点实际效果核对

日期：2026-10-14，分支 `task/20261014-r134-secenforce`，基线 575f88e7。

## 怎么测的

不手写配置。`services/control-api/internal/securitypublication/rule_enforcement_audit_test.go`
把授权端目录（`rulecatalog.CompetitorSeed()` + `BuiltinWAFSeed()`，与迁移 050/052 种子逐字节一致）
里的 11 个 CC 规则组、10 个 WAF 规则集，逐项走真实编译链：

`securitypolicy.ValidatePublishablePolicy`（即 Create/Update 的保存校验）→
`securitypolicy.CompileRuntimeSnapshot` → `securitypublication.CompileSiteSecurityBindings`（edge publish 用的同一函数）→
`edgeconfig.Build`（节点 nginx.conf + `security/<site>/cc.compiled.json`）。

编译不过的策略按生产的真实结果处理：edge publish 返回 `ErrUnsupportedSecurityPolicy`，节点保持旧版本，
即该站点没有这条策略。产物交给 `scripts/security/rule-enforcement-e2e.sh`，在固定镜像
`openresty/openresty:1.27.1.2-0-alpine-fat`（`edge/openresty/runtime.env`）里加载仓库内的 Lua 引擎运行，
`scripts/security/rule-enforcement-probe.sh` 在容器内用 curl 发请求并逐项判定。

```
sh scripts/security/rule-enforcement-e2e.sh      # 输出 PASS/FAIL 与 SUMMARY
```

> 1.0.35 更新（smoke-migrate）：上述 v7 脚本已删除（dr-d13-c3e）；同样的请求逐项判定改在动态路由节点上跑：
> `tests/dynroute-cc/run.sh`（CC 各规则组、宽松速率、双引擎、`ONLY=bench` 性能、`BROWSER=1` 无头浏览器）与
> `tests/dynroute-waf/run.sh` `ONLY=catalog`（CRS 请求目录）。

> 2026-10-15 更新（task/20261015-r135-secwaf）：WAF 规则集改由 OWASP CRS 4.30.0 + libmodsecurity 执行，
> CC 验证页加 SHA-256 工作量证明与网段绑定的 HMAC-SHA256 通行 Cookie，所有参数来自目录/站点规则。
> 选型、映射与最新实测（CRS 官方回归、120 项节点实测、无头浏览器、性能、可复现构建）见
> `docs/security/waf-engine-selection.md` “落地验证”；本文以下为 r134 时的审计记录。

## 结论：大部分规则只有名字

| 目录项 | 名称 | 现状 | 证据 |
| --- | --- | --- | --- |
| cc_rule:10001 | 5秒盾 | 只有名字 | challenge 动作被 `compileCCV2Rule` 拒绝（`ErrUnsupportedRuntime`），发布失败；运行时首个请求 200，无等待页（CC-1..CC-10 FAIL） |
| cc_rule:1 | JS验证 | 只有名字 | 同上，challenge js 无法编译 |
| cc_rule:10000 | 点击验证 | 只有名字 | 同上 |
| cc_rule:10004 | 点击验证(简单) | 只有名字 | 同上 |
| cc_rule:2 | 滑块验证 | 只有名字 | 同上 |
| cc_rule:10005 | 滑块验证(简单) | 只有名字 | 同上 |
| cc_rule:4 | 验证码 | 只有名字 | 同上 |
| cc_rule:10003 | 旋转图片 | 只有名字 | 同上 |
| cc_rule:6 | 宽松（请求速率 5-300-50） | 部分生效 | 总量 5 秒 300 次生效：第 301 次 429（RATE-2 PASS）；单 URL 50 次不存在：同一 URL 第 51 次仍 200（RATE-3 FAIL）；超限只回 429，不拉黑 |
| cc_rule:3 | 临时白名单 | 部分生效 | 同宽松，只是一个限速；与"验证通过后的白名单"没有关系 |
| cc_rule:10002 | 关闭 | 真实生效 | 没有条目，就是不开 CC |
| waf_set:sqli | SQL注入 | 只有名字 | 保存即被拒（`invalid security policy input`：`args`/`regex` 不在可发布字段里）；10 种注入 payload 全部 200（SQLI-1..10 FAIL） |
| waf_set:xss | XSS | 只有名字 | 同上；5 种 payload 全部 200（XSS-1..5 FAIL） |
| waf_set:cmd_injection | 命令注入 | 只有名字 | 保存即被拒，同上 |
| waf_set:file_include | 文件包含 | 只有名字 | 同上 |
| waf_set:file_upload | 文件上传 | 只有名字 | 同上 |
| waf_set:java_code_injection | Java代码注入 | 只有名字 | 同上 |
| waf_set:java_deserialization | Java反序列化 | 只有名字 | 同上 |
| waf_set:php_code_injection | PHP代码注入 | 只有名字 | 同上 |
| waf_set:php_deserialization | PHP反序列化 | 只有名字 | 同上 |
| waf_set:ssti | SSTI模板注入 | 只有名字 | 同上 |

另外两点：

- WAF "仅记录"模式：目录规则存不进去，所以也没有记录可看（LOG-2 FAIL）。现有能力只有 host/端口/方法/路径
  精确或前缀/请求头精确/来源 IP 段，`/admin` 前缀拦截可用（WAF-PATH PASS）。正常请求 8 条全部 200。
- 站点级"挑战策略"（`challengepolicy` + `edge/openresty/challenge/engine.lua`）是另一套产品：对绑定站点的
  所有 HTML GET 请求一律弹验证，没有"统计周期 / 次数阈值"，也不读目录。它的 `runtime-smoke.sh`
  固定的 engine sha256 已与仓库文件不一致，本次未改。

## 根因

1. 目录只进了展示和启停：管理端同步后写进 `cc_reference_*` 表供列表展示，没有任何代码把规则组展开成站点策略。
2. CC 编译链只认 `rate_limit`：`securitypublication/cc_v2.go` 与 `agents/edge-agent/internal/ccv2/compile.go`
   都拒绝 `challenge`；节点 `ccv2/engine.lua` 动作只有 log / 429 / temporary_ban，没有验证页、没有单 URL 计数、
   没有失败次数与拉黑、没有通过后的白名单。
3. WAF 编译链只认精确/前缀/存在：`runtimeConditionSupported` 不接受 args/body/query/cookie/UA，也没有
   包含、正则、解码；节点内联状态机读不到请求参数和请求体。

## 原始输出

修复前运行结果见本文末尾附录 A（`SUMMARY failures=25`，共 39 项）。

## 附录 A：修复前

```
PASS WAF-OK-1 expected=200 actual=200 正常查询
PASS WAF-OK-2 expected=200 actual=200 姓名含单引号
PASS WAF-OK-3 expected=200 actual=200 自然语言含 select/union/or
PASS WAF-OK-4 expected=200 actual=200 撇号文本
PASS WAF-OK-5 expected=200 actual=200 技术文章搜索
PASS WAF-OK-6 expected=200 actual=200 JSON 正常评论
PASS WAF-OK-7 expected=200 actual=200 表单正常提交
PASS WAF-OK-8 expected=200 actual=200 参数里是普通 URL
PASS WAF-PATH expected=403 actual=403 路径前缀规则 /admin（现有能力）
FAIL SQLI-1 expected=403 actual=200 1' OR '1'='1
FAIL SQLI-2 expected=403 actual=200 1' OR 1=1-- -
FAIL SQLI-3 expected=403 actual=200 UNION SELECT
FAIL SQLI-4 expected=403 actual=200 双重 URL 编码
FAIL SQLI-5 expected=403 actual=200 大小写混写 + 注释分隔
FAIL SQLI-6 expected=403 actual=200 堆叠查询
FAIL SQLI-7 expected=403 actual=200 时间盲注
FAIL SQLI-8 expected=403 actual=200 admin'# 注释截断
FAIL SQLI-9 expected=403 actual=200 POST 表单体
FAIL SQLI-10 expected=403 actual=200 JSON 体
FAIL XSS-1 expected=403 actual=200 <script>
FAIL XSS-2 expected=403 actual=200 onerror 事件
FAIL XSS-3 expected=403 actual=200 javascript: 伪协议
FAIL XSS-4 expected=403 actual=200 双重编码 svg onload
FAIL XSS-5 expected=403 actual=200 POST 表单 iframe
PASS LOG-1 expected=200 actual=200 仅记录模式放行 SQL 注入
FAIL LOG-2 expected=1 actual=0 仅记录模式写入安全日志 action=log
FAIL CC-1 expected=503 actual=200 首个未验证请求弹出验证页
FAIL CC-2 expected=delay actual=none 验证页类型为 5 秒等待
FAIL CC-3 expected=403 actual=200 未等满 5 秒提交被拒绝
FAIL CC-4 expected=303 http://cc.audit.example.test/article?id=7 actual=200  等满 5 秒提交通过并跳回原页面
PASS CC-5 expected=200 actual=200 通过后携带白名单 Cookie 放行
PASS CC-6 expected=20 actual=20 白名单内 20 次连续请求全部放行
FAIL CC-7 expected=503 actual=200 伪造 Cookie 重新验证
FAIL CC-8 expected=503 actual=200 Cookie 换 UA 无效
FAIL CC-9 expected=403 actual=200 60 秒内验证失败超过 5 次拉黑
FAIL CC-10 expected=403 actual=200 拉黑期间带 Cookie 也拒绝
PASS RATE-1 expected=pass(200) actual=pass(200) 5 秒内 300 次（不同 URL）未超限放行
PASS RATE-2 expected=blocked actual=blocked 第 301 次超过 300 次阈值被拦截
FAIL RATE-3 expected=blocked actual=pass(200) 同一 URL 5 秒内第 51 次超过单 URL 50 次阈值被拦截
SUMMARY failures=25
```

<!-- APPENDIX_PLACEHOLDER -->
