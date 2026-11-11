# 插件与能力（社区版）

<p align="right"><a href="capabilities.md">English</a></p>

本页列出社区版包含的能力：能解决什么问题、在哪里开通、主要设置。每一项的完整说明在官网[插件与能力](https://www.cdnca.com/docs/capabilities/)，那里也写了商业版。

## 调度

### 按线路拨测与智能调度

线路组里的节点按电信、联通、移动（或省份加运营商）拨测延迟，访客解析到延迟最低、健康且负载没超限的几台节点；某条线路没有可用节点时逐级回退到同运营商全国线路、默认线路。

- 开通：管理端“节点管理 → 线路分组”，在线路组上点“智能调度”。
- 延迟来源：dnspup 拨测模块的检测点，或线路组里节点互相探测；两者都没有时按原来的解析配置。
- 主要设置：每条线路选点数（默认 3）、调度粒度（按运营商 / 按省份加运营商）、延迟统计窗口（默认 15 分钟）、最大负载（默认 85%）。
- 详细说明：[按线路拨测与智能调度](https://www.cdnca.com/docs/capabilities/line-scheduling/)

## 节点市场与插件市场（市场能力随版本开放）

使用前在主控服务器上免费注册一次安装身份：`control-api community-register --account <门户账号> --password-stdin`。

### 节点市场

订阅其他主控上架的节点，或把自己的节点上架出售。报价按天、按流量、按 95 带宽等计费，价格由供货方自定；充值直接付到供货方自己的收款账户。

- 入口：管理端“市场 → 节点市场”。
- 详细说明：[节点市场](https://www.cdnca.com/docs/capabilities/node-market/)

### 插件市场

规则包、主题、DNS 接入等插件在这里获取、购买和启用；每份购买只绑定本主控。官方商品对社区版不免费。
功能类插件付款或领取后直接生效；主题、规则包、页面插件和外部服务由主控管理员在“我的插件”核对权限并确认安装，租户级插件确认时选装给全部租户或指定租户，租户不用操作。

- 入口：管理端“市场 → 插件商店”。
- 详细说明：[插件市场](https://www.cdnca.com/docs/capabilities/plugin-market/)

## 站点与体验

### URL 鉴权

给下载、视频等受保护的路径加签名链接：节点验签通过才放行，过期或签名不对的请求被拒绝。密钥轮换时旧密钥继续有效，已发出的链接不会在轮换瞬间失效。

- 入口：网站管理 → URL鉴权。

### Server-Timing 响应头

按站点打开后，节点在响应里附加 Server-Timing，给出缓存结果、命中层级、回源连接耗时和回源首字节耗时，浏览器开发者工具的网络面板可直接看到。

- 入口：网站编辑的高级设置里的“Server-Timing 响应头”开关。

### 内容改写

按规则流式改写回源响应的内容，不需要改源站。

- 入口：网站管理 → 内容改写。

### 真实用户体验（RUM）

对抽样的访客页面注入采集脚本，统计真实访客的页面加载表现，按站点出报表。

- 入口：监控 → 真实用户体验。

### 客户状态页

在系统设置里维护服务组件与事件，访客通过公开页 /status/ 查看当前状态与历史事件。

- 入口：管理端“系统设置 → 状态页”。

## 安全防护

### WAF 与 CC 防护

WAF 规则库（平台规则与租户规则）、CC 规则集（按客户端 IP、网段、域名、URI、JA4、UA、Referer、请求头、参数计数）、JS 挑战、快速屏蔽、JA4 拦截、访问控制；CC 自动切换在访问量突增时临时换更严的规则组。

- 入口：管理端“网站管理 → WAF 规则 / CC 规则 / 规则包”，网站编辑的“CC 防护”“WAF 防护”“自动防御”标签。
- 浏览器挑战（JS 挑战与 CC 验证）：延迟、点击、滑块、验证码几种内置模式都要求浏览器执行 JavaScript 完成工作量证明，点击、滑块、验证码的图片由节点现画，答案不写进页面；只读页面、不执行 JavaScript 的脚本过不去，真实浏览器自动化（无头浏览器）挡不住，需要更强防护时用外部验证。滑块和验证码页面提供“改用等待验证”给读屏用户。工作量证明难度可在挑战策略里选 12–24（默认 18，中低端手机最坏约 0.4 秒），显式难度只下发给支持该字段的节点。
- 字符串集合：把多条规则共用的 UA、路径、域名放进一份集合，WAF 与 CC 规则按“属于 / 不属于集合”匹配；集合在“网站管理 → 列表与对象 → 字符串集合”维护，成员随站点配置下发到节点。
- 条件：除原有字段外，规则还能按浏览器及其版本、设备类型和请求时间段匹配；条件编辑器里的“试一下”可以解析一条 User-Agent，显示节点会把它识别成什么。
- 第三方人机验证：挑战策略可选 Cloudflare Turnstile 与 Google reCAPTCHA v3，在策略里填站点密钥与服务端密钥，并设置分数阈值，以及提供方不可用时改用站内验证还是暂停访问。
- 官方规则包（OWASP CRS 档位、高级 CC 规则组、自研检测规则集）可以在插件市场购买。
- 详细说明：[WAF 与 CC 防护](https://www.cdnca.com/docs/capabilities/waf-cc/)

### 四层防护

TCP/UDP 转发的防护规则：按首包内容、TLS 握手中的域名（SNI）、客户端 IP、运营商与 IDC、国家判定每个新连接，断开、断开并拉黑或放行；另有单 IP 每秒新建连接数与区域限制。

- 入口：管理端“转发列表”，编辑转发的“防护规则”。
- 详细说明：[四层防护](https://www.cdnca.com/docs/capabilities/l4-protection/)

### 内核封禁与连接防护

在节点内核层限制连接：单客户端并发与新建速率、空连接检测、TCP 异形包过滤、丢弃无效连接、CC 临时封禁同步到内核。节点按原生 XDP、通用 XDP、nftables 的顺序自动选用内核过滤方式。

- 入口：管理端“节点管理 → 连接防护”；网站级“防火墙配置 → 防火墙动作策略”。

### 封禁名单

按网站汇总手动封禁和节点的 WAF/CC 自动封禁，解除后服务该网站的所有节点一起解除。网站由节点市场订阅的节点服务时，名单经市场发给供货方，由供货方的节点执行；每条封禁显示下发状态（已在订阅节点生效、下发中、待下发、对方版本不支持等）。

- 入口：管理端“网站管理 → 封禁名单”。
- 详细说明：[内核封禁与连接防护](https://www.cdnca.com/docs/capabilities/kernel-ban/)

## 内置免费模块

| 模块 | 作用 | 设置位置 | 说明 |
| --- | --- | --- | --- |
| dnspup 拨测 | 用自己的 dnspup Key 从各运营商检测点拨测源站与节点：按用途的额度与降频、ping/http 拨测与细化选点、地区 × 运营商矩阵与线路告警、按需 mtr 排障 | 系统管理 → dnspup 拨测 | [详细](https://www.cdnca.com/docs/capabilities/probe-dnspup/) |
| IP 库实时更新 | 用自己的 dnspup Key 定时拉取最新 IP 情报快照 | 系统管理 → IP 库实时更新（dnspup） | [详细](https://www.cdnca.com/docs/capabilities/ipintel-dnspup/) |
| 备案查询 | 报价要求备案时核对订阅方域名 | 主控 `optional.env` 的 `MARKET_ICP_PROVIDER`、`MARKET_ICP_KEY_FILE` | [详细](https://www.cdnca.com/docs/capabilities/icp/) |
| 短信与邮件 | 阿里云短信、SUBMAIL、阿里云邮件推送、SendGrid | 系统管理 → 系统配置 → 发信配置 | [详细](https://www.cdnca.com/docs/capabilities/sms-mail/) |

## 商业版提供

以下能力不在社区版里，由商业版提供，说明见官网：

- [多 CDN 聚合边缘](https://www.cdnca.com/docs/capabilities/multi-cdn/)、[跨 CDN 调度](https://www.cdnca.com/docs/capabilities/cdn-scheduling/)、[全自动保底链](https://www.cdnca.com/docs/capabilities/fallback-chain/)
- [智能自动防御](https://www.cdnca.com/docs/capabilities/auto-defense/)（社区版只含 CC 自动切换与 WAF 自动封禁）、[攻击自动升级](https://www.cdnca.com/docs/capabilities/escalate/)
- [SDK 游戏盾](https://www.cdnca.com/docs/capabilities/sdk-shield/)（游戏和 App 集成 SDK，首包令牌校验、隐藏源站）
- [CF 优选节点](https://www.cdnca.com/docs/capabilities/cf-optimize/)
- [在线收款](https://www.cdnca.com/docs/capabilities/payments/)、[财务系统对接](https://www.cdnca.com/docs/capabilities/billing-bridge/)、[迁移导入](https://www.cdnca.com/docs/capabilities/migrate-import/)、多租户套餐与计费

完整对比：[社区版与商业版对比](https://www.cdnca.com/docs/capabilities/#editions)。
