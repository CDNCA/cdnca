# 用户端 Web 容器 CSP（1.0.35）

适用于 Docker 镜像部署的用户端（`apps/web/Dockerfile` + `apps/web/nginx.conf`）。原生安装（`scripts/install-control.sh`）的 nginx 不发 CSP。

## 策略

- `script-src 'self' 'nonce-$request_id' 'strict-dynamic'` 加验证码主机：nginx 每个请求生成新 nonce（`$request_id`），并用 `sub_filter` 打在 `index.html` 的 `<script>` / `modulepreload` 上；前端插入的脚本（全站JS代码、验证码 SDK、Turnstile）带同一 nonce。不开 `unsafe-inline`。
- 验证码主机（`script-src` / `frame-src` / `connect-src` / `img-src` 各自固定，见 `scripts/web-container-static.sh`）：
  - Cloudflare Turnstile：`challenges.cloudflare.com`
  - 腾讯验证码：`turing.captcha.qcloud.com`（SDK、iframe、接口；[Web 客户端接入](https://cloud.tencent.com/document/product/1110/36841)、[接入相关问题](https://cloud.tencent.com/document/faq/1110/36828)），`captcha.gtimg.com`（图片；仅有社区回答依据，待下文验收）
  - 极验 v4：`static.geetest.com`、`gcaptcha4.geetest.com` 及容灾 `static.geevisit.com`、`gcaptcha4.geevisit.com`、`gcaptcha4.gsensebot.com`（[Web 部署](https://docs.geetest.com/BehaviorVerification/deploy/client/web)、[业务容灾](https://docs.geetest.com/BehaviorVerification/BusinessDisasterRecovery)）
- 全站JS第三方上报/图片：默认不允许。系统设置“全站JS允许的上报/图片域名”（`global_js_report_hosts`，https 主机名，最多 20 个）只进 `connect-src` 与 `img-src`。nginx 在返回 `index.html` 前用 `auth_request` 读 `/v1/system-settings/csp-hosts`（外部访问 404），只接受 `https://host ...` 形式；读取失败按默认严格策略返回页面。

- 带页面插件（PA-19 ui_page）：只有本安装已启用（插件安装确认后、授权端仍下发）的 ui_page 插件页面 origin 进 `frame-src`，同一次 `auth_request` 从响应头 `X-Cdnca-Plugin-Ui-Origins` 读取，只接受 `https://host ...`；授权停用 / 卸载后下次同步即撤下。插件页面在 `<iframe sandbox="allow-scripts allow-forms">` 里运行（不给 `allow-same-origin`），读不到宿主 Cookie / localStorage；插件 origin 不进 `script-src` / `connect-src` / `img-src`。

## 1.0.35 测试机验收（真实 CaptchaAppId）

腾讯、极验都没有官方完整 CSP 清单，上面的主机按文档和最小需要整理。上线前在 1.0.35 测试机（Docker 镜像部署）逐项确认：

1. 系统设置 › 用户设置：短信（或邮件）防刷选“腾讯验证码”，填真实 CaptchaAppId 与密钥引用；控制面配置 `ACCOUNT_LOGIN_CAPTCHA_SECRETS_JSON`。给一个测试用户开启短信登录验证码。
2. 用 Chrome 打开用户端登录页，开发者工具 › Console 勾选“保留日志”，Network 过滤 `captcha|gtimg|qcloud`。
3. 输入账号密码 → 发送验证码 → 弹出腾讯验证码，完成滑块/点选，确认验证码发送成功。
4. 检查 Console：不得出现 `Refused to load` / `Content Security Policy` 报错。若有，记下被拦的主机与指令（script-src / img-src / frame-src / connect-src），只补该主机到 `apps/web/nginx.conf` 对应 map 与 `scripts/web-container-static.sh` 的固定值。
5. 在 Network 里确认图片主机是否为 `captcha.gtimg.com`；若实际不用它，从 `script-src` / `img-src` 删除。
6. 防刷改为“极验 v4”（真实 captcha_id/captcha_key），重复第 2–5 步；另在测试机 `/etc/hosts` 把 `gcaptcha4.geetest.com` 指向不可达地址，确认组件切到容灾主机后仍能完成验证且无 CSP 报错，验完恢复。
7. 全站JS：填一段统计代码（如 `<script async src="https://hm.baidu.com/hm.js?..."></script>`），系统设置不填上报域名时 Console 应出现 connect/img 被拦；把 `hm.baidu.com` 加进“全站JS允许的上报/图片域名”后刷新，上报请求放行且无其它 CSP 报错。用 `?safe_mode=1` 确认可停用。
8. 结果写回本文件（日期、版本、被拦主机与处理），并更新 `docs/parity/COMPETITOR-TRACKER.md` 对应条目。
