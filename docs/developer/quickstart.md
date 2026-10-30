# 开发者快速开始

示例只使用占位域名、占位 ID 和环境变量，不包含可用凭据。执行前先从部署方取得
对应入口、身份和最小权限，并以 OpenAPI 确认 operation 当前允许的认证方式。

## Bearer 会话读取当前身份

登录响应结构和 refresh Cookie 以 `control.yaml` 为准。不要把密码写进 shell history；
以下只演示已有 access token 的读取请求：

```sh
curl --fail-with-body \
  --header "Authorization: Bearer ${CDNCA_ACCESS_TOKEN}" \
  "${CDNCA_CONTROL_ORIGIN}/v1/auth/me"
```

保存响应的 `X-Request-ID`。`getCurrentIdentity` 要求 `identity.self.read`。

## API key 调用已允许的 operation

只有 OpenAPI 契约里列出 `cdncaApiKey` 的 operation 接受 API key，覆盖安全策略、URL
鉴权、分析、站点发布、四层转发、错误页、任务等多个分组；当前清单以
[开放接口目录](https://www.cdnca.com/developers/api) 中标“API Key 可调”的接口为准（数字从契约
自动计算），不要按分组推断。以下读取需要 key scope 与所有者实时权限交集包含
`security_policies.read`：

```sh
curl --fail-with-body \
  --header "Authorization: CdncaKey ${CDNCA_API_KEY_ID}.${CDNCA_API_KEY_SECRET}" \
  "${CDNCA_CONTROL_ORIGIN}/v1/security-policies?limit=20"
```

API key secret 只在创建或轮换成功响应中显示一次。不要把完整 header 写入日志、
工单、追踪属性或命令历史；生产调用应从进程内 secret provider 注入。

## 幂等写入

对 OpenAPI 声明 `Idempotency-Key` 的写请求，一次用户动作生成一个稳定 key：

```sh
curl --fail-with-body \
  --request POST \
  --header "Authorization: Bearer ${CDNCA_ACCESS_TOKEN}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: ${CDNCA_IDEMPOTENCY_KEY}" \
  --data-binary @request.json \
  "${CDNCA_CONTROL_ORIGIN}/v1/sites"
```

网络结果未知时保留原正文和原 key 精确重试。不要为同一副作用生成新 key；不要把
密码、token 或资源 secret 编入 key。

## Webhook 验签顺序

Webhook 接收方必须保留原始 bytes，在 JSON 解析之前：

1. 计算原始正文 SHA-256，并与 `X-CDNCA-Webhook-Content-Sha256` 常量时间比较。
2. 严格解码 43 字符无 padding base64url secret 为 32 个 raw bytes；按 `X-CDNCA-Webhook-Key-Id` 选择可用密钥。
3. 使用方法 `POST`、实际规范 escaped path、timestamp、独立 event ID、delivery ID、key ID 和正文摘要重建 v2 HMAC；同时要求 `X-CDNCA-Webhook-Signature-Version: v2`，并常量时间比较 signature。
4. 拒绝超过接收端时间正负 300 秒包含边界窗口的 timestamp。
5. 以 delivery ID 持久去重，再解析 CloudEvents JSON 并确认 header event ID 与正文 `id` 相同；不要把 event ID 和 delivery ID 混为一个键。
6. 只有业务事务成功后返回 `2xx`。

签名输入、请求头、重试分类和固定公开测试向量见
[`plugin-integration.md`](plugin-integration.md)。当前已挂载订阅/测试事件控制 API、加密
secret 轮换和持久测试投递运行时；规范 CloudEvents 正文中的可选 `traceparent` 会在存在时
随原始 bytes 传播。通用领域事件 outbox 已接入，7 类已开放事件见
[`plugin-integration.md`](plugin-integration.md) 第 8.1 节；测试 Webhook 仍只用于验签联调。

## 插件发布者的当前可执行步骤

插件市场已交付：开发者在卖家站（developer.cdnca.com）入驻、登记发布者公钥（ui_page
另登记页面来源）、新建插件、上传签名后的版本；市场审核 worker 预检后按规则进入人工审核或
直接通过，发布后经授权端同步到每个主控的插件市场，客户在主控内购买、安装确认和启用。
官网开发者页（<https://www.cdnca.com/developers>）按 `rule_pack`、`theme`、`provider`、
`external_service`/`ui_page` 给出开发指南，并公开审核规则清单。

尚未交付的是对第三方公开的插件工作负载凭据签发端点：插件服务调用主控 OpenAPI 目前只能用
租户创建并交给你的 API Key（见 [`release-status.md`](release-status.md)）。本地可以先离线校验
manifest、领域事件和扩展目录 Schema：

```sh
pnpm contracts:validate
./scripts/verify-developer-docs.sh
```

插件不得直连平台数据库、读取用户 Cookie、在核心进程或 OpenResty 中执行第三方
代码，也不得索取或保存租户用户的登录会话；API Key 只用于租户授权给你的那些接口。
