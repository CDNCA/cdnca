# CDNCA CDN —— 智简魔方财务系统（老版）服务器模块

让智简魔方「财务系统」在开通、暂停、解除暂停、删除、续费、升降级时自动操作 CDNCA 主控上的 CDN 服务，客户在会员中心一键免密登录 CDN 控制台，定时同步流量用量。对应 ADR 0019，`external_system=zjmf`。V10 业务系统请用 `cdnca-zjmf-v10.zip`。

## 要求

- 智简魔方财务系统（ThinkPHP 5.1，PHP 7.2 及以上；已用 `php -l` 检查 PHP 7.4 与 8.3），PHP 扩展 `curl`、`json`。
- CDNCA 主控已启用「财务对接」插件，并在「财务对接」页生成对接密钥（代理商：用户后台 → 代理商 → 财务对接；自建主控：管理后台 → 系统 → 财务对接）。
- 生成密钥时把财务系统服务器的出口 IP 加入 IP 白名单；服务器时间误差须在 ±300 秒内。

## 安装

1. 解压 `cdnca-zjmf.zip`，把其中的 `modules/servers/cdnca/` 整个目录上传到财务系统的服务器模块目录，模块名必须是 `cdnca`：
   - 官方文档写的是 `/modules/servers/cdnca/`；
   - 公开的财务系统发行包里服务器模块实际位于 `public/plugins/servers/<模块>/`（如内置 `nokvm`、`bthosts`）。以你系统里 `nokvm` 所在目录为准，放在它旁边。
2. 后台 → 商品设置 → 通用接口 → 接口 → 创建接口：
   | 字段 | 填写 |
   |---|---|
   | 服务器模块 | CDNCA CDN |
   | 主机名 | 控制台域名，如 `cdn.example.com`（也可填完整 `https://cdn.example.com`）；不填主机名时用 IP 地址 |
   | 用户名 | 对接密钥 key_id（`cbb_` 开头） |
   | 密码 | 对接密钥 secret（`cbs_` 开头） |
   | SSL | 勾选（走 HTTPS） |
   | 端口 | 留空或 443；非标准端口照填 |
   `secret` 填在「密码」而不是「访问散列值（accesshash）」：密码列加密存储，accesshash 是明文且只有 50 个字符。
3. 「接口分组」里建一个分组，类型选 CDNCA CDN，把上面的接口加进去。
4. 新建商品 → 模块设置：接口分组选上一步的分组，「CDN 套餐」下拉选择主控上已上架的套餐。下拉只会在至少有一台 CDNCA 接口能连通时出现，否则是文本框，直接填套餐 ID。
5. 商品定价只开放下表支持的付款周期。

代理商模式和自建主控同时用时，建两个接口分组（分别填两把密钥），各自建商品即可。

## 付款周期映射

| 财务系统 billingcycle | 主控 period |
|---|---|
| `monthly`（月付） | `month` |
| `quarterly`（季付） | `quarter` |
| `annually`（年付） | `year` |
| `semiannually`（半年付）、`biennially`（两年）、`triennially`（三年）、`onetime`、`free`、`ontrial`、`hour`、`day` 等 | 不支持，开通 / 续费 / 升降级时报中文错误 |

## 模块行为

| 财务系统动作 | 模块函数 | 门面接口 | 说明 |
|---|---|---|---|
| 测试连接 | `cdnca_TestLink` | `GET /ping` | 文档未列，按内置模块写法实现 |
| 套餐下拉 | `cdnca_ConfigOptions` | `GET /products` | 1 项，`key=product_id` |
| 开通 | `cdnca_CreateAccount` | `POST /services` | `external_service_id`=hostid、`external_client_id`=uid；客户邮箱必填；同一产品重复开通返回同一服务；开通后 CDN 用户名写回 `shd_host.username` |
| 暂停 / 解除暂停 | `cdnca_SuspendAccount` / `cdnca_UnsuspendAccount` | `/suspend`、`/unsuspend` | 暂停原因透传 |
| 删除 | `cdnca_TerminateAccount` | `/terminate` | 客户名下没有其他有效服务时 CDN 账号停用（数据保留） |
| 续费 | `cdnca_Renew` | `/renew` | 幂等键以 nextduedate 为参照，重试不重复续期 |
| 升降级 | `cdnca_ChangePackage` | `/change` | 主控按新旧价自动判断升 / 降级 |
| 状态 | `cdnca_Status` | `GET /services/zjmf/{hostid}` | `active→on`、`suspended→suspend`、`terminated→off` |
| 前台概览选项卡 | `cdnca_ClientArea` + `cdnca_ClientAreaOutput` | `GET /services/...` + `/usage` | 套餐、状态、到期、本周期流量、登录按钮（`templates/overview.html`） |
| 登录 CDN 控制台 | `cdnca_Vnc`；概览页按钮走 `cdnca_LoginConsole` | `POST /sso` | 一次性链接，60 秒有效 |
| 定时用量 | `cdnca_UsageUpdate` | `GET /usage` | 每 100 个一批，写 `shd_host.bwusage`（GB，两位小数）与 `lastupdate` |

免密登录的两个入口：

- `Vnc`（会员中心「控制台」下拉、后台 VNC 按钮）：文档写明「可以返回一个 url，成功会打开该 url」，是财务系统自己负责打开链接的唯一内置入口，所以选它。`ClientButton` 的自定义方法文档没说明返回值怎么处理，不能保证跳转，因此不用。
- 概览页里的「登录 CDN 控制台」按钮：通过 `AllowFunction` 开放 `LoginConsole`，模板里 POST `$MODULE_CUSTOM_API`（`func=LoginConsole`）拿链接后新窗口打开。自定义方法的归属校验不在文档范围内，`cdnca_LoginConsole` 自己比对当前登录用户与产品 `uid`，拿不到登录用户一律拒绝。

失败时返回 `['status'=>'error','msg'=>中文原因]`，并写一条系统日志（`active_log`，不含密钥）。

## 常见错误

| 错误码 | 含义与处理 |
|---|---|
| `unauthorized` / `bridge_unauthenticated`（401） | 鉴权失败：key_id/secret 填错、密钥已吊销或过期、出口 IP 不在白名单、服务器时间偏差超过 300 秒 |
| `entitlement_feature_denied`（403） | 主控未启用财务对接插件 |
| `bridge_service_not_found`（404） | CDN 侧没有这个服务（尚未开通，或不属于这把密钥） |
| `bridge_product_not_found`（404） | 套餐不存在或已下架，重新选择商品的 CDN 套餐 |
| `bridge_service_conflict`（409） | 该产品已用不同参数开通过 |
| `bridge_service_terminated`（409） | 服务已终止，不能再操作 |
| `reseller_change_irreversible`（409） | 代理商升降级订单不可退款 / 作废 |
| `reseller_prepaid_insufficient`（422） | 代理商预付余额不足，先在 CDN 平台充值 |
| `reseller_wholesale_unpriced`（422） | 该套餐此周期没有批发价，联系 CDN 平台 |
| `bridge_validation_error`（400） | 请求参数不合法（如客户邮箱格式） |
| `network_error` | 连不上主控：域名 / 端口 / HTTPS 证书 / 防火墙 |
| `invalid_response` | 主控返回非预期内容（如反代错误页） |
| `client_invalid_argument` | 本地配置错误：未选 CDN 套餐、不支持的付款周期、客户无邮箱 |

错误文本末尾带 `request_id`，反馈给 CDN 平台时请附上。

## 升级

覆盖上传新版 `cdnca/` 目录即可，接口与商品配置保留，无数据库变更。

## 开发与测试

```bash
php integrations/zjmf/tests/smoke.php   # mock 门面 + 桩 $params，走全流程
integrations/build.sh                   # → integrations/dist/cdnca-zjmf.zip
```

## 待真机核对

财务系统核心代码是 ionCube 加密的，以下按官方文档与公开模块（内置 nokvm、bthosts、V10 兼容层 `idcsmart_common/ProvisionLogic`）推断，尚未在真机验证：

- 模块目录：`/modules/servers/cdnca/` 还是 `public/plugins/servers/cdnca/`；`MetaData.HelpDoc` 写的 `/plugins/servers/cdnca/README.md` 能否访问。
- 「测试连接」调用的函数名是否为 `TestLink`（文档未列），以及返回 `['status'=>200,'data'=>['server_status'=>1]]` 的显示效果。
- `ConfigOptions` 下拉：表 `shd_servers` / `shd_server_groups.type='cdnca'` 的查询与 `aesPasswordDecode` 解密是否可用；保存后 `$params['configoptions']['product_id']` 是否取到。
- `UsageUpdate` 的入参形态（数组 / 逗号串都已兼容）、调用频率，以及会员中心是否展示 `bwusage`（单位按内置 nokvm 取 GB）。
- `Vnc` 返回 `url` 后前后台是否都直接打开；`$params['domainstatus']` 是否传入。
- `cdnca_LoginConsole` 读当前登录用户用的是 `request()->uid`（V10 兼容层写法）；老版自定义方法里该值是否存在。拿不到时按钮会提示「无权操作」，此时请改用「控制台 → VNC」入口并反馈。
- 概览模板里 `{$MODULE_CUSTOM_API}`、`{$Think.get.jwt}` 两个变量与 `Authorization: JWT ...` 请求头写法（照 bthosts 模块）。
- `$params['user_info']` 中邮箱、用户名、公司名的键名（按 `shd_clients` 表取 `email`/`username`/`companyname`）。
- `regdate`、`nextduedate` 为时间戳（`shd_host` 表结构如此），用作幂等参照。
