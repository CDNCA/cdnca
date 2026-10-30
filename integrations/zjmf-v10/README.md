# CDNCA CDN —— 智简魔方 V10 业务系统服务器模块

让智简魔方 V10 业务系统在开通、暂停、解除暂停、删除、续费、升降级商品时自动操作 CDNCA 主控上的 CDN 服务，客户在产品内页一键免密登录 CDN 控制台，并实时查看本周期流量。对应 ADR 0019，`external_system=zjmf_cbap`。老版「财务系统」请用 `cdnca-zjmf.zip`。

实现依据：官方《V10 业务系统开发文档 → 模块开发》，以及官方开源仓库 `idcsmart/ZJMF-CBAP` 10.4.6 的 `ModuleLogic`、`HostModel`、内置模块 `mf_dcim` / `idcsmart_common`。

## 要求

- 智简魔方 V10 业务系统（官方规范 PHP 7.4；已用 `php -l` 检查 7.4 与 8.3），PHP 扩展 `curl`、`json`。
- CDNCA 主控已启用「财务对接」插件并生成对接密钥（见 WHMCS / 老版 README），出口 IP 在白名单内，服务器时间误差 ±300 秒内。

## 安装

1. 解压 `cdnca-zjmf-v10.zip` 到业务系统根目录，得到 `public/plugins/server/cdnca/`。目录名必须是小写 `cdnca`：系统按 `\server\{目录名}\{parse_name(目录名,1)}` 加载，即类 `\server\cdnca\Cdnca`、文件 `Cdnca.php`。
2. 后台 → 商品管理 → 接口管理 → 新增接口：
   | 字段 | 填写 |
   |---|---|
   | 模块 | CDNCA CDN |
   | 地址 | 控制台地址，如 `https://cdn.example.com`（不写协议时按 https） |
   | 用户名 | 对接密钥 key_id（`cbb_` 开头） |
   | 密码 | 对接密钥 secret（`cbs_` 开头，系统加密存储） |
   保存后接口状态显示连接成功即可（`testConnect` → `GET /ping`）。第一次创建本模块接口时会建表 `idcsmart_module_cdnca_product`，删除最后一个接口时删表。
3. 新建商品 → 接口管理：关联上一步的接口（或接口分组），下方出现「CDN 套餐」下拉与月付 / 季付 / 年付售价，选套餐、填要开放的周期售价（留空即不开放），点保存。
4. 商品付费类型选周期付费（不能是一次性 / 免费）。

## 周期映射

V10 的 `host.billing_cycle` 是商品付费类型，周期由 `host.billing_cycle_time`（秒）决定；本模块在计价时只报下面三种周期，因此正常下单只会出现这三种：

| 模块周期 | duration（秒） | 主控 period |
|---|---|---|
| 月付 | 2592000（28–31 天也识别） | `month` |
| 季付 | 7776000（89–92 天） | `quarter` |
| 年付 | 31536000（365–366 天） | `year` |
| 其他时长（如后台改成半年）、付费类型 `onetime` / `free` | — | 不支持，报中文错误 |

## 模块方法

| 方法 | 门面接口 / 说明 |
|---|---|
| `metaData` | `display_name=CDNCA CDN` |
| `afterCreateFirstServer` / `afterDeleteLastServer` | 建 / 删 `idcsmart_module_cdnca_product`（商品 → CDN 套餐、周期售价） |
| `testConnect` | `GET /ping` |
| `createAccount` | `POST /services`；`external_service_id`=host.id、`external_client_id`=host.client_id，客户邮箱必填，重复开通幂等 |
| `suspendAccount` / `unsuspendAccount` | `/suspend`（原因带 `suspend_type`）、`/unsuspend` |
| `terminateAccount` | `/terminate` |
| `renew` | `/renew`，幂等键以新 `due_time` 为参照 |
| `changeProduct` | `/change`，按新商品映射的套餐；`changePackage`（配置项升降级）同样处理（本模块没有配置项） |
| `cartCalculatePrice` / `durationPrice` / `getPriceCycle` | 读商品配置的月 / 季 / 年售价（系统必需） |
| `serverConfigOption` | 后台商品接口配置页（`GET /products` 下拉；拉不到可手填套餐 ID） |
| `clientProductConfigOption` | 前台购买页，只选周期（系统必需，否则不能购买） |
| `hostList` | 前台导航产品列表（系统必需） |
| `clientArea` | 前台产品内页：套餐、状态、到期、本周期流量、登录按钮 |
| `adminArea` / `adminField` / `hostUpdate` | 后台产品内页展示（只读） |

用量：V10 模块规范没有定时用量钩子（`UsageUpdate` 是老版的），所以 `clientArea` 每次打开时实时拉 `GET /usage` 展示，不写库。

## 免密登录

- 路由 `POST /console/v1/cdnca/host/:id/sso`（`route.php`，中间件 `CheckHome` 只做登录验证）。
- 控制器 `controller/home/HostController::sso` → `CdncaLogic::ssoForClient`：必须同时满足「产品存在、未删除、`client_id` 等于当前登录客户（`get_client_id()`）、产品使用本模块、状态为 Active」才调 `POST /sso`；任一不满足统一返回「产品不存在」，不泄露存在性，也不会调用主控。
- 为什么不是 302：V10 前台接口靠请求头 `Authorization: Bearer <localStorage.jwt>` 鉴权（`utils/request.js`），浏览器直接打开链接带不上这个头，会被 `CheckHome` 判为未登录。所以产品内页按钮先同步打开空白窗口，再用 XHR 带 JWT 请求上面的接口，拿到一次性链接（60 秒、一次有效）后让新窗口跳转。

## 常见错误

与老版相同，见 `integrations/zjmf/README.md`「常见错误」。V10 另有：

| 提示 | 处理 |
|---|---|
| 商品未配置 CDN 套餐或售价 | 商品 → 接口管理里选套餐并至少填一个周期售价 |
| CDN 主控不支持该周期 / 付费类型 | 后台改过产品周期或商品为一次性 / 免费；改回月 / 季 / 年周期付费 |
| 客户未填写邮箱 | 客户资料补邮箱后重新开通 |

所有失败写系统日志（`active_log`，类型 `host`，不含密钥），错误文本末尾带 `request_id`。

## 升级

覆盖解压新版 zip 即可，接口与商品配置保留。

## 开发与测试

```bash
php integrations/zjmf-v10/tests/smoke.php   # mock 门面 + 桩 HostModel/ClientModel/ProductModel/ServerModel/Db
integrations/build.sh                       # → integrations/dist/cdnca-zjmf-v10.zip
```

## 待真机核对

- `route.php` 是否被系统自动加载（内置 `mf_dcim` 同样写法），`DIR_ADMIN` 常量在路由文件里可用。
- 前台 `productdetail` 页以 jQuery `.html()` 注入 `clientArea` 内容，模板内 `<script>` 能否执行（按 10.4.6 前端源码应能执行）；移动端主题是否同样。
- 后台商品「接口管理」页注入 `serverConfigOption` 模板的方式，以及模板里 `localStorage.backJwt`、`/{后台目录}/v1` 前缀的取法（照系统 `admin/utils/request.js`）。
- 购买页：`config_options: {duration}` 是否原样作为 `cartCalculatePrice` 的 `custom`；「立即购买」跳 `/cart/settlement.htm` + `sessionStorage.product_information` 的写法（照 `idcsmart_common`）。
- 续费页是否使用 `durationPrice` 返回的三个周期；续费后 `billing_cycle_time` 是否等于所选 duration。
- `suspend_type=overtraffic` 等由系统发起的暂停是否会调到本模块（本模块不发起超流暂停）。
- 子账号（`get_client_parent_id` 钩子）登录时 `get_client_id()` 返回主账号 ID，免密登录按主账号归属判断。
- `lang_plugins` 语言缓存 24 小时：首次安装后若提示显示为键名，清一次系统缓存。
