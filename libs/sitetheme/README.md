# libs/sitetheme

官网主题插件（`cdnca.site-theme/v1`、`cdnca.site-theme/v2`）的解析与校验共享库。市场上传、license 二次验签、主控安装三处都用它，规则只在这里写一份。只做解析和校验，不渲染。

- 包路径：`github.com/cdnca/cdnca/libs/sitetheme`
- 独立 module，不进 `go.work`（与 `libs/themepack` 相同）。使用方在自己的 `go.mod` 里加 `require github.com/cdnca/cdnca/libs/sitetheme v0.0.0` 和 `replace github.com/cdnca/cdnca/libs/sitetheme => ../../libs/sitetheme`；带 Dockerfile 的服务还要 `COPY libs/sitetheme /src/libs/sitetheme`（control-api 已加）。
- 依赖：`libs/edgeconfig`（重复键检测）、`golang.org/x/net/html`。

## 测试

库不在 `go.work` 里，必须加 `GOWORK=off`，否则报 `directory ... is outside module roots`：

```sh
GOWORK=off go -C libs/sitetheme vet ./...
GOWORK=off go -C libs/sitetheme test -count=1 ./...
GOWORK=off go -C libs/sitetheme test -run '^$' -fuzz FuzzParse -fuzztime 30s .
GOWORK=off go -C libs/sitetheme test -run '^$' -fuzz FuzzBundleScan -fuzztime 30s .
```

`scripts/ci-check.sh` 的 `GO_LIBS` 已列入 `libs/sitetheme`，`go-libs` 一项会跑。

## API

```go
type Publisher int // PublisherThirdParty（零值）, PublisherOfficial
type Scope string  // ScopeAdmin "admin", ScopeUser "user", ScopeSite "site"
type ParseOptions struct{ Publisher Publisher }

type Theme struct {
    Schema        string   // SchemaV1 | SchemaV2
    ID, Version   string
    Name          I18nText // 约定之外的补充字段
    Description   I18nText // 同上
    AppliesTo     []Scope  // 规范化为 admin, user, site 的顺序；v1 为 [site]
    Console       []byte   // console_theme 原文（cdnca.theme/v1），交给 themepack.Parse/Render
    Bundle        *Bundle
    AuthStyle     *AuthStyle
    ContentSchema []Field
    Preview       *Image   // 预览图（v1 images.preview / v2 preview），没有为 nil
    V1            *V1Theme // 仅 v1：layout/tokens/images/seed
}
type Bundle struct{ Entry string; Files []File }                 // Entry 默认 "index.html"；Files 按 Path 排序
type File struct{ Path string; SHA256 string; Size int64; Data []byte }
type AuthStyle struct{ CSS string; Images []Image }              // Images 按 Slot 排序，MIMEType 由内容嗅探
type Field struct{ Key string; Type FieldType; Label, Help I18nText; Required bool; MaxLength, MaxItems int; Fields []Field }
type Error struct{ Code, Field string }                          // Code 以 "site_theme." 开头；errors.Is(err, ErrInvalid)

func Parse(raw []byte, opt ParseOptions) (*Theme, error) // v1/v2 都走这里；出错一律是 *Error
func (t *Theme) Allows(s Scope) bool
```

v1 专用（controlsite 用）：`ParseV1(raw) (V1Theme, []Image, error)`、`ValidateContent`、`ValidateSeed`、`ValidHref`、`LayoutTokens`、`LayoutToken`、`ValidToken`、`ValidLayout`、`ValidV1ID`、`SniffImage`、`SafeSVG`。另有 `ValidBundlePath`、`BundleExtensions` 和各个上限常量。

`ParseOptions{}` 的零值就是第三方，调用方忘了设置时按更严的规则处理。`Publisher` 由调用方根据验签结果决定，只有发布者 `io.cdnca` 才能传 `PublisherOfficial`，库本身不验签。

## v2 格式

```json
{
  "schema": "cdnca.site-theme/v2",
  "id": "market.acme.blue",
  "version": "1.0.0",
  "name": {"zh-CN": "…"},
  "description": {"zh-CN": "…"},
  "applies_to": ["user", "site"],
  "console_theme": {"schema": "cdnca.theme/v1", "…": "…"},
  "site_bundle": {"entry": "index.html", "files": [{"path": "index.html", "sha256": "<hex>", "data_base64": "…"}]},
  "auth_style": {"css": "…", "images": {"logo": "<base64>"}},
  "content_schema": [{"key": "hero_title", "type": "text", "label": {"zh-CN": "主标题"}}],
  "preview": "<base64 png/jpeg/webp>"
}
```

未知字段、重复键、尾随数据一律拒绝（`package_json`）。id 和 version 的规则与 v1 相同：id 形如 `official.site-*`、`custom.*`、`market.<plugin id>`，version 为 semver。

## 规则（错误码都省略了 `site_theme.` 前缀）

范围与发布者：
- 第三方的 `applies_to` 只能是 `user+site`、`user`、`site` 三种，顺序随意，不能重复、不能为空。只要含 `admin` 就报 `admin_forbidden`，其他组合报 `applies_to`。
- 官方另外可以用 `admin`、`admin+user`、`admin+user+site`。`admin+site` 不允许。
- 第三方不能使用 `official.*` 开头的 id（v1 也一样），报 `id`。
- 声明了 user 或 admin，就必须带 `console_theme`（`console_theme_required`）；两者都没声明却带了，报 `console_theme_unexpected`。声明了 site 就必须带 `site_bundle`；没声明 site 却带了 `site_bundle` 或 `content_schema`，报 `*_unexpected`。

console_theme：
- 必须是 JSON 对象（`console_theme`），且 `schema == "cdnca.theme/v1"`（`console_theme_schema`）。库不检查其余字段，调用方自己用 `themepack.Parse` 校验、渲染。
- 除非是官方并且声明了 admin，否则不允许出现以下任何一项：`tokens_by_role.admin`（哪怕是空对象）；`scope`、`scopes`、`role`、`roles`、`applies_to` 这几个键（嵌套在任意层都算）下出现 `admin` 这个词；任何字符串里出现 `data-cdnca-role=admin` 选择器（不区分大小写和引号）。第三方报 `admin_forbidden`，官方报 `console_admin`。`administrator`、`sysadmin` 这类自由文本不算。

site_bundle（官方和第三方规则相同）：
- 文件数量 1–2000（`bundle_files`）。路径必须是相对路径，每段只能用 `[A-Za-z0-9._-]`，不能以 `.` 开头，不能有 `.`/`..` 段，不能有空段、`\`、盘符或以 `/` 开头，总长不超过 256（`bundle_path`）。路径按大小写不敏感去重（`bundle_duplicate`）。
- 扩展名白名单（不区分大小写）：html css js mjs json svg png jpg jpeg webp gif ico woff woff2 ttf txt map（`bundle_extension`）。
- `sha256` 必须是 64 位小写 hex（`bundle_sha256`），`data_base64` 必须是严格的标准 base64（`bundle_data`），哈希必须与数据一致（`bundle_sha256_mismatch`）。
- `entry` 默认是 `index.html`，必须是包内存在的 `.html` 文件，大小写也要一致（`bundle_entry`）。
- 文本类文件（html css js mjs json svg txt map）先做归一化再扫描：转小写，并把 `\/`、`\x2f`、`/`、`%2f`、`&#47;`、`&#x2f;`、`&sol;` 统一还原成 `/`。扫描规则：
  - 出现 `/dashboard` → `bundle_dashboard`。只放行三个平台页面，供登录、注册按钮链接：`/dashboard/login`、`/dashboard/register`、`/dashboard/forgot-password`。这三个地址后面可以接 `?query` 或 `#hash`，但不能接下一级路径，也不能有 `/`、`-`、`.`、`%` 之类的后缀。检查在归一化之后进行，所以大小写变体和编码写法照样有效。注意 query 里如果再出现 `/dashboard/...`，会被单独检查（例如 `?next=/dashboard/sites` 会被拒）。`/dashboard`、`/dashboard/`、`/dashboard/sites`、`/dashboard/login/x`、`/dashboard/#/login` 都拒绝。
  - 出现 `/v1`（后面紧跟字母、数字或下划线的除外，比如 `/v10`、`/v1beta`）→ `bundle_api`。只放行两条：恰好是 `/v1/control-site/content`（后面不能再接路径字符），以及 `/v1/control-site/assets/<单段>`（不能含 `/` 或 `..`）。
  - 出现 `serviceworker` → `bundle_service_worker`
  - 出现 `data-cdnca-role=admin` → `bundle_admin`
  - html：出现 `<base` 标签（包括写在脚本字符串里的）→ `bundle_base`；`<script src>`，或 `<link rel=modulepreload>`、`<link as=script>` 的 href 不是同源相对地址（带 scheme、以 `//` 开头、含 `\`）→ `bundle_external_script`；内联 `import ... "https://…"` 也算。
  - js/mjs：同样检查 `<base` 和对外部 URL 的 `import`。
- 二进制文件（png jpg webp gif ico woff woff2 ttf）不扫描，按静态资源对待。外链图片、外链 `<a>`、外链样式表都允许。

auth_style：
- `css` 不超过 256 KiB（`auth_style_size`）。不允许 `\`（防止用转义绕过检查）和控制字符；不允许 `</style`、`<script`、`@import`、`javascript:`、`vbscript:`、`behavior:`、`-moz-binding`，也不允许 `expression(`、`image-set(`、`src(`（括号前有空格也算）。以上都报 `auth_style_css`。
- `url()` 只能指向同源相对路径（不能以 `//` 开头，不能含 `..`），或者 `data:image/(png|jpeg|webp|gif|svg+xml)`；`url()` 外面也不能出现 `://` 或 `"//`（`auth_style_url`）。出现 `data-cdnca-role=admin` 报 `admin_forbidden`。
- `images` 最多 32 张（`auth_style_images`）。slot 规则与 v1 相同（`image_slot`）。图片类型靠内容嗅探，只认 png、jpeg、webp、ico、安全的 svg（`image_body`）。

content_schema：
- 顶层 1–100 个字段，list 内 1–30 个（`content_schema`）。key 格式为 `[a-z][a-z0-9_]{0,63}`（`content_key`），同一层内不能重复（`content_key_duplicate`）。
- type 只能是 text、textarea、richtext、image、link、list（`content_type`）。list 只能嵌套一层，list 里面再放 list 报 `content_nesting`；非 list 字段不能带 `fields`（`content_fields`）。
- `label` 必填，需要 i18n 且必须有 zh-CN；`help` 可选。`max_length` 只能用在文本类字段上，范围 0–20000；`max_items` 只能用在 list 上，范围 0–200。

preview（预览图，主题卡片上的首页截图，可选，v1 与 v2 都支持）：
- v2：顶层 `"preview": "<base64>"`；v1：沿用 `images` 槽位机制，槽名 `preview`（`{mime_type, body_base64}`，声明的类型必须与内容一致）。
- 只认 png、jpeg、webp，按内容嗅探；为空、不是严格 base64、类型不对报 `preview`，超过 512 KiB（`PreviewMaxBytes`）报 `preview_size`。建议 1200×750。
- 解析结果在 `Theme.Preview`（`*Image`，Slot 为 `preview`）；v1 另可用 `V1Preview(images)` 取出。
- `auth_style.images` 不能用 `preview` 槽位名（`image_slot`）：主控把两者存在同一张 `site_theme_images` 表里，按槽位区分。
- 主控只把它当卡片预览，不进官网 `images`、不进定制器、不进登录页样式图片。

体积：
- 整个 content 不超过 8 MiB（`MaxContentBytes`，与 market、license、controlsite 一致），且必须是合法 UTF-8（`package_size`）。单张嵌入图片不超过 2 MiB，预览图不超过 512 KiB。

v1：
- 规则与原来的 `controlsite.ParseTheme` 完全一致：错误码相同（只是多了前缀），字段相同，seed 只能引用本包的 `theme:<slot>`，SVG 安全规则也相同。controlsite 内部的 `ParseTheme` 会去掉前缀再返回 `ThemeValidationError`，所以 HTTP 的 `reason` 保持不变。
