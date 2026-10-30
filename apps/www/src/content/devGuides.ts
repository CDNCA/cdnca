// 按类型开发指南（/developers/guides/<slug>）。每页固定 7 节：快速开始 → manifest 示例与字段表 →
// 协议或接口 → 打包与上传字段 → 审核规则 → 版本与兼容 → 本地调试。中英两份逐块对齐
// （devGuides.test.tsx 校验块类型、命令与表格行数一致，并把字段、常量与源码逐项对照）。
// 依据（字段名、上限、常量全部来自代码，不写未实现的能力）：
//   manifest      api/schemas/marketplace/v1/plugin-manifest.schema.json
//   上传          services/market-service/internal/httpapi/plugin_seller.go parseVersionUpload
//                 services/market-service/internal/plugin/version.go UploadVersion / checkEntrypoint
//   审核          services/market-service/internal/review（规则表 generated/review-rules.json）
//   rule_pack     libs/rulepack（pack.go、budget.go）
//   theme         libs/themepack（model.go、tokens.go、static.go、template.go、render.go）
//   provider      libs/entitlement/pluginprovider（pluginprovider.go、wire.go、payment.go、contract.go、fake.go）
//   ui_page       libs/entitlement/pluginui、docs/developer/plugin-integration.md §8.3、examples/plugin-ui-sdk
import type { L } from '../i18n'
import type { Block } from './docs'
import rulePackExample from '../../../../docs/plugins/examples/rulepack.src.json?raw'
import themeExample from '../../../../docs/plugins/examples/theme.json?raw'

const s = (zh: string, en: string): L => ({ zh, en })
const same = (text: string): L => ({ zh: text, en: text })
const row = (...cells: (string | L)[]): L[] => cells.map((c) => (typeof c === 'string' ? same(c) : c))

export const GUIDES_PATH = '/developers/guides'
export const REVIEW_RULES_PATH = '/developers/review-rules'
export const UI_SDK_PATH = '/developers/ui-sdk'

/** 7 节固定标题（顺序即页面顺序）。 */
export const SECTION_TITLES: L[] = [
  s('快速开始', 'Quick start'),
  s('manifest 示例与字段', 'Manifest example and fields'),
  s('协议与接口', 'Protocol and interfaces'),
  s('打包与上传字段', 'Packaging and upload fields'),
  s('审核规则', 'Review rules'),
  s('版本与兼容', 'Versions and compatibility'),
  s('本地调试', 'Local debugging'),
]

export interface Guide {
  slug: string
  /** kinds.json 中的 kind（external_service 页也覆盖 ui_page） */
  kinds: string[]
  title: L
  lead: L
  /** 与 SECTION_TITLES 一一对应的 7 节 */
  sections: Block[][]
  /** 本页适用的审核分析器（审核规则页按它过滤） */
  analyzers: string[]
}

// ---- 共用块 -------------------------------------------------------------------

const signStep = (file: string): Block => ({ cmd: `./cdnca-plugin sign-manifest -key publisher.key -in ${file} -out manifest.signed.json` })

const UPLOAD_COMMON_HEAD = row(s('表单字段', 'Form field'), s('必填', 'Required'), s('内容与校验', 'Content and checks'))

const uploadCommonRows: L[][] = [
  row('manifest', s('是', 'Yes'), s('签名后的 manifest，1 字节到 256 KiB；身份必须是本插件 ID、本命名空间，integrity.key_id 必须是该命名空间 active 的公钥并验签通过', 'The signed manifest, 1 byte to 256 KiB; it must name this plugin and namespace, and integrity.key_id must be an active key of the namespace whose signature verifies')),
  row('configuration_schema', s('是', 'Yes'), s('配置 JSON Schema 文件，1 字节到 64 KiB；SHA-256 必须等于 spec.configuration_schema.sha256', 'The configuration JSON Schema file, 1 byte to 64 KiB; its SHA-256 must equal spec.configuration_schema.sha256')),
  row('changelog_md', s('否', 'No'), s('更新说明 Markdown，最多 65536 字节', 'Release notes in Markdown, at most 65536 bytes')),
  row('channel', s('否', 'No'), s('stable（默认）或 beta', 'stable (default) or beta')),
  row('auto_publish', s('否', 'No'), s('true / false：审核通过后自动上架', 'true / false: publish automatically once approved')),
]

const uploadNotes: Block[] = [
  { p: s('接口：POST /seller/v1/plugins/{id}/versions，Content-Type: multipart/form-data，必须带一个 1–128 字符的 Idempotency-Key 请求头；同一 key 重试返回同一结果。请求体默认上限 200 MiB。除上表与本类型专属字段外，出现任何其他字段名都返回 400 invalid_upload。',
    'Endpoint: POST /seller/v1/plugins/{id}/versions, Content-Type: multipart/form-data, with exactly one Idempotency-Key header of 1–128 characters; a retry with the same key returns the same result. The body limit defaults to 200 MiB. Any field name other than those in the table and the kind-specific ones returns 400 invalid_upload.') },
  { p: s('同一插件的版本号不能重复，且必须高于任何已审核过的版本（已通过、已上架、已隐藏或已下架）。上传成功后版本进入“预检中”，卖家站版本详情显示预检报告。',
    'A plugin version number cannot repeat and must be higher than every reviewed version (approved, published, hidden or delisted). After upload the version is “scanning”; the seller site’s version detail shows the scan report.') },
]

const reviewFlow = (extra: L[]): Block[] => [
  { p: s('上传后审核 worker 先跑“校验”阶段（manifest、入口、权限、本类型专属检查），出现任何拒绝项就不再扫描；再跑“扫描”阶段。结论：有拒绝项 → 需修改（修好后点“重新提交”，每个版本最多 10 次扫描）；有隔离项 → 待人工审核；都没有 → 视下列条件直接通过或进入人工审核。',
    'After upload the review worker runs the validating phase (manifest, entrypoint, permissions, the kind’s own checks); any reject stops it before scanning, then the scanning phase runs. Outcome: a reject → changes requested (fix it and press “Resubmit”, at most 10 scans per version); a quarantine → human review; neither → approved directly or sent to human review under the conditions below.') },
  { list: [
    s('首个版本（该插件还没有任何已审核版本）', 'The first version (the plugin has no reviewed version yet)'),
    s('权限与上一个已审核版本不同（增加或减少）', 'Permissions differ from the last reviewed version (added or removed)'),
    s('高风险类型：module、engine_module、provider', 'Privileged kinds: module, engine_module, provider'),
    s('入驻未满 90 天的卖家（市场默认值，运营可调）', 'Sellers who joined less than 90 days ago (market default, adjustable by the operator)'),
    s('扫描连续 3 次出错', 'Three scan attempts in a row errored'),
    ...extra,
  ] },
  { p: s('满足任一条即进入人工审核。完整规则表（规则 ID、级别、拒绝或隔离、是否试运行）见审核规则页。', 'Any one of them sends the version to human review. The full rule table (rule ID, severity, reject or quarantine, evaluation mode) is on the review rules page.') },
]

const compatBlocks = (extra: Block[]): Block[] => [
  { p: s('metadata.version 是规范 SemVer（不带前导 v），每次上传必须比已审核版本高；同一版本号不能重复上传。', 'metadata.version is canonical SemVer (no leading v); every upload must be higher than the reviewed versions, and a version number cannot be uploaded twice.') },
  { p: s('spec.compatibility.control_api 是 1–8 个以空格分隔的比较式（>=、<=、=、>、<，后接规范 SemVer），总长不超过 128；全部满足才算兼容。不满足的主控不能安装或升级到该版本，已安装的保持最近兼容版本。',
    'spec.compatibility.control_api is 1–8 space-separated comparators (>=, <=, =, >, < followed by canonical SemVer), at most 128 characters; all must hold. A control plane that does not satisfy it cannot install or upgrade to the version; an installed plugin keeps its last compatible version.') },
  { cmd: '"compatibility": {"control_api": ">=1.0.35 <2.0.0"}' },
  { p: s('新版本增加权限时，客户管理员在主控里要重新确认；权限变化的版本一律人工审核。', 'When a new version adds permissions, the customer’s administrator must confirm them again in the control plane; any version whose permissions change goes to human review.') },
  ...extra,
]

// ---- rule_pack ---------------------------------------------------------------

// 示例文件由 market-service review 测试 TestDeveloperGuideExamplesPassReview 编译并跑审核，必须零拒绝项。
const RULE_PACK_EXAMPLE: string = rulePackExample

const RULE_PACK_MANIFEST = `{
  "api_version": "marketplace.cdnca.io/v1",
  "kind": "Plugin",
  "metadata": {
    "id": "acme.dev.sqli-extra",
    "version": "1.0.0",
    "name": {"zh-CN": "SQL 注入加强", "en-US": "SQLi extra"},
    "description": {"zh-CN": "参数注入检测与后台路径拦截"},
    "publisher": {"id": "acme.dev", "name": "Acme", "support_url": "https://acme.example/support"}
  },
  "spec": {
    "categories": ["security_rules"],
    "compatibility": {"control_api": ">=1.0.35 <2.0.0"},
    "entrypoint": {"type": "rule_pack", "path": "rulepack.json", "sha256": "<rulepack.json 的 SHA-256>"},
    "permissions": ["security.rule_packs.provide"],
    "configuration_schema": {"path": "schemas/config.schema.json", "sha256": "<配置 Schema 的 SHA-256>"},
    "supply_chain": {"sbom_sha256": "<SBOM 的 SHA-256>", "provenance_sha256": "<构建来源证明的 SHA-256>"}
  }
}`

const rulePack: Guide = {
  slug: 'rule-pack',
  kinds: ['rule_pack'],
  analyzers: ['metadata', 'entrypoint', 'permissions', 'rulepack'],
  title: s('防护规则包（rule_pack）开发指南', 'Rule pack (rule_pack) guide'),
  lead: s('规则包是数据，不是代码：用节点已有的 WAF / CC / ACL / 挑战规则模型写规则，主控发布前做冲突检测，节点由核心引擎解释执行。',
    'A rule pack is data, not code: write rules in the WAF / CC / ACL / challenge models the edge already runs; the control plane checks conflicts before publishing and the core engine interprets them.'),
  sections: [
    [
      { list: [
        s('在卖家站完成入驻，登记发布者公钥（插件签名工具页有步骤）。', 'Finish onboarding on the seller site and register a publisher key (see the plugin signing page).'),
        s('卖家站“我的插件”新建插件，类型选 rule_pack，插件 ID 为“你的命名空间.名称”（如 acme.dev.sqli-extra）。', 'On the seller site’s “My plugins”, create a plugin of kind rule_pack whose ID is “your namespace.name” (e.g. acme.dev.sqli-extra).'),
        s('按下面的格式写规则包源文件 rulepack.src.json：pack_id 必须是 dev/<命名空间>/<名称>，layer 为 developer，version 与插件版本相同；再用“本地调试”里的编译器输出规范字节 rulepack.json。', 'Write the pack source rulepack.src.json as below: pack_id must be dev/<namespace>/<name>, layer developer, and version equal to the plugin version; then produce the canonical rulepack.json with the compiler in “Local debugging”.'),
        s('把 rulepack.json 的 SHA-256 写进 manifest 的 spec.entrypoint.sha256，签名 manifest，上传版本。', 'Put the SHA-256 of rulepack.json in the manifest’s spec.entrypoint.sha256, sign the manifest and upload the version.'),
      ], ordered: true },
      { cmd: RULE_PACK_EXAMPLE, label: s('rulepack.src.json 示例', 'rulepack.src.json example') },
    ],
    [
      { cmd: RULE_PACK_MANIFEST, label: s('rule_pack manifest 示例（签名前）', 'rule_pack manifest example (before signing)') },
      { table: { head: row(s('字段', 'Field'), s('要求', 'Requirement')), rows: [
        row('spec.entrypoint.type', s('固定 rule_pack；rule_pack 插件只能上传 rule_pack 版本', 'Always rule_pack; a rule_pack plugin only uploads rule_pack versions')),
        row('spec.entrypoint.path', s('规则包文件在包内的相对路径，不能以 / 开头、不能含 ..，不能与配置 Schema 同名，不能是 manifest.json', 'Relative path of the pack file: no leading /, no .., not the configuration schema path and not manifest.json')),
        row('spec.entrypoint.sha256', s('规则包文件（上传的 content）的小写十六进制 SHA-256', 'Lower-case hex SHA-256 of the pack file (the uploaded content)')),
        row('spec.permissions', s('恰好一个：security.rule_packs.provide', 'Exactly one: security.rule_packs.provide')),
        row('spec.provides', s('不能出现', 'Must be absent')),
        row('metadata.version', s('纯 major.minor.patch，数据包不允许预发布或构建后缀', 'Plain major.minor.patch; data packages allow no pre-release or build suffix')),
        row('spec.categories', s('1 个以上，取值 dns_provider、notification_provider、payment_provider、analytics_exporter、automation_connector、security_rules、theme、ui_page', 'One or more of dns_provider, notification_provider, payment_provider, analytics_exporter, automation_connector, security_rules, theme, ui_page')),
        row('spec.supply_chain', s('sbom_sha256、provenance_sha256 两个 SHA-256；授权端同步目录时要求必须有', 'Two SHA-256 values, sbom_sha256 and provenance_sha256; the licence service requires them when it syncs the catalog')),
        row('integrity', s('由 cdnca-plugin sign-manifest 生成，不要手写', 'Written by cdnca-plugin sign-manifest; do not edit by hand')),
      ] } },
    ],
    [
      { p: s('格式 cdnca.rule-pack/v1，字段严格（未知字段、重复键、尾随内容都拒绝），文件最大 1 MiB。', 'Format cdnca.rule-pack/v1 with strict fields (unknown fields, duplicate keys and trailing data are rejected), at most 1 MiB.') },
      { table: { head: row(s('字段', 'Field'), s('说明', 'Meaning')), rows: [
        row('engine', s('waf_v2、acl、cc_v2、challenge、modsecurity 之一（每个规则包只用一种引擎；modsecurity 规则是 CRS 规则集选择）', 'One of waf_v2, acl, cc_v2, challenge, modsecurity (one engine per pack; modsecurity rules select CRS rule sets)')),
        row('engine_min_version', s('不低于规则实际需要的版本、不高于编译器支持的最高版本（waf_v2 / acl / modsecurity 为 1，cc_v2 / challenge 为 6）', 'At least what the rules need and at most what the compiler knows (1 for waf_v2 / acl / modsecurity, 6 for cc_v2 / challenge)')),
        row('rules[]', s('1–256 条（cc_v2 / challenge 最多 128）；id 匹配 ^[a-z0-9][a-z0-9._-]{0,63}$ 且不重复，按 id 顺序执行；每条规则恰好带本引擎的一个规则体（waf、cc 或 crs），waf / cc 字段是节点规则模型本身，rule_id、priority、host、port 由编译器按站点分配，包内留空', '1–256 rules (128 for cc_v2 / challenge); ids match ^[a-z0-9][a-z0-9._-]{0,63}$, unique, run in id order; each rule has exactly the body of the pack’s engine (waf, cc or crs); the waf / cc body is the node rule model itself, and rule_id, priority, host and port are assigned per site by the compiler and stay empty in the pack')),
        row('exports', s('可以被站点单独开关的规则 id（最多 256）', 'Rule ids a site may switch individually (at most 256)')),
        row('params_schema', s('最多 32 个参数，名称 ^[a-z][a-z0-9_]{0,31}$；type 为 integer / string / boolean，可带 minimum、maximum、enum；bind.target 指向规则字段，bind.rules 为空表示全部规则', 'At most 32 parameters named ^[a-z][a-z0-9_]{0,31}$; type integer / string / boolean with optional minimum, maximum, enum; bind.target names the rule field, empty bind.rules means every rule')),
        row('defaults', s('参数默认值', 'Default parameter values')),
      ] } },
      { p: s('预算：单个规则包最多 256 条规则、64 个正则、4096 个代价单位（默认参数和每个参数边界值都要满足）；一个站点所有挂载合计最多 1024 条、256 个正则、16384 单位。正则最长 512 字节，重复次数上限 256。', 'Budget: one pack at most 256 rules, 64 regexes and 4096 cost units (with defaults and at every parameter boundary); all mounts of one site together at most 1024 rules, 256 regexes and 16384 units. A regex is at most 512 bytes with repeats up to 256.') },
      { p: s('规则包只能匹配并拦截、挑战、限速或封禁，不能改写请求、回源或响应，也不能做任何计算。站点管理员在主控把规则包挂到站点，用户层例外先于开发者层规则执行。', 'A rule pack can only match and then block, challenge, rate-limit or ban; it cannot rewrite requests, origins or responses or compute anything. A site administrator mounts the pack in the control plane; user-layer exceptions run before developer-layer rules.') },
    ],
    [
      { table: { head: UPLOAD_COMMON_HEAD, rows: [
        ...uploadCommonRows,
        row('content', s('是', 'Yes'), s('规则包文件本身，1 字节到 8 MiB，SHA-256 等于 spec.entrypoint.sha256；必须是编译器的规范字节（见本地调试）', 'The pack file, 1 byte to 8 MiB, SHA-256 equal to spec.entrypoint.sha256; it must be the compiler’s canonical bytes (see local debugging)')),
        row('package:<platform>', s('不能有', 'Must be absent'), s('rule_pack 版本不带可执行包', 'A rule_pack version carries no executable package')),
      ] } },
      ...uploadNotes,
    ],
    reviewFlow([]).concat([
      { list: [
        s('rulepack.compile_failed / rulepack.budget_exceeded：编译失败或超预算（拒绝）。', 'rulepack.compile_failed / rulepack.budget_exceeded: does not compile or is over budget (reject).'),
        s('rulepack.layer_invalid：pack_id 不是 dev/<你的命名空间>/<名称> 或 layer 不是 developer（拒绝）。', 'rulepack.layer_invalid: pack_id is not dev/<your namespace>/<name> or layer is not developer (reject).'),
        s('rulepack.version_mismatch：规则包 version 与插件版本不同（拒绝）。', 'rulepack.version_mismatch: the pack version differs from the plugin version (reject).'),
        s('rulepack.not_canonical：上传的不是规范字节（拒绝）。', 'rulepack.not_canonical: the upload is not the canonical bytes (reject).'),
        s('rulepack.gate_failed：单独解析不通过发布质量门（拒绝）。', 'rulepack.gate_failed: the pack fails the publication gate on its own (reject).'),
        s('entrypoint.data_pack_permissions / entrypoint.data_pack_version / entrypoint.packages_present / entrypoint.content_mismatch：权限、版本号、多带包或文件摘要不符（拒绝）。', 'entrypoint.data_pack_permissions / entrypoint.data_pack_version / entrypoint.packages_present / entrypoint.content_mismatch: wrong permission, version, extra packages or file digest (reject).'),
      ] },
    ]),
    compatBlocks([
      { p: s('规则包 version 必须等于插件版本。节点按 engine_min_version 判断能否执行；需要 JA4、IP 情报、CRS 模块或 multipart 检测的规则，节点没有对应能力时主控发布前会提示。', 'The pack version must equal the plugin version. Nodes decide by engine_min_version whether they can run it; for rules that need JA4, IP intelligence, the CRS module or multipart inspection, the control plane warns before publishing when nodes lack the capability.') },
    ]),
    [
      { p: s('平台审核、主控和节点用的是同一个编译器 libs/rulepack。规范字节就是 Compile 后的 Canonical：把它写成 rulepack.json 再算 SHA-256。在仓库根目录这样编译你写的 rulepack.src.json，输出规范字节 rulepack.json：', 'Review, the control plane and the edge use the same compiler, libs/rulepack. The canonical bytes are Compile’s Canonical output. From the repository root, compile your rulepack.src.json into the canonical rulepack.json:') },
      { cmd: 'mkdir -p libs/rulepack/cmd/rpc && cat > libs/rulepack/cmd/rpc/main.go <<\'EOF\'\npackage main\n\nimport (\n\t"fmt"\n\t"os"\n\n\t"github.com/cdnca/cdnca/libs/rulepack"\n)\n\nfunc main() {\n\traw, _ := os.ReadFile(os.Args[1])\n\tc, err := rulepack.Compile(raw)\n\tif err != nil {\n\t\tfmt.Fprintln(os.Stderr, err)\n\t\tos.Exit(1)\n\t}\n\tos.WriteFile(os.Args[2], c.Canonical, 0o644)\n\tfmt.Println(c.SHA256, c.Cost.Rules, c.Cost.Regexes, c.Cost.Units)\n}\nEOF\nGOWORK=off go -C libs/rulepack run ./cmd/rpc "$PWD/rulepack.src.json" "$PWD/rulepack.json"', label: s('规范化工具（Go）', 'Canonicalizer (Go)') },
      { p: s('输出依次是规范字节的 SHA-256（填进 spec.entrypoint.sha256）与规则数、正则数、代价单位。编译报错时的信息与审核报告里 rulepack.compile_failed 的 message 相同。', 'It prints the canonical SHA-256 (put it in spec.entrypoint.sha256) followed by rule, regex and cost-unit counts. A compile error reads the same as the rulepack.compile_failed message in the scan report.') },
    ],
  ],
}

// ---- theme ------------------------------------------------------------------

// 同一个 Go 测试用插件 acme.dev.ocean 跑审核。
const THEME_EXAMPLE: string = themeExample

const theme: Guide = {
  slug: 'theme',
  kinds: ['theme'],
  analyzers: ['metadata', 'entrypoint', 'permissions', 'theme'],
  title: s('主题（theme）开发指南', 'Theme (theme) guide'),
  lead: s('主题包是声明式的：设计令牌、品牌图片、布局槽位和无逻辑模板。主控把它渲染成同源的静态 CSS/JSON，不带脚本、不改任何 CSP。',
    'A theme package is declarative: design tokens, brand images, layout slots and logic-less templates. The control plane renders it into same-origin static CSS/JSON; it carries no script and changes no CSP.'),
  sections: [
    [
      { list: [
        s('新建插件，类型选 theme，插件 ID 如 acme.dev.ocean。', 'Create a plugin of kind theme, with an ID such as acme.dev.ocean.'),
        s('写 theme.json：id 必须是 market.<插件 ID>，version 与插件版本相同。', 'Write theme.json: id must be market.<plugin id> and version equal to the plugin version.'),
        s('把 theme.json 的 SHA-256 写进 spec.entrypoint.sha256，权限只写 platform.themes.provide，签名并上传。', 'Put the SHA-256 of theme.json in spec.entrypoint.sha256, declare only platform.themes.provide, sign and upload.'),
      ], ordered: true },
      { cmd: THEME_EXAMPLE, label: s('theme.json 示例', 'theme.json example') },
    ],
    [
      { p: s('manifest 与规则包相同，只有下表这些字段不同。', 'The manifest is the same as for a rule pack except for the fields below.') },
      { table: { head: row(s('字段', 'Field'), s('要求', 'Requirement')), rows: [
        row('spec.entrypoint', s('{"type": "theme", "path": "theme.json", "sha256": "<theme.json 的 SHA-256>"}', '{"type": "theme", "path": "theme.json", "sha256": "<SHA-256 of theme.json>"}')),
        row('spec.permissions', s('恰好一个：platform.themes.provide', 'Exactly one: platform.themes.provide')),
        row('spec.categories', s('通常为 ["theme"]', 'Usually ["theme"]')),
        row('metadata.version', s('纯 major.minor.patch，每段最多 5 位数字', 'Plain major.minor.patch, each part at most 5 digits')),
      ] } },
    ],
    [
      { table: { head: row(s('字段', 'Field'), s('说明', 'Meaning')), rows: [
        row('schema / id / version', s('cdnca.theme/v1；market.<插件 ID>；与插件版本相同', 'cdnca.theme/v1; market.<plugin id>; equal to the plugin version')),
        row('name / description', s('必须有 zh-CN，可加 zh-TW、en-US；名称最多 64 字，说明最多 512 字', 'zh-CN required, zh-TW and en-US optional; name at most 64 characters, description at most 512')),
        row('tokens', s('白名单令牌（颜色、长度、数字、字体栈、阴影），未列出的令牌名一律拒绝；长度与数字有范围，最多两位小数', 'Whitelisted tokens (colors, lengths, numbers, font stacks, shadows); any unlisted token name is rejected; lengths and numbers have ranges and at most two decimals')),
        row('tokens_by_role', s('只对 admin 或 user 控制台覆盖令牌', 'Token overrides for the admin or user console only')),
        row('brand_slots', s('favicon（image/x-icon、image/vnd.microsoft.icon 或 image/png）、logo / logo_dark / app_icon（image/png）、login_ad / login_background（image/jpeg）；body_base64 为标准 base64，每张最多 2 MiB，文件头必须与 MIME 一致', 'favicon (image/x-icon, image/vnd.microsoft.icon or image/png), logo / logo_dark / app_icon (image/png), login_ad / login_background (image/jpeg); body_base64 is standard base64, at most 2 MiB each, and the file magic must match the MIME type')),
        row('layout_slots', s('login_layout：split / centered / background；sidebar：light / dark；可选 look：classic / tech、motion：off / subtle / rich、最多 8 个 header_links（只能 https）、footer_text、user_home_blocks', 'login_layout: split / centered / background; sidebar: light / dark; optional look: classic / tech, motion: off / subtle / rich, up to 8 header_links (https only), footer_text, user_home_blocks')),
        row('templates', s('styles（选择器 + 声明，值可写 token:<令牌名>）、error_page、email；模板只支持 {{name}}、{{#name}}…{{/name}}、{{^name}}…{{/name}}，错误页变量 status、title、message、footer_text，邮件变量 subject、lines（列表）、footer_text', 'styles (selector + declarations; a value may be token:<name>), error_page, email; templates support only {{name}}, {{#name}}…{{/name}}, {{^name}}…{{/name}}; error-page variables are status, title, message, footer_text, email variables subject, lines (a list), footer_text')),
      ] } },
      { p: s('任何字符串里出现 url(、@import、expression(、javascript:、<script、<link、<iframe、<object、<embed、src=、href=、srcset= 都会被拒绝（header_links 的 url 与 base64 图片除外）。主题包最大 8 MiB。', 'Any string containing url(, @import, expression(, javascript:, <script, <link, <iframe, <object, <embed, src=, href= or srcset= is rejected (except header_links urls and base64 images). A theme package is at most 8 MiB.') },
    ],
    [
      { table: { head: UPLOAD_COMMON_HEAD, rows: [
        ...uploadCommonRows,
        row('content', s('是', 'Yes'), s('theme.json 本身，1 字节到 8 MiB，SHA-256 等于 spec.entrypoint.sha256', 'theme.json itself, 1 byte to 8 MiB, SHA-256 equal to spec.entrypoint.sha256')),
        row('package:<platform>', s('不能有', 'Must be absent'), s('theme 版本不带可执行包', 'A theme version carries no executable package')),
      ] } },
      ...uploadNotes,
    ],
    reviewFlow([]).concat([
      { list: [
        s('theme.invalid：不是合法的 cdnca.theme/v1（令牌、槽位、模板、外部引用），detail 里有 code 和 field（拒绝）。', 'theme.invalid: not a valid cdnca.theme/v1 package (tokens, slots, templates, external references); detail carries code and field (reject).'),
        s('theme.id_mismatch：id 不是 market.<插件 ID>（拒绝）。', 'theme.id_mismatch: id is not market.<plugin id> (reject).'),
        s('theme.version_mismatch：主题 version 与插件版本不同（拒绝）。', 'theme.version_mismatch: the theme version differs from the plugin version (reject).'),
      ] },
    ]),
    compatBlocks([
      { p: s('主题 version 必须等于插件版本。客户启用新版本主题后，主控会为所有租户重新发布错误页。', 'The theme version must equal the plugin version. When a customer enables a new theme version, the control plane republishes error pages for every tenant.') },
    ]),
    [
      { p: s('审核用的就是主控的渲染器 libs/themepack 的 Render。在仓库根目录用它预检，报错的 code / field 与审核报告一致：', 'Review runs the control plane’s renderer, libs/themepack Render. Precheck with it from the repository root; the error code / field match the scan report:') },
      { cmd: 'mkdir -p libs/themepack/cmd/thc && cat > libs/themepack/cmd/thc/main.go <<\'EOF\'\npackage main\n\nimport (\n\t"fmt"\n\t"os"\n\n\t"github.com/cdnca/cdnca/libs/themepack"\n)\n\nfunc main() {\n\traw, _ := os.ReadFile(os.Args[1])\n\tr, err := themepack.Render(raw)\n\tif err != nil {\n\t\tfmt.Fprintln(os.Stderr, err)\n\t\tos.Exit(1)\n\t}\n\tfmt.Println(r.Package.ID, r.Package.Version, r.PackageSHA256)\n}\nEOF\nGOWORK=off go -C libs/themepack run ./cmd/thc "$PWD/theme.json"', label: s('主题预检（Go）', 'Theme precheck (Go)') },
      { p: s('官方内置主题 libs/themepack/builtin/*.json 可作为完整写法参考（id 需改成 market.<你的插件 ID>）。', 'The built-in themes in libs/themepack/builtin/*.json show a complete package (change id to market.<your plugin id>).') },
    ],
  ],
}

// ---- provider ---------------------------------------------------------------

const PROVIDER_MANIFEST = `"spec": {
  "categories": ["dns_provider"],
  "compatibility": {"control_api": ">=1.0.35 <2.0.0"},
  "entrypoint": {
    "type": "external_https",
    "base_url": "https://dns.acme.example/api",
    "health_path": "/healthz",
    "provider_response_key": "<响应签名公钥，43 字符 base64url>"
  },
  "provides": [{"kind": "dns", "protocol_version": "1"}],
  "permissions": ["providers.dns.provide"],
  "configuration_schema": {"path": "schemas/config.schema.json", "sha256": "<SHA-256>"},
  "supply_chain": {"sbom_sha256": "<SHA-256>", "provenance_sha256": "<SHA-256>"}
}`

// fake.go ServeHTTP 改写：验签、时间窗、nonce、签名应答。
const PROVIDER_SERVER = `func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// {base_url}/cdnca-provider/v1/{kind}/{action}
	i := strings.Index(r.URL.Path, "/cdnca-provider/v1/")
	kind, action, _ := strings.Cut(r.URL.Path[i+len("/cdnca-provider/v1/"):], "/")
	nonce := r.Header.Get("X-Cdnca-Provider-Nonce")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	ts := r.Header.Get("X-Cdnca-Provider-Timestamp")
	unix, err := strconv.ParseInt(ts, 10, 64)
	sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Cdnca-Provider-Signature"))
	skew := time.Now().Unix() - unix
	msg := "cdnca-provider-request/v1\\n" + r.Header.Get("X-Cdnca-Provider-Installation") + "\\n" + p.PluginID +
		"\\n" + kind + "\\n" + action + "\\n" + ts + "\\n" + nonce + "\\n" + sha256hex(body)
	if i < 0 || err != nil || len(nonce) != 32 || skew > 300 || skew < -300 || p.seen(nonce) ||
		!ed25519.Verify(p.InstallationKey, []byte(msg), sig) {
		p.reply(w, kind, action, nonce, 401, "unauthorized", nil)
		return
	}
	// … 按 kind/action 处理，写操作按 idempotency_key 去重 …
	p.reply(w, kind, action, nonce, 200, "", map[string]any{})
}

func (p *Plugin) reply(w http.ResponseWriter, kind, action, nonce string, status int, code string, data any) {
	env := map[string]any{"protocol": "cdnca.provider/v1", "ok": code == ""}
	if code != "" {
		env["error"] = map[string]string{"code": code}
	}
	if data != nil {
		env["data"] = data
	}
	body, _ := json.Marshal(env)
	msg := "cdnca-provider-response/v1\\n" + p.PluginID + "\\n" + kind + "\\n" + action + "\\n" + nonce + "\\n" + sha256hex(body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Cdnca-Provider-Response-Signature",
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(p.ResponseKey, []byte(msg))))
	w.WriteHeader(status)
	w.Write(body)
}`

const provider: Guide = {
  slug: 'provider',
  kinds: ['provider'],
  analyzers: ['metadata', 'entrypoint', 'permissions', 'package', 'secrets', 'dependencies', 'malware', 'diff'],
  title: s('服务商接口（provider）开发指南', 'Provider (provider) guide'),
  lead: s('provider 是跑在你自己服务器上的 HTTPS 服务，实现 cdnca.provider/v1 协议，为主控提供 DNS、短信、邮件、备案查询或支付通道。主控只按协议签名调用你，你的代码不进主控进程。',
    'A provider is an HTTPS service on your own server implementing cdnca.provider/v1 to give the control plane a DNS, SMS, mail, ICP lookup or payment channel. The control plane calls you with signed requests; your code never runs inside it.'),
  sections: [
    [
      { list: [
        s('新建插件，类型选 provider。', 'Create a plugin of kind provider.'),
        s('生成一对 Ed25519 响应签名密钥，公钥（base64url，无填充，43 字符）写进 provider_response_key；私钥只留在你的服务里。', 'Generate an Ed25519 response key pair; put the public key (unpadded base64url, 43 characters) in provider_response_key and keep the private key in your service.'),
        s('在 base_url 下实现 /cdnca-provider/v1/{kind}/{action}，先实现 verify，再实现本类型的动作。', 'Implement /cdnca-provider/v1/{kind}/{action} under base_url: verify first, then the kind’s actions.'),
        s('沙箱模式（请求体 sandbox=true）只用测试数据回答，不碰客户账户。', 'In sandbox mode (sandbox=true in the body) answer from test data only and never touch a customer account.'),
        s('签名 manifest，上传版本（带至少一个平台包）。客户安装后，主控先对你的沙箱跑一遍安装契约，全部通过管理员才能启用。', 'Sign the manifest and upload the version (with at least one platform package). After a customer installs it, the control plane runs the installation contract against your sandbox; the administrator can enable it only when every case passes.'),
      ], ordered: true },
      { note: s('当前开放：dns、sms、mail、icp、payment。通知渠道（notify）即将开放：manifest 里可以声明、市场审核也接受，但主控目前不会启用 notify，声明后该协议会被忽略；第三方 CDN（cdn）只限官方。',
        'Open now: dns, sms, mail, icp, payment. Notification channels (notify) are coming soon: the manifest may declare it and market review accepts it, but the control plane does not enable notify yet and ignores the declaration; third-party CDN (cdn) is official only.') },
    ],
    [
      { cmd: PROVIDER_MANIFEST, label: s('provider manifest 的 spec 示例', 'provider manifest spec example') },
      { table: { head: row(s('字段', 'Field'), s('要求', 'Requirement')), rows: [
        row('spec.entrypoint.type', s('external_https', 'external_https')),
        row('spec.entrypoint.base_url', s('https、DNS 主机名（不能是 IP 或 localhost）、默认端口，可带路径，不能有查询串、片段或结尾 /', 'https, a DNS host name (no IP literal or localhost), default port, optional path, no query, fragment or trailing /')),
        row('spec.entrypoint.health_path', s('以 / 开头，最多 512 字节', 'Starts with /, at most 512 bytes')),
        row('spec.entrypoint.provider_response_key', s('响应签名公钥，无填充 base64url 43 字符；声明 dns / sms / icp / mail / payment 时必填', 'Response public key, 43 characters of unpadded base64url; required when providing dns / sms / icp / mail / payment')),
        row('spec.provides[]', s('1–8 项，kind 不重复，protocol_version 当前为 "1"；provider 插件必须至少声明一项，其他 kind 不能声明', '1–8 entries with distinct kinds; protocol_version is "1"; a provider plugin declares at least one, other kinds declare none')),
        row('spec.permissions', s('每个 kind 必须带 providers.<kind>.provide（如 providers.dns.provide），缺了整个 manifest 被拒绝', 'Each kind needs providers.<kind>.provide (e.g. providers.dns.provide); without it the manifest is rejected')),
        row('spec.packages', s('列出每个上传的平台包与 SHA-256（当前为试运行规则）', 'Lists every uploaded platform package and its SHA-256 (currently an evaluation rule)')),
      ] } },
    ],
    [
      { p: s('每次调用都是 POST {base_url}/cdnca-provider/v1/{kind}/{action}，请求体 JSON 带 "protocol": "cdnca.provider/v1" 和 "sandbox"，写操作带 idempotency_key（同一个 key 重复调用必须返回第一次的结果、不能重复执行）。请求体最大 256 KiB，应答最大 1 MiB，超时 15 秒。主控只连公网地址、不走代理、不跟随重定向。',
        'Every call is POST {base_url}/cdnca-provider/v1/{kind}/{action} with a JSON body carrying "protocol": "cdnca.provider/v1" and "sandbox"; writes carry idempotency_key (a repeat must return the first result and not apply twice). Requests are at most 256 KiB, answers 1 MiB, timeout 15 s. The control plane connects to public addresses only, without proxies or redirects.') },
      { table: { head: row(s('请求头', 'Header'), s('内容', 'Content')), rows: [
        row('X-Cdnca-Provider-Installation', s('主控编号', 'Control installation ID')),
        row('X-Cdnca-Provider-Timestamp', s('Unix 秒；与你的时钟相差超过 300 秒必须拒绝', 'Unix seconds; reject a skew over 300 s')),
        row('X-Cdnca-Provider-Nonce', s('32 位十六进制；见过的 nonce 必须拒绝', '32 hex characters; reject any nonce seen before')),
        row('X-Cdnca-Provider-Signature', s('安装私钥对请求消息的 Ed25519 签名，无填充 base64url', 'Ed25519 signature of the request message by the installation key, unpadded base64url')),
        row('X-Cdnca-Provider-Response-Signature', s('（应答头）你的响应私钥对应答消息的签名', '(response header) your response key’s signature of the response message')),
      ] } },
      { cmd: 'request  = "cdnca-provider-request/v1\\n" + installation_id + "\\n" + plugin_id + "\\n" + kind + "\\n" + action + "\\n" + timestamp + "\\n" + nonce + "\\n" + hex(sha256(body))\nresponse = "cdnca-provider-response/v1\\n" + plugin_id + "\\n" + kind + "\\n" + action + "\\n" + nonce + "\\n" + hex(sha256(response_body))', label: s('签名消息', 'Signed messages') },
      { p: s('签名、时间戳或 nonce 不对时返回 HTTP 401。其余情况一律 HTTP 200 + 信封 {"protocol":"cdnca.provider/v1","ok":true,"data":{…}}，失败时 {"ok":false,"error":{"code":"…"}}；code 取 invalid_request、unauthorized、not_found、conflict、zone_not_found、rate_limited、quota_exceeded、unavailable、unsupported、provider_error、invalid_signature，其他值按 provider_error 处理。信封不允许多余字段。应答签名绑定了请求 nonce，抓到的应答不能用于别的调用。安装公钥由客户主控管理员在插件详情“安装签名公钥”处复制给你。',
        'Return HTTP 401 for a bad signature, timestamp or nonce. Otherwise always HTTP 200 with the envelope {"protocol":"cdnca.provider/v1","ok":true,"data":{…}}, or {"ok":false,"error":{"code":"…"}} on failure; code is one of invalid_request, unauthorized, not_found, conflict, zone_not_found, rate_limited, quota_exceeded, unavailable, unsupported, provider_error, invalid_signature, anything else counts as provider_error. The envelope allows no extra fields. The response signature binds the request nonce, so a captured answer cannot be replayed. The customer’s administrator copies the installation public key to you from “Installation signing key” on the plugin detail page.') },
      { table: { head: row('kind', s('动作', 'Actions'), s('请求与应答要点', 'Request and answer')), rows: [
        row('dns', 'verify, list_records, create_record, update_record, delete_record', s('记录 {id, name, type, value, ttl, line}，name 为不带结尾点的完整域名，line 为统一线路名（默认/电信/联通/移动/境外）；list 按 zone（可选 name）返回 records；create 返回 id；未知 zone 返回 zone_not_found，删不存在的记录返回 not_found', 'Record {id, name, type, value, ttl, line}: name is the FQDN without trailing dot, line a unified line name (默认/电信/联通/移动/境外); list by zone (optional name) returns records; create returns id; an unknown zone answers zone_not_found, deleting a missing record not_found')),
        row('sms', 'verify, send', s('{to（E.164）, template_id, params, body, idempotency_key} → {delivery_id}；非 E.164 号码返回 invalid_request', '{to (E.164), template_id, params, body, idempotency_key} → {delivery_id}; a non-E.164 number answers invalid_request')),
        row('mail', 'verify, health, send', s('{to（单个地址，不带显示名）, subject, text, html?, reply_to?, idempotency_key} → {message_id}；发件人由你的配置决定；health 表示上游账户当前能发信', '{to (one address, no display name), subject, text, html?, reply_to?, idempotency_key} → {message_id}; the sender is your own configuration; health means your upstream account can send now')),
        row('icp', 'verify, query', s('{domain（小写、punycode 的可注册域名）} → {status: filed | unfiled, licence?, subject?}', '{domain (lower-case punycode registrable domain)} → {status: filed | unfiled, licence?, subject?}')),
        row('payment', 'verify, create_checkout, query_payment, verify_callback, refund, reconcile, sandbox_settle', s('插件只上报支付事实；主控用自己的订单号、商户、整数金额（amount_minor）、币种绑定每个事实，收到通知后先 query_payment 向你确认才入账。create_checkout 返回 action（redirect 或 qr_code）与 url / qr_content；verify_callback 收到主控转来的原始通知字节；reconcile 返回一个 UTC 日的对账单；sandbox_settle 只在沙箱用，模拟网关回调', 'The plugin only reports payment facts; the control plane binds each fact to its own order number, merchant, integer amount (amount_minor) and currency, and confirms a notification by calling query_payment before crediting. create_checkout returns action (redirect or qr_code) with url / qr_content; verify_callback gets the raw notification bytes the control plane received; reconcile returns one UTC day’s statement; sandbox_settle is sandbox-only and simulates the gateway callback')),
      ] } },
      { table: { head: row(s('沙箱固定值', 'Sandbox value'), s('值', 'Value')), rows: [
        row('SandboxZone', 'contract.cdnca-sandbox.test'),
        row('SandboxPhone', '+8613800000000'),
        row('SandboxMailbox', 'contract@cdnca-sandbox.test'),
        row('SandboxFiledDomain / SandboxUnfiledDomain', 'filed.cdnca-sandbox.test / unfiled.cdnca-sandbox.test'),
        row('SandboxMerchant', 'cdnca-sandbox-merchant'),
      ] } },
    ],
    [
      { table: { head: UPLOAD_COMMON_HEAD, rows: [
        ...uploadCommonRows,
        row('package:<platform>', s('是，1–16 个', 'Yes, 1–16'), s('字段名形如 package:linux-amd64，平台名匹配 ^[a-z0-9]+-[a-z0-9_]+$ 且不重复；每个包默认最大 64 MiB，格式为 zip、tar.gz 或 tar', 'Field names like package:linux-amd64; the platform matches ^[a-z0-9]+-[a-z0-9_]+$ and is unique; each package defaults to at most 64 MiB, as zip, tar.gz or tar')),
        row('content', s('不能有', 'Must be absent'), s('external_https 版本没有数据包文件', 'An external_https version has no data file')),
      ] } },
      ...uploadNotes,
    ],
    reviewFlow([s('provider 是高风险类型，每个版本都人工审核', 'provider is a privileged kind: every version gets human review')]).concat([
      { list: [
        s('entrypoint.provides_invalid：provides 格式错、重复或协议版本不对（拒绝）；entrypoint.provides_official_only：声明了 cdn（拒绝）。', 'entrypoint.provides_invalid: provides is malformed, repeated or has a bad protocol version (reject); entrypoint.provides_official_only: cdn declared (reject).'),
        s('package.*：压缩包损坏、zip 炸弹、路径穿越、符号链接、超出条目数（10000）或解压大小（单文件 32 MiB、合计 128 MiB）上限等（拒绝；setuid 位为隔离）。', 'package.*: corrupt archive, zip bomb, path traversal, links, over the entry (10000) or unpacked size limits (32 MiB per file, 128 MiB total) and so on (reject; setuid bits quarantine).'),
        s('secrets.*：包里有私钥、云厂商或代码托管平台的令牌（拒绝）；JWT 与通用凭据赋值目前是试运行。', 'secrets.*: private keys or cloud / code-hosting tokens in the package (reject); JWTs and generic credential assignments are in evaluation mode.'),
        s('malware.detected、dependencies.malicious：病毒或已知恶意依赖（拒绝）。', 'malware.detected, dependencies.malicious: malware or a known malicious dependency (reject).'),
      ] },
      { p: s('审核接受 notify，但主控暂不启用（见快速开始的说明）。', 'Review accepts notify, but the control plane does not enable it yet (see the note in Quick start).') },
    ]),
    compatBlocks([
      { p: s('provides[].protocol_version 当前只有 "1"（cdnca.provider/v1）。安装契约版本是 cdnca.provider-contract/v1，契约版本变化后主控会重新跑契约。', 'provides[].protocol_version is "1" (cdnca.provider/v1). The installation contract is cdnca.provider-contract/v1; when it changes the control plane runs the contract again.') },
    ]),
    [
      { p: s('仓库里的 libs/entitlement/pluginprovider/fake.go（FakePlugin）就是协议服务端的参考实现：验签、时间窗、nonce、幂等、签名应答和沙箱行为都在里面。上面的协议节示例由它改写：', 'libs/entitlement/pluginprovider/fake.go (FakePlugin) in the repository is the reference server: signature, time window, nonce, idempotency, signed answers and sandbox behaviour are all there. This sketch is adapted from it:') },
      { cmd: PROVIDER_SERVER, label: s('服务端骨架（Go，改写自 fake.go）', 'Server skeleton (Go, adapted from fake.go)') },
      { p: s('主控安装时跑的契约用例（RunContract，contract.go）：所有 kind 都有 verify、rejects_bad_signature、rejects_tampered_body、rejects_stale_timestamp、rejects_replayed_nonce；dns 另有 create_a、list_created、create_idempotent、update_a、delete_a、delete_missing_not_found、txt_line、unknown_zone；sms 有 send、send_idempotent、invalid_number；mail 有 health、send、send_idempotent、invalid_recipient；icp 有 filed、unfiled、invalid_domain；payment 有 create_checkout、query_unpaid、sandbox_settle、query_paid、verify_callback、rejects_tampered_callback、refund_idempotent、refund_over_limit、reconcile、unknown_order。本地可以仿照 pluginprovider_test.go 的 newHarness，把 pluginprovider.NewClient 指向你的服务后调用 pluginprovider.RunContract，看到的结果与客户主控一致。',
        'The cases the control plane runs at install time (RunContract, contract.go): every kind has verify, rejects_bad_signature, rejects_tampered_body, rejects_stale_timestamp, rejects_replayed_nonce; dns adds create_a, list_created, create_idempotent, update_a, delete_a, delete_missing_not_found, txt_line, unknown_zone; sms send, send_idempotent, invalid_number; mail health, send, send_idempotent, invalid_recipient; icp filed, unfiled, invalid_domain; payment create_checkout, query_unpaid, sandbox_settle, query_paid, verify_callback, rejects_tampered_callback, refund_idempotent, refund_over_limit, reconcile, unknown_order. Locally, follow newHarness in pluginprovider_test.go: point pluginprovider.NewClient at your service and call pluginprovider.RunContract to get the same result a customer’s control plane will.') },
    ],
  ],
}

// ---- external_service + ui_page -------------------------------------------

const UI_PAGE_ENTRYPOINT = `"entrypoint": {
  "type": "ui_page",
  "origin": "https://ui.acme.example",
  "api_base_url": "https://api.acme.example/v1",
  "pages": [{
    "id": "report", "path": "/report", "mount": "menu", "menu_parent": "monitor",
    "role": "admin", "title": {"zh-CN": "报表", "en-US": "Reports"}, "required_permission": "sites.read"
  }]
},
"permissions": ["platform.ui_pages.provide"]`

const EXTERNAL_ENTRYPOINT = `"entrypoint": {"type": "external_https", "base_url": "https://hooks.acme.example", "health_path": "/healthz"},
"permissions": ["events.site.read", "events.security.read"],
"subscriptions": ["io.cdnca.site.v1.updated", "io.cdnca.security.v1.incident_detected"]`

const externalService: Guide = {
  slug: 'external-service',
  kinds: ['external_service', 'ui_page'],
  analyzers: ['metadata', 'entrypoint', 'permissions', 'ui_page', 'package', 'secrets', 'dependencies', 'malware', 'diff'],
  title: s('外部服务与带页面的插件（external_service / ui_page）开发指南', 'External service and page plugin (external_service / ui_page) guide'),
  lead: s('external_service 是你自己服务器上的 HTTPS 服务，订阅 Webhook 事件、调用开放 API；ui_page 把你自己 origin 上的页面以沙箱 iframe 嵌进主控菜单或站点“扩展”页签。两者的代码都不进主控进程。',
    'An external service is an HTTPS service on your own server that subscribes to webhook events and calls the open API; a ui_page embeds pages from your own origin as sandboxed iframes in a control plane menu or a site’s “Extensions” tab. Neither runs code inside the control plane.'),
  sections: [
    [
      { list: [
        s('external_service：新建插件选 external_service，manifest 入口为 external_https，用 subscriptions 声明要订阅的事件、permissions 声明对应的 events.*.read 权限，上传 1–16 个平台包。', 'external_service: create a plugin of kind external_service with an external_https entrypoint; declare events in subscriptions and the matching events.*.read permissions, and upload 1–16 platform packages.'),
        s('ui_page：先在卖家站“页面来源”登记并验证你的 origin（以及 api_base_url 的 origin）：把 cdnca-plugin-origin=<令牌> 放在 https://<主机>/.well-known/cdnca-plugin-origin.txt。新建插件选 ui_page，上传时不带任何包或文件。', 'ui_page: first register and verify your origin (and the api_base_url origin) on the seller site’s “Page origins”: put cdnca-plugin-origin=<token> at https://<host>/.well-known/cdnca-plugin-origin.txt. Create a plugin of kind ui_page; its versions carry no package or file.'),
        s('调用主控：当前用租户在主控创建并交给你的 API Key（Authorization: CdncaKey <key_id>.<secret>），只能调 OpenAPI 标注“API Key 可调”的接口。对第三方公开的插件工作负载凭据尚未发布。', 'Calling the control plane: use an API key the tenant creates and hands you (Authorization: CdncaKey <key_id>.<secret>), limited to operations marked “API key”. Workload credentials for third parties are not published yet.'),
      ], ordered: true },
    ],
    [
      { cmd: EXTERNAL_ENTRYPOINT, label: s('external_service 的入口与订阅', 'external_service entrypoint and subscriptions') },
      { cmd: UI_PAGE_ENTRYPOINT, label: s('ui_page 的入口', 'ui_page entrypoint') },
      { table: { head: row(s('字段', 'Field'), s('要求', 'Requirement')), rows: [
        row('subscriptions[]', s('最多 64 个事件类型，形如 io.cdnca.site.v1.updated', 'Up to 64 event types such as io.cdnca.site.v1.updated')),
        row('webhooks[]', s('最多 64 个可接收的 Webhook 能力码，每个安装单独批准', 'Up to 64 webhook capability codes, each approved per installation')),
        row('origin', s('https://<DNS 主机名>，默认端口，可带结尾 /；必须是你已验证的页面来源', 'https://<DNS host>, default port, optional trailing /; must be a verified page origin of yours')),
        row('api_base_url', s('可选，https，主控把页面的受限 API 请求代理到这里；其 origin 也必须已验证', 'Optional, https; the control plane proxies the page’s restricted API calls here; its origin must be verified too')),
        row('pages[]', s('1–16 页：id ^[a-z][a-z0-9-]{0,31}$、path（以 / 开头）、mount（menu 或 site_tab）、role（admin 或 user）、title（zh-CN 必填，最多 32 字）', '1–16 pages: id ^[a-z][a-z0-9-]{0,31}$, path (starts with /), mount (menu or site_tab), role (admin or user), title (zh-CN required, at most 32 characters)')),
        row('menu_parent', s('mount=menu 时必填：admin 为 monitor/node/site/stream/config/package/finance/system，user 为 monitor/site/stream/user-package/account；site_tab 不能填', 'Required for mount=menu: admin monitor/node/site/stream/config/package/finance/system, user monitor/site/stream/user-package/account; not allowed for site_tab')),
        row('required_permission / required_module', s('可选的显示门槛（权限码不能是 platform.admin；模块形如 module.xxx、pack.xxx、theme.xxx）', 'Optional display gates (the permission cannot be platform.admin; modules look like module.xxx, pack.xxx, theme.xxx)')),
        row('permissions', s('ui_page 必须包含 platform.ui_pages.provide；ui_page 不能声明 provides', 'A ui_page must include platform.ui_pages.provide and declares no provides')),
      ] } },
    ],
    [
      { h: s('Webhook 事件', 'Webhook events') },
      { p: s('7 类领域事件：部署状态、站点更新、证书状态、证书到期、节点状态、用量阈值、安全事件，每类要求安装获批对应的 events.*.read 权限。投递 POST，Content-Type: application/cloudevents+json，至少一次；可按站点过滤、补发死信、按时间重放。', 'Seven domain events: deployment status, site updates, certificate status, certificate expiry, node status, usage thresholds and security incidents, each needing the installation’s approved events.*.read permission. Delivered as POST with Content-Type: application/cloudevents+json, at least once; per-site filters, dead-letter redelivery and time-based replay are available.') },
      { list: [
        s('先对原始正文算 SHA-256，与 X-CDNCA-Webhook-Content-Sha256 常量时间比较。', 'Hash the raw body with SHA-256 and compare with X-CDNCA-Webhook-Content-Sha256 in constant time.'),
        s('按 X-CDNCA-Webhook-Key-Id 选密钥（43 字符 base64url 解码为 32 字节），重建 v2 HMAC 与 X-CDNCA-Webhook-Signature 比较。', 'Pick the secret by X-CDNCA-Webhook-Key-Id (43-character base64url decoded to 32 bytes), rebuild the v2 HMAC and compare with X-CDNCA-Webhook-Signature.'),
        s('拒绝与本地时间相差超过 300 秒的 X-CDNCA-Webhook-Timestamp。', 'Reject an X-CDNCA-Webhook-Timestamp more than 300 s from your clock.'),
        s('按 delivery ID 去重，再解析 JSON，用事件 ID 做业务幂等；业务成功后才返回 2xx。', 'Deduplicate by delivery ID, then parse JSON and use the event ID for business idempotency; return 2xx only after your transaction succeeds.'),
      ], ordered: true },
      { cmd: 'cdnca.webhook.signature/v2\nPOST\n<canonical-escaped-request-path>\n<timestamp>\n<event-id>\n<delivery-id>\n<secret-version-id>\n<lowercase-hex-sha256-of-raw-body>', label: s('v2 签名输入（LF 分隔，无结尾换行）', 'v2 signature input (LF-separated, no trailing newline)') },
      { h: s('ui_page 协议', 'ui_page protocol') },
      { p: s('页面在 <iframe sandbox="allow-scripts allow-forms"> 里运行（没有 allow-same-origin），拿不到主控的 Cookie、存储和用户凭据。页面从 URL 片段 #cdnca-nonce=<nonce> 读 nonce，向 parent 发 cdnca.hello，宿主回 cdnca.ready 并交出一个 MessagePort；之后只有 context.get、navigate、api.request 三个方法，其他消息回 message_not_allowed。',
        'Pages run in <iframe sandbox="allow-scripts allow-forms"> (no allow-same-origin) without the control plane’s cookies, storage or user credentials. The page reads the nonce from the URL fragment #cdnca-nonce=<nonce>, posts cdnca.hello to parent, and the host answers cdnca.ready with a MessagePort; after that only context.get, navigate and api.request exist, anything else answers message_not_allowed.') },
      { p: s('api.request 经主控 POST /v1/plugin-ui/{plugin_id}/proxy 转到 api_base_url（只连公网、不跟随重定向、只回 JSON、每用户每插件每分钟 120 次）。主控附带 X-Cdnca-Plugin-Context（60 秒有效，含 nonce）、X-Cdnca-Plugin-Signature（安装私钥 Ed25519）与 X-Cdnca-Plugin-Key-Id，你的后端用安装公钥验签并记住 nonce。SDK 与验签示例见 ui_page SDK 页。',
        'api.request goes through the control plane’s POST /v1/plugin-ui/{plugin_id}/proxy to api_base_url (public addresses only, no redirects, JSON only, 120 per user per plugin per minute). The control plane adds X-Cdnca-Plugin-Context (60 s, with a nonce), X-Cdnca-Plugin-Signature (Ed25519 by the installation key) and X-Cdnca-Plugin-Key-Id; your backend verifies with the installation public key and remembers the nonce. See the ui_page SDK page for the SDK and verifier.') },
    ],
    [
      { table: { head: UPLOAD_COMMON_HEAD, rows: [
        ...uploadCommonRows,
        row('package:<platform>', s('external_service：是，1–16 个；ui_page：不能有', 'external_service: yes, 1–16; ui_page: must be absent'), s('平台名匹配 ^[a-z0-9]+-[a-z0-9_]+$；每个包默认最大 64 MiB，格式为 zip、tar.gz 或 tar', 'The platform matches ^[a-z0-9]+-[a-z0-9_]+$; each package defaults to at most 64 MiB, as zip, tar.gz or tar')),
        row('content', s('不能有', 'Must be absent'), s('两种入口都没有数据包文件', 'Neither entrypoint has a data file')),
      ] } },
      ...uploadNotes,
    ],
    reviewFlow([]).concat([
      { list: [
        s('ui_page.declaration_invalid：origin、pages、挂载点、菜单父级、标题或显示门槛不合法，detail 给出 field 与 reason（拒绝）。', 'ui_page.declaration_invalid: origin, pages, mounts, menu parents, titles or gates are malformed; detail gives field and reason (reject).'),
        s('ui_page.origin_unverified：origin 或 api_base_url 不是你验证过的来源（拒绝）。', 'ui_page.origin_unverified: origin or api_base_url is not a verified origin of yours (reject).'),
        s('ui_page.permission_missing / ui_page.artifacts_present：缺 platform.ui_pages.provide，或版本带了包或文件（拒绝）。', 'ui_page.permission_missing / ui_page.artifacts_present: platform.ui_pages.provide missing, or the version carries a package or file (reject).'),
        s('external_service 的平台包与 provider 一样过 package、secrets、dependencies、malware、diff 各项扫描。', 'external_service packages go through the same package, secrets, dependencies, malware and diff scans as providers.'),
      ] },
    ]),
    compatBlocks([
      { p: s('事件类型里的 vN 与 manifest api_version、OpenAPI 版本各自演进；同一事件大版本只增加可选字段。', 'The vN in event types evolves separately from the manifest api_version and the OpenAPI version; one event major version only adds optional fields.') },
    ]),
    [
      { list: [
        s('Webhook：主控“插件 Webhook 订阅”可以发测试事件（io.cdnca.webhook.v1.test）联调验签；仓库 docs/developer/examples/webhook-v2-receiver.md 是可运行的参考接收端。', 'Webhooks: the control plane’s plugin webhook subscription can send a test event (io.cdnca.webhook.v1.test) to exercise your verifier; docs/developer/examples/webhook-v2-receiver.md in the repository is a runnable reference receiver.'),
        s('ui_page：docs/developer/examples/plugin-ui-sdk/ 有框内 SDK、示例页、Node 后端验签和金标向量，node --test 可以直接跑。', 'ui_page: docs/developer/examples/plugin-ui-sdk/ has the in-frame SDK, a sample page, a Node backend verifier and a golden vector; run it with node --test.'),
        s('manifest：仓库 docs/developer/examples/validate-plugin-manifest.mjs 按 schema、扩展目录和兼容矩阵离线校验 manifest 并验签。', 'Manifest: docs/developer/examples/validate-plugin-manifest.mjs in the repository validates a manifest against the schema, extension catalog and compatibility matrix offline and checks its signature.'),
      ] },
      { cmd: 'node --test docs/developer/examples/plugin-ui-sdk/sdk.test.mjs\nnode docs/developer/examples/validate-plugin-manifest.mjs --control-api-version 1.0.35 plugin.json publisher-public-key.json' },
    ],
  ],
}

export const GUIDES: Guide[] = [rulePack, theme, provider, externalService]

/** 每页签名步骤共用的命令（测试校验与 cdnca-plugin usage 一致）。 */
export const GUIDE_SIGN_BLOCK = signStep('manifest.json')
