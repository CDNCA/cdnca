// 任务式开发教程（/developers/tutorials/<slug>）：按开发者实际要做的事排序，从入驻到卸载。
// 与按类型开发指南（devGuides.ts）互相引用：教程讲“怎么一步步做”，类型页讲“每类插件的字段与规则”。
// 中英两份逐块对齐（devTutorials.test.tsx 校验块结构一致，并把命令、子命令、参数、上限、路径
// 与 cdnca-plugin / cdnca-site-theme 的 usage、market-service、OpenAPI 生成的接口目录逐项对照）。
// 正文不写源码路径、提交号或内部编号；示例域名用 example.com。
import type { L } from '../i18n'
import type { Block } from './docs'
import { DEV_KIT_FETCH, PLUGIN_CLI_DOWNLOADS } from './pluginSigning'

const s = (zh: string, en: string): L => ({ zh, en })
const same = (text: string): L => ({ zh: text, en: text })
const row = (...cells: (string | L)[]): L[] => cells.map((c) => (typeof c === 'string' ? same(c) : c))

export const TUTORIALS_PATH = '/developers/tutorials'
export const TUTORIAL_API_PATH = `${TUTORIALS_PATH}/api`

export interface TutorialSection {
  /** 页内锚点 */
  id: string
  title: L
  blocks: Block[]
}

export interface Tutorial {
  slug: string
  /** 导航与卡片上的短标题 */
  nav: L
  title: L
  lead: L
  sections: TutorialSection[]
  /** 本篇相关的按类型指南 slug（页尾互链） */
  guides: string[]
}

// ---- 1. 入驻 -----------------------------------------------------------------

const onboarding: Tutorial = {
  slug: 'onboarding',
  nav: s('入驻与团队', 'Onboarding and team'),
  title: s('开发者入驻：账号、身份与团队', 'Developer onboarding: account, identity and team'),
  lead: s('先弄清三个作用域：开发者发布插件，客户管理员在自己的主控里购买、安装和授权，普通用户只使用管理员开放的能力。入驻只解决第一件事。',
    'Three scopes first: developers publish plugins, a customer’s administrator buys, installs and authorises them in their own control plane, and ordinary users only use what the administrator opens. Onboarding covers the first one.'),
  guides: [],
  sections: [
    { id: 'what', title: s('先确定你要交付什么', 'Decide what you deliver'), blocks: [
      { table: { head: row(s('目标', 'Goal'), s('插件类型', 'Plugin kind'), s('代码或文件在哪里运行', 'Where it runs'), s('第一次建议', 'First-time advice')), rows: [
        row(s('改用户控制台或公开网站的外观', 'Restyle the user console or public site'), 'theme', s('主控校验并加载受约束的主题内容', 'The control plane validates and loads constrained theme content'), s('用主题工具生成', 'Start from the theme tool')),
        row(s('提供声明式防护规则', 'Ship declarative protection rules'), 'rule_pack', s('主控按规则模型校验，节点核心引擎解释执行', 'The control plane validates against the rule model; the edge engine interprets it'), s('先确认规则模型支持目标能力', 'Check the rule model supports what you need')),
        row(s('提供独立页面或报表', 'Add a page or report'), 'ui_page', s('你自己的 HTTPS 网站，主控用隔离 iframe 挂载', 'Your own HTTPS site, mounted by the control plane in an isolated iframe'), s('先验证页面来源，再接桥接 SDK', 'Verify the page origin, then add the bridge SDK')),
        row(s('提供 DNS、短信、邮件、备案或支付适配', 'Add a DNS, SMS, mail, ICP or payment adapter'), 'provider', s('你部署的 HTTPS 服务', 'An HTTPS service you deploy'), s('先跑通沙箱契约，再接真实供应商', 'Pass the sandbox contract before wiring a real vendor')),
        row(s('订阅事件或调用开放接口', 'Subscribe to events or call the open API'), 'external_service', s('你部署的 HTTPS 服务', 'An HTTPS service you deploy'), s('明确需要的权限与故障处理', 'Pin down the permissions and failure handling')),
      ] } },
      { p: s('插件类型、清单的 kind 和运行入口是三件事：新建插件时选类型；清单顶层 kind 固定为 Plugin；实际运行方式写在 spec.entrypoint。上传服务包不代表主控会执行其中的程序。',
        'Plugin kind, the manifest kind and the entrypoint are three things: you pick the kind when creating the plugin; the manifest’s top-level kind is always Plugin; how it runs is spec.entrypoint. Uploading a service package does not mean the control plane runs it.') },
      { p: s('第一次发布建议先做免费插件，再加收费方案和外部服务，避免同时排查签名、审核、支付和调用问题。',
        'For a first release ship a free plugin, then add paid plans and external services, so you are not debugging signing, review, payment and calls at once.') },
    ] },
    { id: 'apply', title: s('申请开发者身份', 'Apply for the developer role'), blocks: [
      { list: [
        s('打开开发者平台，用统一授权账号登录。', 'Open the developer platform and sign in with your unified account.'),
        s('完成实名认证；以企业主体入驻时还要完成企业认证。', 'Complete identity verification; an organisation also completes business verification.'),
        s('在“入驻申请”里选择插件开发者，填写卖家名称，阅读并勾选卖家条款、插件开发者条款与隐私政策，点“提交入驻申请”。', 'In “Onboarding”, choose plugin developer, enter the seller name, read and accept the seller terms, plugin developer terms and privacy policy, then click “Submit application”.'),
        s('等待运营审核。未通过时按提示修改后点“修改后重新提交”。', 'Wait for the operator’s review. If it is declined, fix what it says and click “Resubmit”.'),
      ], ordered: true },
      { p: s('怎样确认：左侧菜单出现“我的插件”“页面来源”“发布者公钥”。只是能登录不代表已入驻；入驻前点“我的插件”会提示需要“插件开发者”身份审核通过。',
        'How to confirm: “My plugins”, “Page origins” and “Publisher keys” appear in the menu. Signing in alone is not onboarding; before approval “My plugins” says the plugin developer role must be approved first.') },
    ] },
    { id: 'team', title: s('主账号与团队成员', 'Owner and team members'), blocks: [
      { p: s('主账号负责发布身份：登记发布者公钥、页面来源、公开或隐藏版本、维护定价。团队成员可以参与资料和版本维护；遇到权限提示时由主账号在“团队成员”里核对。',
        'The owner holds the publishing identity: publisher keys, page origins, publishing or hiding versions and pricing. Team members can maintain listings and versions; when they hit a permission message the owner checks “Team members”.') },
      { note: s('不要共享主账号密码，也不要向客户索要其主控的管理员会话或安装私钥。', 'Never share the owner’s password, and never ask a customer for their control plane administrator session or installation private key.') },
    ] },
  ],
}

// ---- 2. 工具与签名 -------------------------------------------------------------

const DL = PLUGIN_CLI_DOWNLOADS

const signing: Tutorial = {
  slug: 'signing',
  nav: s('工具与发布密钥', 'Tools and publisher key'),
  title: s('准备签名工具与发布密钥', 'Set up the signing tool and publisher key'),
  lead: s('cdnca-plugin 是单个离线可执行文件，只处理本地文件，不登录平台、不代替上传与审核。一把发布密钥长期使用，不要每个版本重新生成。',
    'cdnca-plugin is one offline executable that only touches local files: it does not sign in, upload or review. One publisher key is used for the long term; do not create a new one per version.'),
  guides: ['theme', 'rule-pack'],
  sections: [
    { id: 'download', title: s('下载并校验', 'Download and verify'), blocks: [
      { p: s('选择与你的系统对应的文件，同时下载 SHA256SUMS；先只取出目标文件那一行再校验，哈希不一致就停下，不要运行。', 'Pick the file for your system and download SHA256SUMS too; select only the target file’s line, then verify. Stop and do not run it if the hash differs.') },
      { cmd: `CDNCA_DOWNLOADS='${DL}'\nCDNCA_CLI_FILE='cdnca-plugin-linux-amd64'   # ARM64: cdnca-plugin-linux-arm64\ncurl --fail --location --show-error --output "$CDNCA_CLI_FILE" "$CDNCA_DOWNLOADS/$CDNCA_CLI_FILE" &&\ncurl --fail --location --show-error --output SHA256SUMS "$CDNCA_DOWNLOADS/SHA256SUMS" &&\nawk -v name="$CDNCA_CLI_FILE" '$2 == name { print; found=1 } END { if (!found) exit 1 }' SHA256SUMS > SHA256SUMS.selected &&\nsha256sum -c SHA256SUMS.selected &&\nchmod +x "$CDNCA_CLI_FILE" &&\nCDNCA_PLUGIN_CLI="$(pwd -P)/$CDNCA_CLI_FILE"`, label: s('Linux', 'Linux') },
      { cmd: `CDNCA_DOWNLOADS='${DL}'\nCDNCA_CLI_FILE='cdnca-plugin-darwin-arm64'\ncurl --fail --location --show-error --output "$CDNCA_CLI_FILE" "$CDNCA_DOWNLOADS/$CDNCA_CLI_FILE" &&\ncurl --fail --location --show-error --output SHA256SUMS "$CDNCA_DOWNLOADS/SHA256SUMS" &&\nawk -v name="$CDNCA_CLI_FILE" '$2 == name { print; found=1 } END { if (!found) exit 1 }' SHA256SUMS > SHA256SUMS.selected &&\nshasum -a 256 -c SHA256SUMS.selected &&\nchmod +x "$CDNCA_CLI_FILE" &&\nCDNCA_PLUGIN_CLI="$(pwd -P)/$CDNCA_CLI_FILE"`, label: s('macOS（Apple 芯片）', 'macOS (Apple silicon)') },
      { cmd: `$CdncaDownloads = '${DL}'\n$CdncaFile = 'cdnca-plugin-windows-amd64.exe'\nInvoke-WebRequest "$CdncaDownloads/$CdncaFile" -OutFile $CdncaFile -ErrorAction Stop\nInvoke-WebRequest "$CdncaDownloads/SHA256SUMS" -OutFile SHA256SUMS -ErrorAction Stop\n$CdncaSumLines = @(Select-String -Path SHA256SUMS -Pattern '^[a-f0-9]{64}\\s+\\*?cdnca-plugin-windows-amd64\\.exe$')\nif ($CdncaSumLines.Count -ne 1) { throw 'SHA256SUMS has no unique line for this file' }\n$CdncaExpected = ($CdncaSumLines[0].Line -split '\\s+')[0]\nif ((Get-FileHash $CdncaFile -Algorithm SHA256).Hash.ToLower() -ne $CdncaExpected) { throw 'hash mismatch' }\n$CdncaPluginCli = (Resolve-Path $CdncaFile).Path`, label: s('Windows（PowerShell）', 'Windows (PowerShell)') },
      { p: s('后面的命令以 Linux/macOS 为例。Windows 用相同的子命令和参数，在 PowerShell 里写成 & $CdncaPluginCli <子命令> …。子命令：keygen（生成密钥）、pubkey（打印公钥）、sign-challenge（登记公钥时签挑战）、sign-manifest（签清单）、verify（上传前离线验签与文件摘要）；不带参数运行会打印完整用法。出错退出 1，用法错误退出 2。',
        'The commands below use Linux/macOS. On Windows use the same subcommands and flags as & $CdncaPluginCli <subcommand> … in PowerShell. Subcommands: keygen (create a key), pubkey (print the public key), sign-challenge (sign the registration challenge), sign-manifest (sign a manifest) and verify (check the signature and file digests offline before uploading); run it without arguments for the full usage. It exits 1 on failure and 2 on a usage error.') },
    ] },
    { id: 'key', title: s('生成一次发布密钥', 'Create the publisher key once'), blocks: [
      { p: s('私钥放在工程目录之外，不要提交到 Git、上传平台或发给客户。', 'Keep the private key outside your project; never commit, upload or send it.') },
      { cmd: 'CDNCA_KEY_DIR="$HOME/.config/cdnca-publisher"\nmkdir -m 700 -p "$CDNCA_KEY_DIR"\nCDNCA_PUBLISHER_KEY="$CDNCA_KEY_DIR/publisher.key"\n\n"$CDNCA_PLUGIN_CLI" keygen -out "$CDNCA_PUBLISHER_KEY"\n"$CDNCA_PLUGIN_CLI" pubkey -key "$CDNCA_PUBLISHER_KEY"' },
      { p: s('keygen 不会覆盖已有文件，私钥权限为 0600，并在标准输出打印公钥；之后随时可以用 pubkey 再打印。私钥丢失无法恢复，只能登记新公钥，请备份到受控位置。',
        'keygen never overwrites an existing file, writes the key with mode 0600 and prints the public key; pubkey prints it again any time. A lost key cannot be recovered, only replaced by a new registration, so back it up somewhere controlled.') },
    ] },
    { id: 'register', title: s('登记公钥并认领命名空间', 'Register the key and claim a namespace'), blocks: [
      { list: [
        s('卖家站“发布者公钥”→“登记公钥”，填命名空间和上一步的公钥，点“获取待签名内容”。', 'Seller site “Publisher keys” → “Register key”: enter the namespace and the public key, click “Get the message to sign”.'),
        s('复制页面上完整的“待签名内容（base64url）”，原样填进下面命令，不要自行解码或拼接。', 'Copy the whole “Message (base64url)” into the command below as is; do not decode or rebuild it.'),
        s('把输出粘贴到“签名（base64url）”，点“提交登记”。', 'Paste the output into “Signature (base64url)” and click “Register”.'),
      ], ordered: true },
      { cmd: '"$CDNCA_PLUGIN_CLI" sign-challenge \\\n  -key "$CDNCA_PUBLISHER_KEY" \\\n  -message \'<message-from-the-page>\'' },
      { table: { head: row(s('规则', 'Rule'), s('取值', 'Value')), rows: [
        row(s('命名空间', 'Namespace'), s('3–96 个字符，小写字母和数字，用点或连字符分段，例如 com.example', '3–96 characters of lower-case letters and digits, segmented by dots or hyphens, e.g. com.example')),
        row(s('保留命名空间', 'Reserved'), s('io.cdnca 只给平台官方', 'io.cdnca is for the platform only')),
        row(s('挑战有效期', 'Challenge lifetime'), s('15 分钟，只能用一次；过期重新获取', '15 minutes, single use; fetch a new one when it expires')),
        row(s('谁能登记', 'Who can register'), s('只有主账号', 'The owner only')),
      ] } },
      { p: s('工具会先确认这段内容确实是平台为这把公钥签发的挑战，否则拒绝签名，私钥不会被拿去签别的东西。首次登记成功即认领命名空间。怎样确认：公钥列表里出现该命名空间和状态有效的公钥。',
        'The tool first checks the message really is the platform’s challenge for this key and refuses otherwise, so the key cannot be tricked into signing anything else. The first successful registration claims the namespace. How to confirm: the namespace and an active key appear in the list.') },
    ] },
    { id: 'manifest', title: s('给清单签名', 'Sign a manifest'), blocks: [
      { cmd: '"$CDNCA_PLUGIN_CLI" sign-manifest \\\n  -key "$CDNCA_PUBLISHER_KEY" \\\n  -in manifest.json \\\n  -out manifest.signed.json' },
      { list: [
        s('工具把清单规范化、计算摘要，写入 integrity（Ed25519、key_id、payload_sha256、signature）；已有的 integrity 会被替换。', 'The tool canonicalises the manifest, computes the digest and writes integrity (Ed25519, key_id, payload_sha256, signature), replacing any existing one.'),
        s('metadata.publisher.id 必须是你已认领的命名空间，key_id 必须是该命名空间下有效的公钥。', 'metadata.publisher.id must be your claimed namespace and key_id an active key of it.'),
        s('清单只允许对象、数组和字符串，出现数字、布尔值或 null 会报错。这个限制只针对清单，不影响主题、规则或配置模型里模型允许的数字和布尔值。', 'A manifest may only contain objects, arrays and strings; numbers, booleans or null are rejected. This applies to the manifest only, not to numbers and booleans the theme, rule or configuration models allow.'),
        s('签名后再改清单任何字段都要重新签名。签名只证明发布者和字节完整，不代替内容扫描和功能测试。', 'Any change after signing needs a new signature. A signature proves publisher and byte integrity only; it does not replace scanning or testing.'),
      ] },
      { p: s('上传前用 verify 离线核对：签名是否对得上这把公钥，以及配置 Schema、数据文件的摘要是否与清单一致（没有的文件省略对应参数）。它不检查公钥在平台上是否已登记有效，也不代替平台预检和审核。',
        'Before uploading, check offline with verify: the signature matches this key, and the configuration schema and data file digests match the manifest (omit the flag for a file you do not have). It does not check that the key is registered and active on the platform, and does not replace the platform pre-check or review.') },
      { cmd: '"$CDNCA_PLUGIN_CLI" verify \\\n  -in manifest.signed.json \\\n  -pubkey "$("$CDNCA_PLUGIN_CLI" pubkey -key "$CDNCA_PUBLISHER_KEY")" \\\n  -schema config.schema.json \\\n  -content content.json' },
    ] },
  ],
}

// ---- 3. 制作插件 ----------------------------------------------------------------

const build: Tutorial = {
  slug: 'build',
  nav: s('制作第一个插件', 'Build your first plugin'),
  title: s('制作插件：先做一个主题，再扩展到其他类型', 'Build a plugin: a theme first, then other kinds'),
  lead: s('以主题为例走完“新建插件 → 生成工程 → 预检预览 → 打包签名”，再看其他类型的清单与上传文件有什么不同。',
    'Walk through “create plugin → generate project → check and preview → pack and sign” with a theme, then see how other kinds differ in manifest and upload files.'),
  guides: ['theme', 'rule-pack', 'provider', 'external-service'],
  sections: [
    { id: 'create', title: s('在卖家站新建插件', 'Create the plugin on the seller site'), blocks: [
      { p: s('“我的插件”→“新建插件”，类型选 theme，插件 ID 用已认领命名空间下的名字，例如 com.example.ocean，填写中文名称和简介。插件 ID 与类型创建后不能修改；ID 标识产品，不要把版本号写进 ID，后续 1.0.0、1.0.1 都用同一个 ID。此时先不加价格、不公开。',
        '“My plugins” → “Create plugin”: kind theme, an ID under your claimed namespace such as com.example.ocean, plus a Chinese name and summary. ID and kind cannot change later; the ID names the product, so keep version numbers out of it — 1.0.0 and 1.0.1 share one ID. Do not add prices or publish yet.') },
    ] },
    { id: 'kit', title: s('取得主题工具', 'Get the theme tool'), blocks: [
      { p: s('主题工具 cdnca-site-theme 在开发套件 cdnca-dev-kit.tar.gz 里，与签名工具同站下载，零依赖，需要 Node.js 20 或更高。套件与主控同版本发布，还带示例主题、页面插件 SDK、Webhook 接收器示例和服务商协议参考实现；先核对哈希再解包，VERSION 是它对应的主控版本。',
        'The theme tool cdnca-site-theme is in the developer kit cdnca-dev-kit.tar.gz, downloaded from the same site as the signing tool. It has no dependencies and needs Node.js 20 or later. The kit ships with each control plane version and also carries the sample themes, the page plugin SDK, the webhook receiver example and the provider protocol reference; check the hash before unpacking, and VERSION names the control plane version it matches.') },
      { cmd: DEV_KIT_FETCH, label: s('下载、校验并解包（macOS 把 sha256sum -c 换成 shasum -a 256 -c）', 'Download, verify and unpack (on macOS use shasum -a 256 -c instead of sha256sum -c)') },
      { cmd: 'cd packages/site-theme-kit &&\nnode --test test/kit.test.mjs test/entrypoint.test.mjs &&\nCDNCA_THEME_TOOL="$(pwd -P)/bin/cdnca-site-theme.mjs"', label: s('在 cdnca-dev-kit 目录里进入主题工具、自测并记下工具路径', 'In cdnca-dev-kit, enter the theme tool, self-test and note the tool path') },
    ] },
    { id: 'init', title: s('生成工程', 'Generate the project'), blocks: [
      { cmd: 'node "$CDNCA_THEME_TOOL" init "$PWD/ocean" \\\n  --template user+site \\\n  --plugin-id com.example.ocean \\\n  --name Ocean\n\ncd ocean' },
      { p: s('把示例 ID 换成你新建的插件 ID，--name 可以直接写中文名称。user+site 同时生成用户控制台与公开网站主题，只要其一时用 user 或 site。目标目录必须为空。', 'Replace the sample ID with yours; --name may be a Chinese name. user+site generates both the user console and public site themes; use user or site for just one. The target directory must be empty.') },
      { table: { head: row(s('文件', 'File'), s('用途', 'Purpose')), rows: [
        row('theme.config.json', s('主题基本设置与打包配置', 'Theme settings and packing configuration')),
        row('console-theme.json', s('用户控制台主题（user 模板）', 'User console theme (user template)')),
        row('site/index.html, site/assets/', s('公开网站模板与资源（site 模板）', 'Public site template and assets (site template)')),
        row('auth/auth.css', s('登录等认证页样式', 'Sign-in page styles')),
        row('content-schema.json, preview/content.json', s('网站内容字段约束与本地预览内容（site 模板）', 'Site content schema and local preview content (site template)')),
        row('plugin.manifest.json', s('插件声明与发布者资料', 'Plugin declaration and publisher details')),
        row('schemas/config.schema.json', s('客户可填写的配置字段', 'Fields the customer can configure')),
        row('supply-chain/', s('SBOM 与构建来源材料', 'SBOM and build provenance')),
      ] } },
      { p: s('修改 plugin.manifest.json 里的发布者名称、支持地址和中文说明。supply-chain/ 应反映真实依赖和构建来源，模板里的示例值不能代替真实声明。', 'Edit the publisher name, support URL and Chinese description in plugin.manifest.json. supply-chain/ must describe your real dependencies and build; the sample values are not a declaration.') },
    ] },
    { id: 'preview', title: s('预检与本地预览', 'Check and preview locally'), blocks: [
      { cmd: 'node "$CDNCA_THEME_TOOL" check\nnode "$CDNCA_THEME_TOOL" preview' },
      { p: s('check 通过时打印“预检通过（N 字节）”，有问题逐条列出代码与字段并退出 1。preview 默认监听 127.0.0.1:4173（--port 可改），终端会打印访问地址并一直运行，按 Ctrl+C 退出。加 --screenshot 会截首屏生成预览图后退出。本地预览只看内容与样式；登录、安装授权、真实数据和客户权限要在主控里另行验证。',
        'check prints “预检通过 (N bytes)” on success and lists each problem with code and field, exiting 1. preview listens on 127.0.0.1:4173 by default (--port changes it), prints the address and keeps running until Ctrl+C. --screenshot captures the first screen as the preview image and exits. Local preview covers content and style only; sign-in, installation, real data and customer permissions are verified in a control plane.') },
    ] },
    { id: 'pack', title: s('打包并签名', 'Pack and sign'), blocks: [
      { cmd: 'node "$CDNCA_THEME_TOOL" pack \\\n  --version 1.0.0 \\\n  --sign \\\n  --key "$CDNCA_PUBLISHER_KEY" \\\n  --cdnca-plugin "$CDNCA_PLUGIN_CLI"' },
      { p: s('pack 计算内容、配置模型和供应链材料的摘要写进清单，再调用 cdnca-plugin sign-manifest。上传时用 dist/ 下这三个文件：', 'pack writes the digests of content, configuration schema and supply-chain files into the manifest, then calls cdnca-plugin sign-manifest. Upload these three files from dist/:') },
      { list: [
        s('dist/manifest.signed.json：已签名清单', 'dist/manifest.signed.json: the signed manifest'),
        s('dist/schemas/config.schema.json：客户配置模型', 'dist/schemas/config.schema.json: the configuration schema'),
        s('dist/theme.json：主题内容', 'dist/theme.json: the theme content'),
      ], ordered: true },
      { p: s('怎样确认：终端依次打印 content、schema、manifest 和 signed 四行，三个文件都在，签名清单里的插件 ID、版本、发布者和兼容范围（模板默认 >=1.0.35 <2.0.0）符合预期。只看退出码不够，一定要核对这几行和文件。缺预览图只提示不报错，但仍建议在工程根目录放 preview.webp（1200×750，不超过 512 KiB）。',
        'How to confirm: the terminal prints the content, schema, manifest and signed lines, the three files exist, and the signed manifest shows the expected plugin ID, version, publisher and compatibility range (template default >=1.0.35 <2.0.0). The exit code alone is not enough; check those lines and files. A missing preview image is only a notice, but put a preview.webp (1200×750, up to 512 KiB) in the project root anyway.') },
      { note: s('不要把整个工程目录压缩上传，也不要只改 dist/ 里的文件；改源文件后重新 check 和 pack，否则摘要与签名会对不上。', 'Do not upload a zip of the project and do not edit files in dist/; change the sources and run check and pack again, or digests and signature will not match.') },
    ] },
    { id: 'others', title: s('其他类型：清单与上传文件', 'Other kinds: manifest and upload files'), blocks: [
      { p: s('不用主题工具的类型按插件清单 schema 手写清单，再用 sign-manifest 签名。清单至少包含：', 'Kinds without the theme tool use a hand-written manifest per the plugin manifest schema, then sign-manifest. A manifest needs at least:') },
      { table: { head: row(s('部分', 'Part'), s('要确认的内容', 'What to check')), rows: [
        row('api_version, kind', s('marketplace.cdnca.io/v1 与 Plugin', 'marketplace.cdnca.io/v1 and Plugin')),
        row('metadata', s('插件 ID、不带 v 的规范 SemVer、中文名称与简介、发布者 ID/名称/支持地址', 'Plugin ID, canonical SemVer without a leading v, Chinese name and summary, publisher ID/name/support URL')),
        row('spec.compatibility.control_api', s('兼容的主控版本范围', 'Compatible control plane versions')),
        row('spec.entrypoint', s('与插件类型相符的唯一入口', 'The single entrypoint that matches the kind')),
        row('spec.permissions', s('实际需要的最小权限', 'The minimum permissions actually needed')),
        row('spec.configuration_schema', s('配置模型的相对路径与 SHA-256', 'Relative path and SHA-256 of the configuration schema')),
        row('spec.supply_chain', s('真实 SBOM 与构建来源材料的 SHA-256', 'SHA-256 of the real SBOM and provenance')),
        row('integrity', s('由 sign-manifest 写入，不要手写', 'Written by sign-manifest; do not edit')),
      ] } },
      { table: { head: row(s('入口类型', 'Entrypoint'), s('上传的文件', 'Files to upload')), rows: [
        row('theme, rule_pack', s('已签名清单、配置模型、内容文件（content）', 'Signed manifest, configuration schema, content file')),
        row('ui_page', s('只有已签名清单和配置模型；页面放在你已验证的 HTTPS 来源上', 'Signed manifest and configuration schema only; pages live on your verified HTTPS origin')),
        row('external_https', s('已签名清单、配置模型、1–16 个平台包（字段 package:<平台>，如 package:linux-amd64）', 'Signed manifest, configuration schema, 1–16 platform packages (field package:<platform>, e.g. package:linux-amd64)')),
      ] } },
      { p: s('上限：清单 256 KiB，配置模型 64 KiB，主题与规则内容 8 MiB，单个平台包默认 64 MiB，整个上传请求默认 200 MiB。平台包是 zip、tar.gz 或 tar，不能含越界路径、符号链接等不安全条目。每类插件的完整字段、协议与审核规则见对应的按类型开发指南。',
        'Limits: manifest 256 KiB, configuration schema 64 KiB, theme and rule content 8 MiB, one platform package 64 MiB by default, a whole upload 200 MiB by default. Packages are zip, tar.gz or tar without path traversal, links or other unsafe entries. Each kind’s full fields, protocol and review rules are in its guide.') },
    ] },
  ],
}

// ---- 4. 本地联调 ----------------------------------------------------------------

const integrate: Tutorial = {
  slug: 'integrate',
  nav: s('本地联调', 'Local integration'),
  title: s('本地联调：服务商、页面与 Webhook', 'Local integration: providers, pages and webhooks'),
  lead: s('主题和规则包能在本地预检；带服务的插件要先在本地把协议、签名与幂等跑通，再交给客户在主控里安装。四类凭据互不替代，先分清楚。',
    'Themes and rule packs are prechecked locally; plugins with a service must get protocol, signatures and idempotency right locally before a customer installs them. Four kinds of credential exist and none replaces another.'),
  guides: ['provider', 'external-service'],
  sections: [
    { id: 'credentials', title: s('四类凭据', 'Four credentials'), blocks: [
      { table: { head: row(s('用途', 'Purpose'), s('私密部分谁保管', 'Who keeps the secret'), s('对方需要什么', 'What the other side needs')), rows: [
        row(s('清单签名', 'Manifest signature'), s('开发者离线保管发布私钥', 'The developer, offline'), s('平台登记的发布者公钥', 'The publisher key registered with the platform')),
        row(s('主控调用插件的请求签名', 'Requests from the control plane'), s('客户主控保管安装私钥', 'The customer’s control plane (installation key)'), s('客户管理员交给你的安装公钥', 'The installation public key the administrator gives you')),
        row(s('插件的响应签名', 'Plugin response signature'), s('开发者服务保管响应私钥', 'Your service (response key)'), s('清单里声明的 provider_response_key', 'provider_response_key in the manifest')),
        row(s('Webhook 消息认证', 'Webhook messages'), s('双方各自保管订阅 secret', 'Both sides keep the subscription secret'), s('按 key ID 选用的 HMAC secret', 'The HMAC secret picked by key ID')),
      ] } },
      { p: s('安装公钥只能由客户管理员经可信渠道交给你：主控插件详情页“安装签名公钥”给出公钥和 key ID。不要信任请求里随附的公钥，也不要向客户索要安装私钥。', 'Only the customer’s administrator hands you the installation public key, over a trusted channel: the plugin detail page’s “Installation signing key” shows the key and its key ID. Never trust a key carried in a request and never ask for the installation private key.') },
    ] },
    { id: 'provider', title: s('服务商插件：先过沙箱契约', 'Provider plugins: pass the sandbox contract first'), blocks: [
      { p: s('第三方可接入的类型为 dns、sms、mail、icp、payment；notify 可以声明但主控暂不启用，cdn 只限官方。主控调用 POST {base_url}/cdnca-provider/v1/{kind}/{action}，请求体最大 256 KiB，响应最大 1 MiB，超时 15 秒，只连公网 HTTPS，不走代理、不跟随重定向。',
        'Third parties can provide dns, sms, mail, icp and payment; notify can be declared but is not enabled yet, and cdn is official only. The control plane calls POST {base_url}/cdnca-provider/v1/{kind}/{action}: request up to 256 KiB, response up to 1 MiB, 15 s timeout, public HTTPS only, no proxy, no redirects.') },
      { cmd: 'POST /cdnca-provider/v1/dns/verify HTTP/1.1\nHost: provider.example.com\nContent-Type: application/json\nX-Cdnca-Provider-Installation: <installation-id>\nX-Cdnca-Provider-Timestamp: <unix-seconds>\nX-Cdnca-Provider-Nonce: <32-hex>\nX-Cdnca-Provider-Signature: <base64url-ed25519>\n\n{"protocol":"cdnca.provider/v1","sandbox":true}', label: s('请求形态（签名由安装身份生成）', 'Request shape (signed by the installation)') },
      { cmd: '{"protocol":"cdnca.provider/v1","ok":true,"data":{}}', label: s('成功响应（同时带 X-Cdnca-Provider-Response-Signature）', 'Success (with X-Cdnca-Provider-Response-Signature)') },
      { list: [
        s('签名错误、时间差超过 300 秒或 nonce 重复：返回 HTTP 401。', 'Bad signature, a skew over 300 s or a repeated nonce: HTTP 401.'),
        s('其他业务失败：HTTP 200 加协议错误信封，例如 {"protocol":"cdnca.provider/v1","ok":false,"error":{"code":"unavailable"}}。', 'Other failures: HTTP 200 with the error envelope, e.g. {"protocol":"cdnca.provider/v1","ok":false,"error":{"code":"unavailable"}}.'),
        s('写操作的 idempotency_key 要持久保存，同一个键重复到达返回第一次的结果；网络层 nonce 每次都换，业务幂等键在同一操作的重试中保持不变。', 'Persist the idempotency_key of writes and return the first result on a repeat; the network nonce changes every call while the business key stays the same across retries of one operation.'),
        s('sandbox=true 只用沙箱数据：不发真实短信邮件、不改客户 DNS、不扣款。', 'sandbox=true uses sandbox data only: no real SMS or mail, no customer DNS change, no charge.'),
      ] },
      { p: s('协议参考实现和契约测试在开发套件里（参考服务端 FakePlugin、主控侧客户端与安装契约 RunContract，只依赖 Go 标准库；目录与自测命令见套件 README）。本地契约测试用你自己生成的沙箱安装身份，把客户端指向你的测试服务后跑完整契约，检查签名、篡改、时间窗、重复 nonce、幂等及各类型业务用例。客户安装时主控会对你的服务再跑一次安装契约，全部通过才能启用，只让健康检查返回 200 不够。签名消息格式、各动作字段和沙箱固定值见服务商接口指南。',
        'The reference server and contract tests are in the developer kit (reference server FakePlugin, the control plane client and the installation contract RunContract; standard library only; the kit README lists the directory and self-test command). For a local contract run, use a sandbox installation identity you generate yourself, point the client at your test service and run the full contract: signatures, tampering, time window, repeated nonce, idempotency and each kind’s business cases. When a customer installs, the control plane runs the installation contract against your service again and enables it only if everything passes; a 200 health check is not enough. Signed message formats, action fields and sandbox values are in the provider guide.') },
    ] },
    { id: 'ui', title: s('带页面的插件：来源、SDK 与后端验签', 'Page plugins: origin, SDK and backend verification'), blocks: [
      { list: [
        s('部署页面的 HTTPS 域名；有后端时再准备 API 域名。', 'Deploy the page on an HTTPS domain, plus an API domain if you have a backend.'),
        s('卖家站“页面来源”→“登记来源”，按页面提示把 cdnca-plugin-origin=<令牌> 原样放到该来源的 /.well-known/cdnca-plugin-origin.txt，点“验证”。origin 和 api_base_url 所属来源都要验证。', 'Seller site “Page origins” → “Register origin”, put cdnca-plugin-origin=<token> as shown at /.well-known/cdnca-plugin-origin.txt on that origin and click “Verify”. Both the page origin and the api_base_url origin must be verified.'),
        s('清单 spec.entrypoint 写 ui_page 入口，权限加 platform.ui_pages.provide，签名后只上传签名清单和配置 Schema；页面源码留在你的 origin 上，不上传数据文件、页面源码或平台包。', 'Write the ui_page entrypoint in spec.entrypoint, add platform.ui_pages.provide, sign it and upload only the signed manifest and the configuration schema; your pages stay on your origin, so upload no data file, page source or platform package.'),
      ], ordered: true },
      { cmd: '{\n  "type": "ui_page",\n  "origin": "https://ui.example.com",\n  "api_base_url": "https://api.example.com/v1",\n  "pages": [\n    {\n      "id": "reports",\n      "path": "/reports",\n      "mount": "menu",\n      "menu_parent": "monitor",\n      "role": "user",\n      "title": {"zh-CN": "报表"}\n    }\n  ]\n}', label: s('spec.entrypoint 片段', 'spec.entrypoint fragment') },
      { p: s('来源必须是公网 HTTPS、默认端口、不跟随重定向；同一来源只属于一个发布者。页面在隔离 iframe 里运行，拿不到主控的 Cookie、存储和父页面 DOM。SDK 的 connect() 完成握手后只有 context()、navigate() 和 request() 三个能力；request 只转发到你自己的 api_base_url，每用户每插件每分钟最多 120 次。直接单独打开页面拿不到主控上下文，要在已安装并挂载的主控里测试。',
        'Origins must be public HTTPS on the default port without redirects, and belong to one publisher. Pages run in an isolated iframe without the control plane’s cookies, storage or parent DOM. After connect() the SDK offers only context(), navigate() and request(); request forwards only to your own api_base_url, at most 120 per user per plugin per minute. Opening the page on its own gets no context; test it mounted in a control plane where it is installed.') },
      { p: s('后端用安装公钥验证 X-Cdnca-Plugin-Context（base64url JSON，60 秒有效，含 nonce）、X-Cdnca-Plugin-Key-Id 与 X-Cdnca-Plugin-Signature，并记住 nonce 防重放；多副本服务要用共享存储保存 nonce，还要检查上下文里的租户、插件与业务资源。SDK 源码、后端验签示例和固定向量都在 ui_page SDK 页公开。',
        'Your backend verifies X-Cdnca-Plugin-Context (base64url JSON, 60 s, with a nonce), X-Cdnca-Plugin-Key-Id and X-Cdnca-Plugin-Signature with the installation public key and remembers the nonce; with several replicas keep nonces in shared storage, and check the tenant, plugin and resources in the context. The SDK source, backend verifier and test vector are published on the ui_page SDK page.') },
    ] },
    { id: 'webhook', title: s('Webhook：先收测试事件', 'Webhooks: receive the test event first'), blocks: [
      { p: s('订阅由客户在目标租户里创建：管理操作要求主控登录会话和 plugin_webhooks.manage，查询要求 plugin_webhooks.read；API Key 不能代替。最小测试订阅只选 io.cdnca.webhook.v1.test，不填安装授权 ID。目标必须是公网 HTTPS 域名、默认 443 端口，不能带查询串或片段，不能是 IP。',
        'The customer creates the subscription in the target tenant: managing needs a control plane session and plugin_webhooks.manage, reading plugin_webhooks.read; an API key cannot do it. The smallest test subscription selects only io.cdnca.webhook.v1.test and no installation authorisation. The target must be a public HTTPS domain on port 443, without query or fragment, not an IP.') },
      { cmd: 'CDNCA_CONTROL_ORIGIN=\'https://control.example.com\'\nCDNCA_TENANT_SCOPE_ID=\'<tenant-scope-uuid>\'\nCDNCA_SUBSCRIPTIONS="${CDNCA_CONTROL_ORIGIN}/v1/tenant-scopes/${CDNCA_TENANT_SCOPE_ID}/plugin-webhook-subscriptions"\n# CDNCA_CONTROL_ACCESS_TOKEN comes from the customer\'s own session\numask 077\ncurl --fail-with-body --silent --show-error \\\n  -X POST "$CDNCA_SUBSCRIPTIONS" \\\n  -H "Authorization: Bearer ${CDNCA_CONTROL_ACCESS_TOKEN:?}" \\\n  -H \'Content-Type: application/json\' \\\n  -H "Idempotency-Key: <unique-key-for-this-create>" \\\n  --data-binary \'{"name":"test","target_url":"https://hooks.example.com/cdnca/hooks","event_types":["io.cdnca.webhook.v1.test"]}\' \\\n  --output webhook-receipt.json', label: s('客户在自己的受控终端创建测试订阅', 'The customer creates a test subscription from a controlled terminal') },
      { p: s('成功返回 201，回执含 subscription 和一次性 secret；把 secret 转存到接收服务的密钥存储，不要把回执写进普通日志。然后对 .../{subscription_id}/test-deliveries 发 POST（空对象正文、新的 Idempotency-Key），返回 202 只表示任务已接受，要再查 .../deliveries 确认状态为 delivered，并核对接收端已持久记录。',
        'Success is 201 with the subscription and a one-time secret; move the secret into the receiver’s secret store and keep the receipt out of ordinary logs. Then POST .../{subscription_id}/test-deliveries (empty object body, a new Idempotency-Key); 202 only means accepted, so check .../deliveries for status delivered and confirm your receiver stored it.') },
      { list: [
        s('校验 POST、路径、Content-Type 和必需请求头。', 'Check POST, path, Content-Type and the required headers.'),
        s('对收到的原始正文算 SHA-256，与 X-CDNCA-Webhook-Content-Sha256 比较。', 'Hash the raw body with SHA-256 and compare with X-CDNCA-Webhook-Content-Sha256.'),
        s('按 X-CDNCA-Webhook-Key-Id 选 secret，严格 base64url 解码为 32 字节后计算 HMAC-SHA256；签名形如 v2=<无填充 base64url>。', 'Pick the secret by X-CDNCA-Webhook-Key-Id, base64url-decode it strictly to 32 bytes and compute HMAC-SHA256; the signature looks like v2=<unpadded base64url>.'),
        s('时间戳与本地时钟相差不超过 300 秒（含边界）。', 'The timestamp is within 300 s of your clock (inclusive).'),
        s('按事件 schema 解析，绑定事件 ID、租户和订阅；delivery ID 去重，事件 ID 做业务幂等。', 'Parse per the event schema and bind event ID, tenant and subscription; dedupe by delivery ID and use the event ID for business idempotency.'),
        s('先可靠落盘或提交事务，再返回 2xx。', 'Persist or commit first, then return 2xx.'),
      ], ordered: true },
      { cmd: 'cdnca.webhook.signature/v2\nPOST\n<canonical-escaped-request-path>\n<X-CDNCA-Webhook-Timestamp>\n<X-CDNCA-Webhook-Event-Id>\n<X-CDNCA-Webhook-Delivery-Id>\n<X-CDNCA-Webhook-Key-Id>\n<lowercase-hex-sha256-of-raw-body>', label: s('签名输入（LF 分隔，无结尾换行）', 'Signature input (LF-separated, no trailing newline)') },
      { p: s('自动投递最多 5 次尝试；自动重试保留 delivery ID 并增加 attempt，显式回放保留 event ID、生成新 delivery ID。单条回放 POST .../deliveries/{delivery_id}/replays，按时间段回放 POST .../delivery-replays（最长 31 天，每批最多 100 条）。轮换与撤销需要 Idempotency-Key 和当前订阅的 If-Match，缺版本得 428，版本过期得 412，回读后再判断。真实领域事件要绑定已启用的安装授权且客户已批准对应 events.*.read 权限；订阅只接收创建之后的新事件。参考接收器在开发套件里（目录见套件 README），同时支持测试事件和网站变更事件 io.cdnca.site.v1.updated，带配套清单（需 Go 1.27，Unix 文件锁，Windows 请在 WSL 或 Linux 里运行）。',
        'Automatic delivery makes at most 5 attempts; a retry keeps the delivery ID and increments attempt, an explicit replay keeps the event ID with a new delivery ID. Replay one with POST .../deliveries/{delivery_id}/replays, a time range with POST .../delivery-replays (up to 31 days, 100 per batch). Rotation and revocation need an Idempotency-Key and the subscription’s If-Match: missing gives 428, stale gives 412; read back, then decide. Real domain events need an enabled installation authorisation with the matching events.*.read permission approved; a subscription only receives events after it was created. The reference receiver is in the developer kit (the kit README lists its directory); it handles both the test event and the site change event io.cdnca.site.v1.updated and comes with a matching manifest (Go 1.27, Unix file locks; on Windows run it in WSL or Linux).') },
    ] },
  ],
}
// ---- 5. 提交审核 ----------------------------------------------------------------

const review: Tutorial = {
  slug: 'review',
  nav: s('上传与审核', 'Upload and review'),
  title: s('上传版本与处理审核结果', 'Upload a version and handle review'),
  lead: s('在插件详情的“版本”标签上传，先等预检，再看是否需要人工审核。页面提示“已上传，正在预检”不等于审核通过，更不等于客户已经可见。',
    'Upload on the plugin’s “Versions” tab, wait for the scan, then see whether human review applies. “Uploaded, scanning” is not approval, let alone visible to customers.'),
  guides: ['theme', 'rule-pack', 'provider', 'external-service'],
  sections: [
    { id: 'upload', title: s('上传版本', 'Upload a version'), blocks: [
      { list: [
        s('打开插件详情 →“版本”→“上传新版本”。', 'Open the plugin → “Versions” → “Upload version”.'),
        s('按类型选文件：清单、配置 Schema，再加内容文件（theme、rule_pack）或 1–16 个平台包（external_https）；页面插件只传清单和配置 Schema。主题用同一次打包的三个产物。', 'Choose the files for the kind: manifest, configuration schema, plus the content file (theme, rule_pack) or 1–16 platform packages (external_https); page plugins upload only the manifest and schema. A theme uses the three outputs of one pack run.'),
        s('选渠道“正式”（stable，默认）或“测试”（beta），填更新说明。', 'Pick the channel “stable” (default) or “beta” and write release notes.'),
        s('第一次建议不勾“审核通过后自动公开”，先人工看审核结果和展示内容。', 'For the first one leave “Publish automatically once approved” off and look at the result yourself.'),
        s('提交后页面自动轮询预检状态；点版本号看详情、预检报告和审核意见。', 'The page polls the scan status; click the version for detail, the scan report and review notes.'),
      ], ordered: true },
      { p: s('同一插件的版本号不能重复，并且必须高于所有已审核过的版本；处于失败、隐藏等状态的版本号也不能再用。怎样确认：版本列表出现该版本号，详情里的文件、权限声明和预检状态符合预期。', 'Version numbers cannot repeat and must be higher than every reviewed version; a number in a failed or hidden state cannot be reused either. How to confirm: the version is listed and its detail shows the expected files, permissions and scan status.') },
    ] },
    { id: 'retry', title: s('上传超时或结果不明时', 'When an upload times out or the result is unknown'), blocks: [
      { list: [
        s('先刷新版本列表，查找这次的版本号。', 'Refresh the version list first and look for this version number.'),
        s('已经存在：直接进入该版本继续处理，不要再上传。', 'It exists: continue with that version; do not upload again.'),
        s('确认不存在：在同一页面不改任何文件和字段再点一次提交。页面对同一上传意图沿用同一个 Idempotency-Key，服务端会重放第一次的结果，而不是再建一个版本。', 'It does not exist: submit again from the same page without changing any file or field. The page keeps the same Idempotency-Key for the same upload, so the server replays the first result instead of creating another version.'),
        s('自己用脚本调用上传接口时同样如此：同一次上传意图的重试沿用原来的 Idempotency-Key 并发送完全相同的请求；如果返回 idempotency_conflict，不要换新键硬传，先回读版本列表确认结果。', 'The same applies when you call the upload endpoint from a script: retries of one upload reuse the original Idempotency-Key and send exactly the same request; on idempotency_conflict do not switch to a new key, read the version list back first.'),
      ], ordered: true },
      { note: s('不要连续点击提交来“试”状态，也不要换一个新的 Idempotency-Key 去掩盖未知结果。', 'Do not click submit repeatedly to probe the state, and do not use a new Idempotency-Key to paper over an unknown result.') },
    ] },
    { id: 'results', title: s('读懂审核结果', 'Read the review result'), blocks: [
      { p: s('审核先跑校验阶段（清单、入口、权限、本类型检查），有拒绝项就不再扫描；再跑扫描阶段。结论：有拒绝项 → 需修改；有隔离项 → 待人工审核；都没有时，满足下列任一条也进入人工审核，否则直接通过：',
        'Review runs a validating phase (manifest, entrypoint, permissions, kind checks) and stops on a reject; then the scanning phase. Outcome: a reject → changes requested; a quarantine → human review; otherwise any one of these also sends it to human review, or it is approved directly:') },
      { list: [
        s('首个版本', 'The first version'),
        s('权限与上一个已审核版本不同', 'Permissions differ from the last reviewed version'),
        s('高风险类型（module、engine_module、provider）', 'Privileged kinds (module, engine_module, provider)'),
        s('入驻未满考察期的卖家', 'Sellers still in their probation period'),
        s('扫描连续出错', 'Repeated scan errors'),
      ] },
      { table: { head: row(s('情况', 'Situation'), s('怎么做', 'What to do')), rows: [
        row(s('文件内容要改', 'Files must change'), s('改工程，递增版本号，重新打包签名，上传新版本', 'Fix the project, bump the version, pack and sign again, upload a new version')),
        row(s('文件不用改，只需重新排队检查', 'Files are fine, only rescan'), s('在版本详情点“修改后重新提交”；它不替换原文件，每个版本最多扫描 10 次', 'Click “Resubmit” on the version; it does not replace files, and a version is scanned at most 10 times')),
      ] } },
      { p: s('每条规则的 ID、级别、拒绝或隔离、是否试运行，见审核规则清单。', 'Every rule’s ID, severity, reject or quarantine and evaluation mode is on the review rules page.') },
    ] },
  ],
}

// ---- 6. 发布与渠道 --------------------------------------------------------------

const publish: Tutorial = {
  slug: 'publish',
  nav: s('发布、渠道与定价', 'Publishing, channels and pricing'),
  title: s('公开版本、选择渠道并设置价格', 'Publish a version, pick a channel and set prices'),
  lead: s('审核通过后由主账号公开；客户能不能获取还取决于是否有生效的价格计划。免费插件也需要一个金额为零的有效计划。',
    'After approval the owner publishes; whether customers can get it also depends on an active price plan. A free plugin needs an active plan with amount zero too.'),
  guides: [],
  sections: [
    { id: 'public', title: s('公开与隐藏', 'Publish and hide'), blocks: [
      { p: s('审核通过后，主账号在版本详情点“公开”；勾了“审核通过后自动公开”的版本会自动推进。已公开的版本可以“隐藏”：隐藏只影响之后的发现和获取，不能用来强制清除客户已经安装的能力。',
        'After approval the owner clicks “Publish” on the version; one uploaded with automatic publishing advances on its own. A published version can be “hidden”: that only affects discovery and new downloads, and cannot remove what customers already installed.') },
      { p: s('公开前核对中文资料、支持地址、兼容范围、权限说明、配置示例与更新说明。卖家站能看到不代表客户市场已经能看到。', 'Before publishing check the Chinese listing, support URL, compatibility, permission text, configuration example and release notes. Seeing it on the seller site does not mean customers can.') },
    ] },
    { id: 'channels', title: s('渠道：正式与测试', 'Channels: stable and beta'), blocks: [
      { p: s('上传时选择渠道：stable（正式，默认）或 beta（测试），记录在版本上，用于标明这个版本的发布性质。渠道在上传时决定，同一版本号不能换渠道重传，要换就递增版本号。第一次发布建议用 stable，并先关闭自动公开。', 'Pick the channel at upload: stable (default) or beta; it is recorded on the version to label its release status. It is fixed at upload; a version number cannot be re-uploaded on another channel, so bump the version instead. For a first release use stable with automatic publishing off.') },
    ] },
    { id: 'pricing', title: s('价格计划', 'Price plans'), blocks: [
      { table: { head: row(s('类型', 'Type'), s('规则', 'Rule')), rows: [
        row(s('免费', 'Free'), s('金额为零', 'Amount zero')),
        row(s('一次性买断', 'One-off'), s('金额大于零', 'Amount above zero')),
        row(s('订阅', 'Subscription'), s('金额大于零，按月或按年；试用天数可选 0、7、10、14、30', 'Amount above zero, monthly or yearly; trial of 0, 7, 10, 14 or 30 days')),
      ] } },
      { list: [
        s('在插件详情“定价”标签“新增价格计划”，只有主账号可以操作。新计划需要运营审核，通过后只对新订单生效。', 'Use “Add price plan” on the plugin’s “Pricing” tab; only the owner can. New plans go through operator review and apply to new orders only.'),
        s('没有生效的价格计划时，客户可能看得到资料却无法获取；最小免费发布也别漏这一步。', 'Without an active plan customers may see the listing but cannot get it; do not skip this even for a free release.'),
        s('收费前要准备结算资料。先发布免费插件并验证安装，再做收费，问题更好区分；不要用真实付款测试接口连通性。', 'Charging needs settlement details. Ship free first and verify installation, then add prices; never test connectivity with a real payment.'),
        s('改价只影响新订单；已有订单、许可证与退款按对应规则处理，不要用隐藏版本或改文件变相改客户订单。', 'Price changes affect new orders only; existing orders, licences and refunds follow their rules. Do not hide versions or change files to alter customer orders.'),
      ] },
      { p: s('收入怎么结算见收入与结算方式页。', 'How income is settled is on the income and settlement page.') },
    ] },
  ],
}

// ---- 7. 安装与授权 --------------------------------------------------------------

const install: Tutorial = {
  slug: 'install',
  nav: s('安装与授权', 'Installation and authorisation'),
  title: s('客户如何取得、安装并授权你的插件', 'How customers get, install and authorise your plugin'),
  lead: s('开发者提供说明、支持渠道和必要的服务地址；购买、安装确认和授权都由客户管理员在自己的主控里完成。下载、确认安装、启用是三个不同状态。',
    'You provide documentation, support and service addresses; buying, confirming and authorising are done by the customer’s administrator in their own control plane. Downloaded, confirmed and enabled are three different states.'),
  guides: [],
  sections: [
    { id: 'get', title: s('客户的操作步骤', 'What the customer does'), blocks: [
      { list: [
        s('平台管理员打开主控“插件商店”（/dashboard/sys/plugin-store），查看发布者、类型、版本、价格与权限。', 'The platform administrator opens “Plugin store” (/dashboard/sys/plugin-store) and checks publisher, kind, version, price and permissions.'),
        s('免费插件直接获取；收费插件先购买，付款完成后再获取。获取后插件进入租户的“插件市场”。', 'Free plugins are fetched directly; paid ones are bought first, then fetched. The plugin then appears in the tenant’s “Plugin marketplace”.'),
        s('租户管理员在“插件市场”（/dashboard/sys/plugin-market）核对权限列表并确认安装；敏感权限和新增权限要单独勾选确认。', 'The tenant administrator reviews the permissions in “Plugin marketplace” (/dashboard/sys/plugin-market) and confirms; sensitive and new permissions are confirmed separately.'),
        s('按类型到启用位置完成启用与配置（见下表），再用目标角色进入实际功能页，验证保存、刷新回读和一次真实调用。', 'Enable and configure at the place for the kind (table below), then use the target role on the real page to check saving, reloading and one real call.'),
      ], ordered: true },
      { table: { head: row(s('类型', 'Kind'), s('主控里的启用位置', 'Where to enable in the control plane')), rows: [
        row('theme', s('主题，/dashboard/sys/themes', 'Themes, /dashboard/sys/themes')),
        row('rule_pack', s('规则包，/dashboard/site/rule-packs', 'Rule packs, /dashboard/site/rule-packs')),
        row('provider', s('第三方服务商插件，/dashboard/sys/plugin-providers（先跑安装契约，全部通过才能启用）', 'Third-party providers, /dashboard/sys/plugin-providers (the installation contract must pass first)')),
        row(s('ui_page、external_service', 'ui_page, external_service'), s('目标租户的插件市场安装列表', 'The target tenant’s plugin marketplace list')),
      ] } },
    ] },
    { id: 'permissions', title: s('身份与权限', 'Identity and permissions'), blocks: [
      { table: { head: row(s('操作', 'Action'), s('需要', 'Needs')), rows: [
        row(s('浏览、购买插件', 'Browse and buy'), s('平台管理员，marketplace.browse / marketplace.purchase', 'Platform administrator, marketplace.browse / marketplace.purchase')),
        row(s('查看租户安装列表', 'View tenant installations'), s('当前会话属于目标租户，并有 plugin_installations.read', 'A session in the target tenant with plugin_installations.read')),
        row(s('确认、升级、停用、卸载', 'Confirm, upgrade, disable, uninstall'), s('plugin_installations.manage；接口要求 If-Match 与 Idempotency-Key', 'plugin_installations.manage; the endpoints need If-Match and Idempotency-Key')),
      ] } },
      { p: s('平台管理员身份与租户身份作用域不同，不能只看用户名判断当前身份。开发者不能替客户批准安装权限。', 'Platform and tenant identities have different scopes; a username alone does not tell you which one is active. A developer can never approve installation permissions for the customer.') },
    ] },
    { id: 'states', title: s('安装状态', 'Installation states'), blocks: [
      { table: { head: row(s('状态', 'State'), s('含义', 'Meaning')), rows: [
        row('pending_confirmation', s('已获取，等待租户管理员确认权限', 'Fetched, waiting for the tenant administrator to confirm permissions')),
        row('authorized, installing', s('已确认，正在安装', 'Confirmed, installing')),
        row('enabled', s('已启用，能力生效', 'Enabled and active')),
        row('disabled', s('已停用：页面移除、页面代理调用拒绝、绑定该安装的新事件停止；客户单独创建的 API Key 不受影响', 'Disabled: pages removed, page proxy calls refused, no new events for subscriptions bound to it; API keys the customer created separately are unaffected')),
        row('upgrade_failed_lkg_preserved', s('升级失败，保留最近一次有效版本', 'Upgrade failed; the last known good version is kept')),
        row('uninstalled', s('已卸载，授权撤销', 'Uninstalled; authorisation revoked')),
      ] } },
      { p: s('看到插件出现在列表里，还要确认它是否已确认、已启用并完成配置。', 'A plugin in the list still needs to be confirmed, enabled and configured.') },
    ] },
  ],
}
// ---- 8. 接口调用 ----------------------------------------------------------------

const api: Tutorial = {
  slug: 'api',
  nav: s('调用开放接口', 'Calling the open API'),
  title: s('调用开放接口：认证、权限、请求与响应、常见失败', 'Calling the open API: auth, permissions, requests, responses and failures'),
  lead: s('每个接口支持的认证方式不同，先看接口详情再决定怎么调。外部服务调用客户主控只能用客户签发的 API Key，而且只能调标“API Key 可调”的接口。',
    'Operations accept different authentication, so read the operation detail first. An external service calls a customer’s control plane only with an API key the customer issued, and only on operations marked “API key”.'),
  guides: ['external-service'],
  sections: [
    { id: 'auth', title: s('先看接口支持哪种认证', 'Check which auth the operation accepts'), blocks: [
      { table: { head: row(s('接口所属', 'Interface'), s('认证方式', 'Authentication'), s('不能混用', 'Never use')), rows: [
        row(s('开发者平台（/seller/v1）', 'Developer platform (/seller/v1)'), s('平台同源的 HttpOnly 会话 Cookie，写操作校验来源', 'The platform’s same-origin HttpOnly session cookie; writes check the origin'), s('主控 API Key、主控会话', 'Control plane API keys or sessions')),
        row(s('客户主控中标“API Key 可调”的接口', 'Control plane operations marked “API key”'), 'Authorization: CdncaKey <key_id>.<secret>', s('不能推断其他接口也接受 API Key', 'Do not assume other operations accept it')),
        row(s('客户主控只接受登录会话的接口', 'Control plane operations that take a session only'), s('客户本人的主控登录会话与对应权限', 'The customer’s own session and permissions'), s('插件不能要求客户交出管理员会话', 'A plugin must never ask for an administrator session')),
        row(s('服务商协议', 'Provider protocol'), s('安装身份的请求签名 + 插件的响应签名', 'Installation request signature + plugin response signature'), s('发布私钥、Cookie、通用 Bearer', 'Publisher key, cookies, generic Bearer')),
        row('Webhook', 'Webhook v2 HMAC', s('主控 API Key、服务商响应密钥', 'Control plane API keys, provider response keys')),
      ] } },
      { p: s('目前没有面向第三方自助申请的 OAuth 或 client credentials 流程。开放接口目录给出了每个接口的认证方式、所需权限、参数、请求体与响应字段和状态码，数字都从接口契约自动计算。',
        'There is no self-service OAuth or client-credentials flow for third parties. The API reference lists every operation’s auth, required permissions, parameters, request and response fields and status codes, all generated from the contracts.') },
    ] },
    { id: 'key', title: s('客户创建并保管 API Key', 'The customer creates and keeps the API key'), blocks: [
      { p: s('由客户在自己主控的“API Key”页（/dashboard/account/api-key）创建最小权限的 Key，按你服务的出口配置 IP 允许列表和有效期。创建接口 POST /v1/account/api-keys 只接受登录会话，需要 api_keys.self.manage、Idempotency-Key 与 If-Match，它自己不接受 CdncaKey。',
        'The customer creates a least-privilege key on their control plane’s “API key” page (/dashboard/account/api-key), with an IP allow-list for your egress and an expiry. The create endpoint POST /v1/account/api-keys takes a session only and needs api_keys.self.manage, an Idempotency-Key and If-Match; it does not accept CdncaKey itself.') },
      { list: [
        s('secret 只在签发回执里出现一次，存进受控的密钥存储；不要放到浏览器前端、插件包或公开仓库。', 'The secret appears once, in the issuing receipt; keep it in a controlled secret store, never in a browser front end, a plugin package or a public repository.'),
        s('有效权限始终是 Key 的范围与所有者当前权限的交集；所有者权限被收回后，旧 Key 也随之失去这些权限。', 'Effective permissions are always the key scopes intersected with the owner’s current permissions; when the owner loses a permission the key loses it too.'),
        s('轮换后旧 secret 立即失效。', 'After rotation the old secret stops working at once.'),
      ] },
    ] },
    { id: 'first', title: s('第一个只读请求', 'A first read-only request'), blocks: [
      { p: s('示例读取安全策略列表，需要 security_policies.read。在客户的受控环境里执行：', 'This lists security policies and needs security_policies.read. Run it in the customer’s controlled environment:') },
      { cmd: 'CDNCA_CONTROL_ORIGIN=\'https://control.example.com\'\n# inject CDNCA_API_KEY_ID and CDNCA_API_KEY_SECRET from your secret store\ncurl --fail-with-body --silent --show-error \\\n  -H "Authorization: CdncaKey ${CDNCA_API_KEY_ID:?}.${CDNCA_API_KEY_SECRET:?}" \\\n  "${CDNCA_CONTROL_ORIGIN}/v1/security-policies?page=1&limit=20"' },
      { cmd: '{"items":[],"total":0,"page":1,"limit":20}', label: s('没有数据时的合法响应', 'A valid empty response') },
      { p: s('这个接口 page 从 1 开始，limit 为 1–100，一直取到已取数量达到 total。其他列表可能用不透明的 cursor 与 next_cursor 翻页，不能统一套页码；每个接口用哪种以接口详情的参数为准。',
        'Here page starts at 1 and limit is 1–100; keep fetching until you have total items. Other lists page with an opaque cursor and next_cursor, so do not assume page numbers everywhere; the parameters in each operation’s detail decide.') },
    ] },
    { id: 'writes', title: s('写请求：幂等与版本', 'Writes: idempotency and revisions'), blocks: [
      { list: [
        s('带 Idempotency-Key 的写接口：同一次逻辑操作的重试保留原键和原请求内容，服务端重放第一次的结果；改了内容再用旧键会得到冲突。', 'Writes with Idempotency-Key: a retry of the same logical operation keeps the key and the body and the server replays the first result; reusing the key with a different body is a conflict.'),
        s('带 If-Match 的写接口：先读取资源拿到 ETag，再带上它提交。缺少返回 428，版本已变返回 412；回读最新状态后重新判断，不要盲目覆盖。', 'Writes with If-Match: read the resource for its ETag and send it. Missing gives 428, a changed revision 412; read the latest state and decide again instead of overwriting.'),
        s('不要对所有写请求无条件自动重试，也不要用新键掩盖结果不明的请求。', 'Do not auto-retry every write, and never use a new key to hide an unknown result.'),
      ] },
    ] },
    { id: 'errors', title: s('常见失败及下一步', 'Common failures and next steps'), blocks: [
      { p: s('失败时响应体是统一的错误信封 {"error":{"code":"…","message":"…","request_id":"…"}}，响应头带 X-Request-ID。按 code 做判断，message 不是本地化键；联系支持时附上 request_id。',
        'Failures return the error envelope {"error":{"code":"…","message":"…","request_id":"…"}} with an X-Request-ID header. Branch on code; message is not a localisation key. Include request_id when you contact support.') },
      { table: { head: row(s('状态码', 'Status'), s('先检查', 'Check first'), s('下一步', 'Next step')), rows: [
        row('400', s('参数、请求体字段', 'Parameters and body fields'), s('按接口详情的字段修正，不要原样重试', 'Fix them per the operation detail; do not retry unchanged')),
        row('401', s('凭据格式、是否过期或已轮换', 'Credential format, expiry, rotation'), s('换成有效凭据', 'Use a valid credential')),
        row('403', s('Key 范围、所有者当前权限、租户作用域', 'Key scopes, owner permissions, tenant scope'), s('请客户调整授权；不要换更高权限账号绕过', 'Ask the customer to adjust; never switch to a more privileged account')),
        row('404', s('资源 ID 与所属租户', 'Resource ID and tenant'), s('确认资源存在且属于当前租户', 'Confirm it exists in this tenant')),
        row('409', s('幂等冲突或状态冲突', 'Idempotency or state conflict'), s('回读当前状态；重试保持原键和原内容', 'Read the state back; retries keep the key and body')),
        row('412 / 428', s('If-Match 版本', 'If-Match revision'), s('回读最新 ETag 后重新判断', 'Read the latest ETag and decide again')),
        row('429', s('调用频率', 'Request rate'), s('等待后降低并发再试', 'Wait, then retry with lower concurrency')),
        row(s('5xx 或网络超时', '5xx or network timeout'), s('请求是否已生效', 'Whether the request took effect'), s('先按 ID 或列表回读确认，再决定是否用原 Idempotency-Key 重试', 'Read back by ID or list first, then decide whether to retry with the original Idempotency-Key')),
      ] } },
    ] },
  ],
}

// ---- 9. 升级与卸载 --------------------------------------------------------------

const lifecycle: Tutorial = {
  slug: 'lifecycle',
  nav: s('升级与卸载', 'Upgrade and uninstall'),
  title: s('升级、隐藏、停用和卸载怎么配合', 'How upgrade, hide, disable and uninstall fit together'),
  lead: s('开发者只能上传新版本和隐藏版本；升级、停用和卸载由客户的安装管理者在主控里操作。每个版本都写清迁移说明，客户才能放心升级。',
    'Developers can only upload new versions and hide versions; upgrading, disabling and uninstalling are done by the customer’s installation manager. Clear migration notes on every version are what make upgrades safe.'),
  guides: [],
  sections: [
    { id: 'matrix', title: s('谁在什么时候做什么', 'Who does what, when'), blocks: [
      { table: { head: row(s('操作', 'Action'), s('发起者', 'By'), s('什么时候用', 'When'), s('之后要验证', 'Verify afterwards')), rows: [
        row(s('上传新版本', 'Upload a new version'), s('开发者', 'Developer'), s('代码、内容、配置模型或权限变化', 'Code, content, schema or permissions change'), s('新版本号、重新签名、审核', 'New version number, new signature, review')),
        row(s('隐藏版本', 'Hide a version'), s('开发者主账号', 'Developer owner'), s('不再推荐或提供该版本', 'Stop offering that version'), s('现有客户的安装与支持安排', 'Existing installations and support')),
        row(s('升级安装', 'Upgrade an installation'), s('客户安装管理者', 'Customer’s installation manager'), s('应用已授权且兼容的新版本', 'Apply an authorised, compatible version'), s('确认新增权限，检查配置与真实调用', 'Confirm new permissions, check configuration and real calls')),
        row(s('停用安装', 'Disable'), s('客户安装管理者（需填写原因）', 'Customer’s installation manager (with a reason)'), s('暂停该安装提供的能力', 'Pause what the installation provides'), s('页面移除、页面代理调用拒绝、绑定该安装的新事件停止；专用 API Key 与测试订阅另行撤销', 'Pages gone, page proxy calls refused, no new events for bound subscriptions; revoke the dedicated API key and test-only subscriptions separately')),
        row(s('卸载安装', 'Uninstall'), s('客户安装管理者（需填写原因）', 'Customer’s installation manager (with a reason)'), s('撤销该安装', 'Revoke the installation'), s('授权失效，回调与数据按约定处理；专用 API Key 与测试订阅另行撤销', 'Authorisation revoked; callbacks and data handled as agreed; revoke the dedicated API key and test-only subscriptions separately')),
      ] } },
    ] },
    { id: 'upgrade', title: s('发布一个升级版本', 'Shipping an upgrade'), blocks: [
      { list: [
        s('递增 metadata.version，并且高于所有已审核版本。', 'Bump metadata.version above every reviewed version.'),
        s('确认 spec.compatibility.control_api 覆盖目标主控版本；不满足的主控不能安装或升级到这个版本，已安装的保留最近的兼容版本。', 'Make sure spec.compatibility.control_api covers the target control planes; ones that do not match cannot install or upgrade to it and keep their last compatible version.'),
        s('权限有变化时版本一律进入人工审核，客户升级时也要重新确认新增权限。', 'Any permission change sends the version to human review, and customers confirm new permissions when upgrading.'),
        s('更新说明写清：改了什么、最低主控版本、是否新增权限、原配置如何迁移、失败怎么恢复。', 'Release notes say what changed, the minimum control plane version, whether permissions were added, how configuration migrates and how to recover from a failure.'),
      ], ordered: true },
      { p: s('升级失败时安装进入 upgrade_failed_lkg_preserved，保留最近一次有效版本。这个机制不能代替你自己的数据迁移和回退方案；回退方式取决于插件类型与平台支持的版本，请在插件说明里写清恢复步骤，不要让客户直接改数据库。',
        'A failed upgrade leaves the installation in upgrade_failed_lkg_preserved with the last good version kept. That does not replace your own data migration and rollback; how to roll back depends on the kind and supported versions, so document recovery steps and never ask customers to edit a database.') },
    ] },
    { id: 'uninstall', title: s('停用与卸载后的处理', 'After disable and uninstall'), blocks: [
      { p: s('停用或撤销权限后，新的业务事件和回放也会经过授权检查。外部服务要能识别授权已被撤销，停止使用已撤销的 API Key 和安装身份，不要无限重试被拒的请求，并按与客户的约定处理已持有的数据。',
        'After disabling or revoking permissions, new events and replays are authorisation-checked too. Your service must recognise the revocation, stop using revoked API keys and installation identities, not retry refused requests forever, and handle data you hold as agreed with the customer.') },
      { p: s('停用或卸载只改变安装本身：页面移除，绑定这个安装的业务订阅不再收到新事件和回放。客户为你的服务单独创建的 API Key 和只选测试事件的订阅不归安装管理，不会自动撤销，要由客户逐项处理。请把下面的清单写进插件说明，交给客户照做：',
        'Disabling or uninstalling changes the installation only: its pages go and business subscriptions bound to it get no new events or replays. The API key the customer created for your service and test-only subscriptions are not tied to the installation and are not revoked automatically; the customer handles each one. Put this checklist in your plugin notes for the customer:') },
      { list: [
        s('你先暂停外部服务的定时任务和对客户主控的写入。', 'You pause your service’s scheduled jobs and writes to the customer’s control plane first.'),
        s('客户在“API Key”页（/dashboard/account/api-key）撤销专供本插件的 Key。先确认没有其他业务共用；有共用时，先给保留的业务换独立 Key，不要直接删共用 Key。', 'The customer revokes the key made for this plugin on the “API key” page (/dashboard/account/api-key). Check nothing else shares it first; if something does, give that work its own key before revoking, never delete a shared key outright.'),
        s('客户在“插件 Webhook 订阅”页（/dashboard/sys/plugin-webhooks）撤销不再需要的业务订阅和测试订阅；测试订阅不绑定安装，停用卸载不会影响它。', 'The customer revokes business and test-only subscriptions no longer needed on the “Plugin webhook subscriptions” page (/dashboard/sys/plugin-webhooks); test-only subscriptions are not bound to the installation, so disabling or uninstalling leaves them active.'),
        s('客户的安装管理者停用或卸载插件并填写原因，刷新确认状态。', 'The customer’s installation manager disables or uninstalls the plugin with a reason and refreshes to check the state.'),
        s('你删除服务中不再需要的 Key、Webhook secret 和安装签名公钥配置，按约定处理已持有的数据。', 'You delete keys, webhook secrets and installation signing keys you no longer need, and handle data you hold as agreed.'),
        s('一起核对：插件页面已不可用，旧 Key 调用返回 401，业务事件已停止，测试订阅已撤销，其他插件和共用 Key 不受影响。', 'Check together: the plugin pages are gone, the old key gets 401, business events have stopped, test-only subscriptions are revoked, and other plugins and shared keys are unaffected.'),
      ], ordered: true },
      { p: s('紧急停止接入时，先撤销专用 Key 再停用安装。外部服务要能识别授权已被撤销，不要无限重试被拒的请求。一次完整交付至少验证：新客户首次安装、老客户升级、普通用户与管理员分别使用、依赖不可用、权限收回、重复请求、升级失败后保留最近有效版本，以及按上面清单停止接入后页面、调用与事件都已停止。',
        'In an emergency, revoke the dedicated key before disabling the installation. Your service must recognise the revocation and not retry refused requests forever. A complete delivery verifies at least: a first install, an upgrade, use by an ordinary user and by an administrator, a dependency outage, revoked permissions, repeated requests, the last good version after a failed upgrade, and pages, calls and events all stopped after following the checklist above.') },
    ] },
    { id: 'troubleshoot', title: s('常见问题先这样排查', 'Troubleshooting'), blocks: [
      { table: { head: row(s('现象', 'Symptom'), s('先检查', 'Check first'), s('下一步', 'Next step')), rows: [
        row(s('进不了“我的插件”', 'Cannot open “My plugins”'), s('入驻状态、当前主体、团队权限', 'Onboarding status, current entity, team role'), s('由主账号核对申请和成员权限', 'The owner checks the application and member roles')),
        row(s('公钥验证失败', 'Key verification fails'), s('挑战是否过期、是否复制完整、私钥是否对应', 'Expired challenge, partial copy, wrong key'), s('重新获取挑战再签名', 'Get a new challenge and sign again')),
        row(s('命名空间冲突', 'Namespace conflict'), s('是否已被其他发布者认领、是否用了保留前缀', 'Claimed by another publisher, reserved prefix'), s('使用自己的命名空间', 'Use your own namespace')),
        row(s('签名或摘要不符', 'Signature or digest mismatch'), s('文件是否来自同一次打包、签名后是否改过', 'Same pack run? Edited after signing?'), s('从源文件重新打包签名', 'Pack and sign again from the sources')),
        row(s('工具退出 0 却没有产物', 'Tool exits 0 without output'), s('终端是否打印了预检与产物行', 'Did it print the check and output lines?'), s('用 pwd -P 得到的真实路径重新执行并核对文件', 'Run again from the real path given by pwd -P and check the files')),
        row(s('提示版本已存在', 'Version already exists'), s('版本列表与详情', 'Version list and detail'), s('已创建就继续处理；要改文件就递增版本', 'Continue with it if created; bump the version to change files')),
        row(s('审核通过但客户看不到', 'Approved but customers cannot see it'), s('是否公开、渠道、兼容范围、价格计划', 'Published? Channel, compatibility, price plan'), s('逐项核对，不要重复改文件', 'Check each one; do not keep changing files')),
        row(s('已获取但没有功能', 'Fetched but nothing works'), s('是否确认安装、启用、完成配置，当前角色', 'Confirmed, enabled, configured? Current role'), s('用目标角色在实际挂载位置验证', 'Verify with the target role where it mounts')),
        row(s('免费插件只有资料不能获取', 'Free plugin cannot be fetched'), s('是否有金额为零的生效价格计划', 'An active zero-price plan?'), s('主账号在“定价”里添加', 'The owner adds one under “Pricing”')),
        row(s('调用被拒绝', 'Calls refused'), s('安装是否有效、批准的权限、凭据类型与作用域', 'Installation state, approved permissions, credential type and scope'), s('按接口的认证方式处理，不要换更高权限账号', 'Follow the operation’s auth; never switch to a more privileged account')),
      ] } },
      { p: s('联系支持时提供：插件 ID、版本、操作时间、request_id、错误码和脱敏截图。不要提交密码、私钥、API secret、Webhook secret 或原始客户数据。',
        'When contacting support give the plugin ID, version, time, request_id, error code and redacted screenshots. Never send passwords, private keys, API or webhook secrets, or raw customer data.') },
    ] },
  ],
}

/** 顺序即导航顺序：入驻 → 工具 → 制作 → 联调 → 审核 → 发布 → 安装 → 接口 → 升级卸载。 */
export const TUTORIALS: Tutorial[] = [onboarding, signing, build, integrate, review, publish, install, api, lifecycle]
