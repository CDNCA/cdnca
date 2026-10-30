// Plugin review rule names and descriptions (market-service internal/review), shared by the public
// review rule list (apps/www), the seller portal and the operator console scan reports, so a stable
// rule ID reads the same everywhere. Keys are rule IDs; apps/www devGuides.test checks every rule in
// generated/review-rules.json has text and nothing extra is listed. The server message stays a
// secondary reference: it is never parsed.
import generated from '../../../apps/www/src/generated/review-rules.json'

export type ReviewText = { zh: string; en: string }
export type ReviewLang = keyof ReviewText

const s = (zh: string, en: string): ReviewText => ({ zh, en })

/** Maps an i18n language tag to the text language (English only for en*). */
export function reviewLang(language?: string): ReviewLang {
  return language?.toLowerCase().startsWith('en') ? 'en' : 'zh'
}

/** Pass names (review.go PassID). */
export const REVIEW_PASS_TEXT: Record<string, ReviewText> = {
  metadata: s('清单与版本', 'Manifest and version'), signature: s('签名', 'Signature'), permissions: s('权限', 'Permissions'),
  package: s('平台包', 'Platform packages'), secrets: s('密钥泄露扫描', 'Leaked secret scan'), malware: s('病毒扫描', 'Malware scan'),
  dependencies: s('依赖漏洞扫描', 'Dependency vulnerability scan'), diff: s('版本差异', 'Version diff'),
  rule_pack: s('规则包', 'Rule pack'), theme: s('主题', 'Theme'), ui_page: s('页面插件', 'Page plugin'),
}

/** 每个分析器都有的两条内置规则（engine.go NewEngine）。 */
export const REVIEW_BUILTIN_SUFFIX: Record<string, ReviewText> = {
  scanner_error: s('该项检查本身出错（扫描器故障），版本转人工审核', 'The check itself failed (scanner fault); the version goes to human review'),
  skipped: s('前置检查未完成，本项没有运行', 'A prerequisite did not complete, so this check did not run'),
}

/** 规则说明（中英），键为规则 ID；*.scanner_error / *.skipped 用 REVIEW_BUILTIN_SUFFIX。 */
export const REVIEW_RULE_TEXT: Record<string, ReviewText> = {
  'metadata.manifest_invalid': s('manifest 不是合法的 marketplace.cdnca.io/v1 Plugin 文档', 'The manifest is not a valid marketplace.cdnca.io/v1 Plugin document'),
  'metadata.identity_mismatch': s('manifest 的 id 或 version 与上传的版本不一致', 'The manifest id or version differs from the uploaded version'),
  'metadata.version_invalid': s('版本号不是规范 SemVer', 'The version is not canonical SemVer'),
  'metadata.version_not_monotonic': s('已有同号或更高的已审核版本', 'A reviewed version with the same or a higher number exists'),
  'metadata.name_missing': s('manifest 缺少 zh-CN 名称', 'The manifest has no zh-CN name'),
  'metadata.publisher_missing': s('manifest 缺少发布者 id 或名称', 'The manifest has no publisher id or name'),
  'metadata.description_missing': s('manifest 缺少 zh-CN 描述（只提示）', 'The manifest has no zh-CN description (notice only)'),
  'metadata.license_missing': s('插件没有声明 SPDX 许可证（只提示）', 'The plugin declares no SPDX licence (notice only)'),
  'metadata.no_packages': s('external_https 版本没有平台包', 'An external_https version has no platform package'),
  'metadata.platform_invalid': s('平台名格式错误或重复', 'A platform name is malformed or repeated'),
  'metadata.manifest_packages': s('manifest 的 spec.packages 没有恰好列出上传的包及摘要', 'The manifest spec.packages does not list exactly the uploaded packages and digests'),
  'entrypoint.type_invalid': s('spec.entrypoint.type 不是 external_https、rule_pack、theme、ui_page 之一，或与插件类型不符', 'spec.entrypoint.type is not external_https, rule_pack, theme or ui_page, or does not match the plugin kind'),
  'entrypoint.content_mismatch': s('上传的数据包文件与签名的 spec.entrypoint.sha256 不一致', 'The uploaded data file does not match the signed spec.entrypoint.sha256'),
  'entrypoint.packages_present': s('rule_pack / theme 版本带了可执行包', 'A rule_pack / theme version carries executable packages'),
  'entrypoint.data_pack_permissions': s('rule_pack 必须只声明 security.rule_packs.provide，theme 必须只声明 platform.themes.provide', 'A rule_pack declares exactly security.rule_packs.provide, a theme exactly platform.themes.provide'),
  'entrypoint.data_pack_version': s('数据包版本必须是纯 major.minor.patch（无预发布后缀）', 'A data package version is plain major.minor.patch (no pre-release)'),
  'entrypoint.provides_invalid': s('spec.provides 格式错误、重复，或由数据包 / ui_page 声明', 'spec.provides is malformed, repeated, or declared by a data package / ui_page'),
  'entrypoint.provides_official_only': s('该服务商类型只限官方发布（第三方 CDN 适配器不开放）', 'This provider kind is official only (third-party CDN adapters are not open)'),
  'permissions.invalid_name': s('权限名格式错误、重复，或超过 64 个', 'A permission name is malformed or repeated, or there are more than 64'),
  'permissions.manifest_mismatch': s('保存的权限与 manifest 不一致', 'Stored permissions differ from the manifest'),
  'permissions.first_version': s('插件首个版本：需人工审核', 'First version of the plugin: human review required'),
  'permissions.expanded': s('权限比上一个已审核版本多：需人工审核', 'Permissions grew since the last reviewed version: human review required'),
  'permissions.reduced': s('权限比上一个已审核版本少：需人工审核', 'Permissions shrank since the last reviewed version: human review required'),
  'permissions.privileged': s('高风险类型（module、engine_module、provider）：需人工审核', 'Privileged kind (module, engine_module, provider): human review required'),
  'rulepack.compile_failed': s('规则包编译失败（cdnca.rule-pack/v1）', 'The rule pack does not compile (cdnca.rule-pack/v1)'),
  'rulepack.budget_exceeded': s('规则包超出规则数、正则数或每请求代价预算', 'The rule pack exceeds the rule count, regex or per-request cost budget'),
  'rulepack.layer_invalid': s('市场规则包必须是发布者命名空间下的开发者层包（dev/<发布者>/<名称>）', 'A market rule pack must be a developer-layer pack in the publisher namespace (dev/<publisher>/<name>)'),
  'rulepack.version_mismatch': s('规则包版本与插件版本不同', 'The rule pack version differs from the plugin version'),
  'rulepack.not_canonical': s('规则包文件不是编译器输出的规范字节', 'The rule pack file is not the compiler’s canonical bytes'),
  'rulepack.gate_failed': s('未通过发布质量门：单独解析失败，或 modsecurity 包算不出 CRS 规则号', 'Fails the publication gate: does not resolve alone, or a modsecurity pack’s CRS rule numbers cannot be computed'),
  'rulepack.summary': s('规则包内容摘要（只展示）', 'What the rule pack contains (display only)'),
  'theme.invalid': s('不是合法的 cdnca.theme/v1 主题包（令牌、槽位、模板、外部引用）', 'Not a valid cdnca.theme/v1 package (tokens, slots, templates, external references)'),
  'theme.id_mismatch': s('市场主题的 id 必须是 market.<插件 ID>', 'A market theme id must be market.<plugin id>'),
  'theme.version_mismatch': s('主题版本与插件版本不同', 'The theme version differs from the plugin version'),
  'theme.summary': s('主题渲染结果摘要（只展示）', 'What the theme renders (display only)'),
  'theme.admin_scope': s('第三方主题声明了管理员控制台（applies_to 含 admin、admin 令牌或 admin 选择器），只有官方发布者 io.cdnca 可以', 'A third-party theme declares the administrator console (applies_to admin, admin tokens or an admin selector); only the official publisher io.cdnca may'),
  'theme.site_invalid': s('不是合法的 cdnca.site-theme/v1 或 v2 官网主题包（页面包路径与禁用内容、登录样式、内容 schema、applies_to）', 'Not a valid cdnca.site-theme/v1 or v2 website theme package (page bundle paths and forbidden content, auth style, content schema, applies_to)'),
  'theme.console_invalid': s('官网主题包里的 console_theme 不是合法的 cdnca.theme/v1 主题包', 'The console_theme of a website theme package is not a valid cdnca.theme/v1 package'),
  'ui_page.declaration_invalid': s('ui_page 声明不合法（origin、页面、挂载点、菜单父级、标题、显示门槛）', 'The ui_page declaration is malformed (origin, pages, mounts, menu parents, titles, gates)'),
  'ui_page.origin_unverified': s('页面 origin 或 api_base_url 不是你在市场验证过的来源', 'A page origin or api_base_url is not one you verified on the market'),
  'ui_page.permission_missing': s('ui_page 插件必须声明 platform.ui_pages.provide', 'A ui_page plugin must declare platform.ui_pages.provide'),
  'ui_page.artifacts_present': s('ui_page 版本不能带包或数据文件（页面在你的 origin 上）', 'A ui_page version carries no package or data file (its pages live on your origin)'),
  'ui_page.summary': s('页面挂载位置摘要（只展示）', 'Where the pages are mounted (display only)'),
  'package.digest_mismatch': s('存储的包与声明的 SHA-256 或大小不符', 'A stored package does not match its declared SHA-256 or size'),
  'package.unknown_format': s('包不是 zip、tar.gz 或 tar', 'A package is not zip, tar.gz or tar'),
  'package.corrupt': s('压缩包损坏', 'The archive is corrupt'),
  'package.zip_bomb': s('解压后远超压缩大小（zip 炸弹）', 'It expands far beyond its compressed size (zip bomb)'),
  'package.limits_exceeded': s('超出条目数或解压大小上限', 'Over the entry count or unpacked size limits'),
  'package.path_traversal': s('条目路径逃出包根目录', 'An entry name escapes the package root'),
  'package.symlink': s('包含符号链接或硬链接', 'Contains a symbolic or hard link'),
  'package.special_file': s('包含设备、管道或套接字文件', 'Contains a device, pipe or socket'),
  'package.duplicate_entry': s('包含重名条目', 'Contains duplicate entry names'),
  'package.setuid': s('条目带 setuid 或 setgid 位', 'An entry has the setuid or setgid bit'),
  'package.unsupported_entry': s('不支持的归档条目类型', 'Unsupported archive entry type'),
  'package.blocked_file': s('文件哈希在平台封禁名单上', 'A file hash is on the platform block list'),
  'secrets.private_key': s('包里嵌有私钥', 'A private key is embedded in the package'),
  'secrets.aws_access_key': s('AWS Access Key ID', 'AWS access key ID'),
  'secrets.github_token': s('GitHub 令牌', 'GitHub token'),
  'secrets.github_fine_grained_pat': s('GitHub 细粒度令牌', 'GitHub fine-grained token'),
  'secrets.gitlab_pat': s('GitLab 个人访问令牌', 'GitLab personal access token'),
  'secrets.slack_token': s('Slack 令牌', 'Slack token'),
  'secrets.slack_webhook': s('Slack Webhook 地址', 'Slack webhook URL'),
  'secrets.stripe_secret_key': s('Stripe 密钥', 'Stripe secret key'),
  'secrets.gcp_api_key': s('Google API Key', 'Google API key'),
  'secrets.alibaba_access_key': s('阿里云 AccessKey ID', 'Alibaba Cloud AccessKey ID'),
  'secrets.tencent_secret_id': s('腾讯云 SecretId', 'Tencent Cloud SecretId'),
  'secrets.jwt': s('JSON Web Token', 'JSON Web Token'),
  'secrets.generic_api_key': s('通用凭据赋值（api_key、secret、token、password 等）', 'Generic credential assignment (api_key, secret, token, password and so on)'),
  'dependencies.not_configured': s('平台未配置 OSV 离线库，依赖扫描跳过（只提示）', 'The OSV offline database is not configured; dependency scan skipped (notice only)'),
  'dependencies.inventory': s('识别到的第三方组件清单（只展示）', 'Third-party components found (display only)'),
  'dependencies.malicious': s('依赖是已知恶意包', 'A dependency is a known malicious package'),
  'dependencies.vulnerable_high': s('依赖有高危或严重漏洞', 'A dependency has a high or critical vulnerability'),
  'dependencies.vulnerable': s('依赖有已知漏洞（只提示）', 'A dependency has a known vulnerability (notice only)'),
  'malware.not_configured': s('平台未配置 clamd，病毒扫描跳过（只提示）', 'clamd is not configured; virus scan skipped (notice only)'),
  'malware.detected': s('clamd 检出恶意代码', 'clamd detected malware'),
  'diff.first_version': s('没有可比较的已审核版本（只展示）', 'No earlier reviewed version to compare with (display only)'),
  'diff.summary': s('与上一个已审核版本的变化（只展示）', 'Changes since the last reviewed version (display only)'),
  'diff.binary_changed': s('新增或修改了可执行文件（只提示）', 'An executable was added or changed (notice only)'),
}

/** Text for one rule ID; undefined for a rule this build does not know. */
export function reviewRuleText(rule: string): ReviewText | undefined {
  return REVIEW_RULE_TEXT[rule] ?? REVIEW_BUILTIN_SUFFIX[rule.slice(rule.indexOf('.') + 1)]
}

const SUMMARY = new Map((generated.rules as { id: string; summary: string }[]).map((r) => [r.id, r.summary]))

/**
 * What a report row shows: the localized description of its rule (or a generic one for an unknown
 * rule) and, only when the server message carries more than the rule's fixed summary (a file, a
 * component, a signature), that message as a secondary detail kept in its original wording.
 */
export function reviewFindingText(finding: { rule: string; message?: string }, lang: ReviewLang): { text: string; known: boolean; detail: string } {
  const known = reviewRuleText(finding.rule)
  const message = finding.message?.trim() ?? ''
  const detail = message && message !== SUMMARY.get(finding.rule) ? message : ''
  return { text: (known ?? REVIEW_UNKNOWN_RULE)[lang], known: Boolean(known), detail }
}

export const REVIEW_UNKNOWN_RULE = s('本版本页面未收录这条规则的说明，请按规则编号查看审核规则说明或联系平台。',
  'This page has no description for the rule yet; look the rule ID up in the review rules or contact the platform.')

// Whether a check actually ran. Scanning passes only read platform packages, so for kinds that upload
// none (rule_pack, theme, ui_page) dependency, malware and secret scans do not apply whatever the
// platform configured.
export type ReviewCoverage = 'not_configured' | 'not_applicable' | 'skipped' | 'failed'
export const PACKAGE_SCANS = ['dependencies', 'malware', 'secrets'] as const

export const REVIEW_COVERAGE_TEXT: Record<ReviewCoverage, ReviewText> = {
  not_configured: s('未执行（平台未配置扫描器）', 'Not run (the platform has not configured the scanner)'),
  not_applicable: s('不适用（本类型没有平台包）', 'Not applicable (this kind has no platform package)'),
  skipped: s('未运行（前置检查未完成）', 'Not run (a prerequisite did not complete)'),
  failed: s('执行失败（已转人工审核）', 'Failed (sent to human review)'),
}

/** Checks of one report that did not complete, by why; a pass appears once. */
export function reviewCoverage(findings: { pass: string; rule: string }[], hasPackages = true): Partial<Record<ReviewCoverage, string[]>> {
  const out: Partial<Record<ReviewCoverage, string[]>> = {}
  const seen = new Set<string>()
  const add = (kind: ReviewCoverage, pass: string) => {
    if (seen.has(pass)) return
    seen.add(pass)
    ;(out[kind] ??= []).push(pass)
  }
  if (!hasPackages) for (const pass of PACKAGE_SCANS) add('not_applicable', pass)
  for (const f of findings) {
    if (f.rule.endsWith('.scanner_error')) add('failed', f.pass)
    else if (f.rule.endsWith('.not_configured')) add('not_configured', f.pass)
    else if (f.rule.endsWith('.skipped')) add('skipped', f.pass)
  }
  return out
}

export const REVIEW_SUMMARY_TEXT = {
  allRan: s('预检已完成，各项适用检查均已执行。', 'The pre-check finished and every applicable check ran.'),
  partial: s('预检已完成，但部分检查未执行或不适用，见下方说明；“通过”只表示当前策略下没有阻断项，不代表未执行的检查已通过。',
    'The pre-check finished, but some checks did not run or do not apply (see below); “passed” only means nothing blocks under the current policy, not that those checks passed.'),
  awaitingReview: s('该版本仍需人工审核，你暂时无需重新上传，请等待审核结果。', 'This version still needs human review; you need not upload again, wait for the decision.'),
}
