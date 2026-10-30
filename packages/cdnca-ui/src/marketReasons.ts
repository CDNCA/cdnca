// MC12 E3: one place that turns node market reason codes into plain words for
// the controller (apps/web 节点市场) and the seller site (apps/seller-portal).
// Each code says why it happened and who acts / how it recovers; an unknown
// code keeps the raw code with a generic next step, so nothing is hidden.
//
// Sources: market-service httpapi classify/errorBody, sla.Close* and
// renewalstop reasons; control-api marketsubscribehttp conflict codes;
// leaf blockers (libs/marketproto/siteconf, control-api marketsupply) and
// site compile blockers (control-api marketsubscribe/compile.go).

import { offerCopyLocale, type OfferCopyLocale } from './offerTerms'

export interface MarketReason {
  code: string
  known: boolean
  reason: string
  next: string
}

type Entry = [reason: string, next: string]

const zhCN: Record<string, Entry> = {
  // Supply and subscription state.
  no_supply: ['当前没有任何有效供给（上游取消、授权撤销或卖方冻结）', '联系直接供货方补给，或改用其他供给'],
  no_active_leaf: ['该供给当前没有可服务的叶子节点，不能绑定新站点', '已绑定站点不受影响；联系直接供货方恢复节点'],
  no_market_binding: ['该站点还没有绑定任何市场供给', '先在上方把供给绑定到该站点，再预检'],
  stale_revision: ['该站点已有更新的市场修订', '刷新后重新预检'],
  site_changed: ['预检之后站点又被保存过，这次应用已拒绝', '查看新的预检结果，确认后再应用'],
  site_package_unavailable: ['该网站没有有效套餐（未绑定、已停用或已删除），主控订阅的市场供给暂不可用，不能下发配置', '为网站绑定或恢复有效套餐后重新预检；网站自己的订阅不受影响'],
  seller_frozen: ['卖方被平台冻结', '平台处理；解冻后自动恢复续费'],
  buyer_frozen: ['订阅方被平台冻结', '联系平台运营处理'],
  upstream_lost: ['上游供给失效', '由直接卖家补给，或改用其他供给'],
  no_grant: ['没有有效授权', '联系直接供货方重新授权'],
  upstream_paused: ['全部供给因上游原因暂停', '恢复后自动续费，暂停期间不补扣；按补偿规则停续或补时长'],
  // Market answers (purchase, listing, money).
  offer_quota_exceeded: ['可上架报价数已用完', '下架不用的报价，或联系平台提高额度'],
  offer_changed: ['报价已在别处修改', '刷新后重新打开再操作'],
  settlement_mode_retired: ['该结算方式已停用', '改用当前支持的结算方式'],
  blacklisted: ['账号被平台限制交易', '联系平台运营复核'],
  icp_unverified: ['域名未通过备案核验', '完成备案后重试'],
  seller_access_rule: ['不符合卖家设置的准入条件', '联系卖家确认准入要求'],
  domain_limit: ['域名数超过报价上限', '减少域名或改买上限更高的报价'],
  commission_overdue: ['平台佣金欠费', '卖方结清佣金后恢复'],
  seller_onboarding_required: ['卖方尚未完成入驻', '在卖家站完成入驻'],
  commission_prepaid_required: ['需要先预付平台佣金', '在卖家站预付佣金后再上架'],
  listing_suspended: ['上架资格被平台暂停', '联系平台运营了解原因'],
  outage_not_eligible: ['当前不符合故障退订条件', '等待达到故障时长或提交故障反馈'],
  deposit_insufficient: ['供货方保证金不足，暂停新订阅与新充值', '等待供货方补足保证金'],
  buyer_cap_exceeded: ['超过平台对单家供货方的预付上限', '先消耗余额或改选其他供货方'],
  risk_unacknowledged: ['尚未确认风险说明', '阅读并勾选风险说明后重试'],
  trial_used: ['试用已用过', '改为正式购买'],
  purchases_paused: ['市场暂停了新购买', '稍后重试'],
  insufficient_balance: ['余额不足', '充值后重试'],
  load_floor_exceeded: ['节点负载超过报价要求的下限', '降低负载或调整报价后重试'],
  plugin_unavailable: ['所需插件在供给中不可用', '联系供货方开通该插件，或去掉相关设置'],
  upstream_terms_exceeded: ['转售条件比上游宽松', '按上游条件收紧后再保存'],
  resale_forbidden: ['上游不允许转售', '改用允许转售的上游，或只自用'],
  forbidden: ['没有权限执行该操作', '请有对应权限的管理员操作'],
  not_found: ['记录不存在或不属于你', '刷新后重试'],
  conflict: ['状态已变化', '刷新后重试'],
  invalid: ['提交的内容不符合要求', '检查后重试'],
  unsupported: ['市场暂不支持该操作', '等待市场升级'],
  market_unavailable: ['市场服务暂时连不上', '稍后重试；不代表订单或供给已停'],
  market_feature_unavailable: ['市场尚未开放该操作', '等待市场升级'],
  market_response_invalid: ['市场返回了无效数据', '稍后重试，持续出现请联系平台'],
  // Leaf blockers: what a supplier's controller cannot serve.
  port_limit: ['端口数超过供给允许的数量', '减少站点端口或改用允许更多端口的供给'],
  websocket_not_allowed: ['供给不允许 WebSocket', '在站点回源设置关闭 WebSocket，或改用允许的供给'],
  http3_not_allowed: ['供给不允许 HTTP/3', '在站点 HTTPS 设置关闭 HTTP/3，或改用允许的供给'],
  leaf_unavailable: ['供货方主控暂时无法处理', '稍后重试；持续出现请联系直接供货方'],
  pool_domain_limit: ['该供给的域名总数已满', '减少域名或联系供货方提高上限'],
  leaf_cname_unconfigured: ['供货方主控未配置供给 CNAME 域名', '联系直接供货方完成配置'],
  icp_checker_unconfigured: ['供货方要求备案但未配置备案查询', '联系直接供货方'],
  icp_check_failed: ['备案查询失败', '稍后重试'],
  icp_unfiled: ['域名未备案，供货方要求备案', '完成备案或改用不要求备案的供给'],
  cache_invalid: ['缓存设置无效', '检查站点缓存设置'],
  unsupported_cache: ['供货方不支持该缓存设置', '简化站点缓存设置'],
  access_invalid: ['访问控制设置无效', '检查站点访问控制'],
  unsupported_access: ['供货方暂不支持该访问控制', '去掉相关访问控制设置'],
  rate_limit_invalid: ['限速设置无效', '检查站点限速设置'],
  unsupported_rate_limit: ['供货方暂不支持该限速设置', '去掉相关限速设置'],
  autodefense_invalid: ['自动防御设置无效', '在自动防御页检查该站点设置'],
  autodefense_capped: ['自动防御已按供给上限收紧', '已生效；需要更高档位请联系供货方'],
  autodefense_unavailable: ['供给不含自动防御', '联系供货方开通，或接受不生效'],
  // What a market site rollout still cannot carry (compiled from the saved site).
  site_disabled: ['站点已停用', '先在站点列表启用该站点'],
  no_enabled_origin: ['站点没有启用的源站', '在站点回源设置启用至少一个源站'],
  site_config_invalid: ['站点配置无法转换为市场配置', '检查站点域名、端口与源站'],
  http3_unavailable: ['该供给节点不支持 HTTP/3，将以 HTTP/2 服务', '已生效；需要 HTTP/3 请联系供货方升级节点运行时'],
  origin_route_geo_unmatched: ['该供给没有对应地区的节点，此条件回源规则在该供给上不生效', '站点已下发（括号内为规则 ID）；需要该规则生效请改用有该地区节点的供给'],
  origin_routes_invalid: ['供货方无法接受该条件回源规则', '检查站点条件回源规则（每条规则需至少一个条件）'],
  site_acl_rule: ['站点黑白名单规则市场配置无法表达', '按括号内原因调整站点黑白名单规则后再下发'],
  site_cc_rule: ['站点 CC 规则市场配置无法表达', '按括号内原因调整站点 CC 规则后再下发'],
  cc_invalid: ['供货方无法接受该 CC 规则', '检查站点 CC 规则与 CC 设置'],
  unsupported_cc: ['供货方暂不支持该 CC 规则', '按括号内原因处理后再下发'],
  site_waf_policy: ['站点 WAF 规则市场配置无法表达', '按括号内原因调整站点 WAF 规则后再下发'],
  waf_invalid: ['供货方无法接受该 WAF 规则', '检查站点 WAF 规则'],
  unsupported_waf: ['供货方暂不支持该 WAF 设置（括号内为缺少的 CRS 档位包）', '联系供货方下载对应 CRS 档位包，或更换站点 CRS 档位'],
  site_origin_routes: ['站点条件回源规则市场配置无法表达', '按括号内原因调整站点条件回源规则后再下发'],
  site_l2_custom: ['站点 L2 配置选择了本平台的自定义 L2 节点，供货方没有这些节点', '把站点 L2 配置改为跟随套餐或关闭后再下发'],
  site_basic_auth: ['站点开启了访问认证（Basic Auth），密码只以本站哈希保存，无法带到供货方', '在站点访问控制里关闭访问认证后再下发'],
  site_http_policy: ['站点启用了 HTTP 策略（源站请求头、上传上限、改写/跳转、CORS、防盗链），市场配置暂不支持', '停用该站点的 HTTP 策略后再下发'],
  http_policy_invalid: ['供货方无法接受该 HTTP 策略', '检查站点 HTTP 策略（源站请求头、上传上限、改写/跳转、CORS、防盗链）'],
  unsupported_http_policy: ['供货方暂不支持 HTTP 策略', '停用该站点的 HTTP 策略，或等供货方升级后再下发'],
  site_origin_auth: ['站点的回源鉴权规则暂时无法带到供货方', '按括号内原因处理后再下发'],
  origin_auth_sealed: ['供货方无法解开回源鉴权凭据（凭据只为各供货方单独加密）', '重新预览后再下发；仍失败请联系供货方核对其市场身份（括号内为规则 ID）'],
  origin_auth_invalid: ['供货方无法接受该回源鉴权规则（括号内为规则 ID）', '检查规则的存储桶地址、区域与凭据有效期；S3 兼容存储需供货方配置同名出站策略'],
  unsupported_origin_auth: ['供货方暂不支持回源鉴权', '关闭站点的回源鉴权开关，或等供货方升级后再下发'],
  origin_auth_delivery: ['回源鉴权凭据还没有送达供货方节点', '站点已下发，供货方会自动重试；括号内为原因'],
  // fix-mktsiteconf7: an applied leaf on its way to its nodes, or not taking effect there.
  site_syncing: ['供货方正在把站点同步到节点', '无需操作，生效后这里会更新'],
  site_sync_failed: ['供货方节点同步站点失败', '供货方会在节点恢复后自动重试；长时间未恢复请联系供货方'],
  security_activating: ['安全策略正在供货方节点上激活', '无需操作，激活后这里会更新'],
  security_failed: ['安全策略在供货方节点上激活失败', '检查站点的 WAF/CC/访问控制设置后重新下发，或联系供货方'],
  origin_auth_delivering: ['回源鉴权凭据正在送达供货方节点', '无需操作，送达后这里会更新'],
  origin_auth_failed: ['回源鉴权凭据未能送达供货方节点', '在回源鉴权页重新校验凭据后重新下发站点，或联系供货方'],
  node_delivery_timeout: ['长时间未在供货方节点生效，已停止自动核对', '重新下发站点，或联系供货方核对节点状态'],
  status_unavailable: ['暂时读不到供货方的节点状态', '会自动重试；多次失败请联系供货方'],
  node_reason_unknown: ['供货方返回了无法识别的节点状态', '把原码发给供货方核对'],
  site_access_invalid: ['供货方无法接受该站点访问控制设置', '检查站点访问控制设置'],
  unsupported_site_access: ['供货方不支持站点访问控制设置', '联系供货方升级主控，或清空站点访问控制设置'],
}

const enUS: Record<string, Entry> = {
  no_supply: ['No valid supply right now (upstream cancelled, grant revoked or seller frozen)', 'Ask your direct supplier to restore it, or switch supply'],
  no_active_leaf: ['This supply has no leaf that can serve, so it takes no new site', 'Bound sites are unaffected; ask your direct supplier'],
  no_market_binding: ['The site has no market supply bound', 'Bind a supply to the site above, then preview'],
  stale_revision: ['The site already has a newer market revision', 'Refresh and preview again'],
  site_changed: ['The site was saved again after the preview, so this apply was refused', 'Review the new preview, then apply'],
  site_package_unavailable: ['The site has no valid package (none bound, disabled or deleted), so the controller\'s market supplies are unavailable and take no config', 'Bind or restore a valid package for the site, then preview again; the site\'s own subscriptions are unaffected'],
  seller_frozen: ['The seller is frozen by the platform', 'The platform handles it; renewal resumes on its own'],
  buyer_frozen: ['The subscriber is frozen by the platform', 'Contact platform operations'],
  upstream_lost: ['The upstream supply is gone', 'Your direct seller restores it, or switch supply'],
  no_grant: ['No valid grant', 'Ask your direct supplier to grant again'],
  upstream_paused: ['Every supply paused upstream', 'Renewal resumes after recovery with no charge for the pause; compensated by stopping renewal or extending time'],
  offer_quota_exceeded: ['No offer quota left', 'Delist unused offers or ask the platform for more'],
  offer_changed: ['The offer was changed elsewhere', 'Refresh and reopen it'],
  settlement_mode_retired: ['This settlement mode is retired', 'Use a supported settlement mode'],
  blacklisted: ['The account may not trade', 'Ask platform operations to review'],
  icp_unverified: ['The domain failed ICP verification', 'Retry after filing'],
  seller_access_rule: ['You do not meet the seller\'s entry rules', 'Ask the seller'],
  domain_limit: ['More domains than the offer allows', 'Remove domains or buy a larger offer'],
  commission_overdue: ['Platform commission is overdue', 'Resumes once the seller pays'],
  seller_onboarding_required: ['Seller onboarding is not complete', 'Finish onboarding on the seller site'],
  commission_prepaid_required: ['Commission must be prepaid first', 'Prepay on the seller site, then list'],
  listing_suspended: ['Listing is suspended by the platform', 'Ask platform operations why'],
  outage_not_eligible: ['Outage cancellation is not available yet', 'Wait for the outage period or file feedback'],
  deposit_insufficient: ['The supplier\'s deposit is short; new subscriptions and top-ups are paused', 'Wait for the supplier to top it up'],
  buyer_cap_exceeded: ['Over the platform\'s prepaid cap for one supplier', 'Use the balance first or pick another supplier'],
  risk_unacknowledged: ['The risk notice is not acknowledged', 'Read and tick it, then retry'],
  trial_used: ['The trial was used already', 'Buy it instead'],
  purchases_paused: ['New purchases are paused', 'Retry later'],
  insufficient_balance: ['Insufficient balance', 'Top up and retry'],
  load_floor_exceeded: ['Node load exceeds the offer\'s floor', 'Lower the load or adjust the offer'],
  plugin_unavailable: ['A needed plugin is not in the supply', 'Ask the supplier to include it, or drop the setting'],
  upstream_terms_exceeded: ['Resale terms are looser than the upstream\'s', 'Tighten them to the upstream terms'],
  resale_forbidden: ['The upstream forbids resale', 'Use an upstream that allows it, or keep it for own use'],
  forbidden: ['You lack the permission', 'Ask an administrator with it'],
  not_found: ['Not found or not yours', 'Refresh and retry'],
  conflict: ['The state changed', 'Refresh and retry'],
  invalid: ['The request is not valid', 'Check and retry'],
  unsupported: ['The market does not support this yet', 'Wait for a market upgrade'],
  market_unavailable: ['The market cannot be reached', 'Retry later; orders and supply are not stopped'],
  market_feature_unavailable: ['The market has not opened this yet', 'Wait for a market upgrade'],
  market_response_invalid: ['The market answered with invalid data', 'Retry later; contact the platform if it persists'],
  port_limit: ['More ports than the supply allows', 'Use fewer ports or a supply with more'],
  websocket_not_allowed: ['The supply does not allow WebSocket', 'Turn WebSocket off on the site, or switch supply'],
  http3_not_allowed: ['The supply does not allow HTTP/3', 'Turn HTTP/3 off on the site, or switch supply'],
  leaf_unavailable: ['The supplier\'s controller cannot handle it now', 'Retry later; ask your direct supplier if it persists'],
  pool_domain_limit: ['The supply\'s domain total is full', 'Use fewer domains or ask the supplier'],
  leaf_cname_unconfigured: ['The supplier has no supply CNAME domain configured', 'Ask your direct supplier'],
  icp_checker_unconfigured: ['The supplier requires ICP filing but has no checker', 'Ask your direct supplier'],
  icp_check_failed: ['The ICP check failed', 'Retry later'],
  icp_unfiled: ['The domain is not ICP filed and the supplier requires it', 'File it or use a supply without the rule'],
  cache_invalid: ['The cache settings are invalid', 'Check the site cache settings'],
  unsupported_cache: ['The supplier does not support these cache settings', 'Simplify the site cache settings'],
  access_invalid: ['The access control is invalid', 'Check the site access control'],
  unsupported_access: ['The supplier does not support this access control yet', 'Remove it'],
  rate_limit_invalid: ['The rate limit is invalid', 'Check the site rate limit'],
  unsupported_rate_limit: ['The supplier does not support this rate limit yet', 'Remove it'],
  autodefense_invalid: ['The automatic defence settings are invalid', 'Check them on the automatic defence page'],
  autodefense_capped: ['Automatic defence was tightened to the supply\'s cap', 'In effect; ask the supplier for more'],
  autodefense_unavailable: ['The supply has no automatic defence', 'Ask the supplier, or accept it is off'],
  site_disabled: ['The site is disabled', 'Enable it in the site list first'],
  no_enabled_origin: ['The site has no enabled origin', 'Enable at least one origin'],
  site_config_invalid: ['The site cannot be turned into a market config', 'Check its domains, ports and origins'],
  http3_unavailable: ['The supply\'s nodes do not support HTTP/3; the site is served over HTTP/2', 'Applied; ask the supplier to upgrade the node runtime for HTTP/3'],
  origin_route_geo_unmatched: ['This supply has no nodes in that location, so this conditional origin rule does not apply on it', 'The site is rolled out (the detail is the rule ID); use a supply with nodes there for the rule to apply'],
  origin_routes_invalid: ['The supplier cannot accept these conditional origin rules', 'Check them (each rule needs at least one condition)'],
  site_acl_rule: ['A site IP allow/block rule cannot be carried', 'Adjust it as the detail says, then roll out'],
  site_cc_rule: ['A site CC rule cannot be carried', 'Adjust it as the detail says, then roll out'],
  cc_invalid: ['The supplier cannot accept these CC rules', 'Check the site CC rules and CC settings'],
  unsupported_cc: ['The supplier does not support these CC rules yet', 'Resolve what the detail says, then roll out'],
  site_waf_policy: ['A site WAF rule cannot be carried', 'Adjust it as the detail says, then roll out'],
  waf_invalid: ['The supplier cannot accept these WAF rules', 'Check the site WAF rules'],
  unsupported_waf: ['The supplier cannot run this WAF setting (the detail is the missing CRS profile pack)', 'Ask the supplier to download that CRS profile pack, or change the site CRS profile'],
  site_origin_routes: ['A site conditional origin rule cannot be carried', 'Adjust it as the detail says, then roll out'],
  site_l2_custom: ['The site uses a custom L2 configuration of this platform\'s nodes, which the supplier does not have', 'Set the site L2 to follow the package or off, then roll out'],
  site_basic_auth: ['The site uses basic authentication, whose passwords are kept only as this platform\'s hashes', 'Turn basic authentication off in the site access settings, then roll out'],
  site_http_policy: ['The site runs an HTTP policy (origin request headers, upload limit, rewrites/redirects, CORS, hotlink protection), which the market config cannot carry yet', 'Disable the site HTTP policy, then roll out'],
  http_policy_invalid: ['The supplier cannot accept this HTTP policy', 'Check the site HTTP policy'],
  unsupported_http_policy: ['The supplier does not support HTTP policies yet', 'Disable the site HTTP policy, or roll out after the supplier upgrades'],
  site_origin_auth: ['The site\'s origin auth rules cannot be carried to the supplier yet', 'Resolve what the detail says, then roll out'],
  origin_auth_sealed: ['The supplier cannot open the origin auth credential (it is sealed for each supplier alone)', 'Preview again, then roll out; if it still fails ask the supplier to check its market identity (the detail is the rule ID)'],
  origin_auth_invalid: ['The supplier cannot accept this origin auth rule (the detail is the rule ID)', 'Check the bucket endpoint, region and credential validity; S3-compatible storage needs an egress policy of the same name on the supplier'],
  unsupported_origin_auth: ['The supplier does not support origin auth yet', 'Turn the site origin auth switch off, or roll out after the supplier upgrades'],
  origin_auth_delivery: ['The origin auth credentials have not reached the supplier nodes yet', 'The site is rolled out and the supplier retries by itself; the detail says why'],
  site_syncing: ['The supplier is syncing the site to its nodes', 'Nothing to do; this updates once it is in effect'],
  site_sync_failed: ['The supplier nodes failed to sync the site', 'The supplier retries once its nodes recover; contact the supplier if it persists'],
  security_activating: ['The security policies are activating on the supplier nodes', 'Nothing to do; this updates once they are active'],
  security_failed: ['A security policy failed to activate on the supplier nodes', 'Check the site WAF/CC/access settings and roll it out again, or contact the supplier'],
  origin_auth_delivering: ['The origin auth credentials are on their way to the supplier nodes', 'Nothing to do; this updates once delivered'],
  origin_auth_failed: ['The origin auth credentials could not reach the supplier nodes', 'Verify the credentials on the origin auth page and roll the site out again, or contact the supplier'],
  node_delivery_timeout: ['Not in effect on the supplier nodes for a long time; checking stopped', 'Roll the site out again, or ask the supplier to check its nodes'],
  status_unavailable: ['The supplier node status cannot be read for now', 'Retried automatically; contact the supplier if it keeps failing'],
  node_reason_unknown: ['The supplier returned a node status that is not recognised', 'Send the raw code to the supplier'],
  site_access_invalid: ['The supplier cannot accept these site access settings', 'Check the site access settings'],
  unsupported_site_access: ['The supplier does not support site access settings', 'Ask the supplier to upgrade, or clear the site access settings'],
}

const unknown: Record<OfferCopyLocale, Entry> = {
  'zh-CN': ['未识别的原因（{{code}}）', '把原码和请求 ID 发给直接供货方或平台'],
  'en-US': ['Unrecognised reason ({{code}})', 'Send the code and request ID to your direct supplier or the platform'],
}

const tables: Record<OfferCopyLocale, Record<string, Entry>> = { 'zh-CN': zhCN, 'en-US': enUS }

// Codes with a description, per language (tests keep the two in step).
export const marketReasonCodes: Record<OfferCopyLocale, string[]> = { 'zh-CN': Object.keys(zhCN), 'en-US': Object.keys(enUS) }

// marketReason describes code. The license proxy prefixes market codes with
// "market_" (seller site); a prefixed code is looked up without it as well.
export function marketReason(code: string, language?: string): MarketReason {
  const locale = offerCopyLocale(language)
  const table = tables[locale]
  const entry = table[code] ?? (code.startsWith('market_') ? table[code.slice('market_'.length)] : undefined)
  if (entry) return { code, known: true, reason: entry[0], next: entry[1] }
  const [reason, next] = unknown[locale]
  return { code, known: false, reason: reason.replace('{{code}}', code), next }
}

// Sub-reasons a rollout blocker carries in its detail (compile_local.go);
// any other detail (a policy name, a host) is shown as is.
const detailZH: Record<string, string> = {
  acl_rule_expiry: '规则设置了过期时间', acl_condition: '规则条件不是单个客户端 IP 段', acl_block_all: '默认拒绝且没有放行规则',
  node_region_geo: '规则按节点区域匹配，但所选区域未设置国家/省份（请在区域管理为该区域设置国家/省份）', ingress_source: '开启了按入口源地址回源', unavailable: '本机无法读取条件回源',
  waf_ip_list: '规则引用的 IP 名单已删除或本租户不可用', waf_crs_apps: '站点选择了 CRS 应用类型排除包', activation_pending: '供货方未开启安全策略激活',
  no_leaf: '站点还没有绑定可用的供给', origin_auth_off: '本平台未开启回源鉴权或市场运行时', credential: '规则使用的凭据未校验或已失效，请在回源鉴权页重新校验',
  waiting_nodes: '部分供货方节点离线或尚未就绪，上线后自动送达', no_nodes: '供货方还没有承载该站点的节点', retrying: '上次下发失败，等待重试',
  failed: '多次下发失败，已停止重试；重新下发站点后再试', node_rejected: '供货方节点拒收了凭据', credential_unreadable: '供货方读不出凭据，请重新预览并下发站点',
  publication_invalid: '供货方的回源鉴权发布无法生成', delivery_unavailable: '供货方下发服务暂时不可用',
}
const detailEN: Record<string, string> = {
  acl_rule_expiry: 'a rule expires', acl_condition: 'a rule is not one client IP range', acl_block_all: 'block by default with no allow rule',
  node_region_geo: 'a rule matches node regions without a country/province (set them in region management)', ingress_source: 'ingress source addresses are on', unavailable: 'conditional origins cannot be read',
  waf_ip_list: 'a rule names an IP list that is deleted or not usable by the tenant', waf_crs_apps: 'the site selects CRS application types', activation_pending: 'the supplier has not enabled security activation',
  no_leaf: 'the site has no usable supply bound yet', origin_auth_off: 'origin auth or the market runtime is off on this platform', credential: 'a rule\'s credential is unverified or no longer valid; verify it again on the origin auth page',
  waiting_nodes: 'some supplier nodes are offline or not ready; they get it once online', no_nodes: 'the supplier has no node carrying the site yet', retrying: 'the last delivery failed; a retry is due',
  failed: 'delivery failed repeatedly and the supplier gave up; roll the site out again', node_rejected: 'a supplier node refused the credentials', credential_unreadable: 'the supplier cannot read the credentials; preview and roll the site out again',
  publication_invalid: 'the supplier cannot build its origin auth publication', delivery_unavailable: 'the supplier delivery service is unavailable for now',
}

// marketReasonDetail is the detail of code in plain words.
export function marketReasonDetail(code: string, detail: string, language?: string): string {
  if (!['site_acl_rule', 'site_cc_rule', 'site_origin_routes', 'site_waf_policy', 'unsupported_waf', 'unsupported_cc', 'site_origin_auth', 'origin_auth_delivery',
    'origin_auth_delivering', 'origin_auth_failed'].includes(code)) return detail
  return (offerCopyLocale(language) === 'zh-CN' ? detailZH : detailEN)[detail] ?? detail
}

// Subscription close codes (market sla.Close*): exact ones, then the range.
const closeZH: Record<number, string> = {
  1: '买方主动退订', 2: '买方设置为不续费', 3: '续费价格条件不满足，未续',
  10001: '卖方下架了报价', 10002: '卖方退役了节点', 10003: '卖方因不稳定关闭', 10004: '卖方平稳退出', 10005: '卖方零在线节点超时，买方退订',
  20001: '余额用尽且超过宽限期', 20002: '连续违反 SLA', 20003: '隔离超过期限',
  30001: '合规下架', 30002: '欺诈处置', 30003: '争议裁决',
}
const closeEN: Record<number, string> = {
  1: 'Cancelled by the buyer', 2: 'Buyer chose not to renew', 3: 'Renewal price condition not met',
  10001: 'Seller delisted the offer', 10002: 'Seller retired the nodes', 10003: 'Seller closed it for instability', 10004: 'Seller exited', 10005: 'No online node past the limit; buyer cancelled',
  20001: 'Balance used up past the grace period', 20002: 'Repeated SLA breaches', 20003: 'Quarantine past its limit',
  30001: 'Compliance takedown', 30002: 'Fraud', 30003: 'Dispute ruling',
}

export function closeReason(code: number, language?: string): MarketReason {
  const zh = offerCopyLocale(language) === 'zh-CN'
  const exact = (zh ? closeZH : closeEN)[code]
  const side = code < 10000 ? (zh ? '买方' : 'buyer') : code < 20000 ? (zh ? '卖方' : 'seller')
    : code < 30000 ? (zh ? '系统' : 'system') : (zh ? '运营' : 'operations')
  const reason = exact ?? (zh ? `${side}关闭（${code}）` : `Closed by ${side} (${code})`)
  return { code: String(code), known: !!exact, reason, next: zh ? '订阅已结束；需要继续服务请重新购买' : 'The subscription ended; buy again to continue' }
}
