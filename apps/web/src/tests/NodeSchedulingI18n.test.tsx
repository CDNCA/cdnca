import type { i18n as I18nInstance, Resource } from 'i18next'
import { vi } from 'vitest'

import { pageRequests, shellBackgroundRequests } from '../test/shellRequests'

type TranslationTree = { [key: string]: string | TranslationTree }

const nodeSchedulingLocales = ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const
type NodeSchedulingLocale = (typeof nodeSchedulingLocales)[number]
type VisibleLocale = Exclude<NodeSchedulingLocale, 'qps-Ploc'>
const cjkPattern = /[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]/
const protectedTokenPattern = /({{[^}]+}}|<[^>]+>)/g

type I18nListener = (...args: unknown[]) => void
type ObserverSnapshot = Record<string, Array<[I18nListener, number]>>
type ObserverRecord = Record<string, Map<I18nListener, number>>
interface NamespaceReporter {
  usedNamespaces: Record<string, true>
  addUsedNamespaces: (namespaces: readonly string[]) => void
  getUsedNamespaces: () => string[]
}
type I18nRuntime = I18nInstance & {
  observers: ObserverRecord
  reportNamespaces?: NamespaceReporter
  store: I18nInstance['store'] & { observers: ObserverRecord }
}

interface I18nSnapshot {
  resources: Resource
  namespaces: I18nInstance['options']['ns']
  observers: ObserverSnapshot
  storeObservers: ObserverSnapshot
  reportNamespaces: {
    instance: NamespaceReporter
    usedNamespaces: Record<string, true>
  } | undefined
  language: string
  languages: readonly string[]
  resolvedLanguage: string | undefined
  storage: Record<string, string>
  documentLanguage: string
}

interface IsolatedAppContext {
  app: typeof import('../App')
  i18nModule: typeof import('../i18n')
}

interface UnmountableView {
  unmount: () => void
}

interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason: unknown) => void
}

interface VisibleContractLeaf {
  key: string
  templates: Record<VisibleLocale, string>
  interpolation?: Record<string, string | number>
}

interface ObservedRequest {
  body: string | null
  credentials: RequestCredentials | undefined
  headers: Record<string, string>
  method: string
  pathname: string
  query: Record<string, string>
  rawURL: string
}

interface ExpectedRequest {
  action: string
  identity: string
  pathname: string
  query: Record<string, string>
}

interface FixedLocaleLeaf {
  zh: string
  en: string
}

const fixedLocaleOracle = {
  "titles.lineGroups": { zh: "线路分组", en: "Line Groups" },
  "titles.l2Topology": { zh: "L2 配置", en: "L2 Configuration" },
  "titles.l2Detail": { zh: "L2 拓扑详情", en: "L2 Topology Details" },
  "titles.createGroup": { zh: "新增线路分组", en: "Add Line Group" },
  "titles.editGroup": { zh: "编辑线路分组", en: "Edit Line Group" },
  "titles.createTopology": { zh: "新增 L2 配置", en: "Add L2 Configuration" },
  "titles.decision": { zh: "调度决策验证", en: "Scheduling Decision Check" },
  "titles.revision": { zh: "历史版本", en: "Revision History" },
  "titles.targetSnapshot": { zh: "L1 目标快照", en: "L1 Target Snapshot" },
  "tabs.configuration": { zh: "L2配置", en: "L2 Configuration" },
  "tabs.conditions": { zh: "L2条件", en: "L2 Conditions" },
  "states.loading": { zh: "正在加载节点调度配置", en: "Loading node scheduling configuration" },
  "states.targetSnapshotLoading": { zh: "正在加载 L1 目标快照", en: "Loading L1 target snapshot" },
  "actions.add": { zh: "新增分组", en: "Add Group" },
  "actions.delete": { zh: "删除", en: "Delete" },
  "actions.confirm": { zh: "确定", en: "Confirm" },
  "actions.createConfiguration": { zh: "新增配置", en: "Add Configuration" },
  "actions.createTopology": { zh: "新增 L2 配置", en: "Add L2 Configuration" },
  "actions.create": { zh: "创建", en: "Create" },
  "actions.edit": { zh: "编辑", en: "Edit" },
  "actions.configureResolution": { zh: "配置解析", en: "Set Resolution" },
  "actions.deleteLineGroup": { zh: "删除线路分组", en: "Delete Line Group" },
  "actions.setPlatformDefault": { zh: "设为平台默认", en: "Set as Platform Default" },
  "actions.unsetPlatformDefault": { zh: "取消平台默认", en: "Unset Platform Default" },
  "notices.platformDefaultSet": { zh: "已设为平台默认线路组，没选套餐的网站用它生成 CNAME", en: "Set as the platform default line group; sites without a package use it for CNAME" },
  "notices.platformDefaultUnset": { zh: "已取消平台默认线路组", en: "Platform default line group unset" },
  "notices.platformDefaultTag": { zh: "平台默认", en: "Platform default" },
  "notices.backupActiveTag": { zh: "{{family}} 备用 IP 中", en: "{{family}} on backup IPs" },
  "notices.backupActiveDetail": {
    zh: "{{family}} 主 IP 不可用，正在解析备用 IP {{addresses}}，启用于 {{changedAt}}。主 IP 恢复后自动切回。",
    en: "{{family}} primary IPs are unavailable; resolving to backup IPs {{addresses}} since {{changedAt}}. Switches back automatically when the primary IPs recover.",
  },
  "actions.save": { zh: "保存", en: "Save" },
  "actions.cancel": { zh: "取消", en: "Cancel" },
  "actions.search": { zh: "查询", en: "Search" },
  "actions.applyScope": { zh: "读取租户", en: "Load Tenant" },
  "actions.clear": { zh: "清除", en: "Clear" },
  "actions.retry": { zh: "重试", en: "Retry" },
  "actions.retrySame": { zh: "使用同一请求重试", en: "Retry Same Request" },
  "actions.refreshReconcile": { zh: "刷新并对账", en: "Refresh and Reconcile" },
  "actions.previous": { zh: "上一页", en: "Previous" },
  "actions.next": { zh: "下一页", en: "Next" },
  "actions.detail": { zh: "配置", en: "Configure" },
  "actions.addEndpoint": { zh: "添加 IP", en: "Add IP" },
  "actions.deleteEndpoint": { zh: "删除 IP", en: "Delete IP" },
  "actions.moveUp": { zh: "上移", en: "Move Up" },
  "actions.moveDown": { zh: "下移", en: "Move Down" },
  "actions.createSnapshot": { zh: "保存 L1 目标快照", en: "Save L1 Target Snapshot" },
  "actions.rollback": { zh: "回滚", en: "Roll Back" },
  "actions.confirmRollback": { zh: "确认回滚", en: "Confirm Rollback" },
  "actions.evaluate": { zh: "验证决策", en: "Check Decision" },
  "actions.loadRevision": { zh: "加载历史版本", en: "Load Revision" },
  "actions.back": { zh: "返回 L2 配置", en: "Back to L2 Configuration" },
  "actions.refresh": { zh: "刷新", en: "Refresh" },
  "filters.searchLabel": { zh: "搜索当前列表", en: "Search Current List" },
  "filters.searchPlaceholder": { zh: "填名称或解析值搜索", en: "Search by name or resolved value" },
  "filters.regionLabel": { zh: "区域", en: "Region" },
  "filters.allRegions": { zh: "所有区域", en: "All Regions" },
  "filters.pageSizeLabel": { zh: "每页数量", en: "Items per Page" },
  "filters.pageSize": { zh: "{{count}} 条/页", en: "{{count}} per page" },
  "filters.targetScope": { zh: "目标租户作用域 ID", en: "Target Tenant Scope ID" },
  "filters.targetScopePlaceholder": { zh: "平台会话必须输入租户作用域 UUID", en: "Platform sessions require a tenant scope UUID" },
  "columns.id": { zh: "ID", en: "ID" },
  "columns.name": { zh: "名称", en: "Name" },
  "columns.region": { zh: "区域", en: "Region" },
  "columns.addresses": { zh: "解析值", en: "Resolved Values" },
  "columns.statistics": { zh: "统计", en: "Statistics" },
  "columns.l2Configuration": { zh: "L2回源配置", en: "L2 origin configuration" },
  "columns.sort": { zh: "排序", en: "Order" },
  "columns.endpointCount": { zh: "IP 数量", en: "IP Count" },
  "columns.health": { zh: "健康状态", en: "Health" },
  "columns.revision": { zh: "版本", en: "Revision" },
  "columns.mode": { zh: "模式", en: "Mode" },
  "columns.loadMethod": { zh: "负载方式", en: "Load Method" },
  "columns.actions": { zh: "操作", en: "Actions" },
  "columns.source": { zh: "L1 目标节点", en: "L1 Target Node" },
  "columns.target": { zh: "L2 目标节点", en: "L2 Target Node" },
  "columns.address": { zh: "IP 地址", en: "IP Address" },
  "columns.port": { zh: "端口", en: "Port" },
  "columns.carrier": { zh: "运营商", en: "Carrier" },
  "columns.priority": { zh: "备用顺序", en: "Failover Order" },
  "columns.weight": { zh: "权重", en: "Weight" },
  "columns.enabled": { zh: "启用", en: "Enabled" },
  "columns.status": { zh: "状态", en: "Status" },
  "values.placeholder": { zh: "—", en: "—" },
  "values.unavailable": { zh: "未提供", en: "Not provided" },
  "values.deleteUnavailable": { zh: "当前接口未提供删除能力", en: "The current API does not provide delete capability" },
  "values.selectBeforeDelete": { zh: "请选择线路分组!", en: "Select at least one line group to delete" },
  "values.ipCount": { zh: "{{count}} 个 IP", en: "{{count}} IPs" },
  "values.healthyCount": { zh: "健康 {{count}}", en: "{{count}} healthy" },
  "values.lineGroupStatistics": { zh: "节点数({{nodeCount}}个) 网站数({{siteCount}}个) 转发数({{forwardCount}}个)", en: "Nodes ({{nodeCount}}) Sites ({{siteCount}}) Forwards ({{forwardCount}})" },
  "values.enabled": { zh: "已启用", en: "Enabled" },
  "values.disabled": { zh: "已禁用", en: "Disabled" },
  "values.healthy": { zh: "健康", en: "Healthy" },
  "values.unhealthy": { zh: "故障", en: "Unhealthy" },
  "values.unknown": { zh: "未知", en: "Unknown" },
  "values.l1ToL2": { zh: "L1 到 L2", en: "L1 to L2" },
  "values.orderedWeighted": { zh: "有序备用 + 权重", en: "Ordered Failover + Weight" },
  "values.weighted_baseline": { zh: "简单权重", en: "Simple Weighting" },
  "values.weighted_rendezvous": { zh: "加权 Rendezvous", en: "Weighted Rendezvous" },
  "values.p2c_least_loaded": { zh: "P2C 最低负载", en: "P2C Least Loaded" },
  "values.advanced": { zh: "高级", en: "Advanced" },
  "values.simpleDefaults": { zh: "简单默认", en: "Simple Defaults" },
  "values.defaultRegion": { zh: "默认", en: "Default" },
  "values.failoverPrimaryOffline": { zh: "有主IP下线时", en: "When a primary IP goes offline" },
  "values.failoverOnlineLessThanBackup": { zh: "在线IP数少于备用IP数时", en: "When online IPs are fewer than standby IPs" },
  "values.yes": { zh: "是", en: "Yes" },
  "values.no": { zh: "否", en: "No" },
  "form.name": { zh: "分组名称", en: "Group Name" },
  "form.namePlaceholder": { zh: "例如：华东主线路", en: "For example, East China Primary" },
  "form.probeInterval": { zh: "探测间隔（毫秒）", en: "Probe Interval (ms)" },
  "form.probeTimeout": { zh: "探测超时（毫秒）", en: "Probe Timeout (ms)" },
  "form.failureThreshold": { zh: "连续失败阈值", en: "Consecutive Failure Threshold" },
  "form.recoveryThreshold": { zh: "连续恢复阈值", en: "Consecutive Recovery Threshold" },
  "form.failureDebounce": { zh: "失败防抖（毫秒）", en: "Failure Debounce (ms)" },
  "form.recoveryDebounce": { zh: "恢复防抖（毫秒）", en: "Recovery Debounce (ms)" },
  "form.endpointID": { zh: "线路 IP ID", en: "Line IP ID" },
  "form.nodeID": { zh: "L2 节点 ID", en: "L2 Node ID" },
  "form.address": { zh: "IP 地址", en: "IP Address" },
  "form.port": { zh: "端口", en: "Port" },
  "form.region": { zh: "区域", en: "Region" },
  "form.carrier": { zh: "运营商", en: "Carrier" },
  "form.carrierHelp": { zh: "填电信/联通/移动时，该IP还会写入网站CNAME对应的运营商线路；区域为境外（如香港、美国）时写入境外线路；BGP或留空只在默认线路。服务商不支持的线路不写。", en: "Telecom, Unicom or Mobile also puts this IP on that carrier line of the site CNAME; a region outside the mainland (for example Hong Kong or US) puts it on the overseas line; BGP or empty stays on the default line only. Lines the DNS provider lacks are not written." },
  "form.priority": { zh: "备用顺序", en: "Failover Order" },
  "form.weight": { zh: "权重", en: "Weight" },
  "form.enabled": { zh: "启用", en: "Enabled" },
  "form.endpoints": { zh: "线路 IP 与备用顺序", en: "Line IPs and Failover Order" },
  "form.l1NodeIDs": { zh: "L1 目标节点 ID", en: "L1 Target Node IDs" },
  "form.l1NodeIDsPlaceholder": { zh: "每行一个 UUID，将按规范集合保存", en: "Enter one UUID per line; values are saved as a canonical set" },
  "form.sourceRevision": { zh: "源版本", en: "Source Revision" },
  "form.rollbackRevision": { zh: "回滚到版本", en: "Roll Back to Revision" },
  "form.selectorRegion": { zh: "决策区域", en: "Decision Region" },
  "form.selectorCarrier": { zh: "决策运营商", en: "Decision Carrier" },
  "form.requestedMode": { zh: "请求模式", en: "Requested Mode" },
  "form.stableKey": { zh: "稳定键", en: "Stable Key" },
  "form.stableKeyPlaceholder": { zh: "例如：site:example.com", en: "For example, site:example.com" },
  "form.advancedSettings": { zh: "高级设置", en: "Advanced Settings" },
  "form.referenceRegion": { zh: "区域：", en: "Region:" },
  "form.referenceName": { zh: "名称：", en: "Name:" },
  "form.referenceNamePlaceholder": { zh: "请输入线路分组名称", en: "Enter a line group name" },
  "form.referenceRegionPlaceholder": { zh: "例如：华东", en: "For example, East China" },
  "form.referenceNote": { zh: "备注：", en: "Note:" },
  "form.referenceNotePlaceholder": { zh: "请输入备注", en: "Enter a note" },
  "form.referenceSort": { zh: "排序：", en: "Sort order:" },
  "form.referenceSortPlaceholder": { zh: "请输入排序", en: "Enter the sort order" },
  "form.referenceResolvedValue": { zh: "解析值：", en: "Resolved value:" },
  "form.referenceResolvedValuePlaceholder": { zh: "留空随机生成 (不填域名部分)", en: "Leave blank to generate randomly (without the domain part)" },
  "form.ipv4ResolvedValue": { zh: "IPv4解析值：", en: "IPv4 resolved value:" },
  "form.ipv4ResolvedValuePlaceholder": { zh: "留空随机生成（不填域名部分）", en: "Leave blank to generate randomly (without the domain part)" },
  "form.l2Configuration": { zh: "L2回源配置：", en: "L2 origin configuration:" },
  "form.l2ConfigurationPlaceholder": { zh: "请选择", en: "Select" },
  "form.l2ConfigurationHelp": { zh: "选择“节点管理 > L2配置”中的配置（区域为空或与本线路组相同）；使用套餐默认 L2 的网站按该配置的模式、负载方式和节点权重回源。", en: "An L2 configuration from Nodes > L2 configuration (no region, or this line group's region). Sites using the package L2 reach their origin by its mode, load method and node weights." },
  "form.l2ConfigurationManage": { zh: "管理 L2配置", en: "Manage L2 configurations" },
  "form.failoverMode": { zh: "备用IP切换：", en: "Standby IP failover:" },
  "form.failoverModeHelp": { zh: "有主IP下线时：每下线一个主IP，按排序启用一个备用IP。在线IP数少于备用IP数时：在线主IP数少于备用IP数，启用全部备用IP。", en: "When a primary IP goes offline: each offline primary brings one standby IP online, in sort order. When online IPs are fewer than standby IPs: all standby IPs come online once fewer primaries are online than there are standbys." },
  "validation.required": { zh: "此项不能为空", en: "This field is required" },
  "validation.nameLength": { zh: "名称长度必须为 1 到 128 个字符", en: "Name must be between 1 and 128 characters" },
  "validation.uuid": { zh: "请输入有效的 UUID", en: "Enter a valid UUID" },
  "validation.ip": { zh: "请输入有效的 IPv4 或 IPv6 地址", en: "Enter a valid IPv4 or IPv6 address" },
  "validation.port": { zh: "端口必须为 1 到 65535", en: "Port must be between 1 and 65535" },
  "validation.priority": { zh: "备用顺序必须为 0 到 65535", en: "Failover order must be between 0 and 65535" },
  "validation.weight": { zh: "权重必须为 1 到 100", en: "Weight must be between 1 and 100" },
  "validation.probeInterval": { zh: "探测间隔必须为 1000 到 300000 毫秒", en: "Probe interval must be between 1000 and 300000 ms" },
  "validation.probeTimeout": { zh: "探测超时必须为 100 到 60000 毫秒，且不能大于探测间隔", en: "Probe timeout must be between 100 and 60000 ms and cannot exceed the probe interval" },
  "validation.threshold": { zh: "连续阈值必须为 1 到 20", en: "Consecutive threshold must be between 1 and 20" },
  "validation.debounce": { zh: "防抖时间必须为 0 到 3600000 毫秒", en: "Debounce must be between 0 and 3600000 ms" },
  "validation.endpoints": { zh: "至少需要一个线路 IP", en: "At least one line IP is required" },
  "validation.duplicateEndpoint": { zh: "线路 IP ID 或 IP 与端口不能重复", en: "Line IP IDs and IP/port pairs must be unique" },
  "validation.l1Targets": { zh: "至少需要一个不重复的 L1 节点 UUID", en: "At least one unique L1 node UUID is required" },
  "validation.targetScope": { zh: "请输入有效的目标租户作用域 UUID", en: "Enter a valid target tenant scope UUID" },
  "validation.stableKey": { zh: "稳定键长度必须为 1 到 1024 个字符", en: "Stable key must be between 1 and 1024 characters" },
  "validation.labelLength": { zh: "区域和运营商长度不能超过 64 个字符", en: "Region and carrier must be 64 characters or fewer" },
  "validation.resolvedValue": { zh: "解析值必须留空或使用 1 到 63 位小写字母、数字和连字符，且首尾不能为连字符", en: "Resolved value must be blank or a 1-63 character lowercase DNS label using letters, numbers, and hyphens, without a leading or trailing hyphen" },
  "validation.note": { zh: "备注不能超过 512 个字符且不能包含控制字符", en: "Note must be 512 characters or fewer and cannot contain control characters" },
  "validation.sortOrder": { zh: "排序必须为 1 到 2147483647", en: "Sort order must be between 1 and 2147483647" },
  "aria.lineGroupActions": { zh: "线路分组操作", en: "Line Group Actions" },
  "aria.lineGroupFilters": { zh: "线路分组筛选", en: "Line Group Filters" },
  "empty.groups": { zh: "暂无线路分组", en: "No line groups" },
  "empty.filtered": { zh: "当前列表无匹配线路分组", en: "No line groups match the current filters" },
  "empty.topology": { zh: "暂无 L2 配置", en: "No L2 configuration" },
  "empty.edges": { zh: "当前版本没有可展示的拓扑关系", en: "This revision has no topology connections to display" },
  "errors.forbiddenTitle": { zh: "无权查看节点调度配置", en: "You cannot view node scheduling configuration" },
  "errors.forbiddenDescription": { zh: "当前账号缺少 node_scheduling.read 权限", en: "Your account lacks the node_scheduling.read permission" },
  "errors.platformWrite": { zh: "平台会话仅允许读取和验证决策，不能写入租户线路配置", en: "Platform sessions can read and check decisions but cannot change tenant line configuration" },
  "errors.tenantReadOnly": { zh: "当前租户账号仅有查看权限，不能修改线路配置", en: "Your tenant account has read-only access and cannot change line configuration" },
  "errors.targetScopeRequired": { zh: "平台会话需要指定目标租户作用域后才能读取", en: "Select a target tenant scope before loading configuration with a platform session" },
  "errors.l2_condition_invalid_regex": { zh: "条件中有无效的正则表达式（不支持零宽断言和反向引用），请修改后再保存", en: "A rule has an invalid regular expression (lookaround and backreferences are not supported). Fix it and save again." },
  "errors.loadFailed": { zh: "节点调度配置加载失败", en: "Node scheduling configuration could not be loaded" },
  "errors.targetSnapshotLoadFailed": { zh: "L1 目标快照加载失败", en: "The L1 target snapshot could not be loaded" },
  "errors.writeFailed": { zh: "线路配置保存失败", en: "Line configuration could not be saved" },
  "errors.deleteFailed": { zh: "线路分组删除失败", en: "The line group could not be deleted" },
  "errors.snapshotFailed": { zh: "L1 目标快照保存失败", en: "The L1 target snapshot could not be saved" },
  "errors.rollbackFailed": { zh: "线路配置回滚失败", en: "Line configuration could not be rolled back" },
  "errors.decisionFailed": { zh: "调度决策验证失败", en: "The scheduling decision check failed" },
  "errors.revisionFailed": { zh: "历史版本加载失败", en: "The revision could not be loaded" },
  "errors.outcomeUnknown": { zh: "操作结果待确认", en: "Operation Outcome Unknown" },
  "errors.outcomeUnknownDescription": { zh: "原请求内容、前置版本和幂等键已冻结。只能原样重试，或刷新后按当前版本对账。", en: "The original request, prerequisite revision, and idempotency key are frozen. Retry it unchanged, or refresh and reconcile against the current revision." },
  "errors.withRequestId": { zh: "{{message}}（请求 ID：{{requestId}}）", en: "{{message}} (Request ID: {{requestId}})" },
  "errors.node_scheduling_invalid_request": { zh: "请求字段、拓扑或前置条件无效", en: "The request fields, topology, or prerequisites are invalid" },
  "errors.node_scheduling_unauthenticated": { zh: "会话已失效，请重新登录", en: "Your session has expired. Sign in again." },
  "errors.node_scheduling_permission_denied": { zh: "当前账号没有执行此操作的权限", en: "Your account cannot perform this operation" },
  "errors.node_scheduling_platform_write_forbidden": { zh: "平台会话不能写入租户线路配置", en: "Platform sessions cannot change tenant line configuration" },
  "errors.node_scheduling_not_found": { zh: "线路组或版本不存在", en: "The line group or revision does not exist" },
  "errors.node_scheduling_name_conflict": { zh: "线路组名称已存在", en: "A line group with this name already exists" },
  "errors.node_scheduling_revision_conflict": { zh: "线路组已被其他操作修改，请刷新后重试", en: "Another operation changed this line group. Refresh and try again." },
  "errors.node_scheduling_idempotency_conflict": { zh: "幂等键已绑定到不同请求，请重新操作", en: "This idempotency key is already bound to a different request. Start the operation again." },
  "errors.node_scheduling_reference_conflict": { zh: "线路组正被其他活动配置引用，请先解除引用", en: "This line group is referenced by another active configuration. Remove the reference first." },
  "errors.node_scheduling_endpoint_address_not_on_node": { zh: "绑定节点的IP必须是该节点的主IP或子IP", en: "An IP bound to a node must be that node's primary IP or one of its secondary IPs" },
  "errors.node_scheduling_invalid_sort_order": { zh: "排序必须为不小于 1 的整数", en: "Sort order must be an integer of at least 1" },
  "errors.node_scheduling_no_healthy_endpoint": { zh: "当前区域没有可用的健康 IP", en: "No healthy IP is available for the current region" },
  "errors.topology_cycle_rejected": { zh: "拓扑包含环路、节点指向自身或空目标组", en: "The topology contains a cycle, a self-reference, or an empty target group" },
  "errors.node_scheduling_target_snapshot_conflict": { zh: "L1 目标快照与当前拓扑冲突", en: "The L1 target snapshot conflicts with the current topology" },
  "errors.node_scheduling_target_snapshot_unavailable": { zh: "L1 目标快照当前不可用", en: "The L1 target snapshot is currently unavailable" },
  "errors.node_scheduling_unavailable": { zh: "节点调度服务暂不可用", en: "The node scheduling service is temporarily unavailable" },
  "errors.requestFailed": { zh: "请求失败，请稍后重试", en: "The request failed. Try again later." },
  "errors.resolutionUnavailable": { zh: "当前 Control API 尚未提供线路分组解析配置契约。", en: "The Control API does not yet provide a line-group resolution configuration contract." },
  "dialogs.deleteTitle": { zh: "删除确认", en: "Delete Confirmation" },
  "dialogs.deleteDescription": { zh: "是否删除线路分组 id:{{ids}}", en: "Delete line group id:{{ids}}?" },
  "notices.created": { zh: "线路组已创建", en: "Line group created" },
  "notices.createdEmpty": { zh: "线路组「{{name}}」已创建，还没有节点 IP", en: "Line group \"{{name}}\" created with no node IPs yet" },
  "notices.createdEmptyNext": { zh: "下一步：点「配置解析」添加节点 IP，线路组才会解析到节点。", en: "Next: choose Set Resolution to add node IPs; the line group resolves to nodes only after that." },
  "notices.updated": { zh: "线路组新版本已保存", en: "A new line group revision was saved" },
  "notices.deleted": { zh: "线路组已删除", en: "Line group deleted" },
  "notices.batchDeleted": { zh: "已删除 {{count}} 个线路组", en: "{{count}} line groups deleted" },
  "notices.snapshotCreated": { zh: "L1 目标快照已保存", en: "L1 target snapshot saved" },
  "notices.rolledBack": { zh: "历史配置已复制为新的当前版本", en: "The previous configuration was copied into a new current revision" },
  "pagination.page": { zh: "第 {{page}} / {{pages}} 页", en: "Page {{page}} of {{pages}}" },
  "pagination.total": { zh: "共 {{count}} 条", en: "{{count}} total" },
  "topology.description": { zh: "每个 L1 目标节点都连接到当前线路组中的全部 L2 节点。", en: "Each L1 target node connects to every L2 node in the current line group." },
  "topology.revision": { zh: "当前线路组版本：{{revision}}", en: "Current line group revision: {{revision}}" },
  "topology.endpoint": { zh: "{{address}}:{{port}} · 优先级 {{priority}} · 权重 {{weight}}", en: "{{address}}:{{port}} · priority {{priority}} · weight {{weight}}" },
  "topology.snapshotRevision": { zh: "目标快照版本：{{revision}}", en: "Target snapshot revision: {{revision}}" },
  "decision.requested": { zh: "请求模式", en: "Requested Mode" },
  "decision.effective": { zh: "实际模式", en: "Effective Mode" },
  "decision.reason": { zh: "原因码", en: "Reason Code" },
  "decision.fallback": { zh: "已回退", en: "Fallback Used" },
  "decision.selected": { zh: "选中 IP", en: "Selected IP" },
  "decision.candidates": { zh: "当前候选", en: "Current Candidates" },
  "decision.standby": { zh: "有序备用", en: "Ordered Failover" },
  "decision.baseline_weighted_selected": { zh: "按简单权重选中", en: "Selected by simple weighting" },
  "decision.weighted_rendezvous_selected": { zh: "按加权 Rendezvous 选中", en: "Selected by weighted Rendezvous" },
  "decision.p2c_least_loaded_selected": { zh: "按 P2C 最低负载选中", en: "Selected by P2C least loaded" },
  "decision.telemetry_insufficient": { zh: "负载样本不足，已回退", en: "Insufficient load samples; fallback used" },
  "decision.telemetry_stale_fallback": { zh: "负载样本过期，已回退", en: "Load samples are stale; fallback used" },
  "decision.telemetry_unavailable_fallback": { zh: "遥测服务不可用，已回退", en: "Telemetry is unavailable; fallback used" },
  "decision.single_candidate_fallback": { zh: "仅有一个候选，已回退", en: "Only one candidate is available; fallback used" },
  "decision.no_healthy_endpoint": { zh: "没有健康候选", en: "No healthy candidates" },
  "rollback.title": { zh: "确认回滚线路配置？", en: "Roll back line configuration?" },
  "rollback.description": { zh: "历史版本不会重新激活；系统会把该配置复制为新的当前版本。", en: "The historical revision will not be reactivated. Its configuration will be copied into a new current revision." },
  "lineDetail.title": { zh: "解析配置", en: "Resolution Configuration" },
  "lineDetail.toolbars.actions": { zh: "解析配置操作", en: "Resolution configuration actions" },
  "lineDetail.toolbars.availableFilters": { zh: "可添加 IP 筛选", en: "Available IP filters" },
  "lineDetail.toolbars.configuredFilters": { zh: "已配置 IP 筛选", en: "Configured IP filters" },
  "lineDetail.actions.batchAdd": { zh: "批量添加", en: "Add in Batch" },
  "lineDetail.actions.batchStandby": { zh: "批量备用", en: "Set Standby in Batch" },
  "lineDetail.actions.enable": { zh: "启用", en: "Enable" },
  "lineDetail.actions.disable": { zh: "禁用", en: "Disable" },
  "lineDetail.actions.delete": { zh: "删除", en: "Delete" },
  "lineDetail.actions.more": { zh: "更多操作", en: "More Actions" },
  "lineDetail.actions.edit": { zh: "编辑", en: "Edit" },
  "lineDetail.filters.availableStatus": { zh: "可添加 IP 状态", en: "Available IP status" },
  "lineDetail.filters.availableHealth": { zh: "可添加 IP 在线状态", en: "Available IP online status" },
  "lineDetail.filters.availableSearch": { zh: "搜索可添加 IP", en: "Search available IPs" },
  "lineDetail.filters.configuredSearch": { zh: "搜索已配置 IP", en: "Search configured IPs" },
  "lineDetail.filters.region": { zh: "解析线路", en: "Resolution line" },
  "lineDetail.filters.searchPlaceholder": { zh: "输入IP或名称", en: "Enter an IP or name" },
  "lineDetail.columns.name": { zh: "名称", en: "Name" },
  "lineDetail.columns.ipAddress": { zh: "IP地址", en: "IP Address" },
  "lineDetail.columns.status": { zh: "状态", en: "Status" },
  "lineDetail.columns.onlineStatus": { zh: "在线状态", en: "Online Status" },
  "lineDetail.values.allStatuses": { zh: "全部状态", en: "All Statuses" },
  "lineDetail.values.allOnlineStatuses": { zh: "全部在线状态", en: "All Online Statuses" },
  "lineDetail.values.select": { zh: "请选择", en: "Select" },
  "lineDetail.empty.available": { zh: "暂无可添加 IP", en: "No available IPs" },
  "lineDetail.empty.configured": { zh: "暂无已配置 IP", en: "No configured IPs" },
  "lineDetail.selection.row": { zh: "选择行", en: "Select row" },
  "lineDetail.dialogs.batchAddTitle": { zh: "批量添加 IP", en: "Add IPs in Batch" },
  "lineDetail.dialogs.batchStandbyTitle": { zh: "批量设置备用 IP", en: "Set Standby IPs in Batch" },
  "lineDetail.dialogs.enableTitle": { zh: "启用解析 IP", en: "Enable Resolution IPs" },
  "lineDetail.dialogs.disableTitle": { zh: "禁用解析 IP", en: "Disable Resolution IPs" },
  "lineDetail.dialogs.editTitle": { zh: "编辑解析 IP", en: "Edit Resolution IP" },
  "lineDetail.dialogs.deleteTitle": { zh: "删除解析 IP", en: "Delete Resolution IP" },
  "lineDetail.dialogs.deleteDescription": { zh: "是否删除解析 IP {{address}}？", en: "Delete resolution IP {{address}}?" },
} satisfies Record<string, FixedLocaleLeaf>


function pseudoFromFixedOracle(value: string): string {
  const expanded = value.split(/({{[^}]+}}|<[^>]+>)/g).map((part) => {
    if (/^{{[^}]+}}$/.test(part) || /^<[^>]+>$/.test(part)) return part
    return [...part].map((character) => /\s/u.test(character) ? character : character.repeat(2)).join('')
  }).join('')
  return `［${expanded}］`
}

const fixedInterpolation: Partial<Record<keyof typeof fixedLocaleOracle, Record<string, string | number>>> = {
  'filters.pageSize': { count: 10 },
  'values.ipCount': { count: 2 },
  'values.healthyCount': { count: 1 },
  'values.lineGroupStatistics': { nodeCount: 1, siteCount: 3, forwardCount: 1 },
  'dialogs.deleteDescription': { ids: '7' },
  'notices.batchDeleted': { count: 2 },
  'pagination.page': { page: 1, pages: 1 },
  'pagination.total': { count: 2 },
}

const fixedVisibleContract = Object.fromEntries(
  Object.entries(fixedLocaleOracle).map(([key, leaf]) => [key, {
    key,
    templates: {
      'zh-CN': leaf.zh,
      'en-US': leaf.en,
      'qps-ploc': pseudoFromFixedOracle(leaf.zh),
    },
    interpolation: fixedInterpolation[key as keyof typeof fixedLocaleOracle],
  }]),
) as Record<keyof typeof fixedLocaleOracle, VisibleContractLeaf>

const visibleContract = {
  l2Title: fixedVisibleContract['titles.l2Topology'],
  detailTitle: fixedVisibleContract['titles.l2Detail'],
  lineGroupsTitle: fixedVisibleContract['titles.lineGroups'],
  targetScope: fixedVisibleContract['filters.targetScope'],
  targetScopePlaceholder: fixedVisibleContract['filters.targetScopePlaceholder'],
  searchLabel: fixedVisibleContract['filters.searchLabel'],
  searchPlaceholder: fixedVisibleContract['filters.searchPlaceholder'],
  pageSizeLabel: fixedVisibleContract['filters.pageSizeLabel'],
  pageSize: fixedVisibleContract['filters.pageSize'],
  page: fixedVisibleContract['pagination.page'],
  applyScope: fixedVisibleContract['actions.applyScope'],
  search: fixedVisibleContract['actions.search'],
  clear: fixedVisibleContract['actions.clear'],
  back: fixedVisibleContract['actions.back'],
  retry: fixedVisibleContract['actions.retry'],
  loading: fixedVisibleContract['states.loading'],
  platformWrite: fixedVisibleContract['errors.platformWrite'],
  loadFailed: fixedVisibleContract['errors.loadFailed'],
  unavailable: fixedVisibleContract['errors.node_scheduling_unavailable'],
  requestFailed: fixedVisibleContract['errors.requestFailed'],
}

const l2TopologyTitleByLocale = {
  'zh-CN': 'L2 配置',
  'en-US': 'L2 node configuration',
  'qps-ploc': '［L2~配置］',
} satisfies Record<VisibleLocale, string>

const l2ConfigFixture = {
  id: '3a3b3c3d-3333-4333-8333-333333333333',
  display_id: '7',
  tenant_scope_id: '4a4b4c4d-4444-4444-8444-444444444444',
  revision: 1,
  name: 'L2 alpha',
  region: 'cn-east',
  remark: '',
  mode: 'cache',
  load_method: 'rr',
  created_at: '2026-10-09T00:00:00Z',
  updated_at: '2026-10-09T00:00:00Z',
}

const allRouteVisibleContracts = Object.values(fixedVisibleContract)
const l2NodeSchedulingKeys = new Set([
  'actions.previous',
  'actions.next',
  'actions.retry',
  'actions.retrySame',
  'actions.refreshReconcile',
])
const routeVisibleContract = {
  l2: [
    ...allRouteVisibleContracts.filter(({ key }) => l2NodeSchedulingKeys.has(key) || key.startsWith('errors.')),
    { key: 'nodeL2Topology.filters.region', templates: { 'zh-CN': '区域', 'en-US': 'Region', 'qps-ploc': '［区域］' } },
  ],
  detail: [
    ...allRouteVisibleContracts.filter(({ key }) => key === 'actions.back' || key === 'lineDetail.actions.more'
      || l2NodeSchedulingKeys.has(key) || key.startsWith('errors.')),
    { key: 'nodeL2Topology.nodes.available', templates: { 'zh-CN': 'L2节点列表', 'en-US': 'Available L2 nodes', 'qps-ploc': '［L2节点列表］' } },
    { key: 'nodeL2Topology.nodes.configured', templates: { 'zh-CN': '已配置的L2节点', 'en-US': 'Configured L2 nodes', 'qps-ploc': '［已配置的L2节点］' } },
    { key: 'nodeL2Topology.nodes.add', templates: { 'zh-CN': '批量添加', 'en-US': 'Add nodes', 'qps-ploc': '［批量添加］' } },
    { key: 'nodeL2Topology.nodes.configuration', templates: { 'zh-CN': 'L2配置', 'en-US': 'L2 configuration', 'qps-ploc': '［L2配置］' } },
    { key: 'nodeL2Topology.filters.region', templates: { 'zh-CN': '区域', 'en-US': 'Region', 'qps-ploc': '［区域］' } },
  ],
  lineGroups: allRouteVisibleContracts.filter(({ key }) => key !== 'actions.applyScope'),
} satisfies Record<string, readonly VisibleContractLeaf[]>
function keyShape(value: unknown): unknown {
  if (!value || typeof value !== 'object') return typeof value
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, keyShape(child)]))
}

function stringLeaves(tree: TranslationTree, prefix = ''): Array<{ path: string; value: string }> {
  return Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [{ path, value }] : stringLeaves(value, path)
  })
}

type LocaleLeafMaps = Record<NodeSchedulingLocale, Map<string, string>>

function expectLocaleBundlesMatchFixedOracle(leaves: LocaleLeafMaps): void {
  const fixedPaths = Object.keys(fixedLocaleOracle).sort()
  for (const locale of nodeSchedulingLocales) {
    expect([...leaves[locale].keys()].sort(), `${locale} fixed oracle paths`).toEqual(fixedPaths)
  }
  for (const [path, expected] of Object.entries(fixedLocaleOracle)) {
    const pseudo = pseudoFromFixedOracle(expected.zh)
    const expectedByLocale: Record<NodeSchedulingLocale, string> = {
      'zh-CN': expected.zh,
      'en-US': expected.en,
      'qps-ploc': pseudo,
      'qps-Ploc': pseudo,
    }
    for (const locale of nodeSchedulingLocales) {
      expect(leaves[locale].get(path), `${locale} fixed oracle ${path}`).toBe(expectedByLocale[locale])
    }
  }
}

function placeholderSet(value: string): string[] {
  return [...new Set(value.match(/{{[^}]+}}/g) ?? [])].sort()
}

function markupSet(value: string): string[] {
  return [...new Set(value.match(/<[^>]+>/g) ?? [])].sort()
}

function expectPseudoExpansion(source: string, pseudoBody: string, label: string): void {
  let offset = 0
  for (const match of source.matchAll(/\{\{[^}]+\}\}|<[^>]+>|[\s\S]/gu)) {
    const token = match[0]
    const protectedToken = token.startsWith('{{') || token.startsWith('<')
    const expectedToken = protectedToken || /\s/u.test(token) ? token : token.repeat(2)
    expect(pseudoBody.slice(offset, offset + expectedToken.length), `${label} token ${token}`).toBe(expectedToken)
    offset += expectedToken.length
  }
  expect(offset, `${label} consumed length`).toBe(pseudoBody.length)
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, reject, resolve }
}

function unavailableResponse(): Response {
  return new Response(JSON.stringify({
    error: { code: 'node_scheduling_unavailable', message: 'server-only failure detail' },
  }), { status: 503, headers: { 'Content-Type': 'application/json' } })
}

function snapshotObservers(i18n: I18nInstance): ObserverSnapshot {
  return snapshotObserverRecord((i18n as I18nRuntime).observers)
}

function snapshotObserverRecord(observers: ObserverRecord): ObserverSnapshot {
  return Object.fromEntries(Object.entries(observers).map(([event, listeners]) => [
    event,
    [...listeners.entries()],
  ]))
}

function restoreObservers(i18n: I18nInstance, snapshot: ObserverSnapshot): void {
  restoreObserverRecord((i18n as I18nRuntime).observers, snapshot)
}

function restoreObserverRecord(target: ObserverRecord, snapshot: ObserverSnapshot): void {
  for (const event of Object.keys(target)) delete target[event]
  for (const [event, listeners] of Object.entries(snapshot)) target[event] = new Map(listeners)
}

function expectObserversRestored(i18n: I18nInstance, snapshot: ObserverSnapshot): void {
  expect(snapshotObservers(i18n)).toEqual(snapshot)
}

type ContractRoot = Element | readonly Element[]

// 加载失败改为 FeedbackWhen 弹窗（挂在 body）后，错误态的可见文案在页面根节点之外
function withFeedback(page: Element): Element[] {
  return [page, ...document.querySelectorAll('.cdnca-feedback')]
}

function renderedExactValues(root: ContractRoot): Set<string> {
  const values = new Set<string>()
  for (const element of (Array.isArray(root) ? root : [root]).flatMap((item: Element) => [item, ...item.querySelectorAll('*')])) {
    const text = element.textContent?.trim()
    if (text) values.add(text)
    // FeedbackWhen 的原因是裸文本节点、后面紧跟重试按钮，元素 textContent 会连在一起
    for (const node of element.childNodes) if (node.nodeType === Node.TEXT_NODE && node.textContent?.trim()) values.add(node.textContent.trim())
    for (const attribute of ['aria-label', 'placeholder', 'title']) {
      const value = element.getAttribute(attribute)?.trim()
      if (value) values.add(value)
    }
  }
  return values
}

function contractValue(contract: VisibleContractLeaf, locale: VisibleLocale): string {
  return contract.templates[locale].replace(/{{([^}]+)}}/g, (token, key: string) =>
    Object.hasOwn(contract.interpolation ?? {}, key) ? String(contract.interpolation?.[key]) : token)
}

function visibleContractLeaves(
  root: ContractRoot,
  contracts: readonly VisibleContractLeaf[],
  locale: VisibleLocale,
): VisibleContractLeaf[] {
  const visibleValues = renderedExactValues(root)
  const valueCounts = new Map<string, number>()
  for (const contract of contracts) {
    const value = contractValue(contract, locale)
    valueCounts.set(value, (valueCounts.get(value) ?? 0) + 1)
  }
  return contracts.filter((contract) => {
    const value = contractValue(contract, locale)
    return valueCounts.get(value) === 1 && visibleValues.has(value)
  })
}

function expectVisibleContractSwitched(
  root: ContractRoot,
  oldVisible: readonly VisibleContractLeaf[],
  oldLocale: VisibleLocale,
  nextLocale: VisibleLocale,
): void {
  const currentValues = renderedExactValues(root)
  for (const contract of oldVisible) {
    const oldValue = contractValue(contract, oldLocale)
    const nextValue = contractValue(contract, nextLocale)
    expect(currentValues, `${nextLocale} visible leaf ${contract.key}`).toContain(nextValue)
    if (oldValue !== nextValue) expect(currentValues, `old locale leaf ${contract.key}`).not.toContain(oldValue)
  }
}

function expectContractKeysVisible(
  root: ContractRoot,
  contracts: readonly VisibleContractLeaf[],
  locale: VisibleLocale,
  expectedKeys: readonly string[],
): VisibleContractLeaf[] {
  const visible = visibleContractLeaves(root, contracts, locale)
  expect(visible.map(({ key }) => key)).toEqual(expect.arrayContaining([...expectedKeys]))
  return visible
}

function observeRequest(input: RequestInfo | URL, init?: RequestInit): ObservedRequest {
  const rawURL = input instanceof Request ? input.url : String(input)
  const url = new URL(rawURL, window.location.origin)
  const headers = new Headers(input instanceof Request ? input.headers : init?.headers)
  return {
    body: init?.body === undefined || init.body === null ? null : String(init.body),
    credentials: input instanceof Request ? input.credentials : init?.credentials,
    headers: Object.fromEntries(headers.entries()),
    method: (input instanceof Request ? input.method : init?.method ?? 'GET').toUpperCase(),
    pathname: url.pathname,
    query: Object.fromEntries(url.searchParams.entries()),
    rawURL,
  }
}

function expectedRequestURL(expected: ExpectedRequest): string {
  return `${expected.pathname}${Object.keys(expected.query).length ? `?${new URLSearchParams(expected.query)}` : ''}`
}

function expectedRequestSignature(expected: ExpectedRequest, accessToken: string): string {
  return JSON.stringify({
    action: expected.action,
    authorization: `Bearer ${accessToken}`,
    body: null,
    credentials: 'include',
    method: 'GET',
    pathname: expected.pathname,
    query: expected.query,
    rawURL: expectedRequestURL(expected),
  })
}

function observedRequestSignature(actual: ObservedRequest, actions: readonly string[]): string {
  const requestID = actual.headers['x-request-id'] ?? ''
  const action = actions.find((candidate) => requestID.startsWith(`node-scheduling-${candidate}-`)) ?? '<invalid>'
  return JSON.stringify({
    action,
    authorization: actual.headers.authorization,
    body: actual.body,
    credentials: actual.credentials,
    method: actual.method,
    pathname: actual.pathname,
    query: actual.query,
    rawURL: actual.rawURL,
  })
}

function createKeyedRequestResolver<T extends ExpectedRequest>(
  requests: readonly T[],
  accessToken: string,
): (actual: ObservedRequest) => T {
  const actions = [...new Set(requests.map(({ action }) => action))]
  const remaining = new Map<string, T>()
  for (const request of requests) {
    const signature = expectedRequestSignature(request, accessToken)
    if (remaining.has(signature)) throw new Error(`duplicate request signature: ${request.identity}`)
    remaining.set(signature, request)
  }
  return (actual) => {
    const request = remaining.get(observedRequestSignature(actual, actions))
    if (!request) throw new Error(`unexpected request signature: ${actual.method} ${actual.rawURL}`)
    expectRequestContract(actual, request, accessToken)
    remaining.delete(expectedRequestSignature(request, accessToken))
    return request
  }
}

function observedRequestFor(
  expected: ExpectedRequest,
  accessToken: string,
  requestIDSuffix: string,
): ObservedRequest {
  return {
    body: null,
    credentials: 'include',
    headers: {
      authorization: `Bearer ${accessToken}`,
      'x-request-id': `node-scheduling-${expected.action}-${requestIDSuffix}`,
    },
    method: 'GET',
    pathname: expected.pathname,
    query: expected.query,
    rawURL: expectedRequestURL(expected),
  }
}

function expectRequestContract(
  actual: ObservedRequest,
  expected: ExpectedRequest,
  accessToken: string,
): void {
  expect(actual.rawURL, `${expected.identity} raw URL`).toBe(
    expectedRequestURL(expected),
  )
  expect(actual.pathname, `${expected.identity} route`).toBe(expected.pathname)
  expect(actual.query, `${expected.identity} query`).toEqual(expected.query)
  expect(actual.method, `${expected.identity} method`).toBe('GET')
  expect(actual.body, `${expected.identity} body`).toBeNull()
  expect(actual.credentials, `${expected.identity} credentials`).toBe('include')
  expect(actual.headers.authorization, `${expected.identity} actor`).toBe(`Bearer ${accessToken}`)
  expect(actual.headers['x-request-id'], `${expected.identity} request identity`).toMatch(
    new RegExp(`^node-scheduling-${expected.action}-`),
  )
  expect(Object.keys(actual.headers).sort(), `${expected.identity} headers`).toEqual([
    'authorization',
    'x-request-id',
  ])
}

function snapshotStorage(): Record<string, string> {
  const snapshot: Record<string, string> = {}
  for (let index = 0; index < window.localStorage.length; index += 1) {
    const key = window.localStorage.key(index)
    if (key !== null) snapshot[key] = window.localStorage.getItem(key) ?? ''
  }
  return snapshot
}

function restoreStorage(snapshot: Record<string, string>): void {
  window.localStorage.clear()
  for (const [key, value] of Object.entries(snapshot)) window.localStorage.setItem(key, value)
}

function snapshotI18n(i18n: I18nInstance): I18nSnapshot {
  const runtime = i18n as I18nRuntime
  return {
    resources: structuredClone(i18n.store.data) as Resource,
    namespaces: structuredClone(i18n.options.ns),
    observers: snapshotObservers(i18n),
    storeObservers: snapshotObserverRecord(runtime.store.observers),
    reportNamespaces: runtime.reportNamespaces ? {
      instance: runtime.reportNamespaces,
      usedNamespaces: structuredClone(runtime.reportNamespaces.usedNamespaces),
    } : undefined,
    language: i18n.language,
    languages: [...i18n.languages],
    resolvedLanguage: i18n.resolvedLanguage,
    storage: snapshotStorage(),
    documentLanguage: document.documentElement.lang,
  }
}

async function restoreI18n(i18n: I18nInstance, snapshot: I18nSnapshot): Promise<void> {
  const runtime = i18n as I18nRuntime
  let failure: unknown
  const attempt = (restore: () => void) => {
    try {
      restore()
    } catch (error) {
      failure ??= error
    }
  }

  attempt(() => { i18n.store.data = structuredClone(snapshot.resources) as Resource })
  attempt(() => { i18n.options.ns = structuredClone(snapshot.namespaces) })
  attempt(() => restoreObservers(i18n, snapshot.observers))
  attempt(() => restoreObserverRecord(runtime.store.observers, snapshot.storeObservers))
  const restoreReportNamespaces = () => {
    if (!snapshot.reportNamespaces) {
      delete runtime.reportNamespaces
      return
    }
    runtime.reportNamespaces = snapshot.reportNamespaces.instance
    runtime.reportNamespaces.usedNamespaces = structuredClone(snapshot.reportNamespaces.usedNamespaces)
  }
  attempt(restoreReportNamespaces)
  try {
    await i18n.changeLanguage(snapshot.language)
  } catch (error) {
    failure ??= error
  }
  attempt(() => {
    i18n.language = snapshot.language
    i18n.languages = [...snapshot.languages]
    i18n.resolvedLanguage = snapshot.resolvedLanguage
  })
  attempt(() => restoreObservers(i18n, snapshot.observers))
  attempt(() => restoreObserverRecord(runtime.store.observers, snapshot.storeObservers))
  attempt(restoreReportNamespaces)
  attempt(() => restoreStorage(snapshot.storage))
  attempt(() => { document.documentElement.lang = snapshot.documentLanguage })
  if (failure) throw failure
}

function expectSnapshotRestored(i18n: I18nInstance, snapshot: I18nSnapshot): void {
  const runtime = i18n as I18nRuntime
  expect(i18n.store.data).toEqual(snapshot.resources)
  expect(i18n.options.ns).toEqual(snapshot.namespaces)
  expectObserversRestored(i18n, snapshot.observers)
  expect(snapshotObserverRecord(runtime.store.observers)).toEqual(snapshot.storeObservers)
  expect(runtime.reportNamespaces).toBe(snapshot.reportNamespaces?.instance)
  expect(runtime.reportNamespaces?.usedNamespaces).toEqual(snapshot.reportNamespaces?.usedNamespaces)
  expect(i18n.language).toBe(snapshot.language)
  expect(i18n.languages).toEqual(snapshot.languages)
  expect(i18n.resolvedLanguage).toBe(snapshot.resolvedLanguage)
  expect(snapshotStorage()).toEqual(snapshot.storage)
  expect(document.documentElement.lang).toBe(snapshot.documentLanguage)
}

async function withIsolatedApp<T>(
  run: (context: IsolatedAppContext) => Promise<T>,
  loadApp: () => Promise<typeof import('../App')> = () => import('../App'),
): Promise<T> {
  const currentModule = await import('../i18n')
  const currentI18n = currentModule.default
  const snapshot = snapshotI18n(currentI18n)
  let result: T | undefined
  let failure: unknown

  try {
    const app = await loadApp()
    result = await run({ app, i18nModule: currentModule })
  } catch (error) {
    failure = error
  } finally {
    try {
      await restoreI18n(currentI18n, snapshot)
    } catch (error) {
      failure ??= error
    }
  }
  if (failure) throw failure
  expectSnapshotRestored(currentI18n, snapshot)
  return result as T
}

async function withProductionAppGraph<T>(run: (context: IsolatedAppContext) => Promise<T>): Promise<T> {
  vi.doUnmock('../App')
  vi.doUnmock('../i18n')
  vi.doUnmock('../pages/node-scheduling/messages')
  const entryModule = await import('../i18n')
  const entryI18n = entryModule.default
  const entrySnapshot = snapshotI18n(entryI18n)
  const instances = new Set<I18nInstance>([entryI18n])
  let result: T | undefined
  let failure: unknown

  try {
    await entryI18n.changeLanguage('zh-CN')
    window.localStorage.removeItem(entryModule.localeStorageKey)
    for (const locale of nodeSchedulingLocales) entryI18n.removeResourceBundle(locale, 'nodeScheduling')
    vi.resetModules()

    const app = await import('../App')
    const i18nModule = await import('../i18n')
    instances.add(i18nModule.default)
    // App 模块加载时会在非登录路径上预取控制台壳（壳模块的补充命名空间 + 全量资源），
    // 等它装完再进入用例，否则这些命名空间会在快照恢复之后才异步写入 store。
    await Promise.all([import('../components/AppShell'), i18nModule.loadFullResources()])
    result = await run({ app, i18nModule })
  } catch (error) {
    failure = error
  } finally {
    for (const instance of instances) {
      try {
        await restoreI18n(instance, entrySnapshot)
      } catch (error) {
        failure ??= error
      }
    }
    vi.doUnmock('../App')
    vi.doUnmock('../i18n')
    vi.doUnmock('../pages/node-scheduling/messages')
    vi.resetModules()
    try {
      const restoredModule = await import('../i18n')
      instances.add(restoredModule.default)
      await restoreI18n(restoredModule.default, entrySnapshot)
    } catch (error) {
      failure ??= error
    }
    for (const instance of instances) {
      try {
        expectSnapshotRestored(instance, entrySnapshot)
      } catch (error) {
        failure ??= error
      }
    }
  }

  if (failure) throw failure
  return result as T
}

async function withMountedSession<T, SessionState>(
  snapshotSession: () => SessionState,
  restoreSession: (snapshot: SessionState) => void,
  setupSession: () => void,
  renderView: () => UnmountableView,
  run: () => Promise<T>,
): Promise<T> {
  const entrySession = snapshotSession()
  const entryBodyChildren = [...document.body.childNodes]
  let view: UnmountableView | undefined
  let result: T | undefined
  let failure: unknown
  try {
    setupSession()
    view = renderView()
    result = await run()
  } catch (error) {
    failure = error
  } finally {
    try {
      view?.unmount()
    } catch (error) {
      failure ??= error
    }
    try {
      document.body.replaceChildren(...entryBodyChildren)
    } catch (error) {
      failure ??= error
    }
    try {
      restoreSession(entrySession)
    } catch (error) {
      failure ??= error
    }
  }
  if (failure) throw failure
  return result as T
}

describe('node scheduling i18n', () => {
  it('renders all three Node Scheduling routes from a clean default zh-CN App graph', async () => {
    await withProductionAppGraph(async ({
        app: { AppRoutes },
        i18nModule: { default: i18n, localeStorageKey },
      }) => {
      expect(i18n.language).toBe('zh-CN')
      expect(i18n.resolvedLanguage).toBe('zh-CN')
      expect(window.localStorage.getItem(localeStorageKey)).toBeNull()
      const bundles = Object.fromEntries(nodeSchedulingLocales.map((locale) => [
        locale,
        i18n.getResourceBundle(locale, 'nodeScheduling') as TranslationTree,
      ])) as Record<NodeSchedulingLocale, TranslationTree>
      const zh = i18n.getFixedT('zh-CN', 'nodeScheduling')
      expect([
        zh('titles.l2Topology'),
        zh('titles.l2Detail'),
        zh('titles.lineGroups'),
      ]).toEqual(['L2 配置', 'L2 拓扑详情', '线路分组'])

      for (const locale of nodeSchedulingLocales) {
        expect(i18n.hasResourceBundle(locale, 'nodeScheduling')).toBe(true)
        expect(keyShape(bundles[locale])).toEqual(keyShape(bundles['zh-CN']))
      }

      const leaves = Object.fromEntries(nodeSchedulingLocales.map((locale) => [
        locale,
        new Map(stringLeaves(bundles[locale]).map(({ path, value }) => [path, value])),
      ])) as LocaleLeafMaps
      expectLocaleBundlesMatchFixedOracle(leaves)
      const synchronizedMistake = Object.fromEntries(nodeSchedulingLocales.map((locale) => [
        locale,
        new Map(leaves[locale]),
      ])) as LocaleLeafMaps
      const wrongZh = '同步错误 {{scope}}'
      synchronizedMistake['zh-CN'].set('errors.targetScopeRequired', wrongZh)
      synchronizedMistake['en-US'].set('errors.targetScopeRequired', 'Synchronized error {{scope}}')
      synchronizedMistake['qps-ploc'].set('errors.targetScopeRequired', pseudoFromFixedOracle(wrongZh))
      synchronizedMistake['qps-Ploc'].set('errors.targetScopeRequired', pseudoFromFixedOracle(wrongZh))
      expect(() => expectLocaleBundlesMatchFixedOracle(synchronizedMistake)).toThrow()
      for (const [path, value] of leaves['en-US']) {
        expect(cjkPattern.test(value), `en-US leaf ${path}`).toBe(false)
      }
      for (const locale of nodeSchedulingLocales) {
        for (const [path, fixed] of Object.entries(fixedLocaleOracle)) {
          expect(placeholderSet(leaves[locale].get(path) ?? ''), `${locale} placeholders at ${path}`).toEqual(
            placeholderSet(fixed.zh),
          )
          expect(markupSet(leaves[locale].get(path) ?? ''), `${locale} markup at ${path}`).toEqual(markupSet(fixed.zh))
        }
      }
      for (const pseudoLocale of ['qps-ploc', 'qps-Ploc'] as const) {
        for (const [path, fixed] of Object.entries(fixedLocaleOracle)) {
          const zhValue = fixed.zh
          const pseudoCharacters = [...(leaves[pseudoLocale].get(path) ?? '')]
          const zhCharacters = [...zhValue]
          const visibleCount = [...zhValue.replace(protectedTokenPattern, '')]
            .filter((character) => !/\s/u.test(character)).length
          expect(pseudoCharacters.at(0), `${pseudoLocale} opening frame at ${path}`).toBe('［')
          expect(pseudoCharacters.at(-1), `${pseudoLocale} closing frame at ${path}`).toBe('］')
          const pseudoBody = pseudoCharacters.slice(1, -1).join('')
          expectPseudoExpansion(zhValue, pseudoBody, `${pseudoLocale} per-character expansion at ${path}`)
          if (visibleCount > 0) {
            expect([...pseudoBody].length - zhCharacters.length, `${pseudoLocale} visible growth at ${path}`).toBe(visibleCount)
            const wrapperOnlyBody = [...`［${zhValue}］`].slice(1, -1)
            expect(wrapperOnlyBody.length - zhCharacters.length, `wrapper-only negative control at ${path}`).not.toBe(visibleCount)
          }
        }
        expect(leaves[pseudoLocale].get('columns.id')).toBe('［IIDD］')
        expect(leaves[pseudoLocale].get('titles.l2Topology')).toBe('［LL22 配配置置］')
        expect(leaves[pseudoLocale].get('values.placeholder')).toBe('［——］')
        expect(leaves[pseudoLocale].get('validation.port')).toContain('11 到到 6655553355')
      }

      const [{ useSessionStore }, { authResponse, principal }, { renderWithProviders }, {
        act,
        screen,
        waitFor,
      }, { useNavigate }] = await Promise.all([
        import('../auth/session'),
        import('../test/fixtures'),
        import('../test/render'),
        import('@testing-library/react'),
        import('react-router-dom'),
      ])
      let navigateTo: ((path: string) => void) | undefined
      function RouteController() {
        const navigate = useNavigate()
        navigateTo = (path) => navigate(path)
        return null
      }
      const actor = principal({
        scope_kind: 'platform',
        scope_id: l2ConfigFixture.tenant_scope_id,
        tenant_id: null,
        roles: ['platform_admin'],
        permissions: ['node_scheduling.read'],
      })
      const translationOnlyCandidate = document.createElement('h1')
      translationOnlyCandidate.textContent = contractValue(visibleContract.l2Title, 'zh-CN')
      expect(document.body.contains(translationOnlyCandidate), 'getFixedT-only candidate is not rendered').toBe(false)

      const session = authResponse(actor)
      const requests: ExpectedRequest[] = [
        { action: 'l2-config-list', identity: 'L2 configs', pathname: '/v1/l2-configs', query: {} },
        { action: 'l2-config', identity: 'L2 config', pathname: `/v1/l2-configs/${l2ConfigFixture.id}`, query: {} },
        { action: 'l2-condition-list', identity: 'L2 conditions', pathname: '/v1/l2-conds', query: {} },
        { action: 'l2-node-list', identity: 'L2 nodes', pathname: '/v1/l2-nodes', query: { config_id: l2ConfigFixture.id } },
        { action: 'l2-node-available', identity: 'L2 candidates', pathname: '/v1/l2-nodes', query: { config_id: l2ConfigFixture.id, available: 'true' } },
        { action: 'list', identity: 'line groups', pathname: '/v1/node-line-groups', query: { target_scope_id: actor.scope_id } },
      ]
      const observed = new Set<string>()
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        const actual = observeRequest(input, init)
        const expected = requests.find((request) => expectedRequestURL(request) === actual.rawURL)
        if (!expected) throw new Error(`unexpected request: ${actual.rawURL}`)
        expectRequestContract(actual, expected, session.access_token)
        observed.add(expected.identity)
        const payload = expected.identity === 'L2 config' ? l2ConfigFixture
          : { items: expected.identity === 'L2 configs' ? [l2ConfigFixture] : [] }
        return new Response(JSON.stringify(payload), { headers: { 'Content-Type': 'application/json' } })
      })
      try {
      await withMountedSession(
        () => useSessionStore.getState(),
        (snapshot) => useSessionStore.setState(snapshot, true),
        () => useSessionStore.getState().setSession(session, actor),
        () => renderWithProviders(<><RouteController /><AppRoutes /></>, ['/node/l2-config']),
        async () => {
        expect(await screen.findByRole('heading', { name: l2TopologyTitleByLocale['zh-CN'] })).toBeInTheDocument()
        expect(screen.queryByRole('textbox', { name: '目标租户作用域 ID' })).not.toBeInTheDocument()
        expect(screen.queryByRole('button', { name: '读取租户' })).not.toBeInTheDocument()
        expect(screen.queryByText(contractValue(fixedVisibleContract['errors.targetScopeRequired'], 'zh-CN')))
          .not.toBeInTheDocument()
        expect(screen.queryByRole('button', { name: '新增配置' })).not.toBeInTheDocument()
        expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
        expect(await screen.findByText(l2ConfigFixture.name, { selector: 'td' })).toBeInTheDocument()
        for (const key of [
          'columns.id',
          'columns.name',
          'columns.region',
          'columns.mode',
          'columns.loadMethod',
          'columns.actions',
        ] as const) {
          expect(screen.getAllByText(contractValue(fixedVisibleContract[key], 'zh-CN')).length).toBeGreaterThan(0)
        }

        await act(async () => { screen.getByRole('tab', { name: 'L2条件' }).click() })
        await waitFor(() => expect(observed.has('L2 conditions')).toBe(true))
        expect(screen.queryByRole('button', { name: '新增条件' })).not.toBeInTheDocument()
        await act(async () => { navigateTo?.(`/node/l2-config/node/${l2ConfigFixture.id}`) })
        expect(await screen.findByRole('heading', { name: 'L2节点列表' })).toBeInTheDocument()
        expect(screen.getByRole('heading', { name: '已配置的L2节点' })).toBeInTheDocument()
        expect(screen.getByRole('button', { name: '返回 L2 配置' })).toBeInTheDocument()
        expect(screen.getByRole('combobox', { name: 'L2配置' })).toBeInTheDocument()
        expect(screen.queryByRole('textbox', { name: '目标租户作用域 ID' })).not.toBeInTheDocument()
        expect(screen.getByRole('button', { name: '批量添加' })).toBeDisabled()
        expect(screen.getByRole('button', { name: '删除' })).toBeDisabled()
        await waitFor(() => expect([...observed].sort()).toEqual(requests.slice(0, -1).map(({ identity }) => identity).sort()))

        await act(async () => { navigateTo?.('/node/line-group') })
        expect(await screen.findByRole('heading', { name: '线路分组' })).toBeInTheDocument()
        expect(screen.queryByRole('textbox', { name: '目标租户作用域 ID' })).not.toBeInTheDocument()
        expect(screen.queryByRole('button', { name: '读取租户' })).not.toBeInTheDocument()
        expect(screen.getByRole('button', { name: '查询' })).toBeInTheDocument()
        for (const key of [
          'columns.id',
          'columns.name',
          'columns.region',
          'columns.addresses',
          'columns.statistics',
          'columns.l2Configuration',
          'columns.sort',
          'columns.actions',
        ] as const) {
          expect(screen.getAllByText(contractValue(fixedVisibleContract[key], 'zh-CN')).length).toBeGreaterThan(0)
        }
        await waitFor(() => expect([...observed].sort()).toEqual(requests.map(({ identity }) => identity).sort()))
        expect(document.body.textContent).not.toContain(session.access_token)
        expect(JSON.stringify(snapshotStorage())).not.toContain(session.access_token)
        },
      )
      } finally {
        fetchSpy.mockRestore()
      }
      })
  })

  it('updates the current App route in place across public locale changes', async () => {
    await withProductionAppGraph(async ({ app: { AppRoutes }, i18nModule: { default: i18n, changeLocale } }) => {
      const [{ useSessionStore }, { authResponse, principal }, { renderWithProviders }, {
        act,
        screen,
        waitFor,
      }, { useNavigate }] = await Promise.all([
        import('../auth/session'),
        import('../test/fixtures'),
        import('../test/render'),
        import('@testing-library/react'),
        import('react-router-dom'),
      ])
      let navigateTo: ((path: string) => void) | undefined
      function RouteController() {
        const navigate = useNavigate()
        navigateTo = (path) => navigate(path)
        return null
      }
      const lineGroupScopeID = l2ConfigFixture.tenant_scope_id
      const actor = principal({
        scope_kind: 'platform',
        scope_id: lineGroupScopeID,
        tenant_id: null,
        roles: ['platform_admin'],
        permissions: ['node_scheduling.read'],
      })
      const session = authResponse(actor)
      const groupID = l2ConfigFixture.id
      const l2Request = deferred<Response>()
      const detailRequest = deferred<Response>()
      const lineGroupRequest = deferred<Response>()
      const requests: Array<ExpectedRequest & { response: Promise<Response> }> = [
        {
          action: 'l2-config-list',
          identity: 'L2 configuration list',
          pathname: '/v1/l2-configs',
          query: {},
          response: l2Request.promise,
        },
        {
          action: 'l2-config-list',
          identity: 'L2 node configuration choices',
          pathname: '/v1/l2-configs',
          query: {},
          response: Promise.resolve(new Response(JSON.stringify({ items: [l2ConfigFixture] }))),
        },
        {
          action: 'l2-config',
          identity: 'L2 node configuration',
          pathname: `/v1/l2-configs/${groupID}`,
          query: {},
          response: Promise.resolve(new Response(JSON.stringify(l2ConfigFixture))),
        },
        {
          action: 'l2-condition-list',
          identity: 'L2 node conditions',
          pathname: '/v1/l2-conds',
          query: {},
          response: Promise.resolve(new Response(JSON.stringify({ items: [] }))),
        },
        {
          action: 'l2-node-list',
          identity: 'L2 configured nodes',
          pathname: '/v1/l2-nodes',
          query: { config_id: groupID },
          response: detailRequest.promise,
        },
        {
          action: 'l2-node-available',
          identity: 'L2 available nodes',
          pathname: '/v1/l2-nodes',
          query: { config_id: groupID, available: 'true' },
          response: Promise.resolve(new Response(JSON.stringify({ items: [] }))),
        },
        {
          action: 'list',
          identity: 'line group list',
          pathname: '/v1/node-line-groups',
          query: { target_scope_id: lineGroupScopeID },
          response: lineGroupRequest.promise,
        },
      ]
      let resolveRequest = createKeyedRequestResolver(requests.slice(0, 1), session.access_token)
      const observedRequests = new Map<string, ObservedRequest>()
      const originalFetch = globalThis.fetch
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        // 外壳级后台请求（插件页、消息铃铛、模块等）与本路由无关，挂起且不计入。
        if (shellBackgroundRequests.has(String(input))) return new Promise<Response>(() => undefined)
        const actual = observeRequest(input, init)
        try {
          const request = resolveRequest(actual)
          observedRequests.set(request.identity, actual)
          return request.response
        } catch (error) {
          return Promise.reject(error)
        }
      })
      const expectRequests = (identities: readonly string[]) => {
        expect([...observedRequests.keys()].sort()).toEqual([...identities].sort())
        for (const identity of identities) {
          const expected = requests.find((request) => request.identity === identity)
          const actual = observedRequests.get(identity)
          expect(expected, `${identity} expected contract`).toBeDefined()
          expect(actual, `${identity} observed request`).toBeDefined()
          expectRequestContract(actual!, expected!, session.access_token)
        }
        expect(new Set([...observedRequests.values()].map(({ headers }) => headers['x-request-id'])).size)
          .toBe(identities.length)
        expect(document.body.textContent).not.toContain(session.access_token)
        expect(JSON.stringify(snapshotStorage())).not.toContain(session.access_token)
      }
      let failure: unknown
      try {
        await withMountedSession(
          () => useSessionStore.getState(),
          (snapshot) => useSessionStore.setState(snapshot, true),
          () => useSessionStore.getState().setSession(session, actor),
          () => renderWithProviders(<><RouteController /><AppRoutes /></>, ['/node/l2-config']),
          async () => {
            const l2ZhHeading = await screen.findByRole('heading', {
              name: l2TopologyTitleByLocale['zh-CN'],
            })
            const l2ConfigurationTab = screen.getByRole('tab', { name: 'L2配置' })
            const l2PageSize = screen.getByRole('combobox', { name: '每页数量' })
            const runtime = i18n as I18nRuntime
            runtime.store.on('added', vi.fn())
            runtime.reportNamespaces?.addUsedNamespaces(['round8-route-mutation'])
            const l2Page = l2ZhHeading.closest('.node-scheduling-page')
            expect(l2Page).not.toBeNull()
            expect(screen.queryByRole('button', {
              name: contractValue(visibleContract.applyScope, 'zh-CN'),
            })).not.toBeInTheDocument()
            expect(screen.queryByRole('textbox', {
              name: contractValue(visibleContract.targetScope, 'zh-CN'),
            })).not.toBeInTheDocument()
            await waitFor(() => expect(pageRequests(fetchSpy)).toHaveLength(1))
            expectRequests(['L2 configuration list'])
            expect(screen.getByTestId('node-l2-topology-table')).toHaveAttribute('aria-busy', 'true')
            const l2OldVisible = expectContractKeysVisible(l2Page!, routeVisibleContract.l2, 'zh-CN', [
              'actions.previous',
              'actions.next',
              'nodeL2Topology.filters.region',
            ])

            await act(async () => { await changeLocale('en-US') })
            const l2EnHeading = await screen.findByRole('heading', {
              name: l2TopologyTitleByLocale['en-US'],
            })
            expect(l2EnHeading).toBe(l2ZhHeading)
            expect(l2EnHeading.closest('.node-scheduling-page')).toBe(l2Page)
            expect(l2ConfigurationTab).toHaveTextContent('L2 configuration')
            expect(l2PageSize).toHaveAttribute('aria-label', 'Rows per page')
            expectVisibleContractSwitched(l2Page!, l2OldVisible, 'zh-CN', 'en-US')
            expect(document.body.textContent).not.toMatch(cjkPattern)
            await act(async () => { l2Request.resolve(unavailableResponse()) })
            await screen.findByText(contractValue(visibleContract.loadFailed, 'en-US'))
            const l2ErrorVisible = expectContractKeysVisible(withFeedback(l2Page!), routeVisibleContract.l2, 'en-US', [
              'errors.loadFailed',
              'errors.node_scheduling_unavailable',
              'actions.retry',
            ])
            expect(screen.queryByText('server-only failure detail')).not.toBeInTheDocument()
            await act(async () => { await changeLocale('qps-ploc') })
            const l2PseudoHeading = await screen.findByRole('heading', {
              name: l2TopologyTitleByLocale['qps-ploc'],
            })
            expect(l2PseudoHeading).toBe(l2ZhHeading)
            expect(l2PseudoHeading.closest('.node-scheduling-page')).toBe(l2Page)
            expect(l2ConfigurationTab).toHaveTextContent('［L2配置］')
            expect(l2PageSize).toHaveAttribute('aria-label', '［每页数量］')
            expectVisibleContractSwitched(withFeedback(l2Page!), l2ErrorVisible, 'en-US', 'qps-ploc')
            const l2PseudoErrorVisible = visibleContractLeaves(withFeedback(l2Page!), routeVisibleContract.l2, 'qps-ploc')
            await act(async () => { await changeLocale('en-US') })
            expect(await screen.findByRole('heading', {
              name: l2TopologyTitleByLocale['en-US'],
            })).toBe(l2ZhHeading)
            expect(l2ConfigurationTab).toHaveTextContent('L2 configuration')
            expect(l2PageSize).toHaveAttribute('aria-label', 'Rows per page')
            expectVisibleContractSwitched(withFeedback(l2Page!), l2PseudoErrorVisible, 'qps-ploc', 'en-US')

            resolveRequest = createKeyedRequestResolver(requests.slice(1, -1), session.access_token)
            await act(async () => { navigateTo?.(`/node/l2-config/node/${groupID}`) })
            const detailEnHeading = await screen.findByRole('heading', {
              name: 'Available L2 nodes',
            })
            const detailPage = detailEnHeading.closest('.node-scheduling-page')
            expect(detailPage).not.toBeNull()
            expect(screen.getByRole('heading', { name: 'Configured L2 nodes' })).toBeInTheDocument()
            expect(screen.getByRole('combobox', { name: 'L2 configuration' })).toBeInTheDocument()
            expect(screen.getByRole('button', { name: 'Add nodes' })).toBeDisabled()
            expect(screen.getByRole('button', { name: 'Delete' })).toBeDisabled()
            expect(screen.queryByRole('textbox', { name: contractValue(visibleContract.targetScope, 'en-US') }))
              .not.toBeInTheDocument()
            await waitFor(() => expect(pageRequests(fetchSpy)).toHaveLength(6))
            expectRequests(requests.slice(0, -1).map(({ identity }) => identity))
            expect(detailPage!.querySelector('.ant-spin-spinning')).not.toBeNull()
            const detailOldVisible = expectContractKeysVisible(detailPage!, routeVisibleContract.detail, 'en-US', [
              'actions.back',
              'nodeL2Topology.nodes.available',
              'nodeL2Topology.nodes.configured',
              'nodeL2Topology.nodes.add',
              'nodeL2Topology.nodes.configuration',
              'nodeL2Topology.filters.region',
            ])

            await act(async () => { await changeLocale('zh-CN') })
            const detailZhHeading = await screen.findByRole('heading', {
              name: 'L2节点列表',
            })
            expect(detailZhHeading).toBe(detailEnHeading)
            expect(detailZhHeading.closest('.node-scheduling-page')).toBe(detailPage)
            expect(screen.getByRole('heading', { name: '已配置的L2节点' })).toBeInTheDocument()
            expect(screen.getByRole('combobox', { name: 'L2配置' })).toBeInTheDocument()
            expectVisibleContractSwitched(detailPage!, detailOldVisible, 'en-US', 'zh-CN')
            await act(async () => { detailRequest.resolve(unavailableResponse()) })
            await screen.findByText(contractValue(visibleContract.loadFailed, 'zh-CN'))
            const detailErrorVisible = expectContractKeysVisible(withFeedback(detailPage!), routeVisibleContract.detail, 'zh-CN', [
              'errors.loadFailed',
              'errors.node_scheduling_unavailable',
              'actions.retry',
            ])
            await act(async () => { await changeLocale('en-US') })
            const detailErrorEnHeading = await screen.findByRole('heading', {
              name: 'Available L2 nodes',
            })
            expect(detailErrorEnHeading).toBe(detailEnHeading)
            expect(detailErrorEnHeading.closest('.node-scheduling-page')).toBe(detailPage)
            expectVisibleContractSwitched(withFeedback(detailPage!), detailErrorVisible, 'zh-CN', 'en-US')
            const detailErrorEnVisible = visibleContractLeaves(detailPage!, routeVisibleContract.detail, 'en-US')
            await act(async () => { await changeLocale('zh-CN') })
            expect(await screen.findByRole('heading', {
              name: 'L2节点列表',
            })).toBe(detailEnHeading)
            expectVisibleContractSwitched(detailPage!, detailErrorEnVisible, 'en-US', 'zh-CN')

            resolveRequest = createKeyedRequestResolver(requests.slice(-1), session.access_token)
            await act(async () => { navigateTo?.('/node/line-group') })
            const lineGroupZhHeading = await screen.findByRole('heading', {
              name: contractValue(visibleContract.lineGroupsTitle, 'zh-CN'),
            })
            const lineGroupPage = lineGroupZhHeading.closest('.node-scheduling-page')
            expect(lineGroupPage).not.toBeNull()
            expect(screen.queryByRole('button', {
              name: contractValue(visibleContract.applyScope, 'zh-CN'),
            })).not.toBeInTheDocument()
            await waitFor(() => expect(pageRequests(fetchSpy)).toHaveLength(7))
            expectRequests(requests.map(({ identity }) => identity))
            expect(screen.getByTestId('node-line-groups-table')).toHaveAttribute('aria-busy', 'true')
            const lineGroupOldVisible = expectContractKeysVisible(
              lineGroupPage!,
              routeVisibleContract.lineGroups,
              'zh-CN',
              [
                'titles.lineGroups',
                'filters.searchLabel',
                'filters.searchPlaceholder',
                'filters.pageSizeLabel',
                'filters.pageSize',
                'actions.search',
                'actions.clear',
              ],
            )
            await act(async () => { await changeLocale('qps-ploc') })
            const lineGroupPseudoHeading = await screen.findByRole('heading', {
              name: contractValue(visibleContract.lineGroupsTitle, 'qps-ploc'),
            })
            expect(lineGroupPseudoHeading).toBe(lineGroupZhHeading)
            expect(lineGroupPseudoHeading.closest('.node-scheduling-page')).toBe(lineGroupPage)
            expectVisibleContractSwitched(lineGroupPage!, lineGroupOldVisible, 'zh-CN', 'qps-ploc')
            await act(async () => { lineGroupRequest.reject(new Error('network failure sentinel')) })
            await screen.findByText(contractValue(visibleContract.loadFailed, 'qps-ploc'))
            const lineGroupErrorVisible = expectContractKeysVisible(
              withFeedback(lineGroupPage!),
              routeVisibleContract.lineGroups,
              'qps-ploc',
              ['errors.loadFailed', 'errors.requestFailed', 'actions.retry'],
            )
            await act(async () => { await changeLocale('en-US') })
            const lineGroupEnHeading = await screen.findByRole('heading', {
              name: contractValue(visibleContract.lineGroupsTitle, 'en-US'),
            })
            expect(lineGroupEnHeading).toBe(lineGroupZhHeading)
            expect(lineGroupEnHeading.closest('.node-scheduling-page')).toBe(lineGroupPage)
            expectVisibleContractSwitched(withFeedback(lineGroupPage!), lineGroupErrorVisible, 'qps-ploc', 'en-US')
            expectRequests(requests.map(({ identity }) => identity))
          },
        )
      } catch (error) {
        failure = error
      } finally {
        fetchSpy.mockRestore()
      }
      expect(globalThis.fetch).toBe(originalFetch)
      if (failure) throw failure
    })
  })

  it('keys reordered concurrent requests to the correct response and rejects scope drift', async () => {
    const accessToken = 'memory-only-access-token'
    const l2 = {
      action: 'l2-config-list',
      identity: 'concurrent L2 list',
      pathname: '/v1/l2-configs',
      query: {},
      response: Promise.resolve(new Response('l2-response')),
    }
    const lineGroups = {
      action: 'list',
      identity: 'concurrent line group list',
      pathname: '/v1/node-line-groups',
      query: { target_scope_id: '4a4b4c4d-4444-4444-8444-444444444444' },
      response: Promise.resolve(new Response('line-group-response')),
    }
    const resolver = createKeyedRequestResolver([l2, lineGroups], accessToken)
    const [lineGroupBody, l2Body] = await Promise.all([
      Promise.resolve().then(() => resolver(observedRequestFor(lineGroups, accessToken, 'line-groups')).response)
        .then((response) => response.text()),
      Promise.resolve().then(() => resolver(observedRequestFor(l2, accessToken, 'l2')).response)
        .then((response) => response.text()),
    ])
    expect([lineGroupBody, l2Body]).toEqual(['line-group-response', 'l2-response'])

    const unexpectedScope = observedRequestFor(l2, accessToken, 'unexpected-scope')
    unexpectedScope.query = { target_scope_id: '2a2b2c2d-2222-4222-8222-222222222222' }
    unexpectedScope.rawURL = `${l2.pathname}?${new URLSearchParams(unexpectedScope.query)}`
    expect(() => createKeyedRequestResolver([l2], accessToken)(unexpectedScope)).toThrow()

    const missingScope = observedRequestFor(lineGroups, accessToken, 'missing-scope')
    missingScope.query = {}
    missingScope.rawURL = lineGroups.pathname
    expect(() => createKeyedRequestResolver([lineGroups], accessToken)(missingScope)).toThrow()

    const nonCanonicalScope = observedRequestFor(lineGroups, accessToken, 'non-canonical-scope')
    nonCanonicalScope.query = { target_scope_id: lineGroups.query.target_scope_id.toUpperCase() }
    nonCanonicalScope.rawURL = `${lineGroups.pathname}?${new URLSearchParams(nonCanonicalScope.query)}`
    expect(() => createKeyedRequestResolver([lineGroups], accessToken)(nonCanonicalScope)).toThrow()
  })

  it('resets session state when render setup throws before returning a view', async () => {
    const currentModule = await import('../i18n')
    const entrySnapshot = snapshotI18n(currentModule.default)
    const setupSession = vi.fn()
    const entrySession = { value: 'entry' }
    let session = entrySession
    const entryNode = document.createElement('div')
    const partialNode = document.createElement('div')
    document.body.append(entryNode)

    try {
      await expect(withProductionAppGraph(async ({ i18nModule }) => {
        const runtime = i18nModule.default as I18nRuntime
        runtime.store.on('added', vi.fn())
        runtime.reportNamespaces?.addUsedNamespaces(['round8-render-mutation'])
        await withMountedSession(
          () => session,
          (snapshot) => { session = snapshot },
          () => {
            session = { value: 'setup' }
            setupSession()
          },
          () => {
            document.body.append(partialNode)
            throw new Error('render setup failure sentinel')
          },
          async () => undefined,
        )
      })).rejects.toThrow('render setup failure sentinel')
      expect(setupSession).toHaveBeenCalledOnce()
      expect(session).toBe(entrySession)
      expect(entryNode).toBeInTheDocument()
      expect(partialNode).not.toBeInTheDocument()
      expectSnapshotRestored(currentModule.default, entrySnapshot)
    } finally {
      await restoreI18n(currentModule.default, entrySnapshot)
      partialNode.remove()
      entryNode.remove()
    }
  })

  it('restores session and partial DOM when callback and unmount both fail', async () => {
    const currentModule = await import('../i18n')
    const entrySnapshot = snapshotI18n(currentModule.default)
    const partialNode = document.createElement('div')
    const view = { unmount: vi.fn(() => { throw new Error('unmount failure sentinel') }) }
    const entrySession = { value: 'entry' }
    let session = entrySession

    try {
      await expect(withProductionAppGraph(async ({ i18nModule }) => {
        const runtime = i18nModule.default as I18nRuntime
        runtime.reportNamespaces ??= {
          usedNamespaces: {},
          addUsedNamespaces(namespaces) {
            for (const namespace of namespaces) this.usedNamespaces[namespace] = true
          },
          getUsedNamespaces() { return Object.keys(this.usedNamespaces) },
        }
        runtime.reportNamespaces.addUsedNamespaces(['round7-unmount-mutation'])
        runtime.store.on('added', vi.fn())
        await withMountedSession(
          () => session,
          (snapshot) => { session = snapshot },
          () => { session = { value: 'setup' } },
          () => {
            document.body.append(partialNode)
            return view
          },
          async () => { throw new Error('callback failure sentinel') },
        )
      })).rejects.toThrow('callback failure sentinel')
      expect(view.unmount).toHaveBeenCalledOnce()
      expect(session).toBe(entrySession)
      expect(partialNode).not.toBeInTheDocument()
      expectSnapshotRestored(currentModule.default, entrySnapshot)
    } finally {
      await restoreI18n(currentModule.default, entrySnapshot)
      partialNode.remove()
    }
  })

  it('restores session and DOM when session setup itself fails', async () => {
    const partialNode = document.createElement('div')
    const renderView = vi.fn()
    const entrySession = { value: 'entry' }
    let session = entrySession

    try {
      await expect(withMountedSession(
        () => session,
        (snapshot) => { session = snapshot },
        () => {
          session = { value: 'setup' }
          document.body.append(partialNode)
          throw new Error('session setup failure sentinel')
        },
        renderView,
        async () => undefined,
      )).rejects.toThrow('session setup failure sentinel')
      expect(renderView).not.toHaveBeenCalled()
      expect(session).toBe(entrySession)
      expect(partialNode).not.toBeInTheDocument()
    } finally {
      partialNode.remove()
    }
  })

  it('restores bundle and locale state after failures and reverse-order isolated runs', async () => {
    await withProductionAppGraph(async ({ i18nModule: currentModule }) => {
      const currentI18n = currentModule.default
      const originalSnapshot = snapshotI18n(currentI18n)
      try {
        for (const locale of nodeSchedulingLocales) {
          expect(currentI18n.hasResourceBundle(locale, 'nodeScheduling')).toBe(true)
        }
      currentI18n.addResourceBundle('en-US', 'round6SharedProbe', { value: 'entry-shared-bundle' }, true, true)
      const entryListener = vi.fn()
      currentI18n.on('round6-shared-listener', entryListener)
      await currentI18n.changeLanguage('en-US')
      window.localStorage.setItem(currentModule.localeStorageKey, 'qps-Ploc')
      window.localStorage.setItem('round6.storage.sentinel', 'entry-storage')
      const entrySnapshot = snapshotI18n(currentI18n)

      await withIsolatedApp(async ({ i18nModule }) => {
        expect(i18nModule.default).toBe(currentI18n)
        await i18nModule.changeLocale('qps-ploc')
        i18nModule.default.addResourceBundle('en-US', 'nodeScheduling', {
          sentinel: { value: 'success-path-mutation' },
        }, true, true)
        i18nModule.default.addResourceBundle('en-US', 'round6SharedProbe', { value: 'mutated-shared-bundle' }, true, true)
        i18nModule.default.off('round6-shared-listener', entryListener)
        i18nModule.default.on('round6-shared-listener', vi.fn())
        i18nModule.default.options.ns = ['round6-mutated-namespace']
        window.localStorage.setItem('round6.storage.sentinel', 'mutated-storage')
      })
      expectSnapshotRestored(currentI18n, entrySnapshot)

      await expect(withIsolatedApp(async ({ i18nModule }) => {
        await i18nModule.default.changeLanguage('qps-Ploc')
        i18nModule.default.addResourceBundle('qps-Ploc', 'nodeScheduling', {
          sentinel: { value: 'failure-path-mutation' },
        }, true, true)
        throw new Error('isolated failure sentinel')
      })).rejects.toThrow('isolated failure sentinel')
      expectSnapshotRestored(currentI18n, entrySnapshot)

      await expect(withIsolatedApp(
        async () => undefined,
        async () => { throw new Error('App setup failure sentinel') },
      )).rejects.toThrow('App setup failure sentinel')
      expectSnapshotRestored(currentI18n, entrySnapshot)

      for (const locale of [...nodeSchedulingLocales].reverse()) {
        await withIsolatedApp(async ({ i18nModule }) => {
          await i18nModule.default.changeLanguage(locale)
          window.localStorage.setItem(i18nModule.localeStorageKey, locale)
          i18nModule.default.addResourceBundle(locale, 'nodeScheduling', {
            sentinel: { value: `${locale}-reverse-mutation` },
          }, true, true)
        })
        expectSnapshotRestored(currentI18n, entrySnapshot)
      }
      } finally {
        await restoreI18n(currentI18n, originalSnapshot)
      }
      expectSnapshotRestored(currentI18n, originalSnapshot)
    })
  })
})
