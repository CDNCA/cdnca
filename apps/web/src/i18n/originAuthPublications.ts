import i18n from './index'

const zhCN = {
  title: '回源鉴权发布',
  description: '查看并生成当前租户的确定性、无密钥回源鉴权快照。',
  loading: '正在加载回源鉴权发布',
  empty: '尚未创建回源鉴权发布',
  version: '版本 {{revision}}',
  rulesCount: '{{count}} 条规则',
  targetScope: {
    label: '目标租户作用域', placeholder: '租户作用域 UUID', apply: '应用目标',
    required: '请先选择要查看的租户作用域。', invalid: '请输入有效的小写租户作用域 UUID。',
  },
  details: {
    createdAt: '创建时间', snapshotHash: '快照哈希', previousHash: '前序哈希', noPrevious: '首个快照',
  },
  columns: {
    site: '站点 ID', source: '源站序号', provider: '提供商', endpoint: '端点', bucket: '存储桶',
    path: '路径前缀', algorithm: '签名算法', ttl: '签名时效', activation: '切换时间',
  },
  providers: { s3: 'S3', oss: '阿里云 OSS', cos: '腾讯云 COS' },
  algorithms: {
    'aws4-hmac-sha256': 'AWS4-HMAC-SHA256',
    'oss4-hmac-sha256': 'OSS4-HMAC-SHA256',
    'cos-hmac-sha1': 'COS-HMAC-SHA1',
  },
  seconds: '{{count}} 秒',
  actions: {
    refresh: '刷新', retry: '重试', publish: '创建新发布', confirmPublish: '确认发布',
    retrySameRequest: '使用同一请求重试', abandonRefresh: '放弃并刷新',
  },
  confirmations: { publish: '确认根据当前已启用规则生成新的不可变发布快照？' },
  comparison: {
    title: '发布快照比较', summary: '新增 {{added}} / 删除 {{removed}} / 变更 {{changed}} / 未变 {{unchanged}}',
  },
  uncertainty: {
    title: '发布结果待确认',
    description: '只能使用完全相同的版本、空请求体和幂等键重试，或放弃并刷新确认当前发布。',
  },
  forbidden: {
    title: '无权查看回源鉴权发布', description: '当前租户身份缺少回源鉴权读取权限。',
  },
  edge: {
    title: '节点发布结果', loading: '正在加载节点发布结果', empty: '尚未执行节点发布',
    nodeCount: '{{count}} 个节点', dialogTitle: '发布源站鉴权到节点',
    fields: {
      nodeIDs: '目标节点 UUID', activationTimeout: '激活超时（毫秒）',
      observationWindow: '观察窗口（毫秒）', requiredSuccesses: '连续成功次数',
      deadline: '截止时间（UTC）',
    },
    details: {
      publicationID: '发布 ID', rolloutID: '灰度 ID', configVersionID: '配置版本 ID',
      configSnapshotHash: '配置快照哈希', artifactManifestHash: '制品清单哈希',
      recipientBindingHash: '接收方绑定哈希', createdAt: '创建时间',
    },
    actions: {
      publish: '发布到节点', confirmPublish: '确认发布到节点', cancel: '取消',
      retryRead: '重试读取节点发布结果', retrySameRequest: '使用同一节点发布请求重试',
      abandonRefresh: '放弃节点发布并刷新',
    },
    uncertainty: {
      title: '节点发布结果待确认',
      description: '只能使用完全相同的目标、健康检查、截止时间和请求元数据重试，或放弃并刷新源发布。',
    },
    forbidden: {
      title: '无权查看节点发布结果', description: '当前平台身份缺少节点发布读取权限。',
    },
  },
  errors: {
    requestFailed: '回源鉴权请求失败，请稍后重试。',
    network_error: '网络连接失败，请确认当前发布状态。',
    invalid_response: '服务响应无效，请刷新确认当前发布状态。',
    invalid_request: '发布请求无效，请刷新后重试。',
    authentication_required: '会话已失效，请重新登录。',
    permission_denied: '当前身份缺少回源鉴权权限。',
    entitlement_denied: '当前授权不允许创建回源鉴权发布。',
    not_found: '尚未创建回源鉴权发布。',
    resource_conflict: '当前规则状态存在冲突，请刷新后重试。',
    idempotency_conflict: '幂等请求与原请求不一致，请刷新确认。',
    revision_conflict: '发布版本已变化，请刷新后重试。',
    validation_error: '当前规则无法生成有效发布，请检查后重试。',
    request_canceled: '请求已中断，请确认当前发布状态。',
    service_unavailable: '回源鉴权服务暂不可用，请稍后重试。',
    edge_outcome_unknown: '节点发布结果待确认。',
    edge_unavailable: '节点发布服务暂不可用，请稍后重试。',
    edge_permission_denied: '当前身份缺少节点发布权限。',
    edge_invalid_request: '节点发布请求无效，请检查后重试。',
    edge_invalid_response: '节点发布响应无效，请刷新确认。',
  },
} as const

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }

const enUS: MessageShape<typeof zhCN> = {
  title: 'Origin authentication publications',
  description: 'Inspect and generate deterministic secret-free origin authentication snapshots for this tenant.',
  loading: 'Loading origin authentication publications',
  empty: 'No origin authentication publication exists',
  version: 'Revision {{revision}}',
  rulesCount: '{{count}} rules',
  targetScope: {
    label: 'Target tenant scope', placeholder: 'Tenant scope UUID', apply: 'Apply target',
    required: 'Select a tenant scope to inspect.', invalid: 'Enter a valid lowercase tenant scope UUID.',
  },
  details: {
    createdAt: 'Created at', snapshotHash: 'Snapshot hash', previousHash: 'Previous hash', noPrevious: 'First snapshot',
  },
  columns: {
    site: 'Site ID', source: 'Origin position', provider: 'Provider', endpoint: 'Endpoint', bucket: 'Bucket',
    path: 'Path prefix', algorithm: 'Signing algorithm', ttl: 'Signature TTL', activation: 'Activation time',
  },
  providers: { s3: 'S3', oss: 'Alibaba Cloud OSS', cos: 'Tencent Cloud COS' },
  algorithms: {
    'aws4-hmac-sha256': 'AWS4-HMAC-SHA256',
    'oss4-hmac-sha256': 'OSS4-HMAC-SHA256',
    'cos-hmac-sha1': 'COS-HMAC-SHA1',
  },
  seconds: '{{count}} seconds',
  actions: {
    refresh: 'Refresh', retry: 'Retry', publish: 'Create publication', confirmPublish: 'Confirm publication',
    retrySameRequest: 'Retry the same request', abandonRefresh: 'Abandon and refresh',
  },
  confirmations: { publish: 'Generate a new immutable publication snapshot from the currently enabled rules?' },
  comparison: {
    title: 'Publication snapshot comparison', summary: 'Added {{added}} / removed {{removed}} / changed {{changed}} / unchanged {{unchanged}}',
  },
  uncertainty: {
    title: 'Publication outcome is unknown',
    description: 'Retry only with the exact same revision, empty body, and idempotency key, or abandon and refresh the current publication.',
  },
  forbidden: {
    title: 'Origin authentication publications unavailable', description: 'This tenant account lacks origin authentication read permission.',
  },
  edge: {
    title: 'Node publication result', loading: 'Loading node publication result', empty: 'No node publication has been run',
    nodeCount: '{{count}} nodes', dialogTitle: 'Publish origin authentication to nodes',
    fields: {
      nodeIDs: 'Target node UUIDs', activationTimeout: 'Activation timeout (milliseconds)',
      observationWindow: 'Observation window (milliseconds)', requiredSuccesses: 'Required consecutive successes',
      deadline: 'Deadline (UTC)',
    },
    details: {
      publicationID: 'Publication ID', rolloutID: 'Rollout ID', configVersionID: 'Configuration version ID',
      configSnapshotHash: 'Configuration snapshot hash', artifactManifestHash: 'Artifact manifest hash',
      recipientBindingHash: 'Recipient binding hash', createdAt: 'Created at',
    },
    actions: {
      publish: 'Publish to nodes', confirmPublish: 'Confirm node publication', cancel: 'Cancel',
      retryRead: 'Retry reading node publication result', retrySameRequest: 'Retry the same node publication request',
      abandonRefresh: 'Abandon node publication and refresh',
    },
    uncertainty: {
      title: 'Node publication outcome is unknown',
      description: 'Retry only with the exact same targets, health check, deadline, and request metadata, or abandon and refresh the source publication.',
    },
    forbidden: {
      title: 'Node publication result unavailable', description: 'This platform account lacks node publication read permission.',
    },
  },
  errors: {
    requestFailed: 'The origin authentication request failed. Try again later.',
    network_error: 'The network request failed. Confirm the current publication state.',
    invalid_response: 'The service response was invalid. Refresh to confirm the current publication state.',
    invalid_request: 'The publication request is invalid. Refresh and try again.',
    authentication_required: 'Your session has expired. Sign in again.',
    permission_denied: 'This account lacks origin authentication permission.',
    entitlement_denied: 'The current entitlement does not allow origin authentication publication.',
    not_found: 'No origin authentication publication exists.',
    resource_conflict: 'The current rule state conflicts with this operation. Refresh and try again.',
    idempotency_conflict: 'This idempotency key was used for another request. Refresh to confirm.',
    revision_conflict: 'The publication revision changed. Refresh and try again.',
    validation_error: 'The current rules cannot produce a valid publication. Review them and try again.',
    request_canceled: 'The request was interrupted. Confirm the current publication state.',
    service_unavailable: 'The origin authentication service is unavailable. Try again later.',
    edge_outcome_unknown: 'The node publication outcome is unknown.',
    edge_unavailable: 'The node publication service is unavailable. Try again later.',
    edge_permission_denied: 'This account lacks node publication permission.',
    edge_invalid_request: 'The node publication request is invalid. Review it and try again.',
    edge_invalid_response: 'The node publication response is invalid. Refresh to confirm.',
  },
}

export type OriginAuthPublicationsMessages = { [key: string]: string | OriginAuthPublicationsMessages }

function pseudoText(value: string): string {
  return `［${value.split(/({{[^}]+}})/g).map((part) => (
    part.startsWith('{{')
      ? part
      : [...part].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join('')
  )).join('')}］`
}

function pseudoTree(value: unknown): unknown {
  return typeof value === 'string'
    ? pseudoText(value)
    : Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudoCN = pseudoTree(zhCN) as OriginAuthPublicationsMessages

export const originAuthPublicationsMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  OriginAuthPublicationsMessages
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(originAuthPublicationsMessages)) {
  i18n.addResourceBundle(locale, 'originAuthPublications', messages, true, true)
}
