// 页面仍在用、但所在命名空间的资源文件里没有的文案，按命名空间补进全量资源（只补缺，不覆盖已有键）。
type TranslationTree = { [key: string]: string | TranslationTree }

export function addMissingCopy(target: Record<string, unknown>, extra: TranslationTree): void {
  for (const [key, value] of Object.entries(extra)) {
    const current = target[key]
    if (current === undefined) target[key] = value
    else if (typeof value !== 'string' && current !== null && typeof current === 'object') {
      addMissingCopy(current as Record<string, unknown>, value)
    }
  }
}

export const communityCopyZhCN: TranslationTree = {
  accountIdentityVerification: {
    empty: {
      description: '尚未选择实名认证案件',
    },
    introduction: '创建认证草稿需要由可信服务签发的一次性证据令牌；页面只展示脱敏案件状态。',
    validation: {
      providerFormat: '认证服务标识格式无效',
      providerRequired: '请输入认证服务标识',
    },
  },
  accountMessages: {
    events: {
      hint: '事件提醒不区分已读未读；网站与套餐 ID 是事件发生时记录的，资源删除后仍保留。',
    },
    filters: {
      packageID: '用户套餐ID',
      siteID: '网站ID',
    },
  },
  accountProfile: {
    profile: {
      compatibility: {
        qq: 'QQ',
        unavailable: '未提供',
      },
    },
  },
  accountSubscriptions: {
    hints: {
      announcementPublished: '平台发布新公告时通知。',
    },
  },
  adminIdentityReview: {
    description: '查看全部租户的实名认证申请，开始审核后可通过或驳回。操作以你的管理员身份记入审计。',
  },
  analytics: {
    filters: {
      attackRequest: '攻击请求',
    },
    states: {
      filterUnsupported: '当前版本不支持此筛选条件。',
    },
  },
  analyticsLogs: {
    blockState: {
      states: {
        tenantRequired: '平台查询必须填写有效的租户 ID。',
      },
    },
  },
  apiKeys: {
    compatibility: {
      advancedDescription: '管理多个密钥、最小权限、有效期、轮换和撤销。',
      allowlistDisabled: '开启 API 后可配置 IP 白名单。',
      allowlistHelp: '限制允许调用 API 的客户端 IP；多个 IP 或网段用竖线、逗号或换行分隔，留空不限制。',
      description: '管理账号 API 密钥、调用开关和允许访问的客户端 IP。',
      enableHint: '开启后自动生成一对密钥（全部权限、永不过期）。',
      keyInfoDisabled: 'API 未开启，暂无可用密钥。',
      keyInfoHelp: 'api_secret 只在开启或重置密钥时显示一次，请妥善保存。',
    },
  },
  customRolesPage: {
    description: '管理租户可委派权限、自定义角色版本和用户授权。',
    fields: {
      permission: '权限名称',
      stepUpRequired: '二次认证要求',
    },
    values: {
      notRequired: '不需要',
      required: '必需',
    },
  },
  errors: {
    demo_account_locked: '演示账号不允许修改',
    sdk_shield_port_shared: 'SDK 防护的四层转发不能和其他转发共用同一端口，请改用独立端口',
  },
  firewall: {
    openresty: {
      cc: {
        blockPageTrafficDescription: '开启后访问拉黑页面不计流量。',
        blockWayDescription: '选择默认拦截动作，并在非 ipset 模式下配置高攻击量切换策略。',
        durationDescription: '设置黑名单拦截时长和临时白名单放行时长。',
        enableDescription: '控制全局 CC 防护是否启用。',
        ipListDescription: '一行一个，支持 # 作为注释。',
        sectionDescription: '控制全局拦截方式、黑白名单时长和临时白名单阈值。',
        temporaryWhitelistDescription: '达到阈值后进入临时白名单，降低误拦截概率。',
      },
      template: {
        description: '模板保存后通过不可变配置版本下发到节点。',
        sectionDescription: '维护各类验证页 HTML，当前选择切换时只展示对应模板。',
      },
    },
  },
  identitySessions: {
    columns: {
      sessions: '会话数',
    },
    values: {
      count: '{{count}} 个',
    },
  },
  jobs: {
    columns: {
      name: '名称',
    },
    confirm: {
      retryTitle: '确认重试任务',
    },
    values: {
      noFact: '暂无事实',
    },
  },
  logCenter: {
    subtitle: '所有改变配置和数据的操作都会记录在这里：谁、什么时候、从哪个 IP、改了什么。',
  },
  marketNames: {
    edit: '别名与备注',
    failed: '保存失败（{{code}}）',
    note: '备注：{{note}}',
    saved: '已保存',
    seller: '卖家 {{name}}',
  },
  marketStore: {
    entitlement: {
      label: '{{name}}：{{source}}，{{state}}',
      labelSource: '{{name}}：{{source}}',
      text: '{{source}} · {{state}}',
    },
    state: {
      ready: '已安装',
    },
    tabs: {
      more: '更多页签',
    },
  },
  navigation: {
    diagnostics: '诊断',
    more: '更多',
    operations: '运营管理',
  },
  nodeMarket: {
    listing: {
      selectionScope: '节点',
    },
  },
  nodeTrafficPolicy: {
    actions: {
      addWindow: '添加停用时段',
      advanced: '高级定时设置',
      evaluate: '立即评估',
      refresh: '刷新',
      removeWindow: '删除时段',
      retry: '重试',
      save: '保存策略',
    },
    description: '按节点自然月流量和定时时段自动停用或恢复，管理员状态始终优先。',
    errors: {
      conflict: '策略已被其他操作修改，请刷新后重试',
      evaluate: '自动评估失败，现有节点状态保持不变',
      forbidden: '无权查看节点流量策略',
      load: '节点流量策略暂不可用，请稍后重试',
      permissionDenied: '无权修改节点流量策略',
      write: '节点流量策略保存失败',
    },
    fields: {
      endMinute: '结束分钟',
      monthlyLimit: '自然月流量上限（字节）',
      override: '手工覆盖',
      overrideExpiry: '覆盖到期时间',
      startMinute: '开始分钟',
      timezone: '结算时区',
      weekday: '星期',
    },
    loading: '正在加载节点流量策略',
    notices: {
      evaluated: '节点流量策略评估完成',
      saved: '节点流量策略已保存',
    },
    reasons: {
      admin_state_protected: '管理员状态受保护',
      manual_force_disabled: '管理员临时强制停用',
      manual_force_enabled: '管理员临时强制启用',
      monthly_limit_reached: '自然月流量已达到上限',
      period_reset: '新自然月已恢复',
      policy_recovered: '策略条件解除后已恢复',
      scheduled_window: '当前处于定时停用时段',
      unknown: '原因暂无法识别，请联系管理员核对。',
      within_policy: '未达到停用条件',
    },
    state: {
      current: '当前节点状态：{{state}}',
      evaluation: '周期 {{period}}，原因：{{reason}}',
      noEvaluation: '尚无自动评估记录',
      saveBeforeEvaluate: '请先保存初始策略，再执行自动评估。',
      sync: '配置同步：{{status}}',
    },
    title: '节点流量与自动状态策略',
    validation: {
      identity: '缺少有效的节点或作用域 ID',
      minute: '分钟必须为 0 到 1439，开始与结束不能相同',
      monthlyLimit: '流量上限必须是不小于 0 的安全整数',
      overrideExpiry: '启用手工覆盖时必须设置未来的到期时间',
      timezone: '请输入有效的 IANA 时区',
    },
    values: {
      active: '运行中',
      disabled: '管理员停用',
      draining: '排空中',
      forceDisabled: '强制停用',
      forceEnabled: '强制启用',
      none: '不覆盖',
      pending: '待审批',
      retired: '已退役',
      unknown: '未知状态',
      unlimited: '0 表示不限制',
    },
  },
  nodes: {
    actions: {
      manage: '管理',
    },
  },
  packageCommerce: {
    autoRenew: {
      enabled: '开启自动续费',
      failed: '自动续费设置失败，请稍后重试',
    },
    columns: {
      nodes: '节点数',
    },
    failure: {
      title: '交易失败',
    },
    form: {
      nodeLimit: '节点上限（-1 为不限）',
    },
  },
  packages: {
    actions: {
      sync: '同步数据',
    },
    notices: {
      addGroupFirst: '请先在“套餐分组”中添加至少一个分组',
    },
  },
  pluginInstallations: {
    consent: {
      addedHelp: '新版本多要的权限不会自动沿用之前的同意。',
      exact: '插件只能使用下面勾选的权限，没勾选的一律不给。',
      firstInstallHelp: '首次安装需要你确认插件要用的每一项权限。',
      sensitiveHelp: '这些权限涉及重要数据，需要单独确认。',
    },
    platform: {
      subtitle: '在插件商店获取或购买的插件都在这里由你确认安装：主题和规则包装到本主控，页面插件和外部服务选择装给哪些租户。租户不需要也不能确认。',
    },
    protective: {
      uninstallTitle: '卸载插件',
    },
    states: {
      awaitingController: '已购买，待你确认',
    },
    uiPage: {
      menuItem: '{{title}}（{{mount}}）',
      mount: {
        menu: '菜单',
        plugin_settings: '插件详情的设置页',
        site_tab: '网站详情页签',
      },
      origin: '页面来源',
      roles: {
        admin: '平台管理员',
        user: '租户用户',
      },
    },
  },
  pluginUI: {
    pageHint: '本页面由插件「{{plugin}}」提供，运行在 {{origin}}。',
  },
  securityPolicies: {
    cc: {
      editor: {
        key: '字段名称',
        ownerPlaceholder: '平台会话必须输入所属用户 UUID',
        targetScopePlaceholder: '平台会话必须输入租户作用域 UUID',
      },
    },
    editor: {
      targetScopePlaceholder: '小写租户作用域 UUID',
    },
  },
  siteAccessReadiness: {
    created: {
      dns: 'DNS 接入',
      dnsStates: {
        checkDns: '检查 DNS 接入',
        cnamePending: 'CNAME 生成中',
        dnsReady: '已接入',
        dnsWaiting: '等待域名解析到 CNAME',
        unknown: '待确认',
      },
      item: '{{label}}：{{value}}',
      label: '创建进度',
      publish: '节点发布',
      publishStates: {
        notPublished: '未完成',
        publishFailed: '发布失败',
        published: '已发布',
        publishing: '发布中',
        unknown: '待确认',
      },
      saved: '保存',
      savedDone: '已保存',
    },
    description: '访客能否通过 CNAME 访问本网站，逐项检查。',
    fail: '未通过',
  },
  siteCreate: {
    cname: {
      help: '留空自动分配；填写则使用你自己的 CNAME 主机名（选了套餐时以套餐分配为准）',
    },
    defaults: '端口和负载均衡留空时按网站默认设置填写（分组优先于全局），没有设置时 HTTP 监听 80、HTTPS 监听 443、轮询。',
    originHost: {
      help: '留空时使用访客访问的域名；建站后可在“回源设置”里改为源站地址或其他值',
    },
    tls: {
      safeOnly: 'TLS 固定启用 TLSv1.2 和 TLSv1.3，不允许降级。',
    },
  },
  siteDiagnostics: {
    actions: {
      next: '下一页',
      previous: '上一页',
      retry: '重试',
    },
    categories: {
      config_mismatch: '配置失配',
      no_host: '无 Host',
      unknown: '未分类异常',
      upstream_5xx: '源站 5xx',
    },
    columns: {
      category: '分类',
      config: '配置版本',
      hostPath: '域名 / 路径',
      node: '节点 ID',
      request: '请求 ID',
      status: '状态码',
      time: '发生时间',
      trace: 'Trace ID',
    },
    reasons: {
      host_missing: '请求缺少 Host',
      status_530: '状态码 530',
      status_5xx_unclassified: '5xx 来源未分类',
      status_5xx_with_upstream_result: '源站返回 5xx',
      upstream_reported_config_mismatch: '上游明确报告配置失配',
      upstream_reported_no_host: '上游明确报告无 Host',
    },
    states: {
      empty: '当前范围内没有诊断事件',
      invalidResponse: '诊断事实未通过完整性校验。',
      loading: '正在加载质量诊断',
      permission: '无权查看质量诊断',
      requestFailed: '质量诊断加载失败，请稍后重试。',
      timeout: '诊断查询超时，请缩小时间范围。',
      unavailable: '诊断证据暂不可用，请稍后重试。',
    },
    title: '质量诊断',
  },
  siteListTabs: {
    create: {
      dnsApiHelp: '建站后用所选账号把域名 CNAME 到网站 CNAME；失败不影响建站，可在「解析检测」查看和重试。',
    },
    defaults: {
      form: {
        sectionScope: '生效范围',
        sectionScopeDesc: '全局默认值作用于全部站点；网站分组只作用于选定分组内的站点。',
        sectionTarget: '配置对象',
        sectionTargetDesc: '先确定用户和设置项，设置项保存后不可在编辑态切换。',
        sectionValue: '设置内容',
        sectionValueDesc: '只配置当前设置项的默认值；复杂规则保持原有编辑器和保存结构。',
        valueNeedsName: '请选择设置项后编辑默认值。',
      },
    },
  },
  siteOriginForwarding: {
    fields: {
      originAuth: '鉴权规则',
      originAuthSwitch: '开关',
    },
  },
  sites: {
    edit: {
      locked: {
        access: {
          allow: '允许',
        },
        columns: {
          action: '执行过滤',
          mode: '匹配模式',
          remark: '备注',
          status: '状态',
          ttl: '有效期',
          type: '类型',
        },
      },
    },
    search: {
      nodeGroupPlaceholder: '输入线路分组ID',
    },
  },
  streamQuickCreate: {
    abandon: '放弃并刷新',
    cancel: '取消',
    columns: {
      port: '监听端口',
      protocol: '协议',
      result: '解析结果',
      revision: '模板修订',
      template: '配置模板',
    },
    completed: '已创建 {{count}} 条规则；发布意图仍需另行确认。',
    create: '创建 {{count}} 条规则',
    creating: '正在创建第 {{current}}/{{total}} 条规则',
    description: '选择同协议的现有规则作为完整配置模板。每个端口会创建独立规则和发布意图，保存成功不代表节点已生效。',
    errors: {
      idempotency_conflict: '幂等键已绑定到不同请求',
      permission_denied: '当前账号无权创建四层转发规则',
      request_failed: '批量创建失败，请检查当前事实后重试',
      stream_name_conflict: '按模板生成的规则名称已存在',
      stream_port_conflict: '监听端口已被现有资源占用',
      stream_shared_port_proxy_protocol: '这个端口有多个使用方（转发或网站），不能开启 PROXY 协议（入站或出站）',
      validation_error: '批量规则未通过服务端校验',
    },
    open: '批量添加监听端口',
    ports: '监听端口清单',
    preview: '创建预览',
    retryExact: '按原请求重试',
    title: '批量添加监听端口',
    unknown: {
      description: '批量操作已暂停。请使用冻结的请求内容和幂等键重试当前端口，或放弃并刷新列表核对事实。',
      title: '创建结果尚未确认',
    },
    valid: '可创建',
    validation: {
      conflict: '监听端口已被当前规则占用',
      duplicate: '同一协议的监听端口不能重复',
      empty: '请输入至少一个监听端口',
      invalid_entry: '端口项只能使用“端口”或“端口/tcp|udp”格式',
      port_range: '监听端口必须是 1 到 65535 的整数',
      template: '每种协议都必须选择一条完整配置模板',
    },
  },
  streams: {
    defaults: {
      description: '配置新增四层转发时自动带入的监听协议、负载方式与 Proxy Protocol。',
    },
    groups: {
      deleteDescription: '删除后引用该分组的转发会失去分组归属，请确认后继续。',
    },
  },
  systemConfigurationPending: {
    scope: {
      description: '保存方式：本页全部字段点「保存」一次提交，只生成新草稿，节点仍按已生效版本运行；要生效请到「节点监控」或「连接防护」页检查并启用（各分类共用一个版本，会一并生效）。',
      title: '作用范围：全部节点的全局默认值（「区域配置」页签可按区域覆盖）',
    },
  },
  systemGlobalSettings: {
    errors: {
      notification_template_invalid: '邮件和短信验证码模板必须包含｛｛captcha｝｝或 ${captcha}，且禁止使用密码占位符',
      system_user_settings_revision_conflict: '内容已被其他人修改，请刷新后再保存',
    },
    fields: {
      dnsProtection: 'DNS记录保护',
      recordRepairMode: '记录定时修复',
      resourceRank: '资源排行显示的数量',
      sourceIPHeader: '源IP请求头',
      syncBatch: '单次同步站点最大个数',
      syncScope: '同步范围',
      tcpFactor: 'TCP系数',
    },
    hints: {
      identityMethod: '三种方式只能选一种；选「不启用」即取消已选方式。修改后点本页底部「保存认证与支付设置」才会生效。',
    },
    innerNavigation: {
      all: '用户相关页内导航',
    },
    options: {
      lineGroup: '按线路组',
      region: '按区域',
      repair: '定时修复记录',
      repairDeleteExtra: '定时修复并删除多余记录',
      repairOff: '关闭',
    },
    states: {
      errorUser: '用户相关配置暂时不可用',
      loadingUser: '正在加载用户相关配置…',
      savedUser: '用户相关配置已保存',
    },
  },
  systemSentLog: {
    content: '标题/内容',
    summary: '共 {{count}} 条记录',
  },
  tenantMembers: {
    quota: '子账号 {{used}} / {{limit}}',
    upgrade: '升级套餐',
  },
  userHome: {
    subscriptions: {
      columns: {
        name: '套餐',
      },
    },
  },
  users: {
    form: {
      unsupportedDescription: '当前用户契约尚未支持改用户名或创建为禁用状态；修改密码不能与其他资料同时保存。请清空这些改动后重试，已支持字段不会被静默丢弃。',
      unsupportedTitle: '这些资料暂不能保存',
    },
    values: {
      balanceUnavailable: '余额暂时无法读取，请重试。',
      remarkMissing: '未填写备注',
    },
  },
}

export const communityCopyEnUS: TranslationTree = {
  accountIdentityVerification: {
    empty: {
      description: 'No identity verification case selected',
    },
    introduction: 'Creating a draft requires a one-time evidence handle issued by a trusted service. Only sanitized case state is displayed.',
    validation: {
      providerFormat: 'The verification service identifier is invalid',
      providerRequired: 'Enter a verification service identifier',
    },
  },
  accountMessages: {
    events: {
      hint: 'Event alerts have no read state; site and package IDs were recorded when the event happened and remain after the resource is deleted.',
    },
    filters: {
      packageID: 'User package ID',
      siteID: 'Site ID',
    },
  },
  accountProfile: {
    profile: {
      compatibility: {
        qq: 'QQ',
        unavailable: 'Not provided',
      },
    },
  },
  accountSubscriptions: {
    hints: {
      announcementPublished: 'Notifies you when the platform publishes an announcement.',
    },
  },
  adminIdentityReview: {
    description: 'Every tenant\'s identity verification requests. Start a review, then approve or reject; actions are audited as you.',
  },
  analytics: {
    filters: {
      attackRequest: 'Attack request',
    },
    states: {
      filterUnsupported: 'This filter is not supported in this version.',
    },
  },
  analyticsLogs: {
    blockState: {
      states: {
        tenantRequired: 'Platform queries require a valid tenant ID.',
      },
    },
  },
  apiKeys: {
    compatibility: {
      advancedDescription: 'Manage multiple keys, least-privilege scopes, expiry, rotation, and revocation.',
      allowlistDisabled: 'Enable API access before configuring an IP allowlist.',
      allowlistHelp: 'Restrict API clients by IP; separate IPs or networks with pipes, commas, or line breaks. Leave empty for no restriction.',
      description: 'Manage account API keys, access status, and allowed client IP addresses.',
      enableHint: 'Turning this on generates a key pair with all permissions and no expiry.',
      keyInfoDisabled: 'API access is disabled and no key is available.',
      keyInfoHelp: 'api_secret appears only once, when access is enabled or the key is reset. Store it securely.',
    },
  },
  customRolesPage: {
    description: 'Manage tenant-delegable permissions, custom role revisions, and user grants.',
    fields: {
      permission: 'Permission',
      stepUpRequired: 'Step-up requirement',
    },
    values: {
      notRequired: 'Not required',
      required: 'Required',
    },
  },
  errors: {
    demo_account_locked: 'Demo accounts cannot be changed.',
    sdk_shield_port_shared: 'An SDK shield forward cannot share its port with another forward. Use a dedicated port.',
  },
  firewall: {
    openresty: {
      cc: {
        blockPageTrafficDescription: 'Visits to the block page do not count toward tenant traffic.',
        blockWayDescription: 'Choose the default method and automatic ipset switching for non-ipset modes.',
        durationDescription: 'Configure blocklist and temporary allowlist durations.',
        enableDescription: 'Default state when no region or node override exists.',
        ipListDescription: 'One per line; # starts a comment.',
        sectionDescription: 'Configure global CC protection, blocking, and temporary allowlisting.',
        temporaryWhitelistDescription: 'Temporarily allow clients that meet the threshold.',
      },
      template: {
        description: 'Templates are distributed through immutable configuration versions.',
        sectionDescription: 'Maintain the HTML template for each challenge type.',
      },
    },
  },
  identitySessions: {
    columns: {
      sessions: 'Sessions',
    },
    values: {
      count: '{{count}}',
    },
  },
  jobs: {
    columns: {
      name: 'Name',
    },
    confirm: {
      retryTitle: 'Confirm task retry',
    },
    values: {
      noFact: 'No recorded fact',
    },
  },
  logCenter: {
    subtitle: 'Every change to configuration and data is recorded here: who, when, from which IP, and what changed.',
  },
  marketNames: {
    edit: 'Alias and note',
    failed: 'Could not save ({{code}})',
    note: 'Note: {{note}}',
    saved: 'Saved',
    seller: 'Seller {{name}}',
  },
  marketStore: {
    entitlement: {
      label: '{{name}}: {{source}}, {{state}}',
      labelSource: '{{name}}: {{source}}',
      text: '{{source}} · {{state}}',
    },
    state: {
      ready: 'Installed',
    },
    tabs: {
      more: 'More tabs',
    },
  },
  navigation: {
    diagnostics: 'Diagnostics',
    more: 'More',
    operations: 'Operations',
  },
  nodeMarket: {
    listing: {
      selectionScope: 'nodes',
    },
  },
  nodeTrafficPolicy: {
    actions: {
      addWindow: 'Add Suppression Window',
      advanced: 'Advanced Schedule',
      evaluate: 'Evaluate Now',
      refresh: 'Refresh',
      removeWindow: 'Remove Window',
      retry: 'Retry',
      save: 'Save Policy',
    },
    description: 'Automatically suppress or restore a node by natural-month traffic and scheduled windows. Administrative state always wins.',
    errors: {
      conflict: 'The policy changed elsewhere. Refresh and try again.',
      evaluate: 'Evaluation failed; existing node state was preserved',
      forbidden: 'You cannot view node traffic policy',
      load: 'Node traffic policy is temporarily unavailable',
      permissionDenied: 'You cannot change node traffic policy',
      write: 'Failed to save node traffic policy',
    },
    fields: {
      endMinute: 'End Minute',
      monthlyLimit: 'Natural-month Traffic Limit (bytes)',
      override: 'Manual Override',
      overrideExpiry: 'Override Expiry',
      startMinute: 'Start Minute',
      timezone: 'Settlement Timezone',
      weekday: 'Weekday',
    },
    loading: 'Loading node traffic policy',
    notices: {
      evaluated: 'Node traffic policy evaluated',
      saved: 'Node traffic policy saved',
    },
    reasons: {
      admin_state_protected: 'Administrative state is protected',
      manual_force_disabled: 'Temporarily forced disabled',
      manual_force_enabled: 'Temporarily forced enabled',
      monthly_limit_reached: 'Natural-month traffic limit reached',
      period_reset: 'Restored for a new natural month',
      policy_recovered: 'Restored after policy conditions cleared',
      scheduled_window: 'Scheduled suppression window is active',
      unknown: 'The reason is not recognized. Ask an administrator to verify it.',
      within_policy: 'No suppression condition matched',
    },
    state: {
      current: 'Current node state: {{state}}',
      evaluation: 'Period {{period}}, reason: {{reason}}',
      noEvaluation: 'No automatic evaluation yet',
      saveBeforeEvaluate: 'Save the initial policy before evaluating it.',
      sync: 'Configuration sync: {{status}}',
    },
    title: 'Node Traffic and Automatic State Policy',
    validation: {
      identity: 'A valid node and scope ID are required',
      minute: 'Minutes must be 0 through 1439 and cannot be equal',
      monthlyLimit: 'Traffic limit must be a non-negative safe integer',
      overrideExpiry: 'A future expiry is required when an override is enabled',
      timezone: 'Enter a valid IANA timezone',
    },
    values: {
      active: 'Active',
      disabled: 'Administratively Disabled',
      draining: 'Draining',
      forceDisabled: 'Force Disabled',
      forceEnabled: 'Force Enabled',
      none: 'No Override',
      pending: 'Pending',
      retired: 'Retired',
      unknown: 'Unknown state',
      unlimited: '0 means unlimited',
    },
  },
  nodes: {
    actions: {
      manage: 'Manage',
    },
  },
  packageCommerce: {
    autoRenew: {
      enabled: 'Enable auto-renew',
      failed: 'Could not save auto-renew settings. Try again later',
    },
    columns: {
      nodes: 'Nodes',
    },
    failure: {
      title: 'Transaction failed',
    },
    form: {
      nodeLimit: 'Node limit (-1 for unlimited)',
    },
  },
  packages: {
    actions: {
      sync: 'Sync data',
    },
    notices: {
      addGroupFirst: 'Add at least one package group in Package groups first',
    },
  },
  pluginInstallations: {
    consent: {
      addedHelp: 'New upgrade permissions never inherit earlier consent.',
      exact: 'Only the listed manifest scopes will be approved. Undeclared scopes remain denied.',
      firstInstallHelp: 'A first installation asks you to confirm each permission the plugin uses.',
      sensitiveHelp: 'Sensitive permissions require separate consent.',
    },
    platform: {
      subtitle: 'Plugins you get or buy in the plugin store are confirmed here: themes and rule packs install on this controller, UI page plugins and external services for the tenants you choose. Tenants neither need nor can confirm them.',
    },
    protective: {
      uninstallTitle: 'Uninstall plugin',
    },
    states: {
      awaitingController: 'Purchased, awaiting your confirmation',
    },
    uiPage: {
      menuItem: '{{title}} ({{mount}})',
      mount: {
        menu: 'menu',
        plugin_settings: 'settings in the plugin detail',
        site_tab: 'site detail tab',
      },
      origin: 'Page origin',
      roles: {
        admin: 'platform administrators',
        user: 'tenant users',
      },
    },
  },
  pluginUI: {
    pageHint: 'This page is provided by plugin "{{plugin}}" and runs on {{origin}}.',
  },
  securityPolicies: {
    cc: {
      editor: {
        key: 'Field name',
        ownerPlaceholder: 'Platform sessions require an owner UUID',
        targetScopePlaceholder: 'Platform sessions require a tenant scope UUID',
      },
    },
    editor: {
      targetScopePlaceholder: 'Canonical lowercase tenant scope UUID',
    },
  },
  siteAccessReadiness: {
    created: {
      dns: 'DNS access',
      dnsStates: {
        checkDns: 'check DNS access',
        cnamePending: 'CNAME generating',
        dnsReady: 'connected',
        dnsWaiting: 'waiting for DNS to point at the CNAME',
        unknown: 'to be confirmed',
      },
      item: '{{label}}: {{value}}',
      label: 'Setup progress',
      publish: 'Node publishing',
      publishStates: {
        notPublished: 'not finished',
        publishFailed: 'failed',
        published: 'published',
        publishing: 'publishing',
        unknown: 'to be confirmed',
      },
      saved: 'Save',
      savedDone: 'saved',
    },
    description: 'Whether visitors can reach this site through its CNAME, check by check.',
    fail: 'Not passed',
  },
  siteCreate: {
    cname: {
      help: 'Leave empty to allocate automatically; fill it to use your own CNAME hostname (with a package, the package allocation wins)',
    },
    defaults: 'Empty ports and load balancing follow your website default settings (group before global); without them HTTP listens on 80, HTTPS on 443, with round robin.',
    originHost: {
      help: 'Empty sends the visitor\'s Host; change it later under Origin settings',
    },
    tls: {
      safeOnly: 'TLSv1.2 and TLSv1.3 are always enabled; downgrade is blocked.',
    },
  },
  siteDiagnostics: {
    actions: {
      next: 'Next',
      previous: 'Previous',
      retry: 'Retry',
    },
    categories: {
      config_mismatch: 'Config mismatch',
      no_host: 'No host',
      unknown: 'Unclassified error',
      upstream_5xx: 'Upstream 5xx',
    },
    columns: {
      category: 'Category',
      config: 'Config version',
      hostPath: 'Host / path',
      node: 'Node ID',
      request: 'Request ID',
      status: 'Status',
      time: 'Occurred at',
      trace: 'Trace ID',
    },
    reasons: {
      host_missing: 'Request host missing',
      status_530: 'Status 530',
      status_5xx_unclassified: '5xx source unclassified',
      status_5xx_with_upstream_result: 'Upstream returned 5xx',
      upstream_reported_config_mismatch: 'Upstream reported config mismatch',
      upstream_reported_no_host: 'Upstream reported no host',
    },
    states: {
      empty: 'No diagnostic events in this range',
      invalidResponse: 'Diagnostic facts failed integrity validation.',
      loading: 'Loading quality diagnostics',
      permission: 'Diagnostics unavailable',
      requestFailed: 'Quality diagnostics could not be loaded.',
      timeout: 'The diagnostic query timed out. Use a smaller range.',
      unavailable: 'Diagnostic evidence is unavailable. Try again later.',
    },
    title: 'Quality diagnostics',
  },
  siteListTabs: {
    create: {
      dnsApiHelp: 'After the site is created, the account points each domain at the site CNAME. A failure does not affect the site; see and retry it under Resolution check.',
    },
    defaults: {
      form: {
        sectionScope: 'Scope',
        sectionScopeDesc: 'A global default applies to all sites; a site group default only to sites in that group.',
        sectionTarget: 'Target',
        sectionTargetDesc: 'Choose the user and the setting first; the setting cannot be switched when editing.',
        sectionValue: 'Value',
        sectionValueDesc: 'Only the default of this setting; complex rules keep their own editor and format.',
        valueNeedsName: 'Choose a setting to edit its default.',
      },
    },
  },
  siteOriginForwarding: {
    fields: {
      originAuth: 'Signing rules',
      originAuthSwitch: 'Enabled',
    },
  },
  sites: {
    edit: {
      locked: {
        access: {
          allow: 'Allow',
        },
        columns: {
          action: 'Filter action',
          mode: 'Match mode',
          remark: 'Remarks',
          status: 'Status',
          ttl: 'TTL',
          type: 'Type',
        },
      },
    },
    search: {
      nodeGroupPlaceholder: 'Enter a line group ID',
    },
  },
  streamQuickCreate: {
    abandon: 'Abandon and refresh',
    cancel: 'Cancel',
    columns: {
      port: 'Listener port',
      protocol: 'Protocol',
      result: 'Parse result',
      revision: 'Template revision',
      template: 'Configuration template',
    },
    completed: 'Created {{count}} rules. Publication intent delivery still needs separate confirmation.',
    create: 'Create {{count}} rules',
    creating: 'Creating rule {{current}}/{{total}}',
    description: 'Reuse an existing rule of the same protocol as the complete configuration template. Each port creates a separate rule and publication intent; saving does not prove node activation.',
    errors: {
      idempotency_conflict: 'The idempotency key is bound to a different request',
      permission_denied: 'This account cannot create layer 4 forwarding rules',
      request_failed: 'Bulk creation failed. Check current facts before retrying',
      stream_name_conflict: 'The rule name generated from the template already exists',
      stream_port_conflict: 'The listener port is already used by an existing resource',
      stream_shared_port_proxy_protocol: 'PROXY protocol (inbound or outbound) cannot be used on a port shared with other streams or websites',
      validation_error: 'The batch rule failed server validation',
    },
    open: 'Add listener ports in bulk',
    ports: 'Listener port list',
    preview: 'Creation preview',
    retryExact: 'Retry exact request',
    title: 'Add listener ports in bulk',
    unknown: {
      description: 'The batch is paused. Retry the current port with the frozen body and idempotency key, or abandon and refresh the list to check durable facts.',
      title: 'Creation result is unconfirmed',
    },
    valid: 'Ready',
    validation: {
      conflict: 'The listener port is already used by a current rule',
      duplicate: 'A listener port cannot repeat within the same protocol',
      empty: 'Enter at least one listener port',
      invalid_entry: 'Each entry must use the port or port/tcp|udp format',
      port_range: 'Listener ports must be integers from 1 to 65535',
      template: 'Select one complete configuration template for every protocol',
    },
  },
  streams: {
    defaults: {
      description: 'Configure the listen protocol, load balancing method and Proxy Protocol applied automatically to new layer 4 forwarding rules.',
    },
    groups: {
      deleteDescription: 'Forwarding rules that reference this group lose their group after deletion. Confirm to continue.',
    },
  },
  systemConfigurationPending: {
    scope: {
      description: 'Saving: Save submits every field on this page as one new draft; nodes keep running the active revision. To make it effective, check and activate it on the Node monitoring or Connection protection page (all categories share one revision and become effective together).',
      title: 'Applies to: the global defaults of every node (the region tab overrides them per region)',
    },
  },
  systemGlobalSettings: {
    errors: {
      notification_template_invalid: 'Email and SMS verification templates must contain the captcha placeholder; password placeholders are forbidden',
      system_user_settings_revision_conflict: 'Someone else changed this content. Refresh before saving.',
    },
    fields: {
      dnsProtection: 'DNS record protection',
      recordRepairMode: 'Record repair',
      resourceRank: 'Resource ranking count',
      sourceIPHeader: 'Source IP header',
      syncBatch: 'Maximum sites per sync',
      syncScope: 'Sync scope',
      tcpFactor: 'TCP coefficient',
    },
    hints: {
      identityMethod: 'Choose one of the three methods; choose "Off" to clear the choice. Changes take effect after "Save identity and payment settings" at the bottom of this tab.',
    },
    innerNavigation: {
      all: 'User settings section navigation',
    },
    options: {
      lineGroup: 'By line group',
      region: 'By region',
      repair: 'Repair records',
      repairDeleteExtra: 'Repair and delete extra records',
      repairOff: 'Disabled',
    },
    states: {
      errorUser: 'User settings are unavailable',
      loadingUser: 'Loading user settings…',
      savedUser: 'User settings saved',
    },
  },
  systemSentLog: {
    content: 'Title/content',
    summary: '{{count}} records',
  },
  tenantMembers: {
    quota: 'Sub-accounts {{used}} / {{limit}}',
    upgrade: 'Upgrade package',
  },
  userHome: {
    subscriptions: {
      columns: {
        name: 'Package',
      },
    },
  },
  users: {
    form: {
      unsupportedDescription: 'The current user contract does not yet support username changes or creating a disabled user; password changes cannot be saved together with other profile changes. Clear those changes and retry. Supported fields are never discarded silently.',
      unsupportedTitle: 'These profile fields cannot be saved yet',
    },
    values: {
      balanceUnavailable: 'Balances could not be loaded. Please retry.',
      remarkMissing: 'Remark not set',
    },
  },
}
