// 文档里会随在途分支变化的运维事实，集中一处（www-design.md §3.8 命名注意）。
// - 服务名前缀 SERVICE_PREFIX。docs.test.ts 会核对这里的服务名与安装脚本 readonly 常量一致。

export const SERVICE_PREFIX = 'cdnca'

export const SERVICES = {
  controlApi: `${SERVICE_PREFIX}-control-api`,
  gateway: `${SERVICE_PREFIX}-agent-gateway`,
  nats: `${SERVICE_PREFIX}-control-nats`,
  web: `${SERVICE_PREFIX}-control-web`,
  edgeAgent: `${SERVICE_PREFIX}-edge-agent`,
}

/** 节点卸载脚本落点（agents/edge-agent/packaging/scripts/install.sh:283） */
export const NODE_UNINSTALL = `/usr/libexec/${SERVICE_PREFIX}-edge-agent/uninstall.sh`
