// ui_page 开发者 SDK 页（/developers/ui-sdk）。内容取自 docs/developer/plugin-integration.md §8.3；
// SDK 与后端验签源码按原文件内容嵌入（?raw），仓库里改了 SDK，官网随构建更新。
// uiSdk.test.tsx 校验协议常量、方法白名单与签名域与 SDK / 主控代码一致。
import type { L } from '../i18n'
import type { Block } from './docs'
import { DEV_KIT_FETCH, DEV_KIT_FILE } from './pluginSigning'
import sdkSource from '../../../../docs/developer/examples/plugin-ui-sdk/cdnca-plugin-ui.mjs?raw'
import backendSource from '../../../../docs/developer/examples/plugin-ui-sdk/verify-backend.mjs?raw'

const s = (zh: string, en: string): L => ({ zh, en })

export const SDK_SOURCE: string = sdkSource
export const BACKEND_SOURCE: string = backendSource

export const UI_PROTOCOL = 'cdnca.plugin-ui/v1'
export const UI_METHODS = ['context.get', 'navigate', 'api.request']
export const PROXY_SIGNATURE_DOMAIN = 'cdnca-plugin-ui-proxy/v1'
export const UI_CONTEXT_SCHEMA = 'cdnca.plugin-ui-context/v1'

export const UI_SDK_BLOCKS: Block[] = [
  { h: s('页面运行环境', 'Where the page runs') },
  { p: s('页面由你自己的 https origin 提供，主控在固定挂载点用 <iframe sandbox="allow-scripts allow-forms"> 加载（不给 allow-same-origin）。框内 origin 是不透明的 null：读不到主控的 Cookie、localStorage、sessionStorage、IndexedDB，碰不到主控 DOM，也不能导航顶层窗口。只有已启用的 ui_page 插件 origin 会进主控的 frame-src，停用或卸载后下次同步即撤下。',
    'Pages are served from your own https origin; the control plane loads them at fixed mount points in <iframe sandbox="allow-scripts allow-forms"> (no allow-same-origin). The frame origin is the opaque null: no access to the control plane’s cookies, localStorage, sessionStorage or IndexedDB, its DOM, or top-level navigation. Only enabled ui_page plugin origins enter the control plane’s frame-src; disabling or uninstalling removes them on the next sync.') },
  { h: s('握手与消息', 'Handshake and messages') },
  { list: [
    s('页面从 URL 片段 #cdnca-nonce=<nonce> 读 nonce，向 parent 发 {protocol, type: "cdnca.hello", nonce}。', 'The page reads the nonce from the URL fragment #cdnca-nonce=<nonce> and posts {protocol, type: "cdnca.hello", nonce} to parent.'),
    s('宿主只认这个 iframe 的窗口和这个 nonce，回 {type: "cdnca.ready"} 并转交一个 MessagePort。', 'The host accepts only this iframe’s window and nonce, answers {type: "cdnca.ready"} and hands over a MessagePort.'),
    s('之后所有请求只走这个端口：{protocol, nonce, id, method, params}，应答 {protocol, nonce, id, ok, result | error}。', 'From then on every request uses that port: {protocol, nonce, id, method, params}, answered with {protocol, nonce, id, ok, result | error}.'),
  ], ordered: true },
  { table: { head: [s('方法', 'Method'), s('说明', 'Meaning')], rows: [
    [s('context.get', 'context.get'), s('用户 ID / 显示名 / 角色、租户作用域、站点 ID、语言、明暗主题；不含任何凭据', 'User ID / display name / role, tenant scope, site ID, locale, light or dark theme; no credentials')],
    [s('navigate', 'navigate'), s('{path}：站内相对路径；登录、找回密码、API 密钥、个人资料等页面会被拒绝', '{path}: an in-app relative path; sign-in, password recovery, API keys, profile and similar pages are refused')],
    [s('api.request', 'api.request'), s('{method, path, query?, body?}：经主控代理调用你的 api_base_url', '{method, path, query?, body?}: call your api_base_url through the control plane proxy')],
  ] } },
  { p: s('其他消息一律回 message_not_allowed。', 'Any other message answers message_not_allowed.') },
  { h: s('受限 API 与后端验签', 'Restricted API and backend verification') },
  { p: s('api.request 由宿主转给主控 POST /v1/plugin-ui/{plugin_id}/proxy，主控再转发到 api_base_url：只连公网、不跟随重定向、只回 JSON、每用户每插件每分钟 120 次。主控不转发用户会话或 token，而是附带三个请求头：',
    'api.request goes to the control plane’s POST /v1/plugin-ui/{plugin_id}/proxy, which forwards it to api_base_url: public addresses only, no redirects, JSON only, 120 per user per plugin per minute. The control plane never forwards the user’s session or token; it adds three headers instead:') },
  { table: { head: [s('请求头', 'Header'), s('内容', 'Content')], rows: [
    [s('X-Cdnca-Plugin-Context', 'X-Cdnca-Plugin-Context'), s('base64url JSON（cdnca.plugin-ui-context/v1），60 秒有效，含 nonce', 'base64url JSON (cdnca.plugin-ui-context/v1), valid 60 s, with a nonce')],
    [s('X-Cdnca-Plugin-Signature', 'X-Cdnca-Plugin-Signature'), s('安装私钥的 Ed25519 签名（base64url）', 'Ed25519 signature by the installation key (base64url)')],
    [s('X-Cdnca-Plugin-Key-Id', 'X-Cdnca-Plugin-Key-Id'), s('安装公钥 ID', 'Installation key ID')],
  ] } },
  { cmd: '"cdnca-plugin-ui-proxy/v1\\n" + METHOD + "\\n" + path?query + "\\n" + hex(sha256(body)) + "\\n" + context', label: s('签名消息', 'Signed message') },
  { p: s('path 是相对 api_base_url 路径部分的路径。后端用安装公钥验签、检查有效期并记住 nonce。安装公钥由客户主控管理员在“插件市场 → 插件详情 → 安装签名公钥”复制给你（接口 GET /v1/plugin-ui/signing-key，key_id 即 X-Cdnca-Plugin-Key-Id）。写操作与被拒调用记审计 plugin.ui_page.proxy。',
    'path is relative to the path part of api_base_url. Your backend verifies with the installation public key, checks validity and remembers the nonce. The customer’s administrator copies the installation public key to you from “Plugin market → plugin detail → Installation signing key” (GET /v1/plugin-ui/signing-key; key_id is X-Cdnca-Plugin-Key-Id). Writes and refused calls are audited as plugin.ui_page.proxy.') },
  { h: s('安装确认', 'Installation confirmation') },
  { p: s('客户管理员确认安装或升级时，弹窗按授权端签过的清单指纹到插件市场核对该版本，列出将添加的菜单、页面 origin 与插件后端；指纹对不上或市场不可达时只提示去平台核实，不展示其他版本的声明。',
    'When the customer’s administrator confirms an install or upgrade, the dialog checks the version on the plugin market by the manifest fingerprint the licence service signed and lists the menus, page origins and plugin backend it adds; if the fingerprint does not match or the market is unreachable it only asks to verify with the platform and never shows another version’s declaration.') },
  { h: s('SDK 文件与自测', 'SDK files and self-test') },
  { list: [
    s('cdnca-plugin-ui.mjs：框内 SDK，无依赖。connect() 完成握手，返回 context() / navigate(path) / request({method, path, query, body})，错误是带 code 的 PluginUIError。', 'cdnca-plugin-ui.mjs: the in-frame SDK, no dependencies. connect() does the handshake and returns context() / navigate(path) / request({method, path, query, body}); errors are PluginUIError with a code.'),
    s('index.html：示例页。', 'index.html: a sample page.'),
    s('verify-backend.mjs：Node.js 后端验签（签名、key_id、有效期、nonce 防重放）。', 'verify-backend.mjs: Node.js backend verifier (signature, key_id, validity, nonce replay).'),
    s('proxy-vector.json：主控测试 TestDeveloperSDKProxyVector 生成的金标向量。', 'proxy-vector.json: the golden vector the control plane test TestDeveloperSDKProxyVector produces.'),
  ] },
  { p: s(`这些文件和自测在开发套件 ${DEV_KIT_FILE} 的 docs/developer/examples/plugin-ui-sdk/ 目录（与签名工具同站下载，与主控同版本发布），自测需要 Node.js 20 或更高。先下载、核对哈希并解包：`,
    `The files and the self-test are in docs/developer/examples/plugin-ui-sdk/ of the developer kit ${DEV_KIT_FILE} (downloaded from the same site as the signing tool, released with each control plane version); the self-test needs Node.js 20 or later. Download, check the hash and unpack:`) },
  { cmd: DEV_KIT_FETCH, label: s('macOS 把 sha256sum -c 换成 shasum -a 256 -c', 'On macOS use shasum -a 256 -c instead of sha256sum -c') },
  { cmd: 'node --test docs/developer/examples/plugin-ui-sdk/sdk.test.mjs', label: s('在 cdnca-dev-kit 目录里自测', 'Self-test in cdnca-dev-kit') },
]
