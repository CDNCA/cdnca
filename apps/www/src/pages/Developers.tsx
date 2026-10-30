import { KeyRound } from 'lucide-react'
import { Figure, PageHero, Section } from '../components/Blocks'
import { FigFlow } from '../components/Figures'
import { getCatalog, getGroupDetail, type ApiField, type ApiGroup, type ApiOperationDetail } from '../content/apiCatalog'
import { CATEGORIES, EARN, INTEGRATIONS, type Category } from '../content/developers'
import { GUIDES_PATH, REVIEW_RULES_PATH } from '../content/devGuides'
import { TUTORIAL_API_PATH, TUTORIALS, TUTORIALS_PATH } from '../content/devTutorials'
import { DOWNLOAD_INTRO, PLUGIN_CLI_DOWNLOADS, PLUGIN_CLI_FILES, PLUGIN_SIGNING_PATH, SIGNING_BLOCKS, VERIFY_BLOCKS } from '../content/pluginSigning'
import { href, type Lang } from '../i18n'
import { LINKS } from '../site'
import { renderBlock } from './Docs'

const T = {
  h1: { zh: '写插件，在每一个 cdnca 主控里售卖', en: 'Build plugins. Sell them in every cdnca control plane.' },
  lead: { zh: '开放 API、事件 Webhook 与插件市场：你的扩展直接出现在每个主控的插件市场里，买家一键购买。', en: 'Open API, event webhooks and a plugin market: your extension appears in every control plane’s market, one click to buy.' },
  enter: { zh: '进入开发者平台', en: 'Open the developer platform' },
  api: { zh: '查看开放接口', en: 'Browse the API' },
  signing: { zh: '插件签名工具', en: 'Plugin signing tool' },
  guides: { zh: '开发指南', en: 'Developer guides' },
  tutorials: { zh: '开发教程', en: 'Tutorials' },
  rules: { zh: '审核规则', en: 'Review rules' },
  soon: { zh: '即将开放', en: 'Coming soon' },
  ways: { zh: '三种对接方式', en: 'Three ways to integrate' },
  start: { zh: '按步骤开始', en: 'Start step by step' },
  startLead: { zh: '从入驻到卸载的任务式教程；每一步都写了怎么做、怎样确认、出错怎么办。', en: 'Task-based tutorials from onboarding to uninstall: how to do each step, how to confirm it, what to do when it fails.' },
  flow: { zh: '从入驻到收款', en: 'From sign-up to payout' },
  cats: { zh: '可以开发什么', en: 'What you can build' },
  catsLead: { zh: '类目与插件市场支持的类型一一对应；标“官方专属”的只由官方发布。', en: 'Categories match the plugin kinds the market accepts; those marked “Official only” are published by cdnca alone.' },
  allCats: { zh: '查看全部类目', en: 'All categories' },
  earn: { zh: '怎么赚钱', en: 'How you earn' },
  earnMore: { zh: '收入与结算方式', en: 'Income and settlement' },
  official: { zh: '官方专属', en: 'Official only' },
  open: { zh: '开放', en: 'Open' },
  kind: { zh: '类型', en: 'Kind' },
  name: { zh: '类目', en: 'Category' },
  desc: { zh: '说明', en: 'Description' },
  who: { zh: '谁可以发布', en: 'Who can publish' },
}

function kindLabel(c: { kind: string; provides?: string }) {
  return c.provides ? `${c.kind} / ${c.provides}` : c.kind
}

function availabilityTag(c: Category, lang: Lang) {
  if (c.officialOnly) return <span className="tag tag-official">{T.official[lang]}</span>
  return <span className="tag">{c.comingSoon ? T.soon[lang] : T.open[lang]}</span>
}

export function DevelopersPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero eyebrow={lang === 'zh' ? '开发者平台' : 'Developer platform'} title={T.h1[lang]} lead={T.lead[lang]}>
        <div className="btn-row">
          <a className="btn btn-primary" href={LINKS.developerLogin}>{T.enter[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, TUTORIALS_PATH)}>{T.tutorials[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, '/developers/api')}>{T.api[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, PLUGIN_SIGNING_PATH)}>{T.signing[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, GUIDES_PATH)}>{T.guides[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, REVIEW_RULES_PATH)}>{T.rules[lang]}</a>
        </div>
      </PageHero>
      <Section id="start" title={T.start[lang]} lead={T.startLead[lang]}>
        <ol className="grid grid-3 api-groups tutorial-cards">
          {TUTORIALS.map((t, i) => (
            <li key={t.slug}>
              <a className="card api-group" href={href(lang, `${TUTORIALS_PATH}/${t.slug}`)}>
                <span className="muted">{i + 1}</span>
                <strong>{t.nav[lang]}</strong>
              </a>
            </li>
          ))}
        </ol>
      </Section>
      <Section id="ways" title={T.ways[lang]} alt>
        <div className="grid grid-3">
          {INTEGRATIONS.map((w) => (
            <article className="card" key={w.title.en}>
              <h3>{w.title[lang]}</h3>
              <p>{w.body[lang]}</p>
              <p className="muted">{w.facts[lang]}</p>
            </article>
          ))}
        </div>
      </Section>
      <Section id="flow" title={T.flow[lang]}>
        <Figure><FigFlow k="H" lang={lang} /></Figure>
      </Section>
      <Section id="cats" title={T.cats[lang]} lead={T.catsLead[lang]} alt>
        <div className="grid grid-3">
          {CATEGORIES.map((c) => (
            <article className="card" key={c.name.en}>
              <p>{availabilityTag(c, lang)} <code>{kindLabel(c)}</code></p>
              <h3>{c.name[lang]}</h3>
              <p>{c.body[lang]}</p>
            </article>
          ))}
        </div>
        <p><a href={href(lang, '/developers/categories')}>{T.allCats[lang]} →</a></p>
      </Section>
      <Section id="earn" title={T.earn[lang]}>
        <div className="grid grid-2">
          {EARN.map((e) => (
            <article className="card" key={e.title.en}><h3>{e.title[lang]}</h3><p>{e.body[lang]}</p></article>
          ))}
        </div>
        <p><a href={href(lang, '/developers/earn')}>{T.earnMore[lang]} →</a></p>
      </Section>
    </>
  )
}

export function CategoriesPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero title={T.cats[lang]} lead={T.catsLead[lang]}>
        <div className="btn-row"><a className="btn btn-primary" href={LINKS.developerLogin}>{T.enter[lang]}</a></div>
      </PageHero>
      <Section id="table">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th scope="col">{T.name[lang]}</th><th scope="col">{T.kind[lang]}</th><th scope="col">{T.who[lang]}</th><th scope="col">{T.desc[lang]}</th></tr></thead>
            <tbody>
              {CATEGORIES.map((c) => (
                <tr key={c.name.en} data-kind={kindLabel(c)}>
                  <th scope="row">{c.name[lang]}</th>
                  <td><code>{kindLabel(c)}</code></td>
                  <td>{c.officialOnly ? <span className="tag tag-official">{T.official[lang]}</span> : c.comingSoon ? <span className="tag">{T.soon[lang]}</span> : (lang === 'zh' ? '认证开发者' : 'Verified developers')}</td>
                  <td>{c.body[lang]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
    </>
  )
}

export function EarnPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero title={T.earnMore[lang]} lead={lang === 'zh' ? '你自己定价，钱怎么到账一目了然。' : 'You set the price; here is how the money reaches you.'}>
        <div className="btn-row"><a className="btn btn-primary" href={LINKS.developerLogin}>{T.enter[lang]}</a></div>
      </PageHero>
      {EARN.map((e, i) => (
        <Section key={e.title.en} id={`earn-${i}`} title={e.title[lang]} alt={i % 2 === 1}>
          <p className="lead">{e.body[lang]}</p>
          <Figure><FigFlow k={e.figure} lang={lang} /></Figure>
        </Section>
      ))}
    </>
  )
}

const SIGN_T = {
  title: { zh: '插件签名：cdnca-plugin', en: 'Plugin signing: cdnca-plugin' },
  lead: { zh: '下载离线签名工具，生成发布者密钥、登记公钥并给 manifest 签名。', en: 'Download the offline signing tool, create a publisher key, register it and sign your manifest.' },
  download: { zh: '下载', en: 'Download' },
  platform: { zh: '平台', en: 'Platform' },
  file: { zh: '文件', en: 'File' },
  sums: { zh: 'SHA256SUMS（全部文件的哈希）', en: 'SHA256SUMS (hashes of all files)' },
  usage: { zh: '使用', en: 'Usage' },
}

export function PluginSigningPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero eyebrow={lang === 'zh' ? '开发者平台' : 'Developer platform'} title={SIGN_T.title[lang]} lead={SIGN_T.lead[lang]}>
        <div className="btn-row"><a className="btn btn-primary" href={LINKS.developerLogin}>{T.enter[lang]}</a></div>
      </PageHero>
      <Section id="download" title={SIGN_T.download[lang]}>
        <article className="prose">
          <p>{DOWNLOAD_INTRO[lang]}</p>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th scope="col">{SIGN_T.platform[lang]}</th><th scope="col">{SIGN_T.file[lang]}</th></tr></thead>
              <tbody>
                {PLUGIN_CLI_FILES.map((f) => (
                  <tr key={f.file}><th scope="row">{f.platform[lang]}</th><td><a href={`${PLUGIN_CLI_DOWNLOADS}/${f.file}`} download><code>{f.file}</code></a></td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <p><a href={`${PLUGIN_CLI_DOWNLOADS}/SHA256SUMS`}>{SIGN_T.sums[lang]}</a></p>
          {VERIFY_BLOCKS.map((b, i) => renderBlock(b, lang, i))}
        </article>
      </Section>
      <Section id="usage" title={SIGN_T.usage[lang]} alt>
        <article className="prose">{SIGNING_BLOCKS.map((b, i) => renderBlock(b, lang, i))}</article>
      </Section>
    </>
  )
}

const AUTH_LABEL: Record<string, { zh: string; en: string }> = {
  apiKey: { zh: 'API Key 可调', en: 'API key' },
  bearer: { zh: '登录会话', en: 'Session' },
  none: { zh: '无需认证', en: 'Public' },
  mtls: { zh: 'mTLS', en: 'mTLS' },
  basic: { zh: 'Basic', en: 'Basic' },
  oauth2: { zh: 'OAuth2', en: 'OAuth2' },
  oidc: { zh: 'OIDC', en: 'OIDC' },
}

/** 认证方式在详情里的完整说明（与开发教程“接口调用”一节一致）。 */
const AUTH_HOW: Record<string, { zh: string; en: string }> = {
  apiKey: { zh: 'API Key：请求头 Authorization: CdncaKey <key_id>.<secret>。有效权限是 Key 的范围与所有者当前权限的交集。', en: 'API key: header Authorization: CdncaKey <key_id>.<secret>. Effective permissions are the key scopes intersected with the owner’s current permissions.' },
  bearer: { zh: '登录会话：主控登录后的 Bearer 会话，由客户本人在自己的主控里使用；插件不能要求客户交出会话。', en: 'Session: the Bearer session of a signed-in control plane user, used by the customer in their own control plane; a plugin must never ask for it.' },
  none: { zh: '无需认证。', en: 'No authentication.' },
  mtls: { zh: '双向 TLS：只用于平台内部组件之间。', en: 'Mutual TLS: only between platform components.' },
  basic: { zh: 'HTTP Basic。', en: 'HTTP Basic.' },
  oauth2: { zh: 'OAuth2。', en: 'OAuth2.' },
  oidc: { zh: 'OpenID Connect。', en: 'OpenID Connect.' },
}

const API_T = {
  h1: { zh: '开放接口', en: 'API reference' },
  lead: { zh: '从 OpenAPI 契约自动生成，只列面向集成方的接口（不含内部接口）。每个分组页给出接口的认证方式、所需权限、参数、请求与响应字段和状态码。', en: 'Generated from the OpenAPI contracts. Integration-facing operations only (internal ones excluded). Each group page gives every operation’s auth, required permissions, parameters, request and response fields and status codes.' },
  groups: { zh: '接口分组', en: 'Groups' },
  ops: { zh: '个接口', en: 'operations' },
  keyOps: { zh: '个接口支持 API Key', en: 'support API keys' },
  onlyKey: { zh: 'API Key 可调', en: 'API key' },
  unavailable: { zh: '接口目录加载失败，请刷新重试。', en: 'Could not load the catalogue. Please reload.' },
  method: { zh: '方法', en: 'Method' },
  path: { zh: '路径', en: 'Path' },
  summary: { zh: '摘要', en: 'Summary' },
  auth: { zh: '认证', en: 'Auth' },
  back: { zh: '全部分组', en: 'All groups' },
  deprecated: { zh: '已废弃', en: 'Deprecated' },
  howKey: { zh: '标“API Key 可调”的接口可以用客户签发的 API Key 调用（Authorization: CdncaKey <key_id>.<secret>）；其余接口只接受主控登录会话。', en: 'Operations marked “API key” accept a customer-issued API key (Authorization: CdncaKey <key_id>.<secret>); the others accept only a control plane session.' },
  tutorial: { zh: '第一次调用？先看教程：认证、权限、请求与响应、常见失败', en: 'First call? Read the tutorial: auth, permissions, requests and responses, common failures' },
  details: { zh: '接口详情', en: 'Operation details' },
  toTable: { zh: '回到列表', en: 'Back to list' },
  description: { zh: '说明（契约原文）', en: 'Description (from the contract)' },
  descriptionZh: { zh: '说明', en: 'Description' },
  permissions: { zh: '所需权限', en: 'Required permissions' },
  allOf: { zh: '全部需要', en: 'All of' },
  anyOf: { zh: '任一即可', en: 'Any of' },
  features: { zh: '需要开通的功能', en: 'Required features' },
  reauth: { zh: '需要近期重新验证身份', en: 'Requires recent re-authentication' },
  noPerm: { zh: '契约没有单独标注权限码，权限要求见下方说明与 403 响应。', en: 'The contract has no separate permission annotation; see the description below and the 403 response.' },
  params: { zh: '参数', en: 'Parameters' },
  body: { zh: '请求体', en: 'Request body' },
  responses: { zh: '响应', en: 'Responses' },
  name: { zh: '名称', en: 'Name' },
  in: { zh: '位置', en: 'In' },
  type: { zh: '类型', en: 'Type' },
  required: { zh: '必填', en: 'Required' },
  yes: { zh: '是', en: 'Yes' },
  no: { zh: '否', en: 'No' },
  desc: { zh: '说明', en: 'Description' },
  status: { zh: '状态码', en: 'Status' },
  fields: { zh: '字段', en: 'Fields' },
  next: { zh: '失败时怎么办', en: 'What to do on failure' },
  source: { zh: '契约文件', en: 'Contract file' },
  detailMissing: { zh: '接口详情加载失败，请刷新重试。', en: 'Could not load the operation details. Please reload.' },
}

/** 常见状态码的下一步（与开发教程“常见失败及下一步”一致；只对响应里出现的状态码显示）。 */
const NEXT_STEP: Record<string, { zh: string; en: string }> = {
  '400': { zh: '按字段说明修正参数或请求体再发；不要原样重试。', en: 'Fix the parameters or body per the field list; do not retry unchanged.' },
  '401': { zh: '检查凭据格式、是否过期或被轮换。', en: 'Check the credential format and whether it expired or was rotated.' },
  '403': { zh: '检查 Key 范围与所有者当前权限、当前租户作用域；不要换更高权限账号绕过。', en: 'Check the key scopes, the owner’s current permissions and the tenant scope; never switch to a more privileged account.' },
  '404': { zh: '资源不存在或不属于当前租户。', en: 'The resource does not exist or belongs to another tenant.' },
  '409': { zh: '先回读资源当前状态；同一操作重试保持原 Idempotency-Key 和原请求内容。', en: 'Read the current state first; a retry of the same operation keeps the original Idempotency-Key and body.' },
  '412': { zh: '版本已变：回读最新 ETag 后重新判断，再带新的 If-Match 提交。', en: 'The revision changed: read the latest ETag, decide again, then send the new If-Match.' },
  '428': { zh: '缺少前置条件：回读资源，带 If-Match（或页面要求的验证）再提交。', en: 'A precondition is missing: read the resource and send If-Match (or the required proof).' },
  '429': { zh: '被限速：等待后再试，降低并发。', en: 'Rate limited: wait, then retry with lower concurrency.' },
  '500': { zh: '结果未知：先按资源 ID 或列表回读确认，再决定是否用原 Idempotency-Key 重试。', en: 'Outcome unknown: read back by ID or list first, then decide whether to retry with the original Idempotency-Key.' },
  '503': { zh: '依赖暂不可用：稍后用原 Idempotency-Key 重试。', en: 'A dependency is unavailable: retry later with the original Idempotency-Key.' },
}

export function ApiIndexPage({ lang }: { lang: Lang }) {
  const c = getCatalog()
  return (
    <>
      <PageHero title={API_T.h1[lang]} lead={API_T.lead[lang]}>
        {c ? <p><strong>{c.total}</strong> {API_T.ops[lang]} · <strong>{c.api_key_count}</strong> {API_T.keyOps[lang]} · <strong>{c.groups.length}</strong> {API_T.groups[lang]}</p> : null}
        <p className="muted">{API_T.howKey[lang]}</p>
        <p><a href={href(lang, TUTORIAL_API_PATH)}>{API_T.tutorial[lang]} →</a></p>
      </PageHero>
      <Section id="groups" title={API_T.groups[lang]}>
        {c ? (
          <nav aria-label={API_T.groups[lang]}>
            <ul className="grid grid-4 api-groups">
              {c.groups.map((g) => (
                <li key={g.id}>
                  <a className="card api-group" href={href(lang, `/developers/api/${g.id}`)}>
                    <code>{g.prefix}</code>
                    <span className="muted">{g.count} {API_T.ops[lang]}</span>
                    {g.api_key_count ? <span className="tag tag-key"><KeyRound aria-hidden="true" size={12} /> {g.api_key_count} {API_T.onlyKey[lang]}</span> : null}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        ) : <p role="alert">{API_T.unavailable[lang]}</p>}
      </Section>
    </>
  )
}

const yesNo = (v: boolean | undefined, lang: Lang) => (v ? API_T.yes[lang] : API_T.no[lang])

/** 中文页优先用契约里写的中文（x-summary-zh / x-description-zh）；没有中文时显示英文原文并标 lang="en"。 */
function Text({ en, zh, lang }: { en?: string; zh?: string; lang: Lang }) {
  if (lang === 'zh' && zh) return <>{zh}</>
  return en ? <span lang="en">{en}</span> : <>—</>
}

function FieldTable({ fields, lang, caption, withIn }: { fields: ApiField[]; lang: Lang; caption: string; withIn?: boolean }) {
  return (
    <div className="table-wrap">
      <table className="table api-fields">
        <caption className="sr-only">{caption}</caption>
        <thead><tr>
          <th scope="col">{API_T.name[lang]}</th>
          {withIn ? <th scope="col">{API_T.in[lang]}</th> : null}
          <th scope="col">{API_T.type[lang]}</th>
          <th scope="col">{API_T.required[lang]}</th>
          <th scope="col">{API_T.desc[lang]}</th>
        </tr></thead>
        <tbody>
          {fields.map((f) => (
            <tr key={`${f.in ?? ''}:${f.name}`}>
              <th scope="row"><code>{f.name}</code></th>
              {withIn ? <td>{f.in}</td> : null}
              <td><code>{f.type}</code></td>
              <td>{yesNo(f.required, lang)}</td>
              <td><Text en={f.description} zh={f.description_zh} lang={lang} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function OperationDetail({ op, lang }: { op: ApiOperationDetail; lang: Lang }) {
  const titleID = `op-${op.operation_id}-title`
  const perms = op.permissions ?? []
  const anyPerms = op.any_permissions ?? []
  const failures = (op.responses ?? []).filter((r) => NEXT_STEP[r.status])
  return (
    <article className="api-op" id={op.operation_id} aria-labelledby={titleID}>
      <h3 id={titleID}>
        <span className={`method method-${op.method.toLowerCase()}`}>{op.method}</span> <code className="api-op-path">{op.path}</code>
      </h3>
      {op.summary || op.summary_zh ? <p className="api-op-summary"><Text en={op.summary} zh={op.summary_zh} lang={lang} /></p> : null}
      <dl className="api-meta">
        <dt>operationId</dt><dd><code>{op.operation_id}</code></dd>
        <dt>{API_T.auth[lang]}</dt>
        <dd><ul className="plain">{op.auth.map((a) => <li key={a}>{(AUTH_HOW[a] ?? { zh: a, en: a })[lang]}</li>)}</ul></dd>
        <dt>{API_T.permissions[lang]}</dt>
        <dd>
          {perms.length ? <p>{API_T.allOf[lang]}：{perms.map((p) => <code key={p}>{p} </code>)}</p> : null}
          {anyPerms.length ? <p>{API_T.anyOf[lang]}：{anyPerms.map((p) => <code key={p}>{p} </code>)}</p> : null}
          {!perms.length && !anyPerms.length ? <p className="muted">{API_T.noPerm[lang]}</p> : null}
          {op.features?.length ? <p>{API_T.features[lang]}：{op.features.map((p) => <code key={p}>{p} </code>)}</p> : null}
          {op.recent_reauth ? <p>{API_T.reauth[lang]}</p> : null}
        </dd>
      </dl>
      {lang === 'zh' && op.description_zh ? (
        <>
          <h4>{API_T.descriptionZh[lang]}</h4><p>{op.description_zh}</p>
          {op.description ? <details><summary>{API_T.description[lang]}</summary><p lang="en">{op.description}</p></details> : null}
        </>
      ) : op.description ? <><h4>{API_T.description[lang]}</h4><p lang="en">{op.description}</p></> : null}
      {op.params?.length ? <><h4>{API_T.params[lang]}</h4><FieldTable fields={op.params} lang={lang} caption={`${op.operation_id} ${API_T.params[lang]}`} withIn /></> : null}
      {op.body ? (
        <>
          <h4>{API_T.body[lang]}</h4>
          <p><code>{op.body.content_types.join(', ')}</code> · {API_T.required[lang]}：{yesNo(op.body.required, lang)}</p>
          {op.body.fields?.length ? <FieldTable fields={op.body.fields} lang={lang} caption={`${op.operation_id} ${API_T.body[lang]}`} /> : null}
        </>
      ) : null}
      {op.responses?.length ? (
        <>
          <h4>{API_T.responses[lang]}</h4>
          <div className="table-wrap">
            <table className="table api-fields">
              <caption className="sr-only">{`${op.operation_id} ${API_T.responses[lang]}`}</caption>
              <thead><tr><th scope="col">{API_T.status[lang]}</th><th scope="col">{API_T.desc[lang]}</th></tr></thead>
              <tbody>
                {op.responses.map((r) => (
                  <tr key={r.status}>
                    <th scope="row"><code>{r.status}</code></th>
                    <td>
                      <Text en={r.description} zh={r.description_zh} lang={lang} />
                      {r.fields?.length ? <p className="muted">{API_T.fields[lang]}：{r.fields.map((f) => <code key={f.name}>{f.name}{f.required ? '' : '?'}: {f.type} </code>)}</p> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
      {failures.length ? (
        <>
          <h4>{API_T.next[lang]}</h4>
          <ul>{failures.map((r) => <li key={r.status}><code>{r.status}</code> {NEXT_STEP[r.status][lang]}</li>)}</ul>
        </>
      ) : null}
      <p><a href="#ops">↑ {API_T.toTable[lang]}</a></p>
    </article>
  )
}

export function ApiGroupPage({ lang, group }: { lang: Lang; group: ApiGroup }) {
  const detail = getGroupDetail(group.id)
  return (
    <>
      <PageHero eyebrow={API_T.h1[lang]} title={<code>{group.prefix}</code>} lead={`${group.count} ${API_T.ops[lang]}${group.api_key_count ? ` · ${group.api_key_count} ${API_T.keyOps[lang]}` : ''}`}>
        <p><a href={href(lang, '/developers/api')}>← {API_T.back[lang]}</a> · <a href={href(lang, TUTORIAL_API_PATH)}>{API_T.tutorial[lang]}</a></p>
      </PageHero>
      <Section id="ops">
        <div className="table-wrap">
          <table className="table api-table">
            <thead><tr><th scope="col">{API_T.method[lang]}</th><th scope="col">{API_T.path[lang]}</th><th scope="col">{API_T.summary[lang]}</th><th scope="col">{API_T.auth[lang]}</th></tr></thead>
            <tbody>
              {group.operations.map((o) => (
                <tr key={`${o.method} ${o.path}`}>
                  <td><span className={`method method-${o.method.toLowerCase()}`}>{o.method}</span></td>
                  <td><a href={`#${o.operation_id}`}><code>{o.path}</code></a>{o.deprecated ? <> <span className="tag">{API_T.deprecated[lang]}</span></> : null}</td>
                  <td><Text en={o.summary} zh={o.summary_zh} lang={lang} /></td>
                  <td>{o.auth.map((a) => <span key={a} className={a === 'apiKey' ? 'tag tag-key' : 'tag'}>{(AUTH_LABEL[a] ?? { zh: a, en: a })[lang]}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="footnote">{API_T.source[lang]}：{[...new Set(group.operations.map((o) => o.source))].map((s) => <code key={s}>{s} </code>)}</p>
      </Section>
      <Section id="details" title={API_T.details[lang]} alt>
        {detail ? detail.operations.map((op) => <OperationDetail key={op.operation_id} op={op} lang={lang} />) : <p role="alert">{API_T.detailMissing[lang]}</p>}
      </Section>
    </>
  )
}
