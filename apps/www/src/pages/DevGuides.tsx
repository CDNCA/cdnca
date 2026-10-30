import { CodeBlock, PageHero, Section } from '../components/Blocks'
import { GUIDES, GUIDES_PATH, REVIEW_RULES_PATH, SECTION_TITLES, UI_SDK_PATH, type Guide } from '../content/devGuides'
import { TUTORIALS, TUTORIALS_PATH } from '../content/devTutorials'
import { PLUGIN_SIGNING_PATH } from '../content/pluginSigning'
import { ANALYZERS, ENGINE_VERSION, HUMAN_REVIEW, PRIVILEGED_KINDS, REVIEW_RULES, ruleText, type ReviewRule } from '../content/reviewRules'
import { BACKEND_SOURCE, SDK_SOURCE, UI_SDK_BLOCKS } from '../content/uiSdk'
import { href, type Lang } from '../i18n'
import { LINKS } from '../site'
import { renderBlock } from './Docs'

const T = {
  eyebrow: { zh: '开发者平台', en: 'Developer platform' },
  enter: { zh: '进入开发者平台', en: 'Open the developer platform' },
  guides: { zh: '按类型开发指南', en: 'Guides by plugin kind' },
  guidesLead: { zh: '每类插件一页：快速开始、manifest 字段、协议、上传字段、审核规则、版本兼容与本地调试，全部以平台代码为准。', en: 'One page per plugin kind: quick start, manifest fields, protocol, upload fields, review rules, compatibility and local debugging, all taken from the platform code.' },
  toc: { zh: '本页目录', en: 'On this page' },
  allGuides: { zh: '全部开发指南', en: 'All guides' },
  rules: { zh: '审核规则清单', en: 'Review rules' },
  rulesLead: { zh: '市场审核 worker 的全部规则，由审核引擎代码自动导出。', en: 'Every rule of the market review worker, exported from the review engine code.' },
  rulesForKind: { zh: '本类型相关的规则见审核规则清单：', en: 'Rules for this kind are in the review rule list:' },
  signing: { zh: '签名工具与步骤', en: 'Signing tool and steps' },
  signingNote: { zh: '签名与公钥登记见插件签名工具页。', en: 'Signing and key registration are on the plugin signing page.' },
  sdk: { zh: 'ui_page 开发者 SDK', en: 'ui_page developer SDK' },
  sdkLead: { zh: '带页面插件的协议、受限 API 与后端验签，以及可直接使用的 SDK 源码。', en: 'The page plugin protocol, restricted API and backend verification, with ready-to-use SDK source.' },
  rule: { zh: '规则 ID', en: 'Rule ID' },
  severity: { zh: '级别', en: 'Severity' },
  action: { zh: '结果', en: 'Outcome' },
  mode: { zh: '状态', en: 'Mode' },
  desc: { zh: '说明', en: 'Description' },
  human: { zh: '必须人工审核的情况', en: 'When a human reviewer is required' },
  humanLead: { zh: '预检没有拒绝项时，满足以下任一条即进入人工审核，否则直接通过：', en: 'With no reject finding, any one of these sends the version to human review; otherwise it is approved directly:' },
  outcome: { zh: '结论规则', en: 'How the outcome is decided' },
  sdkSource: { zh: 'cdnca-plugin-ui.mjs（框内 SDK）', en: 'cdnca-plugin-ui.mjs (in-frame SDK)' },
  backendSource: { zh: 'verify-backend.mjs（后端验签）', en: 'verify-backend.mjs (backend verifier)' },
  tutorials: { zh: '开发教程', en: 'Tutorials' },
  tutorialsLead: { zh: '按步骤走的教程：', en: 'Step-by-step tutorials:' },
  debugNote: { zh: '框内 SDK 与后端验签源码可在 SDK 页直接复制；联调步骤与示例工程的获取方式见教程。', en: 'Copy the in-frame SDK and backend verifier source from the SDK page; the integration steps and how to get the sample projects are in the tutorial.' },
}

const SEVERITY: Record<ReviewRule['severity'], { zh: string; en: string }> = {
  info: { zh: '信息', en: 'Info' }, low: { zh: '低', en: 'Low' }, medium: { zh: '中', en: 'Medium' },
  high: { zh: '高', en: 'High' }, critical: { zh: '严重', en: 'Critical' },
}
const ACTION: Record<ReviewRule['action'], { zh: string; en: string }> = {
  reject: { zh: '拒绝', en: 'Reject' }, quarantine: { zh: '隔离（转人工）', en: 'Quarantine (human review)' }, none: { zh: '仅记录', en: 'Record only' },
}
const MODE: Record<ReviewRule['mode'], { zh: string; en: string }> = {
  enforcement: { zh: '生效', en: 'Enforced' }, evaluation: { zh: '试运行（只记录）', en: 'Evaluation (recorded only)' },
}

const sectionId = (i: number) => `s${i + 1}`
const tutorialsFor = (slug: string) => TUTORIALS.filter((t) => t.guides.includes(slug))

export function GuidesIndexPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero eyebrow={T.eyebrow[lang]} title={T.guides[lang]} lead={T.guidesLead[lang]}>
        <div className="btn-row">
          <a className="btn btn-primary" href={LINKS.developerLogin}>{T.enter[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, TUTORIALS_PATH)}>{T.tutorials[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, REVIEW_RULES_PATH)}>{T.rules[lang]}</a>
        </div>
      </PageHero>
      <Section id="guides">
        <nav aria-label={T.guides[lang]}>
          <ul className="grid grid-2 api-groups">
            {GUIDES.map((g) => (
              <li key={g.slug}>
                <a className="card api-group" href={href(lang, `${GUIDES_PATH}/${g.slug}`)}>
                  <strong>{g.title[lang]}</strong>
                  <span className="muted">{g.kinds.map((k) => <code key={k}>{k} </code>)}</span>
                  <span className="muted">{g.lead[lang]}</span>
                </a>
              </li>
            ))}
            <li>
              <a className="card api-group" href={href(lang, UI_SDK_PATH)}>
                <strong>{T.sdk[lang]}</strong>
                <span className="muted">{T.sdkLead[lang]}</span>
              </a>
            </li>
          </ul>
        </nav>
      </Section>
    </>
  )
}

export function GuidePage({ lang, guide }: { lang: Lang; guide: Guide }) {
  return (
    <>
      <PageHero eyebrow={T.guides[lang]} title={guide.title[lang]} lead={guide.lead[lang]}>
        <p><a href={href(lang, GUIDES_PATH)}>← {T.allGuides[lang]}</a></p>
        {tutorialsFor(guide.slug).length ? (
          <p>{T.tutorialsLead[lang]} {tutorialsFor(guide.slug).map((t, i) => (
            <span key={t.slug}>{i ? ' · ' : ''}<a href={href(lang, `${TUTORIALS_PATH}/${t.slug}`)}>{t.nav[lang]}</a></span>
          ))}</p>
        ) : null}
        <nav aria-label={T.toc[lang]}>
          <ol className="guide-toc">
            {SECTION_TITLES.map((t, i) => <li key={t.en}><a href={`#${sectionId(i)}`}>{t[lang]}</a></li>)}
          </ol>
        </nav>
      </PageHero>
      {guide.sections.map((blocks, i) => (
        <Section key={SECTION_TITLES[i].en} id={sectionId(i)} title={SECTION_TITLES[i][lang]} alt={i % 2 === 1} className="guide-section">
          <article className="prose">
            {blocks.map((b, j) => renderBlock(b, lang, j))}
            {i === 0 ? <p>{T.signingNote[lang]} <a href={href(lang, PLUGIN_SIGNING_PATH)}>{T.signing[lang]} →</a></p> : null}
            {i === 4 ? (
              <p>{T.rulesForKind[lang]} {guide.analyzers.map((a) => (
                <a key={a} href={`${href(lang, REVIEW_RULES_PATH)}#rules-${a}`}><code>{a}.*</code> </a>
              ))}</p>
            ) : null}
            {i === 6 && guide.kinds.includes('ui_page') ? (
              <p>{T.debugNote[lang]} <a href={href(lang, UI_SDK_PATH)}>{T.sdk[lang]} →</a>
                {' · '}<a href={href(lang, `${TUTORIALS_PATH}/integrate`)}>{TUTORIALS.find((t) => t.slug === 'integrate')!.nav[lang]} →</a></p>
            ) : null}
          </article>
        </Section>
      ))}
    </>
  )
}

export function ReviewRulesPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero eyebrow={T.eyebrow[lang]} title={T.rules[lang]} lead={T.rulesLead[lang]}>
        <p className="muted"><code>{ENGINE_VERSION}</code> · {REVIEW_RULES.length} {lang === 'zh' ? '条规则' : 'rules'}</p>
      </PageHero>
      <Section id="outcome" title={T.outcome[lang]}>
        <article className="prose">
          <ul>
            <li>{lang === 'zh' ? '有任一“生效”的拒绝项：版本退回“需修改”，修好后重新提交（每个版本最多 10 次扫描）；校验阶段出现拒绝时不再进入扫描阶段。' : 'Any enforced reject: the version goes back to “changes requested”; fix it and resubmit (at most 10 scans per version). A reject in the validating phase skips the scanning phase.'}</li>
            <li>{lang === 'zh' ? '有任一“生效”的隔离项：进入人工审核。' : 'Any enforced quarantine: human review.'}</li>
            <li>{lang === 'zh' ? '“试运行”规则只记录在报告里（标出本会采取的结果），不影响结论；“仅记录”规则只是提示或展示。' : 'Evaluation rules are only recorded in the report (with the outcome they would have had) and do not affect the result; record-only rules are notices or summaries.'}</li>
            <li>{lang === 'zh' ? '运营可以把文件哈希加入放行或封禁名单：放行名单上的文件，其发现项降级为只记录（封禁规则与扫描器故障除外）；封禁名单上的文件直接拒绝（package.blocked_file）。' : 'The operator can allow-list or block-list file hashes: findings on allow-listed files drop to record-only (except the block rule and scanner faults); block-listed files are rejected (package.blocked_file).'}</li>
          </ul>
        </article>
      </Section>
      <Section id="human" title={T.human[lang]} alt>
        <article className="prose">
          <p>{T.humanLead[lang]}</p>
          <ul>
            {HUMAN_REVIEW.map((h) => (
              <li key={h.reason}><code>{h.reason}</code>{lang === 'zh' ? '：' : ': '}{h.text[lang]}{h.reason === 'privileged' ? PRIVILEGED_KINDS.join(lang === 'zh' ? '、' : ', ') : null}</li>
            ))}
          </ul>
        </article>
      </Section>
      {ANALYZERS.map((a) => {
        const rules = REVIEW_RULES.filter((r) => r.analyzer === a.id)
        return (
          <Section key={a.id} id={`rules-${a.id}`} title={a.title[lang]}>
            <div className="table-wrap">
              <table className="table" data-analyzer={a.id}>
                <thead><tr><th scope="col">{T.rule[lang]}</th><th scope="col">{T.severity[lang]}</th><th scope="col">{T.action[lang]}</th><th scope="col">{T.mode[lang]}</th><th scope="col">{T.desc[lang]}</th></tr></thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.id} data-rule={r.id}>
                      <th scope="row"><code>{r.id}</code></th>
                      <td>{SEVERITY[r.severity][lang]}</td>
                      <td>{ACTION[r.action][lang]}</td>
                      <td>{MODE[r.mode][lang]}</td>
                      <td>{ruleText(r)[lang]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        )
      })}
    </>
  )
}

export function UISdkPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero eyebrow={T.guides[lang]} title={T.sdk[lang]} lead={T.sdkLead[lang]}>
        <p><a href={`${href(lang, `${GUIDES_PATH}/external-service`)}#s7`}>← {GUIDES[3].title[lang]}</a></p>
      </PageHero>
      <Section id="protocol">
        <article className="prose">{UI_SDK_BLOCKS.map((b, i) => renderBlock(b, lang, i))}</article>
      </Section>
      <Section id="source" alt>
        <article className="prose">
          <h2>{T.sdkSource[lang]}</h2>
          <CodeBlock code={SDK_SOURCE} lang={lang} label={T.sdkSource[lang]} />
          <h2>{T.backendSource[lang]}</h2>
          <CodeBlock code={BACKEND_SOURCE} lang={lang} label={T.backendSource[lang]} />
        </article>
      </Section>
    </>
  )
}
