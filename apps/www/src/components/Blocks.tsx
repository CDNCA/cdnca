import { useState, type ReactNode } from 'react'
import type { Lang } from '../i18n'

/** 页面首段：眉标 + 大字 + 导语 + 按钮区 */
export function PageHero({ eyebrow, title, lead, children }: { eyebrow?: string; title: ReactNode; lead?: ReactNode; children?: ReactNode }) {
  return (
    <section className="hero">
      <div className="container narrow">
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        {lead ? <p className="lead">{lead}</p> : null}
        {children}
      </div>
    </section>
  )
}

export function Section({ id, title, lead, alt, dark, className, children }: { id?: string; title?: ReactNode; lead?: ReactNode; alt?: boolean; dark?: boolean; className?: string; children: ReactNode }) {
  const cls = ['section', alt ? 'section-alt' : '', dark ? 'section-dark' : '', className ?? ''].filter(Boolean).join(' ')
  return (
    <section className={cls} id={id} aria-labelledby={id && title ? `${id}-title` : undefined}>
      <div className="container">
        {title ? (
          <div className="section-head">
            <h2 id={id ? `${id}-title` : undefined}>{title}</h2>
            {lead ? <p className="lead">{lead}</p> : null}
          </div>
        ) : null}
        {children}
      </div>
    </section>
  )
}

const COPY = {
  copy: { zh: '复制', en: 'Copy' },
  copied: { zh: '已复制', en: 'Copied' },
  failed: { zh: '请手动复制', en: 'Copy manually' },
}

/** 命令块 + 复制按钮（按钮仅在水合后可用；无 JS 时命令仍可选中复制）。 */
export function CodeBlock({ code, lang, label }: { code: string; lang: Lang; label?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setState('copied')
    } catch {
      setState('failed')
    }
  }
  const text = state === 'copied' ? COPY.copied[lang] : state === 'failed' ? COPY.failed[lang] : COPY.copy[lang]
  return (
    <pre className="code" aria-label={label}>
      <code>{code}</code>
      <button type="button" className="copy-btn" onClick={onCopy} aria-live="polite">{text}</button>
    </pre>
  )
}

export function Faq({ items }: { items: { q: string; a: ReactNode }[] }) {
  return (
    <div>
      {items.map((it) => (
        <details className="faq" key={it.q}>
          <summary>{it.q}</summary>
          <div>{it.a}</div>
        </details>
      ))}
    </div>
  )
}

/** 带标题与文字说明的插图容器；图本身用 role="img" + aria-labelledby。 */
export function Figure({ children, caption }: { children: ReactNode; caption?: ReactNode }) {
  return (
    <figure className="figure">
      {children}
      {caption ? <figcaption>{caption}</figcaption> : null}
    </figure>
  )
}
