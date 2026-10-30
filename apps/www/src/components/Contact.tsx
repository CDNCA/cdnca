import { useEffect, useRef, useState, type MouseEvent, type KeyboardEvent } from 'react'
import { Check, Copy, Headset, Link, Mail, Send, Users, X } from 'lucide-react'
import { safeHref, useSiteContent, type ContactKind } from '../content/siteContent'
import { href, type Lang } from '../i18n'

const T = {
  copy: { zh: '复制', en: 'Copy' },
  copied: { zh: '已复制', en: 'Copied' },
  failed: { zh: '复制失败，请手动复制', en: 'Copy failed, please copy manually' },
  close: { zh: '关闭', en: 'Close' },
}

const ICONS: Record<ContactKind, typeof Send> = { telegram: Send, email: Mail, group: Users, other: Link }

/** 联系方式列表：图标 + 名称 + 值 + 复制按钮。弹窗与 /about 页共用。 */
export function ContactList({ lang }: { lang: Lang }) {
  const { contact } = useSiteContent()
  const [copied, setCopied] = useState<{ value: string; ok: boolean } | null>(null)
  useEffect(() => {
    if (!copied) return
    const t = setTimeout(() => setCopied(null), 2000)
    return () => clearTimeout(t)
  }, [copied])
  const onCopy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied({ value, ok: true })
    } catch {
      setCopied({ value, ok: false })
    }
  }
  const status = copied ? (copied.ok ? `${T.copied[lang]}：${copied.value}` : T.failed[lang]) : ''
  return (
    <>
      <ul className="contact-list">
        {contact.items.map((c, i) => {
          const Icon = ICONS[c.kind]
          const done = copied?.ok && copied.value === c.value
          const link = safeHref(c.href)
          return (
            <li key={i} className="contact-row">
              <span className="contact-icon" aria-hidden="true"><Icon size={18} /></span>
              <span className="contact-label">{c.label[lang]}</span>
              {link ? <a className="contact-value" href={link} {...(link.startsWith('mailto:') ? {} : { target: '_blank', rel: 'noopener noreferrer' })}>{c.value}</a> : <span className="contact-value">{c.value}</span>}
              <button type="button" className="contact-copy" aria-label={`${T.copy[lang]} ${c.label[lang]}`} onClick={() => void onCopy(c.value)}>
                {done ? <Check aria-hidden="true" size={16} /> : <Copy aria-hidden="true" size={16} />}
                <span aria-hidden="true">{done ? T.copied[lang] : T.copy[lang]}</span>
              </button>
            </li>
          )
        })}
      </ul>
      <p className={copied && !copied.ok ? 'contact-status contact-status-error' : 'contact-status'} role="status" aria-live="polite">{status}</p>
    </>
  )
}

const FOCUSABLE = 'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'

/**
 * 页脚“联系我们”入口 + 弹窗。无 JS（预渲染未水合）时是普通链接，指向 /about 页（同内容）。
 * 弹窗：role=dialog + aria-modal，打开时焦点进入、Tab 循环在弹窗内、Esc/遮罩/关闭按钮关闭，
 * 关闭后焦点回到入口。
 */
export function ContactEntry({ lang, label }: { lang: Lang; label: string }) {
  const { contact } = useSiteContent()
  const [open, setOpen] = useState(false)
  const trigger = useRef<HTMLAnchorElement>(null)
  const dialog = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const first = dialog.current?.querySelector<HTMLElement>(FOCUSABLE)
    first?.focus()
    document.body.classList.add('modal-open')
    // Esc 挂在 document 上：焦点落在弹窗内非可聚焦处（点了正文文字）时也能关闭。
    const onEsc = (e: globalThis.KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('keydown', onEsc)
    const back = trigger.current
    return () => {
      document.removeEventListener('keydown', onEsc)
      document.body.classList.remove('modal-open')
      back?.focus()
    }
  }, [open])

  const onOpen = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    e.preventDefault()
    setOpen(true)
  }

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'Tab' || !dialog.current) return
    const items = Array.from(dialog.current.querySelectorAll<HTMLElement>(FOCUSABLE))
    if (!items.length) return
    const first = items[0]
    const last = items[items.length - 1]
    const active = document.activeElement
    if (e.shiftKey && (active === first || !dialog.current.contains(active))) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && (active === last || !dialog.current.contains(active))) {
      e.preventDefault()
      first.focus()
    }
  }

  return (
    <>
      <a ref={trigger} href={href(lang, '/about')} onClick={onOpen} aria-haspopup="dialog">{label}</a>
      {open ? (
        <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setOpen(false) }}>
          <div
            ref={dialog}
            className="modal contact-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="contact-modal-title"
            aria-describedby="contact-modal-desc"
            lang={lang === 'zh' ? 'zh-CN' : 'en'}
            onKeyDown={onKeyDown}
          >
            <div className="contact-modal-head">
              <span className="contact-modal-badge" aria-hidden="true"><Headset size={28} /></span>
              <h2 id="contact-modal-title">{contact.title[lang]}</h2>
              <p id="contact-modal-desc">{contact.subtitle[lang]}</p>
              <button type="button" className="modal-close" aria-label={T.close[lang]} onClick={() => setOpen(false)}>
                <X aria-hidden="true" size={20} />
              </button>
            </div>
            <div className="contact-modal-body">
              <ContactList lang={lang} />
            </div>
          </div>
        </div>
      ) : null}
    </>
  )
}
