import { Alert, Button, Input, Modal, Space, Tabs } from 'antd'
import type { TextAreaRef } from 'antd/es/input/TextArea'
import { Copy, RefreshCw } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

export interface UpgradeLogSection {
  key: 'script' | 'program'
  label: string
  lines: string[]
  emptyText: string
  notice?: string
}

// Plain-text upgrade log in two tabs: the step-by-step script output and the
// services' program log. Read-only, copyable, and kept scrolled to the newest
// line while the caller refreshes it.
export default function UpgradeLogModal({ title, open, sections, loading, error, contentLabel, refreshLabel, copyLabel, copiedLabel,
  copyFailedLabel, onRefresh, onClose }: {
  title: string
  open: boolean
  sections: UpgradeLogSection[]
  loading: boolean
  error?: string
  contentLabel: string
  refreshLabel: string
  copyLabel: string
  copiedLabel: string
  copyFailedLabel: string
  onRefresh: () => void
  onClose: () => void
}) {
  const [active, setActive] = useState<UpgradeLogSection['key']>('script')
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const areas = useRef(new Map<string, TextAreaRef | null>())
  const section = sections.find((item) => item.key === active) ?? sections[0]
  const text = section && section.lines.length > 0 ? section.lines.join('\n') : section?.emptyText ?? ''
  useEffect(() => {
    if (!open) {
      setActive('script')
      setCopyState('idle')
    }
  }, [open])
  useEffect(() => { setCopyState('idle') }, [active, text])
  // Follow the newest line, as a tail would, whenever the content changes.
  useEffect(() => {
    const element = areas.current.get(active)?.resizableTextArea?.textArea
    if (element) element.scrollTop = element.scrollHeight
  }, [active, text, open])
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(section && section.lines.length > 0 ? section.lines.join('\n') : '')
      setCopyState('copied')
    } catch {
      setCopyState('failed')
    }
  }
  return <Modal title={title} open={open} onCancel={onClose} footer={null} width={860} className="upgrade-log-modal" destroyOnHidden>
    {error ? <Alert type="error" showIcon message={error} /> : null}
    <Tabs size="small" activeKey={section?.key} onChange={(key) => setActive(key as UpgradeLogSection['key'])}
      tabBarExtraContent={<Space size={8}>
        <Button size="small" icon={<Copy size={13} />} disabled={!section || section.lines.length === 0} onClick={() => void copy()}>
          {copyState === 'copied' ? copiedLabel : copyLabel}
        </Button>
        <Button type="primary" size="small" icon={<RefreshCw size={13} />} loading={loading} onClick={onRefresh}>{refreshLabel}</Button>
      </Space>}
      items={sections.map((item) => ({
        key: item.key, label: item.label,
        children: <>
          {item.notice ? <Alert className="upgrade-log-notice" type="info" showIcon message={item.notice} /> : null}
          <Input.TextArea aria-label={`${contentLabel} ${item.label}`} className="upgrade-log-content" readOnly rows={18} spellCheck={false}
            ref={(ref) => { areas.current.set(item.key, ref) }}
            value={item.lines.length > 0 ? item.lines.join('\n') : item.emptyText} />
        </>,
      }))} />
    {copyState === 'failed' ? <Alert type="warning" showIcon message={copyFailedLabel} /> : null}
  </Modal>
}
