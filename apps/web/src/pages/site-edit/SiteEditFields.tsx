import { useId } from 'react'
import { Alert, Tag, Tooltip } from 'antd'
import { CircleHelp, LockKeyhole } from 'lucide-react'
import { useTranslation } from 'react-i18next'

// HelpTip is the (?) icon that holds a long explanation (keyboard focusable;
// the full text is its accessible name).
export function HelpTip({ tip }: { tip: string }) {
  return (
    <Tooltip title={tip}>
      <span className="site-form-row-tip" role="img" tabIndex={0} aria-label={tip}>
        <CircleHelp size={14} aria-hidden="true" />
      </span>
    </Tooltip>
  )
}

export function SettingSection({
  title,
  tip,
  help,
  id,
  children,
}: {
  title: string
  // anchor for the 本页摘要 jump (site-parity4)
  id?: string
  // long explanation, behind the (?) next to the title
  tip?: string
  // one short line under the title
  help?: string
  children: React.ReactNode
}) {
  return (
    <section className="site-setting-section" id={id}>
      {tip ? <div className="site-setting-title-line"><h2>{title}</h2><HelpTip tip={tip} /></div> : <h2>{title}</h2>}
      {help ? <p className="site-setting-section-help">{help}</p> : null}
      {children}
    </section>
  )
}

// SettingGroup is one feature card inside a section (title, optional state
// tag such as "未生效", one short line of help, long text behind the tip).
export function SettingGroup({
  title,
  tip,
  help,
  status,
  extra,
  children,
}: {
  title: string
  tip?: string
  help?: React.ReactNode
  status?: string
  // right side of the title line (a switch or an add button, competitor layout)
  extra?: React.ReactNode
  children?: React.ReactNode
}) {
  const id = useId()
  return (
    <section className="site-setting-group" aria-labelledby={id}>
      <div className="site-setting-group-head">
        <h3 id={id} className="site-setting-subtitle">{title}</h3>
        {tip ? <HelpTip tip={tip} /> : null}
        {status ? <Tag className="site-setting-group-status">{status}</Tag> : null}
        {extra ? <div className="site-setting-group-extra">{extra}</div> : null}
      </div>
      {help ? <p className="site-setting-section-help">{help}</p> : null}
      {children}
    </section>
  )
}

export function SettingRow({
  label,
  children,
  help,
}: {
  label: string
  children: React.ReactNode
  help?: string
}) {
  return (
    <div className="site-setting-row">
      <span className="site-setting-label">{label}</span>
      <div className="site-setting-control">
        {children}
        {help ? <p>{help}</p> : null}
      </div>
    </div>
  )
}

// FormRow is the horizontal form row of the site edit tabs (competitor
// layout): a fixed-width label column, then the control with an optional
// short help line. A long explanation goes in `tip` (Tooltip on the label).
export function FormRow({
  label,
  labelId,
  tip,
  help,
  children,
}: {
  label: React.ReactNode
  labelId?: string
  tip?: string
  help?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="site-form-row">
      <div className="site-form-row-label">
        <span id={labelId}>{label}</span>
        {tip ? <HelpTip tip={tip} /> : null}
      </div>
      <div className="site-form-row-control">
        {children}
        {help ? <p className="site-form-row-help">{help}</p> : null}
      </div>
    </div>
  )
}

export function LockedSectionNotice() {
  const { t } = useTranslation('sites')
  return (
    <Alert
      className="site-edit-locked-notice"
      showIcon
      icon={<LockKeyhole size={15} aria-hidden="true" />}
      type="info"
      message={t('edit.locked.notice')}
    />
  )
}

export function LockedControl({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation('sites')
  return <Tooltip title={t('edit.locked.unavailable')}>{children}</Tooltip>
}
