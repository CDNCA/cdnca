import { cloneElement, useId, useState, type ReactElement } from 'react'
import { Tooltip } from 'antd'
import { CircleHelp } from 'lucide-react'
import './FieldHelp.css'

// 字段说明（/）：作为 Form.Item 的子元素包住控件，
// 控件旁放一个紧凑的帮助按钮（名称由调用方给，如「缓存总容量说明」），悬停、聚焦或点击显示说明，Escape 关闭。
// 控件的可访问名称只保留字段名；说明另有一份隐藏文字，经 aria-describedby 关联到控件。Form.Item 出错时注入的
// aria-describedby（指向错误）会覆盖子元素自己的值，这里把两者合并。
export function FieldWithHelp({ label, tip, children, ...control }: {
  label: string
  tip: string
  children: ReactElement<Record<string, unknown>>
  id?: string
  'aria-describedby'?: string
}) {
  const fallback = useId()
  const descriptionId = `${control.id ?? fallback}_tip`
  const [open, setOpen] = useState(false)
  return <div className="field-help-row">
    {cloneElement(children, { ...control, 'aria-describedby': [control['aria-describedby'], descriptionId].filter(Boolean).join(' ') })}
    <Tooltip title={tip} open={open} onOpenChange={setOpen} trigger={['hover', 'focus', 'click']}>
      <button
        type="button"
        className="field-help-button"
        aria-label={label}
        onKeyDown={(event) => {
          if (event.key !== 'Escape' || !open) return
          // 只关说明，不连带关闭所在的弹窗
          event.stopPropagation()
          setOpen(false)
        }}
      >
        <CircleHelp size={14} aria-hidden="true" />
      </button>
    </Tooltip>
    <span id={descriptionId} hidden>{tip}</span>
  </div>
}
