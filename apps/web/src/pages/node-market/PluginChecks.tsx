import { Checkbox, Space } from 'antd'
import { useTranslation } from 'react-i18next'
import '../../i18n/nodeMarket'

// The node plugins of an offer as checkboxes with a 全选 box on top.
// Used as a Form.Item child: value/onChange come from the form.
export function PluginChecks({ options, value, onChange }: {
  options: { value: string; label: string }[]; value?: string[]; onChange?: (next: string[]) => void
}) {
  const { t } = useTranslation('nodeMarket')
  const picked = value ?? []
  const all = options.map((o) => o.value)
  const count = all.filter((code) => picked.includes(code)).length
  if (options.length === 0) return <Checkbox.Group options={options} value={picked} onChange={(v) => onChange?.(v as string[])} />
  return (
    <Space direction="vertical" size={6} style={{ width: '100%' }}>
      <Checkbox indeterminate={count > 0 && count < all.length} checked={count === all.length}
        onChange={(e) => onChange?.(e.target.checked ? [...new Set([...picked, ...all])] : picked.filter((code) => !all.includes(code)))}>
        {t('caps.pluginsAll')}
      </Checkbox>
      <Checkbox.Group options={options} value={picked} onChange={(v) => onChange?.(v as string[])} />
    </Space>
  )
}
