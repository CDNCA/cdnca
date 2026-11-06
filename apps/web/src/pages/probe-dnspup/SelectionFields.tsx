import { Checkbox, Form, InputNumber, Select, Space, Switch, type FormInstance } from 'antd'
import { useTranslation } from 'react-i18next'

import { probeAreas, probeCarriers, type ProbeArea, type ProbeCarrier, type ProbeSelection } from '../../api/probeDNSPup'
import '../../i18n/probeDNSPup'

// Form fields of a checkpoint selection (flat, so antd validates each one).
export interface SelectionValues {
  selection_enabled?: boolean
  areas?: ProbeArea[]
  carriers?: ProbeCarrier[]
  include_provinces?: string[]
  exclude_provinces?: string[]
  exclude_checkpoints?: string[]
  points_per_group?: number
  rotate?: boolean
}

/** The selection the form describes, or null when detailed selection is off. */
export function selectionOf(values: SelectionValues): ProbeSelection | null {
  if (!values.selection_enabled) return null
  const list = <T,>(items?: T[]) => (items && items.length > 0 ? items : undefined)
  return { areas: list(values.areas), carriers: list(values.carriers), include_provinces: list(values.include_provinces),
    exclude_provinces: list(values.exclude_provinces), exclude_checkpoints: list(values.exclude_checkpoints),
    points_per_group: values.points_per_group ?? 3, rotate: Boolean(values.rotate) }
}

/** Form values of a stored selection. */
export function valuesOf(selection: ProbeSelection | null | undefined): SelectionValues {
  if (!selection) return { selection_enabled: false, points_per_group: 3, rotate: true }
  return { selection_enabled: true, areas: selection.areas ?? [], carriers: selection.carriers ?? [],
    include_provinces: selection.include_provinces ?? [], exclude_provinces: selection.exclude_provinces ?? [],
    exclude_checkpoints: selection.exclude_checkpoints ?? [], points_per_group: selection.points_per_group,
    rotate: Boolean(selection.rotate) }
}

// prefix: the form field holding the values (the node card nests them under
// "selection"; the override form keeps them at the top).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function SelectionFields({ form, prefix }: { form: FormInstance<any>; prefix?: string }) {
  const { t } = useTranslation('probeDNSPup')
  const field = (name: keyof SelectionValues) => (prefix ? [prefix, name] : name)
  const enabled = Form.useWatch(field('selection_enabled'), form)
  const tags = (name: keyof SelectionValues, label: string, extra?: string) =>
    <Form.Item name={field(name)} label={label} extra={extra}>
      <Select mode="tags" tokenSeparators={[',', '，', ' ']} aria-label={label} open={false} style={{ minWidth: 280 }} />
    </Form.Item>
  return <>
    <Form.Item name={field('selection_enabled')} label={t('unified.selection.title')} valuePropName="checked">
      <Switch aria-label={t('unified.selection.enabled')} />
    </Form.Item>
    {enabled ? <>
      <Form.Item name={field('areas')} label={t('unified.selection.areas')}>
        <Checkbox.Group options={probeAreas.map((value) => ({ value, label: t(`unified.areas.${value}`) }))} />
      </Form.Item>
      <Form.Item name={field('carriers')} label={t('unified.selection.carriers')}>
        <Checkbox.Group options={probeCarriers.map((value) => ({ value, label: t(`unified.carriers.${value}`) }))} />
      </Form.Item>
      <Space wrap size="large" align="start">
        {tags('include_provinces', t('unified.selection.includeProvinces'), t('unified.selection.provincesExtra'))}
        {tags('exclude_provinces', t('unified.selection.excludeProvinces'))}
        {tags('exclude_checkpoints', t('unified.selection.excludeCheckpoints'))}
      </Space>
      <Space wrap size="large">
        <Form.Item name={field('points_per_group')} label={t('unified.selection.pointsPerGroup')} rules={[{ required: true }]}>
          <InputNumber min={1} max={20} precision={0} aria-label={t('unified.selection.pointsPerGroup')} />
        </Form.Item>
        <Form.Item name={field('rotate')} label={t('unified.selection.rotate')} valuePropName="checked">
          <Switch aria-label={t('unified.selection.rotate')} />
        </Form.Item>
      </Space>
    </> : null}
  </>
}
