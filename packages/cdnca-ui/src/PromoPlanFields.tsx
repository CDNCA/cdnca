// 限免 fields of a price plan form (fix-plugpromo): deadline, the charging mode after it (one-time or
// monthly) and its price, with the one-sentence holder rules preview. Shared by the seller centre and
// the operator console's official entry editor; render inside their antd Form.
import { useContext } from 'react'
import { ConfigProvider, DatePicker, Form, InputNumber, Radio } from 'antd'
import dayjs, { type Dayjs } from 'dayjs'

import { PromoBillingNote } from './PriceBadge'

export interface PromoFormValues { promo_until?: Dayjs; promo_then_kind?: 'one_time' | 'subscription'; promo_then_yuan?: number }

/** The API body part of a promo (PricePlanInput.promo); yuan → minor units. */
export function promoInputOf(values: PromoFormValues): { until: string; then_kind: 'one_time' | 'subscription'; then_price_minor: number } {
  return { until: values.promo_until!.toISOString(), then_kind: values.promo_then_kind ?? 'subscription',
    then_price_minor: Math.round((values.promo_then_yuan ?? 0) * 100) }
}

const texts = {
  'zh-CN': { until: '限免截止时间', future: '请选择将来的时间', thenKind: '到期后收费方式', once: '一次性买断', month: '按月订阅',
    thenPrice: '到期后价格（元）', price: '请输入大于 0 的价格', preview: '到期后已领取者如何计费' },
  'zh-TW': { until: '限免截止時間', future: '請選擇將來的時間', thenKind: '到期後收費方式', once: '一次性買斷', month: '按月訂閱',
    thenPrice: '到期後價格（元）', price: '請輸入大於 0 的價格', preview: '到期後已領取者如何計費' },
  'en-US': { until: 'Free until', future: 'Choose a time in the future', thenKind: 'Then charged', once: 'One-time', month: 'Monthly',
    thenPrice: 'Price after the promo (CNY)', price: 'Enter a price above 0', preview: 'How holders are billed after the promo' },
}

export function PromoPlanFields() {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  const t = texts[locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN']
  const form = Form.useFormInstance<PromoFormValues>()
  const thenKind = Form.useWatch('promo_then_kind', form) ?? 'subscription'
  const yuan = Form.useWatch('promo_then_yuan', form)
  return (
    <div className="cdnca-promo-fields">
      <Form.Item name="promo_until" label={t.until} rules={[{ required: true, message: t.future }, { validator: async (_, value?: Dayjs) => {
        if (value && !value.isAfter(dayjs())) throw new Error(t.future)
      } }]}>
        <DatePicker showTime={{ format: 'HH:mm' }} format="YYYY-MM-DD HH:mm" disabledDate={(d) => d.isBefore(dayjs(), 'day')} style={{ width: '100%', maxWidth: 260 }} />
      </Form.Item>
      <Form.Item name="promo_then_kind" label={t.thenKind} initialValue="subscription">
        <Radio.Group options={[{ value: 'subscription', label: t.month }, { value: 'one_time', label: t.once }]} />
      </Form.Item>
      <Form.Item name="promo_then_yuan" label={t.thenPrice} rules={[{ validator: async (_, value?: number) => {
        if (!value || value <= 0) throw new Error(t.price)
      } }]}>
        <InputNumber min={0.01} precision={2} step={1} style={{ width: 200 }} />
      </Form.Item>
      <div className="cdnca-promo-preview" role="note" aria-label={t.preview}>
        <strong>{t.preview}</strong>
        <PromoBillingNote thenKind={thenKind} priceMinor={yuan ? Math.round(yuan * 100) : undefined} />
      </div>
    </div>
  )
}
