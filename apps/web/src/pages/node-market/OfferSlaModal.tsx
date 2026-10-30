import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Form, InputNumber, Modal, Select, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { marketApi, newIdempotencyKey, type MarketOfferListing, type MarketSlaPolicy } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { slaProblem } from './slaModel'
import { useFeedback } from '@cdnca/ui'
import { minorToYuan, yuanToMinor } from '@cdnca/ui/offer-terms'

interface Values {
  target: number
  window: 'day' | 'month'
  penalty: number
  maxCredit: number
  terminateAfter: number
  tiers: Array<{ below: number; credit: number }>
  remove: boolean
}

const ratio = (percent: number) => Math.round(percent * 1000) / 100000
const percent = (value: number) => Math.round(value * 100000) / 1000

export function OfferSlaModal({ offer, onClose }: { offer: MarketOfferListing | null; onClose: () => void }) {
  const { t } = useTranslation('nodeMarket')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [form] = Form.useForm<Values>()
  const save = useMutation({
    mutationFn: (body: { pricing: MarketOfferListing['pricing']; sla?: MarketSlaPolicy; remove_sla?: boolean }) =>
      // 卡 11：回传的是打开时的整份价格，带上打开时的修订号；别处已改价则 409 offer_changed，不覆盖新价。
      marketApi.updateOfferTerms(token, offer!.id, { ...body, ...(offer?.revision ? { expected_revision: offer.revision } : {}) }, newIdempotencyKey('offer-terms')),
    onSuccess: () => {
      void message.success(t('sla.saved'))
      void client.invalidateQueries({ queryKey: ['nodeMarket'] })
      onClose()
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === 'offer_changed') {
        void feedback.error(t('sla.changed'))
        void client.invalidateQueries({ queryKey: ['nodeMarket'] })
        return
      }
      void feedback.error(t('errors.failed', { code: error instanceof ApiError ? error.code : 'request_failed' }))
    },
  })
  const current = offer?.sla
  const submit = (v: Values) => {
    // Pricing goes back unchanged: currency and billing model cannot change here.
    if (v.remove) {
      save.mutate({ pricing: offer!.pricing, remove_sla: true })
      return
    }
    const tiers = (v.tiers ?? []).filter((x) => x && x.below !== undefined && x.credit !== undefined)
    const problem = slaProblem({ target: v.target, tiers, maxCredit: v.maxCredit ?? 0, terminateAfter: v.terminateAfter ?? 0 })
    if (problem) {
      form.setFields([{ name: 'target', errors: [t(`sla.problems.${problem}`)] }])
      return
    }
    save.mutate({ pricing: offer!.pricing, sla: {
      availability_target: ratio(v.target), measure_window: v.window, daily_penalty_minor: yuanToMinor(v.penalty ?? 0) ?? 0,
      max_credit_percent: v.maxCredit ?? 0, terminate_after: v.terminateAfter ?? 0,
      credit_schedule: tiers.map((x) => ({ below: ratio(x.below), credit_percent: x.credit })),
    } })
  }
  return (
    <Modal open={!!offer} title={t('sla.title', { name: offer?.name ?? '' })} onCancel={onClose} footer={null} destroyOnHidden width={620}>
      <Typography.Paragraph type="secondary">{t('sla.help')}</Typography.Paragraph>
      {offer ? <Form<Values> form={form} layout="vertical" onFinish={submit} initialValues={{
        target: current ? percent(current.availability_target) : 99.9, window: current?.measure_window ?? 'month',
        penalty: minorToYuan(current?.daily_penalty_minor ?? 0), maxCredit: current?.max_credit_percent ?? 100,
        terminateAfter: current?.terminate_after ?? 0, remove: false,
        tiers: (current?.credit_schedule ?? [{ below: 0.999, credit_percent: 10 }, { below: 0.99, credit_percent: 25 }])
          .map((x) => ({ below: percent(x.below), credit: x.credit_percent })),
      }}>
        <Space wrap>
          <Form.Item name="target" label={t('sla.target')}><InputNumber min={0.001} max={100} step={0.01} /></Form.Item>
          <Form.Item name="window" label={t('sla.window')}>
            <Select style={{ width: 110 }} aria-label={t('sla.window')}
              options={[{ value: 'day', label: t('sla.windows.day') }, { value: 'month', label: t('sla.windows.month') }]} />
          </Form.Item>
          <Form.Item name="penalty" label={t('sla.penalty')}><InputNumber min={0} precision={2} /></Form.Item>
          <Form.Item name="maxCredit" label={t('sla.maxCredit')}><InputNumber min={0} max={100} /></Form.Item>
          <Form.Item name="terminateAfter" label={t('sla.terminateAfter')}><InputNumber min={0} max={365} /></Form.Item>
        </Space>
        <Typography.Text strong>{t('sla.schedule')}</Typography.Text>
        <Form.List name="tiers">
          {(fields, { add, remove }) => <>
            {fields.map((field, index) => <Space key={field.key} align="baseline">
              <Form.Item name={[field.name, 'below']} label={index === 0 ? t('sla.below') : undefined}>
                <InputNumber min={0.001} max={100} step={0.01} aria-label={`${t('sla.below')} ${index + 1}`} />
              </Form.Item>
              <Form.Item name={[field.name, 'credit']} label={index === 0 ? t('sla.credit') : undefined}>
                <InputNumber min={1} max={100} aria-label={`${t('sla.credit')} ${index + 1}`} />
              </Form.Item>
              <Button size="small" onClick={() => remove(field.name)}>{t('sla.removeTier')}</Button>
            </Space>)}
            <Button size="small" disabled={fields.length >= 10} onClick={() => add({ below: 99, credit: 10 })}>{t('sla.addTier')}</Button>
          </>}
        </Form.List>
        {current ? <Form.Item name="remove" valuePropName="checked" style={{ marginTop: 12 }}>
          <Checkbox>{t('sla.remove')}</Checkbox>
        </Form.Item> : null}
        <Alert type="info" showIcon style={{ margin: '12px 0' }} message={t('sla.revisionNotice')} />
        <Space>
          <Button type="primary" htmlType="submit" loading={save.isPending}>{t('subscription.save')}</Button>
          <Button onClick={onClose}>{t('sla.cancel')}</Button>
        </Space>
      </Form> : null}
    </Modal>
  )
}
