import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Modal, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { marketApi, type MarketAgreement, type MarketAgreementKind } from '../../api/market'
import { SafeMarkdown } from '../AccountMessagesPage'
import '../../i18n/marketAgreements'

// MARKET-03: agreements a buyer sees, in footer order. Only published ones are
// returned by the market; a failed read shows nothing (no published text known).
const footerKinds: MarketAgreementKind[] = ['privacy', 'seller_terms']

export function useMarketAgreements(token: string): MarketAgreement[] {
  const query = useQuery({ queryKey: ['marketAgreements'], queryFn: () => marketApi.agreements(token), enabled: !!token, retry: false, staleTime: 300_000 })
  return query.data ?? []
}

function AgreementLink({ agreement, quoted = false }: { agreement: MarketAgreement; quoted?: boolean }) {
  const { t } = useTranslation('marketAgreements')
  const [open, setOpen] = useState(false)
  const title = t(`kinds.${agreement.kind}`)
  return (
    <>
      <Button type="link" size="small" style={{ padding: 0 }} onClick={() => setOpen(true)}>{quoted ? t('quoted', { name: title }) : title}</Button>
      <Modal open={open} title={title} onCancel={() => setOpen(false)} destroyOnHidden width={720}
        footer={<Button onClick={() => setOpen(false)}>{t('close')}</Button>}>
        <Typography.Text type="secondary">{t('version', { version: agreement.version })}</Typography.Text>
        <div className="cdnca-dialog-scroll" style={{ maxHeight: '60vh', overflowY: 'auto' }}><SafeMarkdown value={agreement.body} /></div>
      </Modal>
    </>
  )
}

/** Footer links to the published buyer agreements; renders nothing when none is published. */
export function MarketAgreementFooter({ agreements }: { agreements: MarketAgreement[] }) {
  const { t } = useTranslation('marketAgreements')
  const shown = footerKinds.flatMap((kind) => agreements.filter((a) => a.kind === kind))
  if (shown.length === 0) return null
  return (
    <Space size={16} wrap style={{ marginTop: 24 }} aria-label={t('footerLabel')}>
      {shown.map((a) => <AgreementLink key={a.kind} agreement={a} />)}
    </Space>
  )
}

/** "购买即表示同意《隐私政策》" for a purchase confirmation; nothing when privacy is not published. */
export function PrivacyConsent({ agreements }: { agreements: MarketAgreement[] }) {
  const { t } = useTranslation('marketAgreements')
  const privacy = agreements.find((a) => a.kind === 'privacy')
  if (!privacy) return null
  return <Typography.Text type="secondary">{t('consent')}<AgreementLink agreement={privacy} quoted /></Typography.Text>
}
