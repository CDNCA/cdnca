// MC12 E3: one reason code as plain words (why + next step); the raw code and
// detail stay copyable for support.
import { Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { marketReason, marketReasonDetail } from '@cdnca/ui/market-reasons'

export function ReasonText({ code, detail }: { code: string; detail?: string }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const r = marketReason(code, i18n.language)
  const raw = detail ? `${code}: ${detail}` : code
  return (
    <Typography.Text>
      {r.reason}{detail && r.known ? `（${marketReasonDetail(code, detail, i18n.language)}）` : ''}。{r.next}
      <Typography.Text type="secondary" copyable={{ text: raw, tooltips: [t('supplies.copyCode'), t('supplies.copied')] }} style={{ marginInlineStart: 8, fontSize: 12 }}>
        {t('supplies.rawCode')}
      </Typography.Text>
    </Typography.Text>
  )
}
