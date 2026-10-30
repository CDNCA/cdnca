import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Space } from 'antd'
import { ExternalLink } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { marketApi, type MarketMember } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import '../../i18n/nodeMarket'

// sellerSiteOrigin is the seller site the market answered with:
// member.seller_site_url, else the origin of supplier.apply_url (a market
// before fix-sellersite only sends that, and only to members who cannot sell).
// null when the market has no seller site configured.
export function sellerSiteOrigin(member: MarketMember | undefined): string | null {
  for (const raw of [member?.seller_site_url, member?.supplier?.apply_url]) {
    if (!raw) continue
    try {
      const url = new URL(raw)
      if (url.protocol === 'https:' || url.protocol === 'http:') return url.origin
    } catch {
      // not a URL: try the next one
    }
  }
  return null
}

export function useSellerSite(): { origin: string | null; canSell: boolean | null } {
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const query = useQuery({ queryKey: ['nodeMarket', 'member'], queryFn: () => marketApi.member(token), enabled: !!token })
  const supplier = query.data?.supplier
  return { origin: sellerSiteOrigin(query.data), canSell: supplier ? supplier.can_sell : null }
}

// SellerSiteGuide points at what only the seller site does (income, payouts,
// payout accounts, deposit, team, plugin publishing, onboarding). Without a
// seller site address it keeps the text and hides the button.
export function SellerSiteGuide({ scope }: { scope: 'node' | 'plugin' }) {
  const { t } = useTranslation('nodeMarket')
  const { origin, canSell } = useSellerSite()
  const applying = scope === 'node' && canSell === false
  const target = origin ? (applying ? `${origin}/onboarding?role=node_supplier` : `${origin}${scope === 'plugin' ? '/plugins' : '/finance'}`) : null
  return (
    <Alert type="info" showIcon className="seller-site-guide"
      message={applying ? t('sellerSite.applyTitle') : t(`sellerSite.${scope}Title`)}
      description={<Space direction="vertical" size={8}>
        <span>{applying ? t('sellerSite.applyBody') : t(`sellerSite.${scope}Body`)}</span>
        {target ? <Button size="small" href={target} target="_blank" rel="noopener noreferrer"
          icon={<ExternalLink size={14} aria-hidden="true" />}>{applying ? t('sellerSite.apply') : t('sellerSite.open')}</Button> : null}
      </Space>} />
  )
}
