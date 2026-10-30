import { useQuery } from '@tanstack/react-query'
import { Result, Spin } from 'antd'
import { useTranslation } from 'react-i18next'

import { fetchRuntimeFeatures } from '../../api/runtimeFeatures'
import { useSessionStore } from '../../auth/session'
import { runtimeFeaturesQueryKey } from '../../components/useRuntimeFeatures'
import '../../i18n/pluginWebhooks'
import PluginWebhooksPage from './PluginWebhooksPage'

// PluginWebhooksRoute applies the menu's plugin_webhooks runtime gate to a
// typed URL (live-click-C E1): when GET /v1/runtime-features does not report
// the runtime, or fails as the menu also treats it, the console shows "feature
// not enabled" instead of a page whose subscription API answers 404.
export default function PluginWebhooksRoute() {
  const { t } = useTranslation('pluginWebhooks')
  const accessToken = useSessionStore((state) => state.accessToken)
  const features = useQuery({
    queryKey: runtimeFeaturesQueryKey,
    queryFn: () => fetchRuntimeFeatures(accessToken ?? ''),
    enabled: Boolean(accessToken),
    staleTime: Infinity,
    retry: false,
  })
  if (accessToken && features.isPending) return <Spin aria-label={t('accessibility.loading')} />
  if (accessToken && !features.data?.includes('plugin_webhooks')) {
    return <Result status="info" title={t('notEnabled.title')} subTitle={t('notEnabled.description')} />
  }
  return <PluginWebhooksPage />
}
