import { useQuery } from '@tanstack/react-query'
import { Alert, Descriptions, List, Spin, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { marketApi, type MarketUIPage } from '../../api/market'
import { fetchPluginUISigningKey } from '../../api/pluginUI'
import '../../i18n/pluginInstallations'
import { FeedbackWhen } from '@cdnca/ui'

// UIPageDeclaration is the market's signed ui_page declaration of exactly the
// version being confirmed. With the authorized manifest digest (installation)
// it is shown only when the market's digest equals it; an upgrade target
// carries no digest, so it is matched by version. Otherwise the administrator
// is told to ask the platform (never a declaration of some other version).
type UIPageDeclaration =
  | { state: 'none' }
  | { state: 'declared'; uiPage: MarketUIPage }
  | { state: 'mismatch' }
  | { state: 'unavailable' }

async function loadUIPageDeclaration(token: string, pluginID: string, version: string,
  manifestSHA256?: string): Promise<UIPageDeclaration> {
  try {
    const found = (await marketApi.plugins(token, { q: pluginID })).items.find((item) => item.plugin_id === pluginID)
    if (!found) return { state: 'unavailable' }
    const detail = await marketApi.plugin(token, found.id)
    const match = detail.versions.find((item) => item.version === version)
    if (!match) return { state: 'unavailable' }
    if (manifestSHA256 && match.manifest_sha256.toLowerCase() !== manifestSHA256.toLowerCase()) return { state: 'mismatch' }
    return match.ui_page ? { state: 'declared', uiPage: match.ui_page } : { state: 'none' }
  } catch {
    return { state: 'unavailable' }
  }
}

export function UIPageDisclosure({ token, pluginID, version, manifestSHA256 }: {
  token: string; pluginID: string; version: string; manifestSHA256?: string
}) {
  const { t, i18n } = useTranslation('pluginInstallations')
  const query = useQuery({
    queryKey: ['plugin-installation-ui-page', pluginID, version, manifestSHA256 ?? ''],
    queryFn: () => loadUIPageDeclaration(token, pluginID, version, manifestSHA256),
    retry: false,
  })
  const english = i18n.resolvedLanguage === 'en-US'
  const result = query.data
  return <section className="plugin-market-ui-page" aria-label={t('uiPage.title')}>
    <Typography.Title level={5}>{t('uiPage.title')}</Typography.Title>
    {query.isLoading ? <Spin size="small" aria-label={t('uiPage.loading')} /> : null}
    {result?.state === 'none' ? <Typography.Text type="secondary">{t('uiPage.none')}</Typography.Text> : null}
    {result?.state === 'mismatch' ? <Alert type="error" showIcon message={t('uiPage.mismatch', { version })} /> : null}
    {result?.state === 'unavailable' ? <Alert type="warning" showIcon message={t('uiPage.unavailable')} /> : null}
    {result?.state === 'declared' ? <>
      <Alert type="info" showIcon message={t('uiPage.notice', { origin: result.uiPage.origin })} />
      <Descriptions size="small" column={1}>
        <Descriptions.Item label={t('uiPage.origin')}><code>{result.uiPage.origin}</code></Descriptions.Item>
        {result.uiPage.api_base_url ? <Descriptions.Item label={t('uiPage.api')}><code>{result.uiPage.api_base_url}</code></Descriptions.Item> : null}
      </Descriptions>
      <List size="small" bordered dataSource={result.uiPage.pages} rowKey="id" renderItem={(page) => <List.Item>
        {t('uiPage.menuItem', { title: (english && page.title['en-US']) || page.title['zh-CN'], mount: t(`uiPage.mount.${page.mount}`) })}
        <Typography.Text type="secondary"> · {t(`uiPage.roles.${page.role}`)}{page.menu_parent ? ` · ${page.menu_parent}` : ''}</Typography.Text>
      </List.Item>} />
    </> : null}
  </section>
}

// SigningKeyPanel shows the installation public key ui_page plugin backends
// verify proxied calls with.
export function SigningKeyPanel({ token }: { token: string }) {
  const { t } = useTranslation('pluginInstallations')
  const query = useQuery({ queryKey: ['plugin-ui-signing-key'], queryFn: () => fetchPluginUISigningKey(token), retry: false })
  return <section className="plugin-market-signing-key" aria-label={t('signingKey.title')}>
    <Typography.Title level={5}>{t('signingKey.title')}</Typography.Title>
    <Typography.Paragraph type="secondary">{t('signingKey.help')}</Typography.Paragraph>
    {query.isLoading ? <Spin size="small" /> : null}
    {query.error ? (query.error instanceof ApiError && query.error.status === 503 ? <Alert type="info" showIcon message={t('signingKey.unavailable')} />
      : <FeedbackWhen title={t('signingKey.load')} />) : null}
    {query.data ? <Descriptions bordered size="small" column={1}>
      <Descriptions.Item label={t('signingKey.publicKey')}>
        <Typography.Text code copyable className="plugin-market-digest">{query.data.public_key}</Typography.Text>
      </Descriptions.Item>
      <Descriptions.Item label={t('signingKey.keyId')}><code>{query.data.key_id}</code></Descriptions.Item>
      <Descriptions.Item label={t('signingKey.domain')}><code>{query.data.signature_domain}</code></Descriptions.Item>
      <Descriptions.Item label={t('signingKey.installation')}><code>{query.data.installation_id}</code></Descriptions.Item>
    </Descriptions> : null}
  </section>
}
