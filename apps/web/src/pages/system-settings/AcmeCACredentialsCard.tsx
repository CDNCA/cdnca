import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Space, Tag, Typography } from 'antd'
import type { TFunction } from 'i18next'

import { ApiError } from '../../api/auth'
import { acmeCACredentialsApi, type AcmeCACredential, type AcmeEABCA } from '../../api/acmeCACredentials'
import { useSessionStore } from '../../auth/session'
import { FeedbackWhen } from '@cdnca/ui'

// EAB credentials of ZeroSSL and Google Trust Services. The
// HMAC key is write-only; saving replaces the stored pair.
export default function AcmeCACredentialsCard({ t, editable }: { t: TFunction<'systemSettings'>; editable: boolean }) {
  const accessToken = useSessionStore((state) => state.accessToken)
  const queryClient = useQueryClient()
  const query = useQuery({
    queryKey: ['acme-ca-credentials', accessToken],
    queryFn: () => acmeCACredentialsApi.list(accessToken ?? ''),
    enabled: Boolean(accessToken),
  })
  if (!accessToken) return null
  if (query.isError) {
    return <FeedbackWhen title={t('parity.defaults.eab.loadError')} />
  }
  return <Space direction="vertical" style={{ width: '100%' }} size="middle">
    <Typography.Text type="secondary">{t('parity.defaults.eab.help')}</Typography.Text>
    {(query.data ?? []).map((item) => <EABRow key={item.ca} item={item} t={t} editable={editable}
      onSaved={() => void queryClient.invalidateQueries({ queryKey: ['acme-ca-credentials'] })} />)}
  </Space>
}

function EABRow({ item, t, editable, onSaved }: { item: AcmeCACredential; t: TFunction<'systemSettings'>; editable: boolean; onSaved: () => void }) {
  const accessToken = useSessionStore((state) => state.accessToken) ?? ''
  const [keyID, setKeyID] = useState('')
  const [hmacKey, setHMACKey] = useState('')
  const [email, setEmail] = useState('')
  // ZeroSSL 可按账户邮箱自动获取 EAB（后端调 ZeroSSL 公开接口并加密保存）。
  const emailMutation = useMutation({
    mutationFn: () => acmeCACredentialsApi.fetchZeroSSLFromEmail(accessToken, { expected_revision: item.revision, email: email.trim() }),
    onSuccess: () => { setEmail(''); onSaved() },
  })
  const mutation = useMutation({
    mutationFn: (clear: boolean) => acmeCACredentialsApi.save(accessToken, item.ca as AcmeEABCA, clear
      ? { expected_revision: item.revision, clear: true }
      : { expected_revision: item.revision, eab_key_id: keyID.trim(), eab_hmac_key: hmacKey.trim() }),
    onSuccess: () => { setKeyID(''); setHMACKey(''); onSaved() },
  })
  const failure = mutation.error ?? emailMutation.error
  const error = failure instanceof ApiError ? failure : null
  const busy = mutation.isPending || emailMutation.isPending
  const label = t(`parity.defaults.eab.cas.${item.ca}`)
  return <div className="configuration-eab-row" data-testid={`eab-${item.ca}`}>
    <Space wrap align="center">
      <strong>{label}</strong>
      {item.configured
        ? <Tag color="success">{t('parity.defaults.eab.configured', { kid: item.eab_key_id, prefix: item.eab_hmac_sha256_prefix })}</Tag>
        : <Tag>{t('parity.defaults.eab.notConfigured')}</Tag>}
    </Space>
    {editable ? <Space.Compact style={{ width: '100%', marginTop: 8 }}>
      <Input aria-label={`${label} ${t('parity.defaults.eab.keyID')}`} placeholder={t('parity.defaults.eab.keyID')}
        value={keyID} onChange={(event) => setKeyID(event.target.value)} autoComplete="off" />
      <Input.Password aria-label={`${label} ${t('parity.defaults.eab.hmacKey')}`} placeholder={t('parity.defaults.eab.hmacKey')}
        value={hmacKey} onChange={(event) => setHMACKey(event.target.value)} autoComplete="new-password" />
      <Button type="primary" loading={mutation.isPending} disabled={busy || !keyID.trim() || hmacKey.trim().length < 22}
        onClick={() => mutation.mutate(false)}>{t('parity.defaults.eab.save')}</Button>
      {item.configured ? <Button danger loading={mutation.isPending} disabled={busy} onClick={() => mutation.mutate(true)}>{t('parity.defaults.eab.clear')}</Button> : null}
    </Space.Compact> : null}
    {editable && item.ca === 'zerossl' ? <Space.Compact style={{ width: '100%', marginTop: 8 }}>
      <Input type="email" aria-label={`${label} ${t('parity.defaults.eab.email')}`} placeholder={t('parity.defaults.eab.emailPlaceholder')}
        value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" />
      <Button loading={emailMutation.isPending} disabled={busy || !/^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/.test(email.trim())}
        onClick={() => emailMutation.mutate()}>{t('parity.defaults.eab.fetchByEmail')}</Button>
    </Space.Compact> : null}
    {error ? <FeedbackWhen title={t(`parity.defaults.eab.errors.${error.code}`, { defaultValue: t('parity.defaults.eab.saveError') })} /> : null}
  </div>
}
