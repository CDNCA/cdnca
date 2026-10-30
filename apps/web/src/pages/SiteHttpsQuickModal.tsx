import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Modal, Spin } from 'antd'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { MODAL_WIDTH } from '@cdnca/ui'

import { ApiError } from '../api/auth'
import { certificatesApi } from '../api/certificates'
import { sitesApi, type SiteDetail, type SiteListItem } from '../api/sites'
import '../i18n/siteHttpsQuick'

/**
 * site-parity3a：网站列表 HTTPS 列「未开启」的快捷开启。走站点 HTTPS 现有流程：
 * HTTPS 只能在已绑定证书时开启（服务端同样拒绝 certificate_required），所以先查绑定：
 * 已绑定 → 一次 PATCH basic（https_enabled=true，其余字段按详情原样回写）；
 * 未绑定 → 引导去申请证书，或到站点 HTTPS 设置里选择证书。
 */
export default function SiteHttpsQuickModal({ site, accessToken, platform, onClose, onSaved }: {
  site: SiteListItem | null
  /** 当前会话的令牌（调用方已校验 sites.manage） */
  accessToken: string | null
  platform: boolean
  onClose: () => void
  onSaved: (saved: SiteDetail) => void
}) {
  const { t } = useTranslation('siteHttpsQuick')
  const navigate = useNavigate()
  const open = site !== null && accessToken !== null
  const detail = useQuery({
    queryKey: ['site-https-quick', site?.id],
    enabled: open,
    retry: false,
    gcTime: 0,
    queryFn: async () => {
      const value = await sitesApi.detail(accessToken!, site!.id)
      if (!value) throw new ApiError('site not found', 404, 'site_not_found')
      // 平台会话读站点所属租户的绑定（与 HTTPS 设置页同一接口）
      const targetScope = platform ? value.scope_id ?? undefined : undefined
      let bound = value.https_certificate_bound !== false
      try {
        await certificatesApi.getSiteBinding(accessToken!, value.id, targetScope)
        bound = true
      } catch (error) {
        if (error instanceof ApiError && error.status === 404 && error.code === 'certificate_site_binding_not_found') bound = false
        else if (value.https_certificate_bound === undefined) throw error
      }
      return { value, bound }
    },
  })
  const enable = useMutation({
    mutationFn: async () => {
      const current = detail.data!.value
      const changes = { ...current.basic, https_enabled: true }
      return sitesApi.patchBasic(accessToken!, current.id, { expected_version: current.version, section: 'basic', changes }, crypto.randomUUID())
    },
    onSuccess: (saved) => { onSaved(saved); onClose() },
  })
  const close = () => { enable.reset(); onClose() }
  const domains = site?.domains?.length ? site.domains : site ? [site.domain] : []
  const bound = detail.data?.bound
  const ports = detail.data?.value.basic.https_listen_ports.join(', ') || '443'
  return (
    <Modal title={t('title')} open={open} width={MODAL_WIDTH.S} onCancel={close} destroyOnHidden
      footer={
        <div className="cdnca-modal-footer">
          <Button onClick={close}>{t('cancel')}</Button>
          {bound === false ? (
            <>
              <Button onClick={() => { close(); navigate(`/site/${site!.id}/edit?tab=https`) }}>{t('chooseCertificate')}</Button>
              <Button type="primary" onClick={() => { close(); navigate(`/site/cert?domains=${encodeURIComponent(domains.join('\n'))}&site=${encodeURIComponent(site!.id)}`) }}>{t('applyCertificate')}</Button>
            </>
          ) : (
            <Button type="primary" loading={enable.isPending} disabled={bound !== true} onClick={() => enable.mutate()}>{t('confirm')}</Button>
          )}
        </div>
      }>
      <p className="site-https-quick-site"><span>{t('site')}</span><strong>{site?.domain}</strong></p>
      {detail.isPending ? <Spin size="small" tip={t('checking')}><div className="site-https-quick-spin" /></Spin> : null}
      {detail.isError ? (
        <Alert type="error" showIcon message={t('loadFailed')} action={<Button size="small" onClick={() => void detail.refetch()}>{t('retry')}</Button>} />
      ) : null}
      {bound === true ? <Alert type="info" showIcon message={t('bound', { ports })} /> : null}
      {bound === false ? <Alert type="warning" showIcon message={t('unbound')} /> : null}
      {enable.isError ? (
        <Alert type="error" showIcon message={t('failed', { message: enable.error instanceof ApiError ? enable.error.message : String(enable.error) })} />
      ) : null}
    </Modal>
  )
}
