import { Tag, Tooltip } from 'antd'
import { useTranslation } from 'react-i18next'
import type { CertificateAssetSync } from '../api/certificates'
import { certificatePublicationFailureMessage } from '../i18n/certificatePublicationFailures'
import './CertificateSyncStatus.css'

// 证书列表状态列的「同步失败」标签（管理端与用户端共用）。
// 只在当前绑定的发布永久失败时显示；原因按失败码翻译，悬停或聚焦看全文。
// detailed（证书详情、绑定网站表）显示三态，失败原因直接显示在标签下。
export function CertificateSyncStatus({ sync, detailed = false }: { sync?: CertificateAssetSync; detailed?: boolean }) {
  const { t } = useTranslation('certificatePublicationFailures')
  if (detailed && sync && sync.state !== 'failed') {
    return <Tag color={sync.state === 'complete' ? 'success' : 'processing'}>{t(sync.state === 'complete' ? 'syncComplete' : 'syncPending')}</Tag>
  }
  if (sync?.state !== 'failed') return null
  const reason = sync.failure_code ? certificatePublicationFailureMessage(sync.failure_code, t) : t('unknown')
  if (detailed) {
    return (
      <span className="certificate-sync-status">
        <Tag color="error">{t('syncFailed')}</Tag>
        <span className="certificate-sync-reason" title={reason}>{reason}</span>
      </span>
    )
  }
  return (
    <Tooltip title={reason}>
      <Tag color="error" tabIndex={0} aria-label={t('syncFailedReason', { reason })}>{t('syncFailed')}</Tag>
    </Tooltip>
  )
}
