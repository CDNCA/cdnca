import { useEffect, useState } from 'react'
import { Alert, Button, Input, Modal, Space } from 'antd'
import { Copy, Eye, EyeOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { CertificateAssetPEM } from '../api/certificates'
import './CertificatePEMDialog.css'

// 查看证书：证书链与私钥两栏只读显示，各带复制；私钥默认遮住，复制不需要先显示。
export function CertificatePEMDialog({ title, open, loading, value, error, onClose }: {
  title: string
  open: boolean
  loading: boolean
  value?: CertificateAssetPEM
  error?: string
  onClose: () => void
}) {
  const { t } = useTranslation('certificateAssets')
  const [revealed, setRevealed] = useState(false)
  const [copied, setCopied] = useState<'certificate' | 'key' | null>(null)
  const [copyFailed, setCopyFailed] = useState(false)
  useEffect(() => {
    if (!open) { setRevealed(false); setCopied(null); setCopyFailed(false) }
  }, [open])
  const copy = (which: 'certificate' | 'key', text: string) => {
    setCopyFailed(false)
    void navigator.clipboard.writeText(text).then(() => setCopied(which), () => { setCopied(null); setCopyFailed(true) })
  }
  const pane = (which: 'certificate' | 'key', label: string, text: string, masked: boolean) => (
    <section className="certificate-pem-pane" aria-label={label}>
      <header>
        <strong>{label}</strong>
        <Space size={4}>
          {which === 'key' ? (
            <Button size="small" type="text" icon={revealed ? <EyeOff size={14} /> : <Eye size={14} />} onClick={() => setRevealed((value) => !value)}>
              {revealed ? t('viewPEM.hide') : t('viewPEM.show')}
            </Button>
          ) : null}
          <Button size="small" icon={<Copy size={14} />} disabled={!text} onClick={() => copy(which, text)}>
            {copied === which ? t('viewPEM.copied') : t('viewPEM.copy')}
          </Button>
        </Space>
      </header>
      {masked
        ? <div className="certificate-pem-masked" role="note">{t('viewPEM.masked')}</div>
        : <Input.TextArea className="certificate-pem-text" readOnly value={text} autoSize={{ minRows: 10, maxRows: 18 }} aria-label={label} spellCheck={false} />}
    </section>
  )
  return (
    <Modal className="identity-modal certificate-pem-modal" width={880} title={`${t('viewPEM.title')} · ${title}`} open={open}
      onCancel={onClose} footer={<Button onClick={onClose}>{t('viewPEM.close')}</Button>} destroyOnHidden>
      {error ? <Alert className="identity-alert" type="error" showIcon message={error} /> : null}
      {copyFailed ? <Alert className="identity-alert" type="warning" showIcon message={t('viewPEM.copyFailed')} /> : null}
      {loading ? <div className="certificate-pem-loading" aria-busy="true">{t('viewPEM.loading')}</div> : null}
      {value ? (
        <div className="certificate-pem-grid">
          {pane('certificate', t('viewPEM.certificate'), value.certificate_pem, false)}
          {pane('key', t('viewPEM.privateKey'), value.private_key_pem, !revealed)}
        </div>
      ) : null}
    </Modal>
  )
}
