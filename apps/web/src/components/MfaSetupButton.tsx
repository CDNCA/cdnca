import { lazy, Suspense, useState } from 'react'
import { Button, Modal, Spin } from 'antd'
import { useTranslation } from 'react-i18next'

import '../i18n/accountMfa'

const AccountMfaPanel = lazy(() => import('../pages/account/AccountMfaPanel'))

export function MfaSetupButton({ disabled = false }: { disabled?: boolean }) {
  const { t } = useTranslation('accountMfa')
  const [open, setOpen] = useState(false)
  return <div onKeyDown={(event) => {
    if (event.key === 'Escape') event.stopPropagation()
  }}>
    <Button disabled={disabled} onClick={() => setOpen(true)}>{t('actions.manage')}</Button>
    <Modal title={t('actions.manage')} open={open} onCancel={() => setOpen(false)}
      footer={null} width={760} keyboard={false} destroyOnHidden>
      <Suspense fallback={<Spin aria-label={t('loading')} />}>
        <AccountMfaPanel />
      </Suspense>
    </Modal>
  </div>
}
