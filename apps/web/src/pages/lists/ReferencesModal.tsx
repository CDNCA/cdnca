import { useQuery } from '@tanstack/react-query'
import { Button, Modal } from 'antd'
import { ExternalLink } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { listSecurityStringSetReferences, type SecurityStringSetAudience } from '../../api/securityStringSets'
import '../../i18n/securityLists'
import { DataTable, FeedbackWhen, MODAL_WIDTH } from '@cdnca/ui'

// 引用弹窗: the policies referencing one set, each opening
// its rule page in a new tab.
const policyPage: Record<string, string> = { waf: '/site/waf-rule', acl: '/site/acl', cc: '/site/cc-rule' }

export function ReferencesModal({ target, audience, accessToken, onClose }: {
  target: { id: string; name: string } | null
  audience: SecurityStringSetAudience
  accessToken: string
  onClose: () => void
}) {
  const { t } = useTranslation('securityLists')
  const query = useQuery({
    queryKey: ['security-string-sets', audience, 'references', target?.id],
    queryFn: () => listSecurityStringSetReferences(accessToken, audience, target?.id ?? ''),
    enabled: Boolean(target && accessToken),
    retry: false,
  })
  return (
    <Modal open={target !== null} title={t('references.title', { name: target?.name ?? '' })} width={MODAL_WIDTH.M} onCancel={onClose}
      footer={<Button type="primary" onClick={onClose}>{t('actions.gotIt')}</Button>} destroyOnHidden>
      {query.isError ? <FeedbackWhen title={t('errors.load')} action={<Button onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      <DataTable rowKey="policy_id" loading={query.isLoading} dataSource={query.data ?? []} pagination={false}
        locale={{ emptyText: t('references.empty') }}
        columns={[
          { title: t('references.policy'), dataIndex: 'policy_name', key: 'policy_name' },
          { title: t('references.kind'), dataIndex: 'policy_kind', key: 'policy_kind', render: (kind: string) => kind.toUpperCase() },
          { title: t('references.rules'), dataIndex: 'rule_count', key: 'rule_count' },
          {
            title: t('columns.actions'), key: 'open', render: (_, reference) => policyPage[reference.policy_kind] ? (
              <a href={`${policyPage[reference.policy_kind]}?policy_id=${encodeURIComponent(reference.policy_id)}`} target="_blank" rel="noreferrer">
                {t('actions.openPolicy')} <ExternalLink size={12} aria-hidden />
              </a>
            ) : null,
          },
        ]} />
    </Modal>
  )
}
