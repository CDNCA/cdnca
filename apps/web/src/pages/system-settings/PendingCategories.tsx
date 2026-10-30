import { Alert, App, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import type { SystemConfigurationCategory } from '../../api/systemConfiguration'
import { systemConfigurationPendingNamespace as namespace } from '../../i18n/systemConfigurationPending'

// All system configuration categories share one revision stream: activating
// from any category page makes every pending category effective together.

const categoryPaths: Partial<Record<SystemConfigurationCategory, string>> = {
  nginx: '/config/nginx',
  defaults: '/config/default',
  resources: '/config/res',
  error_pages: '/config/error',
  node_monitoring: '/node/monitor-setting',
  ddos_protection: '/node/ddos-protection',
  access_log_fields: '/config/access-log',
}

export function otherPendingCategories(
  current: SystemConfigurationCategory,
  pending: readonly SystemConfigurationCategory[],
): SystemConfigurationCategory[] {
  return pending.filter((category) => category !== current)
}

function CategoryLinks({ categories, onNavigate }: {
  categories: SystemConfigurationCategory[]
  onNavigate: (path: string) => void
}) {
  const { t } = useTranslation(namespace)
  return (
    <Space wrap size={[12, 4]}>
      {categories.map((category) => {
        const path = categoryPaths[category]
        return path ? (
          <Typography.Link key={category} onClick={() => onNavigate(path)}>
            {`${t('view')}：${t(`categories.${category}`)}`}
          </Typography.Link>
        ) : null
      })}
    </Space>
  )
}

/** Scope and save granularity of the nginx/resources/defaults pages: saving only creates a draft (ADMIN-CURRENT-08). */
export function CategoryScopeNotice() {
  const { t } = useTranslation(namespace)
  return <Alert type="info" showIcon data-testid="category-scope-notice" message={t('scope.title')} description={t('scope.description')} />
}

/** Banner shown on a category page when the shared head carries other categories' unactivated changes. */
export function PendingCategoriesNotice({ current, pending }: {
  current: SystemConfigurationCategory
  pending: readonly SystemConfigurationCategory[]
}) {
  const { t } = useTranslation(namespace)
  const navigate = useNavigate()
  const others = otherPendingCategories(current, pending)
  if (others.length === 0) return null
  const names = others.map((category) => t(`categories.${category}`)).join('、')
  return (
    <Alert
      type="warning"
      showIcon
      data-testid="pending-categories-notice"
      message={t('notice.title')}
      description={<Space direction="vertical" size={4}>
        <span>{t('notice.description', { categories: names })}</span>
        <CategoryLinks categories={others} onNavigate={navigate} />
      </Space>}
    />
  )
}

/**
 * Returns a guard that runs `proceed` directly when only the current category
 * is pending, and otherwise asks the operator to confirm the other categories first.
 */
export function usePendingActivationConfirm(current: SystemConfigurationCategory) {
  const { t } = useTranslation(namespace)
  const { modal } = App.useApp()
  const navigate = useNavigate()
  return (pending: readonly SystemConfigurationCategory[], proceed: () => void) => {
    const others = otherPendingCategories(current, pending)
    if (others.length === 0) {
      proceed()
      return
    }
    const names = others.map((category) => t(`categories.${category}`)).join('、')
    const dialog = modal.confirm({
      title: t('confirm.title'),
      content: <Space direction="vertical" size={8}>
        <span>{t('confirm.description', { categories: names })}</span>
        <CategoryLinks categories={others} onNavigate={(path) => {
          dialog.destroy()
          navigate(path)
        }} />
      </Space>,
      okText: t('confirm.ok'),
      cancelText: t('confirm.cancel'),
      onOk: proceed,
    })
  }
}
