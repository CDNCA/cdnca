import { useState } from 'react'
import { useInfiniteQuery, useMutation } from '@tanstack/react-query'
import { Alert, Button, Modal, Select, Spin, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { sitesApi, type SiteTransferItem, type TransferSiteResult } from '../../api/sites'
import { usersApi, type ManagedUser } from '../../api/users'
import '../../i18n/siteTransfer'

// 更换所属用户（fix-transfer，平台管理员）：选目标用户（可搜索），确认后服务端在目标用户租户里重建站点并删除原站，自动发布。站点 ID 与
// CNAME 会变（CNAME 主机名全局唯一且按租户分区，不能保留），弹窗写明要改解析。
export interface SiteTransferSite {
  id: string
  version: number
  domain: string
  cname: string
  ownerID: string | null
  ownerName: string
}

export interface SiteTransferModalProps {
  open: boolean
  accessToken: string
  site: SiteTransferSite
  // The administrator may read users (identity.users.manage).
  canReadUsers: boolean
  onClose: () => void
  // The new site (its ID differs from the old one).
  onTransferred: (result: TransferSiteResult) => void
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.failed'
  if (error.code === 'site_transfer_target_invalid') return 'errors.target'
  if (error.code === 'domain_verified_by_other') return 'errors.domainVerified'
  if (error.code === 'site_transfer_domain_in_use') return 'errors.domainInUse'
  if (error.code === 'version_conflict' || error.status === 409 || error.status === 412) return 'errors.conflict'
  if (error.status === 403) return 'errors.forbidden'
  if (error.status === 422 || error.status === 400) return 'errors.invalid'
  return 'errors.failed'
}

export default function SiteTransferModal({ open, accessToken, site, canReadUsers, onClose, onTransferred }: SiteTransferModalProps) {
  const { t } = useTranslation('siteTransfer')
  const [search, setSearch] = useState('')
  const [user, setUser] = useState<ManagedUser | null>(null)
  const [idempotencyKey, setIdempotencyKey] = useState(() => crypto.randomUUID())
  const [result, setResult] = useState<TransferSiteResult | null>(null)

  const users = useInfiniteQuery({
    queryKey: ['site-transfer-users', search],
    enabled: open && canReadUsers,
    initialPageParam: 1,
    queryFn: ({ pageParam }) => usersApi.list(accessToken, { page: pageParam, limit: 20, search, status: 'active' }),
    getNextPageParam: (last) => last.page * last.limit < last.total ? last.page + 1 : undefined,
    retry: false,
  })
  const userOptions = (users.data?.pages.flatMap((page) => page.items) ?? [])
    .filter((item) => item.status === 'active' && item.id !== site.ownerID)

  const transfer = useMutation({
    mutationFn: () => sitesApi.transfer(accessToken, site.id, {
      expected_version: site.version, target_user_id: user!.id, target_package_subscription_id: null,
    }, idempotencyKey),
    onSuccess: (value) => setResult(value),
    onError: (error) => {
      // A definite refusal: a new attempt is a new request.
      if (error instanceof ApiError && error.status >= 400 && error.status < 500) setIdempotencyKey(crypto.randomUUID())
    },
  })

  const close = () => {
    if (transfer.isPending) return
    if (result) onTransferred(result)
    onClose()
  }
  const itemText = (items: SiteTransferItem[]) => items.map((item) => t(`items.${item}`)).join('、')

  if (result) {
    return (
      <Modal open={open} title={t('doneTitle', { domain: site.domain })} onCancel={close}
        footer={<Button type="primary" onClick={close}>{t('doneConfirm')}</Button>}>
        <Alert type="success" showIcon message={t('done', { user: user?.username ?? '' })} />
        <dl className="site-transfer-result">
          <dt>{t('oldCname')}</dt><dd><Typography.Text code>{result.from_cname || t('none')}</Typography.Text></dd>
          <dt>{t('newCname')}</dt>
          <dd>{result.site.basic.cname ? <Typography.Text code copyable>{result.site.basic.cname}</Typography.Text> : t('newCnamePending')}</dd>
        </dl>
        <Alert type="warning" showIcon message={t('dnsChange')} />
        {result.copied.length ? <p>{t('copied', { items: itemText(result.copied) })}</p> : null}
        {result.released.length ? <Alert type="info" showIcon message={t('released', { items: itemText(result.released) })} /> : null}
      </Modal>
    )
  }

  return (
    <Modal
      open={open}
      title={t('title', { domain: site.domain })}
      okText={t('confirm')}
      okButtonProps={{ danger: true, disabled: !user, loading: transfer.isPending }}
      cancelButtonProps={{ disabled: transfer.isPending }}
      onOk={() => transfer.mutate()}
      onCancel={close}
      maskClosable={false}
    >
      <p>{t('currentOwner', { owner: site.ownerName || t('none') })}</p>
      <label className="site-transfer-field">
        <span>{t('targetUser')}</span>
        <Select
          aria-label={t('targetUser')}
          showSearch
          filterOption={false}
          style={{ width: '100%' }}
          placeholder={t('targetUserPlaceholder')}
          disabled={!canReadUsers || transfer.isPending}
          loading={users.isFetching}
          value={user?.id}
          options={userOptions.map((item) => ({ value: item.id, label: `${item.username}（${item.display_id}）` }))}
          onSearch={setSearch}
          onChange={(value: string) => {
            setUser(userOptions.find((item) => item.id === value) ?? null)
          }}
          notFoundContent={users.isFetching ? <Spin size="small" /> : t('empty')}
          popupRender={(menu) => <>{menu}{users.hasNextPage ? <Button block loading={users.isFetchingNextPage} onClick={() => void users.fetchNextPage()}>{t('more')}</Button> : null}</>}
        />
        {!canReadUsers ? <small role="alert">{t('usersDenied')}</small> : null}
      </label>
      <Alert
        type="warning"
        showIcon
        message={t('impactTitle')}
        description={
          <ul className="site-transfer-impact">
            <li>{t('impact.cname', { cname: site.cname || t('none') })}</li>
            <li>{t('impact.dns')}</li>
            <li>{t('impact.id')}</li>
            <li>{t('impact.copied')}</li>
            <li>{t('impact.released')}</li>
            <li>{t('impact.domainOwnership')}</li>
            <li>{t('impact.history')}</li>
            <li>{t('impact.publish')}</li>
          </ul>
        }
      />
      {transfer.isError ? <Alert type="error" showIcon role="alert" message={t(errorKey(transfer.error))} /> : null}
    </Modal>
  )
}
