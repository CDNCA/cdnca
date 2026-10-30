// MC12 E2 (MK-BUYER-FLOW-01): pick a saved site, bind supplies to it and roll
// it out. The server compiles the revision from the saved site; the manual
// revision + JSON form stays under "advanced diagnostics" only.
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Collapse, Descriptions, Popconfirm, Select, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { marketReason } from '@cdnca/ui/market-reasons'

import { ApiError } from '../../api/auth'
import { marketApi, type MarketLeafStatus, type MarketRollout, type MarketSiteRollout } from '../../api/market'
import { sitesApi } from '../../api/sites'
import { useSessionStore } from '../../auth/session'
import { DataState } from '../../components/DataState'
import { ReasonText } from './ReasonText'

export type PickedSite = { id: string; domain: string }

// SitePicker searches sites by domain, one page at a time (the session's own
// site list permission decides what it sees).
export function SitePicker({ value, onChange }: { value: PickedSite | null; onChange: (site: PickedSite | null) => void }) {
  const { t } = useTranslation('nodeMarket')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const [search, setSearch] = useState('')
  const sites = useQuery({
    queryKey: ['nodeMarket', 'sitePicker', search],
    queryFn: () => sitesApi.list(token, { page: 1, limit: 20, ...(search.trim() ? { domain: search.trim() } : {}) }),
    enabled: !!token,
  })
  const options = (sites.data?.items ?? []).map((s) => ({
    value: s.id, label: s.owner ? `${s.domain}（${s.owner.display_name}）` : s.domain, domain: s.domain,
  }))
  if (value && !options.some((o) => o.value === value.id)) options.unshift({ value: value.id, label: value.domain, domain: value.domain })
  return (
    <Select showSearch allowClear filterOption={false} style={{ width: 'min(360px, calc(100vw - 72px))' }} aria-label={t('supplies.site')} placeholder={t('supplies.sitePlaceholder')}
      value={value?.id} loading={sites.isFetching} onSearch={setSearch} options={options}
      notFoundContent={sites.error ? t('supplies.siteLoadFailed') : t('supplies.siteNone')}
      onChange={(id, option) => onChange(id ? { id, domain: (option as { domain: string }).domain } : null)} />
  )
}

function failureText(t: (key: string, o?: Record<string, unknown>) => string, language: string, error: unknown) {
  const code = error instanceof ApiError ? error.code : 'request_failed'
  const r = marketReason(code, language)
  return t('supplies.failedWith', { reason: r.reason, next: r.next })
}

// BoundSupplies reads back what is bound to the picked site.
export function BoundSupplies({ site }: { site: PickedSite }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const bound = useQuery({ queryKey: ['nodeMarket', 'siteBindings', site.id], queryFn: () => marketApi.siteBindings(token, site.id), enabled: !!token })
  const unbind = useMutation({
    mutationFn: (supply: string) => marketApi.unbind(token, site.id, supply),
    onSuccess: () => { void message.success(t('supplies.unbound')); void client.invalidateQueries({ queryKey: ['nodeMarket'] }) },
    onError: (error) => { void message.error(failureText(t, i18n.language, error)) },
  })
  if (bound.error) return <DataState status="error" message={t('supplies.boundLoadFailed')} onRetry={() => void bound.refetch()} />
  const rows = bound.data ?? []
  return (
    <Table rowKey="supply_id" size="small" pagination={false} scroll={{ x: 'max-content' }} loading={bound.isLoading} dataSource={rows}
      locale={{ emptyText: t('supplies.boundNone', { site: site.domain }) }}
      columns={[
        { title: t('supplies.name'), dataIndex: 'name' },
        { title: t('supplies.role'), dataIndex: 'role', render: (v: string) => t(v === 'primary' ? 'supplies.primary' : 'supplies.backup') },
        { title: t('supplies.leaves'), dataIndex: 'leaves' },
        {
          key: 'unbind', render: (_: unknown, b) => {
            const backups = rows.filter((r) => r.supply_id !== b.supply_id).length
            return (
              <Popconfirm title={t('supplies.unbindConfirm', { site: site.domain, supply: b.name })}
                description={backups > 0 ? t('supplies.unbindOthers', { count: backups }) : t('supplies.unbindLast')}
                onConfirm={() => unbind.mutate(b.supply_id)}>
                <Button size="small" loading={unbind.isPending && unbind.variables === b.supply_id}>{t('supplies.unbind')}</Button>
              </Popconfirm>
            )
          },
        },
      ]} />
  )
}

// ClampedReason (fix-mktsiteconf7 §3): the reasons wrap (no horizontal
// scroll), show two lines and open in place when there is more. Lines are
// inline (line clamp does not reach into flex children).
export function ClampedReason({ lines }: { lines: ReactNode[] }) {
  const { t } = useTranslation('nodeMarket')
  const box = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)
  const [overflows, setOverflows] = useState(false)
  useLayoutEffect(() => {
    const el = box.current
    if (el && !open) setOverflows(el.scrollHeight > el.clientHeight + 1)
  }, [lines, open])
  return (
    <div>
      <div ref={box} data-clamp={open ? 'open' : '2'} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere',
        ...(open ? {} : { display: '-webkit-box', WebkitBoxOrient: 'vertical', WebkitLineClamp: 2, overflow: 'hidden' }) }}>
        {lines.map((line, i) => <span key={i}>{i > 0 ? <br /> : null}{line}</span>)}
      </div>
      {overflows || open ? (
        <Button type="link" size="small" style={{ paddingInline: 0, height: 'auto' }} aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? t('supplies.reasonLess') : t('supplies.reasonMore')}
        </Button>
      ) : null}
    </div>
  )
}

const leafKey = (l: { leaf: { leaf_member_id: string; node_pool_ref: string } }) => `${l.leaf.leaf_member_id}/${l.leaf.node_pool_ref}`
const nodeColor: Record<string, string> = { delivering: 'processing', effective: 'success', failed: 'error' }

// LeafTable shows each leaf's answer; after an apply (nodes set) also where
// the revision is on that leaf's nodes, from the subscriber's saved checks.
function LeafTable({ result, nodes }: { result: MarketRollout; nodes?: Map<string, MarketLeafStatus> }) {
  const { t } = useTranslation('nodeMarket')
  return (
    <Table rowKey={leafKey} dataSource={result.leaves} pagination={false} size="small"
      columns={[
        { title: t('supplies.leaf'), key: 'leaf', width: 1, render: (_: unknown, l) => <Typography.Text code style={{ whiteSpace: 'nowrap' }}>{l.leaf.leaf_member_id.slice(0, 8)}</Typography.Text> },
        { title: t('supplies.status'), dataIndex: 'state', width: 1, render: (v: string, l) => {
          const node = nodes?.get(leafKey(l))?.node
          return (
            <Space direction="vertical" size={4}>
              <Tag color={v === 'applied' ? 'success' : ['blocked', 'failed', 'inconsistent'].includes(v) ? 'error' : 'default'}>{t(`states.${v}`, { defaultValue: v })}</Tag>
              {v === 'applied' && node?.state ? <Tag color={nodeColor[node.state]}>{t(`supplies.node.${node.state}`)}</Tag> : null}
            </Space>
          )
        } },
        { title: t('supplies.reason'), key: 'detail', onCell: () => ({ style: { minWidth: 160 } }), render: (_: unknown, l) => {
          const node = l.state === 'applied' ? nodes?.get(leafKey(l))?.node : undefined
          const lines = [
            ...(node?.reason ? [<ReasonText key="node" code={node.reason} detail={node.detail} />] : []),
            ...(l.blockers ?? []).map((b, i) => <ReasonText key={`${b.code}-${i}`} code={b.code} detail={b.detail} />),
            ...(l.error ? [<Typography.Text key="error" type="secondary" copyable={{ text: l.error }}>{t('supplies.leafError')}</Typography.Text>] : []),
          ]
          if (lines.length === 0) return null
          return <ClampedReason lines={lines} />
        } },
      ]} />
  )
}

// useLeafNodes polls the leaves' node delivery after an apply until every
// applied leaf has settled (effective or failed); refresh asks at once.
function useLeafNodes(siteID: string, enabled: boolean) {
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const query = useQuery({
    queryKey: ['nodeMarket', 'siteLeaves', siteID],
    queryFn: () => marketApi.siteLeaves(token, siteID),
    enabled: enabled && !!token,
    refetchInterval: (q) => (q.state.data ?? []).some((l) => l.node.state === 'delivering') ? 15_000 : false,
  })
  const map = new Map((query.data ?? []).map((l) => [leafKey(l), l]))
  return { nodes: enabled ? map : undefined, query }
}

// RolloutRequest is one preview or apply, frozen when it is sent (MC06,
// MK-BUYER-RESULT-01): account, site, sequence and, for an apply, the version
// and digest of the confirmed preview. Its answer or error only counts while
// the panel is still on the same account and site and no later request went out.
type RolloutRequest = { account: string; site: PickedSite; seq: number; apply: boolean; version?: number; digest?: string }
type RolloutFailure = { request: RolloutRequest; error: unknown } | { request: RolloutRequest; mismatch: string }

// SiteRollout previews the saved site and applies exactly that preview.
export function SiteRollout({ site }: { site: PickedSite }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const { modal } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const account = useSessionStore((state) => state.principal ? `${state.principal.user_id}/${state.principal.scope_id}` : '')
  const context = `${account}/${site.id}`
  const [answer, setAnswer] = useState<{ request: RolloutRequest; out: MarketSiteRollout; at: Date } | null>(null)
  const [failure, setFailure] = useState<RolloutFailure | null>(null)
  const latest = useRef(0)
  const live = useRef(context)
  live.current = context
  const confirm = useRef<{ destroy: () => void } | null>(null)
  // epoch counts lifetimes of this account+site in this mounted panel; an apply
  // confirmation only acts in the epoch it was opened in (D-补1).
  const epoch = useRef(0)
  // Another account or site: earlier answers, errors, requests in flight and
  // an open apply confirmation all belong to the old one.
  const [shown, setShown] = useState(context)
  if (shown !== context) { setShown(context); setAnswer(null); setFailure(null) }
  useEffect(() => {
    // The cleanup runs on a context change and on unmount (leaving the page,
    // history back): requests in flight stop counting and only the confirmation
    // this panel opened is closed. StrictMode's replayed cleanup runs before any
    // confirmation exists, so it cannot close a later one.
    epoch.current += 1
    return () => {
      epoch.current += 1
      latest.current += 1
      // eslint-disable-next-line react-hooks/exhaustive-deps -- the confirmation open at cleanup time is meant
      confirm.current?.destroy()
      confirm.current = null
    }
  }, [context])
  const owns = (r: RolloutRequest) => latest.current === r.seq && live.current === `${r.account}/${r.site.id}`
  const run = useMutation({
    mutationFn: async (r: RolloutRequest & { token: string }) => {
      try {
        return r.apply ? await marketApi.siteApply(r.token, r.site.id, r.version!, r.digest!) : await marketApi.sitePreview(r.token, r.site.id)
      } catch (error) {
        // site_changed carries the fresh plan: show it as a new preview to re-check.
        const refusal = (error as { refusal?: { plan?: MarketSiteRollout['plan'] } }).refusal
        if (error instanceof ApiError && error.code === 'site_changed' && refusal?.plan) {
          return { plan: refusal.plan, changed: true } as MarketSiteRollout & { changed: true }
        }
        throw error
      }
    },
    onSuccess: (out, r) => {
      if (!owns(r)) return
      // The plan must be of the site asked for; anything else is not shown as it.
      if (out.plan.site_id !== r.site.id) { setAnswer(null); setFailure({ request: r, mismatch: out.plan.domain || out.plan.site_id }); return }
      setFailure(null)
      setAnswer({ request: r, out, at: new Date() })
    },
    onError: (error, r) => { if (owns(r)) { setAnswer(null); setFailure({ request: r, error }) } },
  })
  const send = (apply: boolean, from?: MarketSiteRollout['plan']) => {
    if (apply && (!from || live.current !== context)) return
    latest.current += 1
    setFailure(null)
    run.mutate({ token, account, site, seq: latest.current, apply, version: from?.site_version, digest: from?.digest })
  }
  const current = answer
  const plan = current?.out.plan
  const changed = !!current && 'changed' in current.out
  const blocked = !!plan && plan.unsupported.length > 0
  const canApply = !!current && !current.request.apply && !blocked && !changed && !!current.out.result && current.out.result.leaves.every((l) => l.state === 'applied')
  const applied = !!current?.request.apply && !!current.out.result
  const leafNodes = useLeafNodes(site.id, applied)
  // Busy only for the request that still counts; one made stale by a switch does not hold the buttons.
  const pending = run.isPending && run.variables && owns(run.variables) ? run.variables : null
  const openConfirm = () => {
    if (!plan) return
    const from = plan
    const opened = epoch.current
    const handle = modal.confirm({
      title: t('supplies.applyConfirmSite', { site: from.domain, version: from.site_version }),
      // A click that reaches a confirmation of an earlier epoch (panel left or
      // context changed) applies nothing.
      onOk: () => { if (confirm.current === handle) confirm.current = null; if (epoch.current === opened) send(true, from) },
      onCancel: () => { if (confirm.current === handle) confirm.current = null },
    })
    confirm.current = handle
  }
  return (
    <section aria-label={t('supplies.rollout')}>
      <Typography.Paragraph type="secondary">{t('supplies.rolloutHelp')}</Typography.Paragraph>
      <Space wrap>
        <Button onClick={() => send(false)} loading={!!pending && !pending.apply}>{t('supplies.preview')}</Button>
        <Button type="primary" disabled={!canApply} loading={!!pending?.apply} onClick={openConfirm}>
          {t('supplies.apply')}</Button>
        <Link to={`/site/${encodeURIComponent(site.id)}/edit`}>{t('supplies.editSite')}</Link>
      </Space>
      {failure ? <Alert style={{ marginTop: 12 }} type="error" showIcon
        message={t(failure.request.apply ? 'supplies.applyFailedOn' : 'supplies.previewFailedOn', { site: failure.request.site.domain })}
        description={'mismatch' in failure ? t('supplies.siteMismatch', { site: failure.request.site.domain, other: failure.mismatch })
          : failureText(t, i18n.language, failure.error)}
        action={<Button size="small" onClick={() => send(false)}>{t('supplies.retry')}</Button>} /> : null}
      {current && plan ? (
        <div style={{ marginTop: 12 }}>
          <Descriptions size="small" column={{ xs: 1, sm: 2, md: 4 }} items={[
            { key: 'site', label: t('supplies.resultSite'), children: plan.domain },
            { key: 'version', label: t('supplies.siteVersion'), children: plan.site_version },
            { key: 'revision', label: t('supplies.revision'), children: plan.revision || '—' },
            { key: 'at', label: t('supplies.resultAt'), children: current.at.toLocaleTimeString() },
          ]} />
          {changed ? <Alert type="warning" showIcon message={t('supplies.siteChanged')} /> : null}
          {blocked ? (
            <Alert type="warning" showIcon message={t('supplies.siteBlocked')}
              description={<Space direction="vertical" size={2}>{plan.unsupported.map((u, i) => <ReasonText key={`${u.code}-${i}`} code={u.code} detail={u.detail} />)}</Space>} />
          ) : null}
          {current.out.result ? <>
            <Alert type={current.out.result.applied ? 'success' : current.request.apply ? 'warning' : 'info'} showIcon
              message={current.request.apply ? t(current.out.result.applied ? 'supplies.applied' : 'supplies.notApplied')
                : t(canApply ? 'supplies.previewOk' : 'supplies.previewBlocked')} />
            {applied ? (
              <Space wrap style={{ margin: '8px 0' }}>
                <Typography.Text type="secondary">{t('supplies.nodeHelp')}</Typography.Text>
                <Button size="small" loading={leafNodes.query.isFetching} onClick={() => void leafNodes.query.refetch()}>{t('supplies.nodeRefresh')}</Button>
              </Space>
            ) : null}
            {applied && leafNodes.query.error ? <Alert type="warning" showIcon message={t('supplies.nodeLoadFailed')} /> : null}
            <LeafTable result={current.out.result} nodes={leafNodes.nodes} />
          </> : null}
          <Collapse ghost size="small" items={[{ key: 'diag', label: t('supplies.diagnostics'), children: (
            <Typography.Paragraph copyable={{ text: JSON.stringify(plan.config, null, 2) }}>
              <Typography.Text type="secondary">{t('supplies.digest')}：{plan.digest || '—'}</Typography.Text>
              <pre style={{ maxHeight: 240, overflow: 'auto' }}>{JSON.stringify(plan.config, null, 2)}</pre>
            </Typography.Paragraph>
          ) }]} />
        </div>
      ) : null}
    </section>
  )
}
