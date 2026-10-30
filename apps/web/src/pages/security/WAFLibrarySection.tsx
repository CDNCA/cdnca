import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Popconfirm, Tag } from 'antd'
import { useFeedbackMessage, useFeedback } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { wafRuleSubscriptionsApi, type WAFRuleLibrary } from '../../api/wafRuleSubscriptions'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/wafRuleSubscriptions'

const statusColors: Record<WAFRuleLibrary['subscription'], string> = {
  not_subscribed: 'default', subscribed: 'green', update_available: 'orange', not_applicable: 'default',
}

// "平台 WAF 规则库" of the WAF rule page, folded into the rule library table (tp-b4): the platform libraries
// the license center delivers (GET /v1/waf-rule-libraries, origin system) and subscribe / update / unsubscribe /
// refresh-all. A subscription is a protected copy in the caller's policy list (library_id names the library).
// Reading needs security_policies.read (the page), the actions security_policies.manage.
export function useWAFLibraries(accessToken: string, onChanged: () => void) {
  const { t } = useTranslation('securityPolicies')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const query = useQuery({ queryKey: ['waf-rule-libraries'], retry: false, queryFn: () => wafRuleSubscriptionsApi.libraries(accessToken) })
  const done = (notice: string) => {
    void messageApi.success(t(`wafLibraries.notices.${notice}`))
    void queryClient.invalidateQueries({ queryKey: ['waf-rule-libraries'] })
    void queryClient.invalidateQueries({ queryKey: ['waf-pending-publications'] })
    onChanged()
  }
  const failure = (error: unknown) => void feedback.error(t('wafLibraries.notices.failed', { reason: localizedUnknownApiError(error, t('errors.request_failed')) }))
  const subscribe = useMutation({
    mutationFn: (library: WAFRuleLibrary) => wafRuleSubscriptionsApi.subscribeLibrary(accessToken, library.id),
    onSuccess: (_, library) => done(library.subscription === 'update_available' ? 'updated' : 'subscribed'),
    onError: failure,
  })
  const unsubscribe = useMutation({
    mutationFn: (id: string) => wafRuleSubscriptionsApi.unsubscribeLibrary(accessToken, id),
    onSuccess: () => done('unsubscribed'),
    onError: failure,
  })
  const refresh = useMutation({
    mutationFn: () => wafRuleSubscriptionsApi.refreshLibraries(accessToken),
    onSuccess: () => done('refreshed'),
    onError: failure,
  })
  // An unavailable catalog hides the platform rows but is reported (SEC-ACCOUNT-03):
  // a read failure must not look like "no platform library" or "nothing to update".
  const libraries = query.isError ? [] : (query.data ?? []).filter((library) => library.origin === 'system')
  // A subscription's protected copy names its library by ID (library_id).
  const forCopy = (libraryID?: string) => libraryID
    ? libraries.find((library) => library.id === libraryID && library.subscription !== 'not_subscribed')
    : undefined
  const loadError = query.isError ? query.error : null
  return { libraries, forCopy, loading: query.isPending, loadError, retry: () => void query.refetch(), subscribe, unsubscribe, refresh, messageContext }
}

export type WAFLibraries = ReturnType<typeof useWAFLibraries>

/** 订阅 column: the subscription state of a platform library row or of a subscribed copy. */
export function WAFSubscriptionTag({ library, subscribedCopy }: { library?: WAFRuleLibrary; subscribedCopy?: boolean }) {
  const { t } = useTranslation('securityPolicies')
  const status = library?.subscription ?? (subscribedCopy ? 'subscribed' : 'not_applicable')
  if (status === 'not_applicable') return <span className="waf-rule-pill waf-rule-pill--muted">{t('wafLibraries.statuses.not_subscribed')}</span>
  return <Tag className="waf-rule-subscription-tag" color={statusColors[status]}>{t(`wafLibraries.statuses.${status}`)}</Tag>
}

/** Row actions of a platform library: subscribe or update, and unsubscribe once subscribed. */
export function WAFSubscriptionActions({ library, state }: { library: WAFRuleLibrary; state: WAFLibraries }) {
  const { t } = useTranslation('securityPolicies')
  return <>
    {library.subscription !== 'subscribed'
      ? <Button type="link" size="small" loading={state.subscribe.isPending && state.subscribe.variables?.id === library.id}
        aria-label={`${t(library.subscription === 'update_available' ? 'wafLibraries.update' : 'wafLibraries.subscribe')} ${library.name}`}
        onClick={() => state.subscribe.mutate(library)}>
        {t(library.subscription === 'update_available' ? 'wafLibraries.update' : 'wafLibraries.subscribe')}
      </Button>
      : null}
    {library.subscription !== 'not_subscribed'
      ? <Popconfirm title={t('wafLibraries.unsubscribeConfirm')} okText={t('wafLibraries.unsubscribe')} onConfirm={() => state.unsubscribe.mutate(library.id)}>
        <Button type="link" size="small" danger loading={state.unsubscribe.isPending && state.unsubscribe.variables === library.id}
          aria-label={`${t('wafLibraries.unsubscribe')} ${library.name}`}>{t('wafLibraries.unsubscribe')}</Button>
      </Popconfirm>
      : null}
  </>
}
