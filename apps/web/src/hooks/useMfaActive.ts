import { useQuery } from '@tanstack/react-query'

import { mfaApi } from '../api/mfa'
import { useSessionStore } from '../auth/session'

// MFA optional：只有操作者启用了 MFA，敏感操作才验证 MFA。
// 返回 true/false；读不到（加载中或出错）时返回 undefined，调用方按「需要验证」保守处理，
// 后端照样以真实状态为准（未启用放行、已启用缺码拒绝）。
// enabled=false：暂不请求（例如表单未打开时），返回 undefined。
export function useMfaActive(enabled = true): boolean | undefined {
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const query = useQuery({
    queryKey: ['account-mfa-active', sessionEpoch],
    enabled: enabled && Boolean(accessToken),
    retry: false,
    staleTime: 30_000,
    queryFn: async () => (await mfaApi.getStatus(accessToken!)).status === 'active',
  })
  return query.data
}
