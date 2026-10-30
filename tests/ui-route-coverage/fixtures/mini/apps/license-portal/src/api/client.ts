export const API_PREFIX = '/portal/v1'
export async function request<T>(path: string, options: { method?: string; prefix?: string } = {}): Promise<T> {
  const response = await fetch(`${options.prefix ?? API_PREFIX}${path}`, { method: options.method })
  return (await response.json()) as T
}
export const portalApi = {
  plans: () => request<unknown>('/plans'),
}
