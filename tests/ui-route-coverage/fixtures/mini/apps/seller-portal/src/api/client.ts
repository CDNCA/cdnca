export const API_PREFIX = '/seller/v1'
export async function request<T>(path: string, options: { method?: string } = {}): Promise<T> {
  const response = await fetch(`${API_PREFIX}${path}`, { method: options.method })
  return (await response.json()) as T
}
const seller = (path: string) => `/${path}`
export const sellerApi = {
  me: () => request<unknown>(seller('me')),
}
