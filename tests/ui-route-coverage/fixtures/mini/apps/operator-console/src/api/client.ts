async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, init)
  return (await response.json()) as T
}
export const operatorApi = {
  customers: () => request<unknown>('/operator/v1/customers'),
  sellers: () => request<unknown>('/operator/v1/market/sellers'),
  future: () => request<unknown>('/operator/v1/market/future'),
}
