// ETag 在这里只用于乐观并发（读到的 revision 作 If-Match 回发），不是安全边界，也不证明内容完整。
// Cloudflare 等网关压缩 JSON 时会把强 ETag "n" 改成弱 W/"n"（RFC 9110 §8.8.3），内容与版本不变。
// 读取时去掉 W/ 前缀按强值比对；回发 If-Match 也用强值，因为服务端 If-Match 只接受 "n" 形式。
export function responseETag(response: Pick<Response, 'headers'>): string | null {
  const value = response.headers.get('ETag')
  return value !== null && value.startsWith('W/') ? value.slice(2) : value
}
