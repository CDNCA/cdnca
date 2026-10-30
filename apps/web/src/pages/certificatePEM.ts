// CERT-01：服务端把上传的 PEM 规范化（重新编码换行、去掉块外文字）后保存，
// 回包与输入逐字比较会把 CRLF、无末尾换行等合法输入误判成未知结果。按证书
// 块的 DER 内容（base64 去空白）逐块比较：同一条链才算同一证书。
export function samePEMCertificateChain(left: string, right: string): boolean {
  const blocks = (pem: string) => [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/gu)]
    .map((match) => match[1].replace(/\s+/gu, ''))
  const a = blocks(left)
  const b = blocks(right)
  if (a.length === 0 && b.length === 0) return left.trim() !== '' && left.replace(/\s+/gu, '') === right.replace(/\s+/gu, '')
  return a.length > 0 && a.length === b.length && a.every((value, index) => value.length > 0 && value === b[index])
}
