// CERT-02：浏览器本地读取证书/私钥文件填入 PEM 文本框（不上传文件本身，仍走同一 JSON 上传）。
// 只做客户端预检：大小上限与服务端一致，内容须含对应的 PEM 块；证钥是否匹配由服务端判定。

/** Matches certificateasset.MaxCertificatePEMBytes / MaxPrivateKeyPEMBytes. */
export const maxCertificatePEMBytes = 256 * 1024
export const maxPrivateKeyPEMBytes = 64 * 1024

export type PEMFileKind = 'certificate' | 'privateKey'
export type PEMFileError = 'tooLarge' | 'notPEM' | 'unreadable'

const certificateBlock = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/
const privateKeyBlock = /-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/

export const pemFileAccept: Record<PEMFileKind, string> = {
  certificate: '.pem,.crt,.cer,.cert,.txt',
  privateKey: '.pem,.key,.txt',
}

export async function readPEMFile(file: File, kind: PEMFileKind): Promise<{ text: string } | { error: PEMFileError }> {
  if (file.size > (kind === 'certificate' ? maxCertificatePEMBytes : maxPrivateKeyPEMBytes)) return { error: 'tooLarge' }
  let text: string
  try {
    text = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => typeof reader.result === 'string' ? resolve(reader.result) : reject(new Error('unreadable'))
      reader.onerror = () => reject(reader.error ?? new Error('unreadable'))
      reader.readAsText(file)
    })
  } catch {
    return { error: 'unreadable' }
  }
  if (!(kind === 'certificate' ? certificateBlock : privateKeyBlock).test(text)) return { error: 'notPEM' }
  return { text }
}
