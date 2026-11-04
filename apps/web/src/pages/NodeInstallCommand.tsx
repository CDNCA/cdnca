import { useEffect, useRef, useState } from 'react'
import { Button, Input, Popconfirm, Space } from 'antd'
import { useTranslation } from 'react-i18next'
import { ApiError } from '../api/auth'
import { nodesApi, type NodeInstallGateway } from '../api/nodes'
import './NodeListPage.locale'
import { FeedbackWhen } from '@cdnca/ui'
import { buildInstallerCommand, quoteShellArgument as quote } from '@cdnca/ui/installer-command'

function publicOrigin(value: string): URL {
  const url = new URL(value)
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
    throw new Error('invalid installation origin')
  }
  return url
}

// The copied command stays short: install-node.sh reads the upgrade trust pin,
// Gateway endpoints and download fallback from this console over HTTPS, and
// keeps verifying every artifact signature and checksum itself.
// __CDNCA_CONTROL_CA_SHA256__ pins /downloads/gateway-ca.pem
// when this console serves the installer-generated self-signed root; it is
// empty for a publicly trusted certificate.
export type InstallRuntime = { __CDNCA_NODE_UPGRADE_TRUST_SHA256__?: string; __CDNCA_CONTROL_CA_SHA256__?: string }

const registrationCredentialPattern = /^nrk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/
// Same forms install-node.sh accepts for node-install-defaults.
const gatewayAddressPattern = /^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}$/
const gatewayServerPattern = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$/

// One command for every node: the host registers itself with the scope-level
// credential and appears as pending ("待初始化"); nothing is created here.
// The credential reaches the installer on stdin through the shell's printf
// builtin, so it never appears in a process argument list (ps). The installer
// is downloaded to a temporary file and checked before it runs; the command
// returns the installer's own exit status (packages/cdnca-ui/src/installerCommand.ts).
// language: console UI language; an English UI adds --lang en, a Chinese one --lang zh.
// gateway (the node connects to the Gateway IP directly): the console's
// published direct Gateway entry, the same values as node-install-defaults; absent
// for a ws (CDN tunnel) console, whose command stays unchanged.
export function buildNodeInstallCommand(credential: string, origin: string, runtime: InstallRuntime = {}, language?: string,
  gateway?: NodeInstallGateway): string {
  if (!registrationCredentialPattern.test(credential)) throw new Error('invalid registration credential')
  return installerCommand('--registration-key-stdin', credential, origin, runtime, language, gateway)
}

// Raw one-time token of POST /v1/nodes/{id}/enrollment-tokens (32 random bytes, base64url).
const enrollmentTokenPattern = /^[A-Za-z0-9_-]{43}$/

// 重装此节点: the same command with the node's one-time re_enrollment token on
// stdin instead of the registration key. The installer skips registration and
// enrolls as that node, keeping its ID and settings.
export function buildNodeReinstallCommand(token: string, origin: string, runtime: InstallRuntime = {}, language?: string,
  gateway?: NodeInstallGateway): string {
  if (!enrollmentTokenPattern.test(token)) throw new Error('invalid enrollment token')
  return installerCommand('--enrollment-token-stdin', token, origin, runtime, language, gateway)
}

function installerCommand(secretFlag: string, secret: string, origin: string, runtime: InstallRuntime, language?: string,
  gateway?: NodeInstallGateway): string {
  // Published by install-control.sh together with node-install-defaults; a
  // console without it cannot hand out an upgradable node.
  if (!/^[0-9a-f]{64}$/.test(runtime.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ ?? '')) throw new Error('invalid upgrade trust digest')
  const control = publicOrigin(origin).origin
  const caDigest = runtime.__CDNCA_CONTROL_CA_SHA256__ ?? ''
  if (caDigest !== '' && !/^[0-9a-f]{64}$/.test(caDigest)) throw new Error('invalid control-plane CA digest')
  if (gateway && !(gatewayAddressPattern.test(gateway.enrollment_address) && gatewayAddressPattern.test(gateway.address) &&
      gatewayServerPattern.test(gateway.server_name))) throw new Error('invalid gateway entry')
  const gatewayArgs = gateway ? ` --gateway-enrollment-address ${quote(gateway.enrollment_address)} --gateway-address ${quote(gateway.address)}` +
    ` --gateway-server-name ${quote(gateway.server_name)} --gateway-transport grpc` : ''
  return buildInstallerCommand({
    urls: [`${control}/downloads/install-node.sh`], protocols: '=https', label: '[cdnca-edge]',
    args: `--control-plane ${quote(control)} ${secretFlag}${gatewayArgs}`, stdinSecret: secret, language,
    controlPlaneCA: caDigest ? { url: `${control}/downloads/gateway-ca.pem`, sha256: caDigest } : undefined,
  })
}

export default function NodeInstallCommand({ getAccessToken, errorText }: {
  getAccessToken: () => string | null
  errorText: (error: ApiError) => string
}) {
  const { t, i18n } = useTranslation('nodes')
  const active = useRef(true)
  const [busy, setBusy] = useState(false)
  const [command, setCommand] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [forbidden, setForbidden] = useState(false)
  // Callers pass inline callbacks; read the latest ones without refetching.
  const props = useRef({ getAccessToken, errorText })
  props.current = { getAccessToken, errorText }

  const load = async (reset: boolean) => {
    const { getAccessToken, errorText } = props.current
    const accessToken = getAccessToken()
    if (!accessToken) return
    setBusy(true)
    setError(null)
    try {
      const result = reset
        ? await nodesApi.resetRegistrationCredential(accessToken)
        : await nodesApi.getRegistrationCredential(accessToken)
      if (!active.current || !getAccessToken()) return
      setCommand(buildNodeInstallCommand(result.credential, window.location.origin, window as InstallRuntime, i18n.resolvedLanguage, result.gateway))
      setCopied(false)
    } catch (cause) {
      if (!active.current || !getAccessToken()) return
      if (cause instanceof ApiError && cause.status === 403) { setForbidden(true); setCommand(null) }
      setError(cause instanceof ApiError ? errorText(cause) : t('install.unavailable'))
    } finally {
      if (active.current) setBusy(false)
    }
  }

  useEffect(() => {
    active.current = true
    void load(false)
    return () => { active.current = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- fetch once per mount
  }, [])

  const copy = async () => {
    if (!command || !getAccessToken()) return
    try {
      await navigator.clipboard.writeText(command)
      if (active.current) { setCopied(true); setError(null) }
    } catch {
      if (active.current) setError(t('install.copyFailed'))
    }
  }

  return <>
    <p className="node-install-description">{t('install.reserveDescription')}</p>
    {error && <FeedbackWhen title={error} />}
    {command && <div className="node-install-command"><Input.TextArea aria-label={t('install.commandLabel')} value={command} readOnly autoSize={{ minRows: 3, maxRows: 8 }} /></div>}
    <Space wrap>
      <Button type="primary" disabled={forbidden || !command} loading={busy && !command} onClick={() => void copy()}>{t(copied ? 'install.copied' : 'install.copyCommand')}</Button>
      <Popconfirm title={t('install.resetTitle')} description={t('install.resetConfirm')} okText={t('install.resetOk')}
        okButtonProps={{ danger: true }} cancelText={t('install.resetCancel')} disabled={forbidden || busy} onConfirm={() => load(true)}>
        <Button danger disabled={forbidden || busy}>{t('install.reset')}</Button>
      </Popconfirm>
    </Space>
  </>
}
