import { useEffect, useRef, useState } from 'react'
import { Button, Input, Popconfirm, Space } from 'antd'
import { useTranslation } from 'react-i18next'
import { ApiError } from '../api/auth'
import { nodesApi } from '../api/nodes'
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
type InstallRuntime = { __CDNCA_NODE_UPGRADE_TRUST_SHA256__?: string }

const registrationCredentialPattern = /^nrk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/

// One command for every node: the host registers itself with the scope-level
// credential and appears as pending ("待初始化"); nothing is created here.
// The credential reaches the installer on stdin through the shell's printf
// builtin, so it never appears in a process argument list (ps). The installer
// is downloaded to a temporary file and checked before it runs; the command
// returns the installer's own exit status (packages/cdnca-ui/src/installerCommand.ts).
export function buildNodeInstallCommand(credential: string, origin: string, runtime: InstallRuntime = {}): string {
  if (!registrationCredentialPattern.test(credential)) throw new Error('invalid registration credential')
  // Published by install-control.sh together with node-install-defaults; a
  // console without it cannot hand out an upgradable node.
  if (!/^[0-9a-f]{64}$/.test(runtime.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ ?? '')) throw new Error('invalid upgrade trust digest')
  const control = publicOrigin(origin).origin
  return buildInstallerCommand({
    urls: [`${control}/downloads/install-node.sh`], protocols: '=https', label: '[cdnca-edge]',
    args: `--control-plane ${quote(control)} --registration-key-stdin`, stdinSecret: credential,
  })
}

export default function NodeInstallCommand({ getAccessToken, errorText }: {
  getAccessToken: () => string | null
  errorText: (error: ApiError) => string
}) {
  const { t } = useTranslation('nodes')
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
      setCommand(buildNodeInstallCommand(result.credential, window.location.origin, window as InstallRuntime))
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
