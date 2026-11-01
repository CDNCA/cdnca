// One-line installer commands shared by every console (主控安装、授权门户一键安装、节点安装、网关安装).
//
// Shape (one subshell, so `exit` never closes the operator's shell):
//   (f=$(mktemp) || exit 1; trap 'rc=$?; rm -f "$f" …; exit $rc' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM;
//    { curl … -o "$f" URL1 || curl … -o "$f" URL2; } || { rc=$?; echo '… 无法下载安装脚本' >&2; exit $rc; };
//    <the file starts with #! and ends with `main "$@"`> || { echo '… 不完整' >&2; exit 1; };
//    [secret to a private mktemp file, or on stdin]; bash "$f" ARGS)
// The command returns the installer's own exit status, a failed download returns
// curl's status, an empty or truncated download returns 1, and the downloaded
// script and any credential file are removed on every exit, including Ctrl-C.
// `bash "$f"` keeps the terminal as the installer's stdin for its prompts.
//
// controlPlaneCA (a console on the installer-generated self-signed root): the
// root is fetched once without verification into a private temporary file and
// used only after its SHA-256 equals the pin the console published; the script
// is then downloaded with --cacert (falling back to the system trust store, for
// a console that later moved to a public certificate) and the installer gets
// the same file and pin. Nothing fetched unverified is ever executed.

export function quoteShellArgument(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`
}

export interface InstallerCommand {
  /** Installer URLs, tried in order. */
  urls: string[]
  /** curl --proto value: '=https', or '=http,https' for a loopback development origin. */
  protocols: string
  /** Prefix of the error lines, e.g. '[cdnca-control]'. */
  label: string
  /** Installer arguments, already quoted. */
  args: string
  /** Secret written to the installer's stdin (followed by a newline). */
  stdinSecret?: string
  /** Secret written to a private temporary file; the installer receives `flag <file>`. */
  secretFile?: { flag: string; value: string }
  /** Console UI language (i18next code). An English UI adds `--lang en`, a Chinese one `--lang zh`; any other keeps the installer default. */
  language?: string
  /** Pinned management CA (self-signed console): `url` of the PEM and its SHA-256 (64 lowercase hex). */
  controlPlaneCA?: { url: string; sha256: string }
}

/**
 * ` --lang en` / ` --lang zh` for an English / Chinese console UI, '' otherwise (the installer's own default applies).
 * Chinese is explicit too: without a terminal the installer falls back to $LANG, which is C.UTF-8 on a stock Ubuntu.
 */
export function installerLanguageArgument(language?: string): string {
  const code = language?.toLowerCase() ?? ''
  if (code.startsWith('en')) return ' --lang en'
  return code.startsWith('zh') ? ' --lang zh' : ''
}

// Wrapper error lines (before the installer runs, so --lang cannot reach them) follow the console UI language too.
const wrapperErrors = {
  download: { zh: '无法下载安装脚本', en: 'cannot download the installer' },
  incomplete: { zh: '下载的安装脚本为空或不完整', en: 'the downloaded installer is empty or incomplete' },
  secretFile: { zh: '无法写入临时凭据文件', en: 'cannot write the temporary credential file' },
  controlPlaneCA: { zh: '无法下载主控根证书或其指纹不符', en: 'cannot download the management root CA or its fingerprint does not match' },
}

export function buildInstallerCommand(command: InstallerCommand): string {
  const english = installerLanguageArgument(command.language) === ' --lang en'
  const message = (key: keyof typeof wrapperErrors) => wrapperErrors[key][english ? 'en' : 'zh']
  const ca = command.controlPlaneCA
  if (ca && !/^[0-9a-f]{64}$/.test(ca.sha256)) throw new Error('invalid control-plane CA digest')
  const curl = `curl --proto ${quoteShellArgument(command.protocols)} --proto-redir '=https'`
  const downloads = command.urls
    .map((url) => {
      const plain = `${curl} -fsSL -o "$f" ${quoteShellArgument(url)}`
      return ca ? `${curl} --cacert "$a" -fsSL -o "$f" ${quoteShellArgument(url)} || ${plain}` : plain
    })
    .join(' || ')
  const error = (text: string) => quoteShellArgument(`${command.label} error: ${text}`)
  const cleanup = ['"$f"', ...(ca ? ['"$a"'] : []), ...(command.secretFile ? ['"$c"'] : [])].join(' ')
  const steps = [
    'f=$(mktemp) || exit 1',
    ...(ca ? ["a=''"] : []),
    ...(command.secretFile ? ["c=''"] : []),
    `trap 'rc=$?; rm -f ${cleanup}; exit $rc' EXIT`,
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
    ...(ca ? [`a=$(mktemp) && ${curl} -k -fsSL --max-filesize 65536 -o "$a" ${quoteShellArgument(ca.url)} && ` +
      `[ "$(sha256sum "$a" | cut -d ' ' -f 1)" = ${quoteShellArgument(ca.sha256)} ] || { echo ${error(message('controlPlaneCA'))} >&2; exit 1; }`] : []),
    `{ ${downloads}; } || { rc=$?; echo ${error(message('download'))} >&2; exit $rc; }`,
    `{ [ "$(head -c 2 "$f")" = '#!' ] && [ "$(tail -n 1 "$f")" = 'main "$@"' ]; } || { echo ${error(message('incomplete'))} >&2; exit 1; }`,
  ]
  const trust = ca ? ` --control-plane-ca-file "$a" --control-plane-ca-sha256 ${quoteShellArgument(ca.sha256)}` : ''
  let run = `bash "$f" ${command.args}${trust}${installerLanguageArgument(command.language)}`
  if (command.secretFile) {
    steps.push(`c=$(mktemp) && printf '%s\\n' ${quoteShellArgument(command.secretFile.value)} > "$c" || { echo ${error(message('secretFile'))} >&2; exit 1; }`)
    run = `${run} ${command.secretFile.flag} "$c"`
  }
  if (command.stdinSecret !== undefined) run = `printf '%s\\n' ${quoteShellArgument(command.stdinSecret)} | ${run}`
  return `(${[...steps, run].join('; ')})`
}
