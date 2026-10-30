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
}

export function buildInstallerCommand(command: InstallerCommand): string {
  const downloads = command.urls
    .map((url) => `curl --proto ${quoteShellArgument(command.protocols)} --proto-redir '=https' -fsSL -o "$f" ${quoteShellArgument(url)}`)
    .join(' || ')
  const error = (text: string) => quoteShellArgument(`${command.label} error: ${text}`)
  const cleanup = command.secretFile ? '"$f" "$c"' : '"$f"'
  const steps = [
    'f=$(mktemp) || exit 1',
    ...(command.secretFile ? ["c=''"] : []),
    `trap 'rc=$?; rm -f ${cleanup}; exit $rc' EXIT`,
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
    `{ ${downloads}; } || { rc=$?; echo ${error('无法下载安装脚本')} >&2; exit $rc; }`,
    `{ [ "$(head -c 2 "$f")" = '#!' ] && [ "$(tail -n 1 "$f")" = 'main "$@"' ]; } || { echo ${error('下载的安装脚本为空或不完整')} >&2; exit 1; }`,
  ]
  let run = `bash "$f" ${command.args}`
  if (command.secretFile) {
    steps.push(`c=$(mktemp) && printf '%s\\n' ${quoteShellArgument(command.secretFile.value)} > "$c" || { echo ${error('无法写入临时凭据文件')} >&2; exit 1; }`)
    run = `${run} ${command.secretFile.flag} "$c"`
  }
  if (command.stdinSecret !== undefined) run = `printf '%s\\n' ${quoteShellArgument(command.stdinSecret)} | ${run}`
  return `(${[...steps, run].join('; ')})`
}
