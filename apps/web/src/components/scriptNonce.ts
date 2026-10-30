// The container's nginx sends `script-src 'nonce-…' 'strict-dynamic'` and
// stamps the same per-request nonce on index.html's <script> tags. Every script
// element the SPA inserts (global JS, CAPTCHA SDKs) carries it, so inline code
// runs without 'unsafe-inline'. Browsers hide the nonce attribute after load;
// the `nonce` property keeps it. Without nginx (dev server, native install) it
// is empty and nothing is set.
export function pageScriptNonce(root: Document = document): string {
  for (const script of Array.from(root.querySelectorAll('script'))) {
    const nonce = script.nonce || script.getAttribute('nonce') || ''
    if (nonce) return nonce
  }
  return ''
}

export function applyScriptNonce(script: HTMLScriptElement, root: Document = document): HTMLScriptElement {
  const nonce = pageScriptNonce(root)
  if (nonce) script.nonce = nonce
  return script
}
