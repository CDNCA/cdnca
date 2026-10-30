// Visual baseline tests assert the default look. Stylesheets wrap their
// default colors in var(--cdnca-*, <default>) so a theme can recolor them;
// this expands each wrapper back to its default (the lock test
// DefaultLookLock.test.ts proves the fallback is the default) so the
// baselines keep comparing literal values (translucent ones in the
// rgb(r g b / N%) spelling).
const wrapped = /var\(--cdnca-[a-z0-9-]+,\s*((?:[^()]|\([^()]*\))+)\)/g

export function defaultLookCSS(css: string): string {
  let previous: string
  let current = css
  do {
    previous = current
    current = current.replace(wrapped, (_, fallback: string) => fallback.trim())
  } while (current !== previous)
  // Translucent colors derived from a token: color-mix(in srgb, #rrggbb N%,
  // transparent) computes to rgb(r g b / N%).
  return current.replace(/color-mix\(in srgb,\s*#([0-9a-fA-F]{6})\s+([\d.]+)%,\s*transparent\)/g, (_, hex: string, percent: string) =>
    `rgb(${[0, 2, 4].map((at) => parseInt(hex.slice(at, at + 2), 16)).join(' ')} / ${percent}%)`)
}
