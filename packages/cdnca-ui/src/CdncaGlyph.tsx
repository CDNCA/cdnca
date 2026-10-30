// The cdnca brand glyph: an open "c" with a node dot, white, drawn on the
// .cdnca-brand-mark gradient tile. Same drawing as assets/brand/cdnca/mark.svg
// (64 grid; the tile itself comes from CSS). Decorative: the brand name is
// always written next to it or given by the caller's aria-label.
export function CdncaGlyph({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="11 11 42 42" aria-hidden="true" focusable="false">
      <path d="M42.9 21.1A15.4 15.4 0 1 0 42.9 42.9" fill="none" stroke="currentColor" strokeWidth="7.7" strokeLinecap="round" />
      <circle cx="47.4" cy="32" r="5.3" fill="currentColor" />
    </svg>
  )
}
