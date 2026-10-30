import { useSiteContent } from '../content/siteContent'

// cdnca 标志：渐变圆角方块里开口的 "c" 与节点点（assets/brand/cdnca/mark.svg）。装饰性，名称由旁边的文字给出。

export function Logo({ size = 28 }: { size?: number }) {
  // 运营在授权端「官网内容 · 品牌」上传了 logo（PNG/WebP，同源资源）时用它，否则用下面的默认 SVG。
  const { brand } = useSiteContent()
  if (brand.logo) return <img className="brand-logo" src={brand.logo} width={size} height={size} alt="" />
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="www-brand-mark" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#3b82f6" />
          <stop offset="1" stopColor="#1d4ed8" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="16" fill="url(#www-brand-mark)" />
      <path d="M42.9 21.1A15.4 15.4 0 1 0 42.9 42.9" fill="none" stroke="#fff" strokeWidth="7.7" strokeLinecap="round" />
      <circle cx="47.4" cy="32" r="5.3" fill="#fff" />
    </svg>
  )
}
