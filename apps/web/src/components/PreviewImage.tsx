import { Image, type ImageProps } from 'antd'
import { icons } from 'antd/es/image/PreviewGroup'
import { cloneElement, isValidElement, type ReactElement, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

// antd 大图预览的工具栏是只有图标的 div（读作 swap、rotate-left、zoom-in…，不能用键盘操作），
// 关闭按钮读作 close，对话框也没有名称；ConfigProvider 的 image 配置只接受 closeIcon。全站大图预览统一从这里取：
// 工具栏换成带本地化名称的按钮（类名、禁用态与点击动作沿用 antd 原节点），关闭按钮带名称，对话框以 previewTitle（默认 alt）命名。
type Operation = 'flipY' | 'flipX' | 'rotateLeft' | 'rotateRight' | 'zoomOut' | 'zoomIn'
const operations: { key: Operation; icon: 'flipYIcon' | 'flipXIcon' | 'rotateLeftIcon' | 'rotateRightIcon' | 'zoomOutIcon' | 'zoomInIcon' }[] = [
  { key: 'flipY', icon: 'flipYIcon' }, { key: 'flipX', icon: 'flipXIcon' },
  { key: 'rotateLeft', icon: 'rotateLeftIcon' }, { key: 'rotateRight', icon: 'rotateRightIcon' },
  { key: 'zoomOut', icon: 'zoomOutIcon' }, { key: 'zoomIn', icon: 'zoomInIcon' },
]

type OperationNode = ReactElement<{ className?: string; onClick?: () => void; children?: ReactNode }>

export type PreviewImageProps = ImageProps & {
  /** 预览对话框的名称；默认取 alt。 */
  previewTitle?: string
}

export function PreviewImage({ preview, previewTitle, ...props }: PreviewImageProps) {
  const { t } = useTranslation()
  if (preview === false) return <Image {...props} preview={false} />
  const own = typeof preview === 'object' ? preview : {}
  const title = previewTitle ?? props.alt
  return (
    <Image {...props} preview={{
      closeIcon: cloneElement(icons.close, { 'aria-label': t('imagePreview.close') }),
      ...(title ? { title: <span className="visually-hidden">{title}</span> } : {}),
      toolbarRender: (original, info) => (
        <div className={isValidElement<{ className?: string }>(original) ? original.props.className : undefined}>
          {operations.map(({ key, icon }) => {
            const node = info.icons[icon] as OperationNode
            const disabled = /-operations-operation-disabled\b/.test(node.props.className ?? '')
            return (
              <button key={key} type="button" className={`${node.props.className ?? ''} preview-image-operation`} aria-label={t(`imagePreview.${key}`)}
                disabled={disabled} onClick={node.props.onClick}>
                {isValidElement(node.props.children) ? cloneElement(node.props.children as ReactElement<{ 'aria-hidden'?: boolean }>, { 'aria-hidden': true }) : node.props.children}
              </button>
            )
          })}
        </div>
      ),
      ...own,
    }} />
  )
}
