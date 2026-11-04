import { useApp } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'
import '../i18n/unconfirmedClose'

// 结果未确认（*_result_unknown）时离开弹窗：先确认，确认后由调用方关闭并刷新该页数据。
// 请求进行中时由调用方禁用关闭，这里不处理。
export function useConfirmUnconfirmedClose() {
  const { modal } = useApp()
  const { t } = useTranslation('unconfirmedClose')
  return (onConfirm: () => void) => {
    modal.confirm({ title: t('title'), content: t('content'), okText: t('close'), cancelText: t('cancel'), onOk: onConfirm })
  }
}
