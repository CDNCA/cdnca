import { Button, Descriptions, Modal } from 'antd'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import i18n from '../i18n'
import type { Stream, StreamPublishIntent } from '../api/streams'

// A3-04：已知失败码给中文/英文说明，未知的原样显示失败码。
export function streamPublicationFailure(intent: StreamPublishIntent, t: TFunction<'streams'>): string {
  const code = intent.failure_code
  if (!code) return t('publication.failureUnrecorded')
  const key = `publication.failures.${code}`
  return i18n.exists(key, { ns: 'streams' }) ? t(key as 'publication.result') : code
}

// 转发的发布详情（发布意图、目标运行时修订、发布/灰度 ID 与结果）；列表与详情页共用。
export default function StreamPublicationModal({ item, onClose }: { item: Stream | null; onClose: () => void }) {
  const { t } = useTranslation('streams')
  const intent = item?.publish_intent
  const runtime = intent?.runtime_spec
  return (
    <Modal
      className="identity-modal stream-publication-modal"
      title={t('publication.title')}
      open={Boolean(item)}
      width={660}
      footer={<Button onClick={onClose}>{t('actions.close')}</Button>}
      onCancel={onClose}
      destroyOnHidden
    >
      {intent && runtime ? <Descriptions bordered size="small" column={1}>
        <Descriptions.Item label={t('publication.intentId')}><code>{intent.id}</code></Descriptions.Item>
        <Descriptions.Item label={t('publication.intentVersion')}>{intent.version}</Descriptions.Item>
        <Descriptions.Item label={t('publication.sourceRevision')}>{intent.configuration_source_revision}</Descriptions.Item>
        <Descriptions.Item label={t('publication.streamId')}><code>{runtime.stream_id}</code></Descriptions.Item>
        <Descriptions.Item label={t('publication.runtimeRevision')}>{runtime.revision}</Descriptions.Item>
        <Descriptions.Item label={t('publication.publicationId')}>{intent.publication_id ?? t('values.placeholder')}</Descriptions.Item>
        <Descriptions.Item label={t('publication.rolloutId')}>{intent.rollout_id ?? t('values.placeholder')}</Descriptions.Item>
        <Descriptions.Item label={t('publication.result')}>{t(`publication.states.${intent.state}`)}</Descriptions.Item>
        {intent.state === 'failed' ? <Descriptions.Item label={t('publication.failureReason')}>
          <span className="stream-publication-failure">{streamPublicationFailure(intent, t)}</span>
          {intent.failure_code ? <> <code>{intent.failure_code}</code></> : null}
        </Descriptions.Item> : null}
      </Descriptions> : null}
    </Modal>
  )
}
