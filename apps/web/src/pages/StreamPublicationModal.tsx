import { Button, Descriptions, Modal } from 'antd'
import { useTranslation } from 'react-i18next'
import type { Stream } from '../api/streams'

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
      </Descriptions> : null}
    </Modal>
  )
}
