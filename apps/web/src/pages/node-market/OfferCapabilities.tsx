import { Form, InputNumber, Space, Switch, Tag } from 'antd'
import { useTranslation } from 'react-i18next'

import type { MarketOfferListing } from '../../api/market'

// an offer's capabilities (spec.Allocation). The form
// edits HTTP(S) / L4 port counts and HTTP/3; WebSocket is required for every
// node listing, shown as included and never a switch. Used by 新建报价 (own,
// resale with the upstream's bounds, combo) and by 修改报价. 支持 L2 回源
// is a switch only in 修改报价 (l2): the market accepts it once every node
// behind the offer reports the seller's L2, which needs a listed supply.

const maxPorts = 65_535

export function CapabilityFields({ maxHttp, maxStream, http3Allowed = true, l2 }: { maxHttp?: number; maxStream?: number; http3Allowed?: boolean;
  l2?: { help: string } }) {
  const { t } = useTranslation('nodeMarket')
  return (
    <Space wrap align="start" size={16}>
      <Form.Item name="httpPorts" label={t('caps.httpPorts')} extra={t('caps.httpPortsHelp')} style={{ maxWidth: 280 }}>
        <InputNumber min={0} max={maxHttp ?? maxPorts} precision={0} aria-label={t('caps.httpPorts')} /></Form.Item>
      <Form.Item name="streamPorts" label={t('caps.streamPorts')}>
        <InputNumber min={0} max={maxStream ?? maxPorts} precision={0} aria-label={t('caps.streamPorts')} /></Form.Item>
      <Form.Item label={t('caps.websocket')}>
        <Tag color="blue" bordered={false} data-testid="caps-websocket">{t('caps.includedFixed')}</Tag></Form.Item>
      <Form.Item name="http3" label={t('caps.http3')} valuePropName="checked">
        <Switch disabled={!http3Allowed} aria-label={t('caps.http3')} /></Form.Item>
      {l2 ? <Form.Item name="l2" label={t('caps.l2')} valuePropName="checked" extra={l2.help} style={{ maxWidth: 360 }}>
        <Switch aria-label={t('caps.l2')} /></Form.Item> : null}
    </Space>
  )
}

// capabilityRows: the same items, read only (buyer detail, seller views);
// l2Unavailable: the offer declares L2 its supply no longer has.
export function capabilityRows(t: (key: string, options?: Record<string, unknown>) => string, a: MarketOfferListing['allocation'],
  l2Unavailable = false) {
  return [
    { key: 'httpPorts', label: t('caps.httpPorts'), value: t('caps.portsCount', { count: a.http_ports ?? 0 }) },
    { key: 'streamPorts', label: t('caps.streamPorts'), value: t('caps.portsCount', { count: a.stream_ports ?? 0 }) },
    { key: 'websocket', label: t('caps.websocket'), value: t('caps.included') },
    { key: 'http3', label: t('caps.http3'), value: a.http3 ? t('caps.supported') : t('caps.unsupported') },
    { key: 'l2', label: t('caps.l2'), value: !a.l2 ? t('caps.unsupported') : l2Unavailable ? t('caps.l2Unavailable') : t('caps.supported') },
  ]
}
