import type { InboxMessage } from '../api/announcements'

export function AnnouncementBody({ item }: { item: Pick<InboxMessage, 'title' | 'body' | 'format' | 'link_url'> }) {
  if (item.format === 'link') {
    return /^https?:\/\//i.test(item.link_url ?? '')
      ? <a href={item.link_url} target="_blank" rel="noopener noreferrer">{item.link_url}</a>
      : null
  }
  if (!/<[a-z][\s\S]*>/i.test(item.body)) return <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{item.body}</div>
  return <iframe title={item.title} sandbox="" referrerPolicy="no-referrer" style={{ width: '100%', height: 360, border: 0 }} srcDoc={`<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'"><style>body{font:14px/1.6 system-ui;margin:0;overflow-wrap:anywhere}img,table{max-width:100%}</style></head><body>${item.body}</body></html>`} />
}
