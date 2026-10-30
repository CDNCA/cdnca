import { widgetsApi } from '../api/widgets'

export default function WidgetsPage() {
  void widgetsApi.list('t')
  void widgetsApi.create('t', {})
  void widgetsApi.missing('t')
  void widgetsApi.bans('t', true)
  return null
}
