// Registers only the ECharts features the console renders; import this module
// lazily instead of the full `echarts` bundle. A missing registration renders
// nothing silently, so extend echartsRuntime.test.ts with any new feature.
// 改名导入：ECharts 的 use() 与 React 19 的 use hook 同名，react-hooks/rules-of-hooks 会误报。
import { graphic, init, use as registerEChartsFeatures } from 'echarts/core'
import { BarChart, LineChart } from 'echarts/charts'
import { GraphicComponent, GridComponent, LegendComponent, TitleComponent, TooltipComponent } from 'echarts/components'
import { LegacyGridContainLabel } from 'echarts/features'
import { CanvasRenderer } from 'echarts/renderers'

registerEChartsFeatures([
  LineChart, BarChart, GridComponent, TooltipComponent, LegendComponent, TitleComponent, GraphicComponent,
  // `grid.containLabel` needs this in ECharts 6; the full bundle registered it implicitly.
  LegacyGridContainLabel, CanvasRenderer,
])

export { graphic, init }
export type { ECharts } from 'echarts/core'
