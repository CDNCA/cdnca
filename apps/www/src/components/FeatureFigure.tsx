import type { Lang } from '../i18n'
import type { FigureKey } from '../content/features'
import { Cloud, Network, Puzzle, Radar, Route, Shield } from 'lucide-react'
import { FigAggregated, FigArchitecture, FigDefenseLoop, FigFlow, FigPluginCard, FigResale } from './Figures'

export function FeatureFigure({ k, lang }: { k: FigureKey; lang: Lang }) {
  switch (k) {
    case 'A': return <FigArchitecture lang={lang} />
    case 'B': return <FigResale lang={lang} />
    case 'C': return <FigDefenseLoop lang={lang} />
    case 'F': return <FigAggregated lang={lang} />
    case 'G': return <FigPluginCard lang={lang} />
    default: return <FigFlow k={k} lang={lang} />
  }
}

const ICONS = { network: Network, route: Route, shield: Shield, radar: Radar, cloud: Cloud, puzzle: Puzzle }

export function FeatureIcon({ name }: { name: keyof typeof ICONS }) {
  const I = ICONS[name]
  return <span className="card-icon"><I aria-hidden="true" size={26} /></span>
}
