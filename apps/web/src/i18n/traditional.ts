type TranslationValue = string | TranslationValue[] | { [key: string]: TranslationValue } | number | boolean | null

type TraditionalConverter = (value: string) => string

let converterPromise: Promise<TraditionalConverter> | undefined

async function getTraditionalConverter(): Promise<TraditionalConverter> {
  converterPromise ??= import('opencc-js/cn2t').then(({ default: OpenCC }) => OpenCC.Converter({ from: 'cn', to: 'tw' }))
  return converterPromise
}

function convertTree(value: TranslationValue, converter: TraditionalConverter): TranslationValue {
  if (typeof value === 'string') return converter(value)
  if (Array.isArray(value)) return value.map((item) => convertTree(item, converter))
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, convertTree(child, converter)]),
    )
  }
  return value
}

export async function traditionalize<T>(value: T): Promise<T> {
  const converter = await getTraditionalConverter()
  return convertTree(value as TranslationValue, converter) as T
}
