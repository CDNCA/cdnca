import { describe, expect, it } from 'vitest'

import { areaOptions, areaPath, geoLabel, regionInArea } from './regionGeo'

type Group = { label: string; options: { value: string; label: string }[] }

describe('regionGeo areas (geoarea v2: global, continents, regions)', () => {
  it('offers global, then each continent as a group with the whole continent first and its regions', () => {
    const options = areaOptions('zh-CN')
    expect(options[0]).toEqual({ value: 'global', label: '全球' })
    const groups = options.slice(1) as Group[]
    expect(groups.map((group) => group.label)).toEqual(['亚洲', '欧洲', '非洲', '北美洲', '南美洲', '大洋洲'])
    expect(groups[0].options.map((option) => option.value)).toEqual(['asia', 'east_asia', 'southeast_asia', 'south_asia', 'west_asia', 'central_asia'])
    expect(groups[0].options[0].label).toBe('亚洲（全部）')
    expect(groups[4].options).toEqual([{ value: 'south_america', label: '南美洲（全部）' }])
    const en = areaOptions('en-US').slice(1) as Group[]
    expect(en[1].label).toBe('Europe')
    expect(en[1].options[0]).toEqual({ value: 'europe', label: 'All of Europe' })
    expect(en[1].options[1]).toEqual({ value: 'northern_europe', label: 'Northern Europe' })
  })

  it('maps option values through a prefix (node list filter)', () => {
    const groups = areaOptions('zh-CN', 'area:').slice(1) as Group[]
    expect(areaOptions('zh-CN', 'area:')[0]).toEqual({ value: 'area:global', label: '全球' })
    expect(groups[0].options[1].value).toBe('area:east_asia')
  })

  it('labels areas as 大洲 / 区域 and a country region by the country', () => {
    expect(areaPath('southeast_asia', 'zh-CN')).toBe('亚洲 / 东南亚')
    expect(areaPath('asia', 'zh-CN')).toBe('亚洲')
    expect(areaPath('global', 'en-US')).toBe('Global')
    expect(areaPath('caribbean', 'en-US')).toBe('North America / Caribbean')
    expect(areaPath('mars', 'zh-CN')).toBe('')
    expect(geoLabel('southeast_asia', '', '', 'zh-CN')).toBe('亚洲 / 东南亚')
    expect(geoLabel('europe', '', '', 'zh-CN')).toBe('欧洲')
    expect(geoLabel('', 'CN', '440000', 'zh-CN')).toBe('中国 / 广东')
    expect(geoLabel('', '', '', 'zh-CN')).toBe('')
  })

  it('places a region in an area by its own area (a continent holds its regions) or its country', () => {
    expect(regionInArea('southeast_asia', { area_code: 'southeast_asia', country_code: '' })).toBe(true)
    expect(regionInArea('southeast_asia', { area_code: '', country_code: 'SG' })).toBe(true)
    expect(regionInArea('southeast_asia', { area_code: '', country_code: 'JP' })).toBe(false)
    expect(regionInArea('east_asia', { area_code: 'southeast_asia', country_code: '' })).toBe(false)
    expect(regionInArea('asia', { area_code: 'southeast_asia', country_code: '' })).toBe(true)
    expect(regionInArea('asia', { area_code: '', country_code: 'IN' })).toBe(true)
    expect(regionInArea('east_asia', { area_code: 'asia', country_code: '' })).toBe(false)
    expect(regionInArea('europe', { area_code: '', country_code: 'RU' })).toBe(true)
    expect(regionInArea('oceania', { area_code: '', country_code: 'AU' })).toBe(true)
    expect(regionInArea('global', { area_code: 'europe', country_code: '' })).toBe(true)
    expect(regionInArea('global', { area_code: '', country_code: 'AU' })).toBe(true)
    expect(regionInArea('global', { area_code: '', country_code: '' })).toBe(false)
  })
})
