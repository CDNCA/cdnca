import { render, screen, within } from '@testing-library/react'
import { App } from '../App'
import { PLUGIN_CLI_DOWNLOADS, PLUGIN_CLI_FILES, PLUGIN_SIGNING_PATH } from '../content/pluginSigning'
import { urls } from '../entry-server'

describe('插件签名文档页', () => {
  it('中英文都预渲染，开发者平台页链过来', () => {
    expect(urls()).toEqual(expect.arrayContaining([PLUGIN_SIGNING_PATH, `/en${PLUGIN_SIGNING_PATH}`]))
    render(<App pathname="/developers" />)
    expect(screen.getByRole('link', { name: '插件签名工具' })).toHaveAttribute('href', PLUGIN_SIGNING_PATH)
  })

  it('列出四个平台的下载、SHA256SUMS 与校验命令', () => {
    render(<App pathname={PLUGIN_SIGNING_PATH} />)
    expect(screen.getByRole('heading', { level: 1, name: '插件签名：cdnca-plugin' })).toBeInTheDocument()
    const table = screen.getByRole('table')
    for (const f of PLUGIN_CLI_FILES) {
      expect(within(table).getByRole('link', { name: f.file })).toHaveAttribute('href', `${PLUGIN_CLI_DOWNLOADS}/${f.file}`)
    }
    expect(screen.getByRole('link', { name: /SHA256SUMS/ })).toHaveAttribute('href', `${PLUGIN_CLI_DOWNLOADS}/SHA256SUMS`)
    expect(screen.getByLabelText('Linux 下载与校验')).toHaveTextContent('sha256sum -c --ignore-missing SHA256SUMS')
    expect(screen.getByText('./cdnca-plugin sign-manifest -key publisher.key -in manifest.json -out manifest.signed.json')).toBeInTheDocument()
  })

  it('英文页', () => {
    render(<App pathname={`/en${PLUGIN_SIGNING_PATH}`} />)
    expect(screen.getByRole('heading', { level: 1, name: 'Plugin signing: cdnca-plugin' })).toBeInTheDocument()
    expect(screen.getByLabelText('Windows download and verify')).toHaveTextContent('Get-FileHash')
  })
})
