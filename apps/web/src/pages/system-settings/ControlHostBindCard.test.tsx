import { fireEvent, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'

import i18n from '../../i18n'
import { controlHostBindMessages } from '../../i18n/controlHostBind'
import { renderWithProviders } from '../../test/render'
import ControlHostBindCard, { bindCommand, isBindableDomain } from './ControlHostBindCard'

const ipLocation = { hostname: '203.0.113.10', origin: 'https://203.0.113.10' }

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

describe('ControlHostBindCard (ctl-bind-domain)', () => {
  it('shows an IP console with its private certificate and builds the bind command for a typed domain', () => {
    renderWithProviders(<ControlHostBindCard location={ipLocation} runtime={{ __CDNCA_CONTROL_CA_SHA256__: 'a'.repeat(64), __CDNCA_GATEWAY_SERVER_NAME__: '203.0.113.10' }} />)
    expect(screen.getByTestId('control-host-address').textContent).toBe('https://203.0.113.10')
    expect(screen.getByText(controlHostBindMessages['zh-CN'].certificatePrivate)).toBeTruthy()
    expect(screen.getByText(controlHostBindMessages['zh-CN'].ipNotice)).toBeTruthy()
    const input = screen.getByLabelText(controlHostBindMessages['zh-CN'].domainLabel)
    fireEvent.change(input, { target: { value: '203.0.113.10' } })
    expect(screen.getByText(controlHostBindMessages['zh-CN'].domainInvalid)).toBeTruthy()
    fireEvent.change(input, { target: { value: 'Console.Example.com.' } })
    expect(screen.queryByText(controlHostBindMessages['zh-CN'].domainInvalid)).toBeNull()
    expect(screen.getByTestId('control-host-bind-command').textContent).toContain(
      'sudo /data/cdnca-native-root/cdnca/current/bin/control-api control-host bind --domain console.example.com')
    expect(screen.getByTestId('control-host-bind-command-cert').textContent).toContain('--cert-file /path/fullchain.pem --key-file /path/privkey.pem')
    for (const item of controlHostBindMessages['zh-CN'].requirements) expect(screen.getByText(item)).toBeTruthy()
  })

  it('prefills the domain the console is already reached by and reports a public certificate', () => {
    renderWithProviders(<ControlHostBindCard location={{ hostname: 'console.example.com', origin: 'https://console.example.com' }} runtime={{ __CDNCA_CONTROL_CA_SHA256__: '' }} />)
    expect(screen.getByText(controlHostBindMessages['zh-CN'].certificatePublic)).toBeTruthy()
    expect(screen.queryByText(controlHostBindMessages['zh-CN'].ipNotice)).toBeNull()
    expect(screen.getByTestId('control-host-bind-command').textContent).toContain('--domain console.example.com')
  })

  it('renders English text in the English console', async () => {
    await i18n.changeLanguage('en-US')
    renderWithProviders(<ControlHostBindCard location={ipLocation} runtime={{}} />)
    expect(screen.getByText(controlHostBindMessages['en-US'].title)).toBeTruthy()
  })

  it('accepts only DNS names', () => {
    expect(isBindableDomain('console.example.com')).toBe(true)
    for (const value of ['203.0.113.10', '*.example.com', 'localhost', 'a b.com', 'example.com;rm']) expect(isBindableDomain(value)).toBe(false)
    expect(bindCommand('console.example.com')).toBe('sudo /data/cdnca-native-root/cdnca/current/bin/control-api control-host bind --domain console.example.com')
  })
})
