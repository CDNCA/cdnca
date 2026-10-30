import type { ReactElement } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CdncaProvider } from '@cdnca/ui'
import { render } from '@testing-library/react'
import { MemoryRouter, type InitialEntry } from 'react-router-dom'

export function renderWithProviders(ui: ReactElement, initialEntries: InitialEntry[] = ['/']) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })

  return render(
    <CdncaProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={initialEntries}>{ui}</MemoryRouter>
      </QueryClientProvider>
    </CdncaProvider>,
  )
}
