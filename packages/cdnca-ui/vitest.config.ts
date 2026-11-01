import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'jsdom', globals: true, setupFiles: './src/test-setup.ts', testTimeout: 30_000,
    // vitest loads antd as CJS (antd/lib); send app.tsx's antd/es deep imports to the same copy so AppContext is shared.
    alias: [{ find: /^antd\/es\//, replacement: 'antd/lib/' }],
  },
})
