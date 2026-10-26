import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    // Vitest 5 defaults to pool "forks" and maxWorkers = CPU count - 1.
    // Each worker boots Node, Vite, and jsdom. This suite is 8 files, so
    // the default started almost one worker per file. Under load a worker
    // missed the hardcoded 60s start handshake
    // ("Timeout waiting for worker to respond"), and the file was reported
    // as an unhandled pool error. Two workers is enough for this suite.
    pool: 'forks',
    maxWorkers: 2,
    testTimeout: 10_000,
    hookTimeout: 10_000,
  },
})
