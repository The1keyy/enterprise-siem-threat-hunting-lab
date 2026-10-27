const onVercel = process.env.VERCEL === '1'

if (!onVercel) {
  process.exit(0)
}

const mode = process.env.VITE_DATA_MODE
if (mode !== 'demo') {
  console.error(
    'Refusing to build on Vercel. This site is demo-only. Set VITE_DATA_MODE=demo. A live-mode build could point the public site at a lab.',
  )
  process.exit(1)
}

const extras = Object.keys(process.env).filter(
  (key) => key.startsWith('VITE_') && key !== 'VITE_DATA_MODE',
)
if (extras.length > 0) {
  console.error(
    `Refusing to inline ${extras.join(', ')} into the public bundle. On Vercel, the only allowed frontend env var is VITE_DATA_MODE=demo.`,
  )
  process.exit(1)
}
