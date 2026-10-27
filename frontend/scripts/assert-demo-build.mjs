const onVercel = process.env.VERCEL === '1'

if (!onVercel) {
  process.exit(0)
}

// Names SentinelForge may inline. VITE_API_URL is a lab setting and is not
// in this set. Anything else we did not list is refused.
const OWN_VITE = new Set(['VITE_DATA_MODE'])

// Vercel injects this one name so Vite can inline the observability client
// config. A VITE_VERCEL_* prefix is not an allowlist: a project can set
// another name with that prefix, and that value would ship in the public
// bundle. Add a system variable here only after checking it is Vercel's.
const VERCEL_SYSTEM_VITE = new Set([
  'VITE_VERCEL_OBSERVABILITY_CLIENT_CONFIG',
])

const mode = process.env.VITE_DATA_MODE
if (mode && mode !== 'demo') {
  console.error(
    'Refusing to build on Vercel. This site is demo-only. Leave VITE_DATA_MODE unset or set it to demo. A live-mode build could point the public site at a lab.',
  )
  process.exit(1)
}

const viteKeys = Object.keys(process.env).filter((key) =>
  key.startsWith('VITE_'),
)
const systemSeen = viteKeys
  .filter((key) => VERCEL_SYSTEM_VITE.has(key))
  .sort()
const blocked = viteKeys
  .filter((key) => !OWN_VITE.has(key) && !VERCEL_SYSTEM_VITE.has(key))
  .sort()

if (systemSeen.length > 0) {
  console.log(`Allowing Vercel system variables: ${systemSeen.join(', ')}`)
}

if (blocked.length > 0) {
  console.error(
    `Refusing to inline ${blocked.join(', ')} into the public bundle. On Vercel, VITE_DATA_MODE may be unset or demo. VITE_API_URL and any other VITE_ variable we did not define are refused.`,
  )
  process.exit(1)
}
