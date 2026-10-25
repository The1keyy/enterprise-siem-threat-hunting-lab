/**
 * One-time export of the frontend demo fixtures into /fixtures.
 * Run from the repo root:
 *   node scripts/validation/export_fixtures.mjs
 * The frontend must still be able to load its fixture modules (Vite SSR).
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const repo = path.resolve(import.meta.dirname, '../..')
const frontend = path.join(repo, 'frontend')
const outDir = path.join(repo, 'fixtures')
const NOTICE = 'DEMO DATA — synthetic, not real telemetry'

const viteEntry = pathToFileURL(
  path.join(frontend, 'node_modules/vite/dist/node/index.js'),
).href
const { createServer } = await import(viteEntry)

const server = await createServer({
  root: frontend,
  configFile: path.join(frontend, 'vite.config.ts'),
  server: { middlewareMode: true },
  appType: 'custom',
  logLevel: 'error',
})

try {
  const incidentsMod = await server.ssrLoadModule('/src/fixtures/incidents.ts')
  const overviewMod = await server.ssrLoadModule('/src/fixtures/overview.ts')
  const detectionsMod = await server.ssrLoadModule('/src/fixtures/detections.ts')
  const huntsMod = await server.ssrLoadModule('/src/fixtures/hunts.ts')
  const entityMod = await server.ssrLoadModule('/src/lib/entityModel.ts')
  const opsMod = await server.ssrLoadModule('/src/lib/operationsModel.ts')

  const incidents = incidentsMod.incidentFixtures
  const detections = detectionsMod.detectionFixtures
  const users = entityMod
    .listUsers(incidents)
    .map((row) => entityMod.buildUser(incidents, row.name))
    .filter(Boolean)
  const hosts = entityMod
    .listHosts(incidents)
    .map((row) => entityMod.buildHost(incidents, row.name))
    .filter(Boolean)
  const enabled = detections.filter((item) => item.enabled).length

  mkdirSync(outDir, { recursive: true })

  const files = {
    'overview.json': { _notice: NOTICE, ...overviewMod.overviewFixture },
    'incidents.json': { _notice: NOTICE, incidents },
    'detections.json': { _notice: NOTICE, detections },
    'hunts.json': { _notice: NOTICE, hunts: huntsMod.huntFixtures },
    'entities.json': {
      _notice: NOTICE,
      users: entityMod.listUsers(incidents),
      hosts: entityMod.listHosts(incidents),
      userProfiles: users,
      hostProfiles: hosts,
    },
    'sources.json': {
      _notice: NOTICE,
      sources: opsMod.buildSources(incidents),
    },
    'health.json': {
      _notice: NOTICE,
      ...opsMod.buildHealth(enabled),
    },
  }

  for (const [name, body] of Object.entries(files)) {
    writeFileSync(
      path.join(outDir, name),
      `${JSON.stringify(body, null, 2)}\n`,
    )
    process.stdout.write(`wrote fixtures/${name}\n`)
  }
} finally {
  await server.close()
}
