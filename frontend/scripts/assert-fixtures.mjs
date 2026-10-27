import { access } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const frontendDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const repoFixtures = path.resolve(frontendDir, '../fixtures')
const required = [
  'overview.json',
  'incidents.json',
  'detections.json',
  'hunts.json',
]

const missing = []
for (const name of required) {
  try {
    await access(path.join(repoFixtures, name))
  } catch {
    missing.push(name)
  }
}

if (missing.length === 0) {
  process.exit(0)
}

console.error(
  `Missing fixture files next to the frontend: ${missing.join(', ')}`,
)
console.error(
  'The console imports ../fixtures. On Vercel that directory is outside the frontend root.',
)
console.error(
  'Project Settings → Build and Deployment → Root Directory → Edit → turn on "Include source files outside of the Root Directory in the Build Step".',
)
process.exit(1)
