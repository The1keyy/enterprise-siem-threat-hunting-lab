// Walks the production demo preview. Run after `vite preview` is listening.
import { readFileSync } from 'node:fs'
import { chromium } from 'playwright'

const base = process.env.SMOKE_BASE ?? 'http://127.0.0.1:4173'
const incidents = JSON.parse(
  readFileSync(new URL('../../fixtures/incidents.json', import.meta.url), 'utf8'),
)
const story = incidents.incidents.find((item) => item.risk.final === 230)
if (!story || story.severity !== 'critical') {
  throw new Error('The attack-story incident must be 230 and critical')
}

const pages = [
  '/',
  '/incidents',
  `/incidents/${story.id}`,
  '/hunting',
  '/entities',
  '/entities/users/sf-test-alice',
  '/entities/hosts/DC01',
  '/detections',
  '/detections/SF-002',
  '/mitre',
  '/automation',
  '/sources',
  '/health',
  '/settings',
  '/about',
  '/tour',
]

const errors = []
const browser = await chromium.launch()

function watch(page) {
  page.on('pageerror', (error) => {
    errors.push(`pageerror ${page.url()} ${error.message}`)
  })
  page.on('console', (message) => {
    if (message.type() === 'error') {
      errors.push(`console ${page.url()} ${message.text()}`)
    }
  })
}

const page = await browser.newPage()
watch(page)

for (const path of pages) {
  const response = await page.goto(`${base}${path}`, { waitUntil: 'networkidle' })
  if (!response || response.status() >= 400) {
    errors.push(`status ${response?.status() ?? 'none'} ${path}`)
  }
  const heading = page.getByRole('heading', { level: 1 })
  if ((await heading.count()) === 0) {
    errors.push(`missing heading ${path}`)
  }
}

await page.goto(`${base}/tour`, { waitUntil: 'networkidle' })
await page.getByRole('button', { name: 'Start' }).click()
await page.waitForURL(`${base}/`)
const seen = [page.url()]
for (let index = 0; index < 5; index += 1) {
  await page.getByRole('button', { name: 'Next' }).click()
  await page.waitForTimeout(200)
  seen.push(page.url())
}
if (!seen.some((url) => url.includes(story.id))) {
  errors.push(`tour missed ${story.id}: ${seen.join(' ')}`)
}
if (!page.url().includes('/mitre')) {
  errors.push(`tour ended at ${page.url()}`)
}
await page.getByRole('button', { name: 'Done' }).click()

const deep = await browser.newPage()
watch(deep)
await deep.goto(`${base}/incidents/${story.id}`, { waitUntil: 'networkidle' })
await deep.getByText('Risk 230').waitFor()
await deep.reload({ waitUntil: 'networkidle' })
await deep.getByText('Risk 230').waitFor()
await deep.getByText(/spray confirmed/).first().waitFor()
await deep.getByText('Why these alerts are grouped').waitFor()

await browser.close()

if (errors.length > 0) {
  console.error(errors.join('\n'))
  process.exit(1)
}
console.log(`smoke ok ${pages.length} pages, tour, deep link ${story.id} score 230`)
