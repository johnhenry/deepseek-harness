/**
 * End-to-end smoke test against a REAL local Ollama.
 *
 * Not a unit test and deliberately not mocked: the whole risk in this adapter
 * is whether it speaks Ollama's actual NDJSON dialect, so a fake server would
 * test the fake. Skips cleanly when no daemon is listening.
 */

import { OllamaAdapter } from '../src/adapter.ts'

const BASE_URL = process.env.OLLAMA_BASE_URL ?? 'http://127.0.0.1:11434'

const adapter = new OllamaAdapter({
  options: () => ({ baseURL: BASE_URL, requestTimeoutMs: 120_000 }),
})

async function main(): Promise<void> {
  const models = await adapter.listModels('ollama')
  if (models.length === 0) {
    console.log('SKIP: no ollama daemon or no models at', BASE_URL)
    process.exit(0)
  }
  console.log(`listModels: ${models.length} model(s)`)
  for (const m of models) console.log(`  - ${m.id}  (${m.name})  provider=${m.provider}`)

  const model = models[0]!.id
  const resolved = await adapter.resolveModel('ollama', model)
  console.log(`resolveModel(${model}): context=${JSON.stringify(resolved.context ?? null)}`)

  console.log(`stream(${model}):`)
  const chunks: string[] = []
  let text = ''
  let finish: unknown
  let usage: unknown
  for await (const chunk of adapter.stream({
    provider: 'ollama',
    model,
    messages: [
      {
        id: 'm1' as never,
        role: 'user',
        content: [{ type: 'text', text: 'Reply with exactly: PLUGIN OK' }],
        source: { kind: 'user' },
      } as never,
    ],
    system: 'You are terse. Obey exactly.',
    maxTokens: 600,
    temperature: 0,
  } as never)) {
    chunks.push(chunk.type)
    if (chunk.type === 'text-delta') text += chunk.text
    if (chunk.type === 'usage') usage = chunk.usage
    if (chunk.type === 'finish') finish = chunk.reason
  }

  console.log('  chunk types:', [...new Set(chunks)].join(', '))
  console.log('  text:', JSON.stringify(text.trim().slice(0, 120)))
  console.log('  usage:', JSON.stringify(usage))
  console.log('  finish:', JSON.stringify(finish))

  // A thinking model may legitimately emit only reasoning if it runs out of
  // budget; require real content, which is what a caller actually consumes.
  const ok = text.length > 0
    && chunks.includes('block-start')
    && chunks.includes('block-end')
    && chunks.includes('finish')
  console.log(ok ? 'PASS' : 'FAIL')
  process.exit(ok ? 0 : 1)
}

main().catch((error: unknown) => {
  console.error('FAIL', error)
  process.exit(1)
})
