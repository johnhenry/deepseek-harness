/**
 * Register an {@link OllamaAdapter} for the `ollama` provider route on
 * `ctx.llm`. Connection facts resolve per request rather than freezing at
 * load, mirroring `llm-deepseek`: a changed base URL or context size reaches
 * the next request without a restart, while an in-flight stream keeps the
 * facts it started with.
 *
 * Deliberately has NO credential seam. Ollama is a local daemon with no API
 * key, so there is nothing to resolve and nothing to store — asking for a
 * credential would invent an authentication step the provider does not have.
 *
 * @module @deepseek-ai/dsh-llm-ollama
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { resolveRetryPolicy, RetryPolicySchema } from '@deepseek-ai/dsh-llm'
import type { RetryPolicyConfig } from '@deepseek-ai/dsh-llm'
import { deepEqualJson, installSettingsSection, settingsNamespace } from '@deepseek-ai/dsh-settings'
import { OllamaAdapter } from './adapter.ts'
import type { OllamaConnectionOptions } from './adapter.ts'

export { OllamaAdapter } from './adapter.ts'
export type { OllamaAdapterOptions, OllamaConnectionOptions } from './adapter.ts'

export const name = 'llm-ollama'
export const inject = ['llm']

/** Ollama's own default bind address. */
export const DEFAULT_BASE_URL = 'http://127.0.0.1:11434'
/**
 * Generous by web-API standards, and it has to be. Ollama loads the model on
 * the first request after an idle period; on a handheld iGPU that cold load is
 * tens of seconds before a single token appears.
 */
export const DEFAULT_REQUEST_TIMEOUT_MS = 600_000

export interface Config {
  baseURL?: string
  requestTimeoutMs?: number
  numCtx?: number
  keepAlive?: string
  retryPolicy?: RetryPolicyConfig
}

export const Config: z<Config> = z.object({
  baseURL: z.string().default(DEFAULT_BASE_URL)
    .description('Base URL of the Ollama HTTP API.'),
  requestTimeoutMs: z.natural().default(DEFAULT_REQUEST_TIMEOUT_MS)
    .description('Per-request timeout. Must absorb a cold model load, not just generation.'),
  numCtx: z.natural()
    .description('Context window to request (options.num_ctx). Unset uses the server default, which is often far smaller than the model supports and truncates silently.'),
  keepAlive: z.string()
    .description('How long the model stays resident after a request (e.g. "5m", "-1" to pin). Unset uses the server default.'),
  retryPolicy: RetryPolicySchema,
}).description('Local Ollama inference.')

export function apply(ctx: Context, config: Config): void {
  const NS = settingsNamespace('llm-ollama')
  const PROVIDER = 'ollama'

  // A thunk, not a value. `installSettingsSection` hands back a getter so the
  // authoritative source can swap underneath — the resolved settings scope
  // while one is attached, the plain composition entry otherwise — without
  // this plugin re-reading or caching anything. Holding the value instead
  // would freeze whichever source happened to be active at load.
  let current: () => Config = () => config

  const options = (): OllamaConnectionOptions & { retryPolicy: unknown } => {
    const raw = current()
    return {
      baseURL: raw.baseURL ?? DEFAULT_BASE_URL,
      requestTimeoutMs: raw.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      ...(raw.numCtx !== undefined ? { numCtx: raw.numCtx } : {}),
      ...(raw.keepAlive !== undefined ? { keepAlive: raw.keepAlive } : {}),
      retryPolicy: resolveRetryPolicy(raw.retryPolicy, 'llm-ollama.retryPolicy'),
    }
  }

  const adapter = new OllamaAdapter({ options })

  ctx.llm.registerConfigurableProviders([
    { provider: PROVIDER, displayName: 'Ollama (local)', settingsNs: NS, settingsPath: [] },
  ])

  const registration = ctx.llm.registerAdapter([PROVIDER], adapter)

  // The retry policy is the one fact captured at registration rather than
  // resolved per request, so a change to it has to re-register the route.
  // `replace` does that in one synchronous registry section; disposing and
  // re-registering would publish an empty route set in between, and anything
  // watching `llm/adapters-updated` would see Ollama vanish and return.
  let registeredPolicy = options().retryPolicy
  const ensureRegistrationFacts = (): void => {
    const policy = options().retryPolicy
    if (deepEqualJson(policy, registeredPolicy)) return
    registration.replace([PROVIDER])
    registeredPolicy = policy
  }

  installSettingsSection(ctx, NS, Config, config, {
    setSource: (source) => {
      current = source
    },
    onChange: ensureRegistrationFacts,
  })
}
