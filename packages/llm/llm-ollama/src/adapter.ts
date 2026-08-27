/**
 * Ollama adapter for the DeepSeek Harness LLM seam.
 *
 * Speaks Ollama's NATIVE `/api/chat` and `/api/tags`, not its
 * OpenAI-compatible `/v1` shim. That choice is deliberate: `/api/tags` is the
 * only endpoint that reports real local model identity (digest, parameter
 * size, quantization, context length), and `listModels()`/`resolveModel()`
 * exist precisely to surface that. Routing an OpenAI adapter at Ollama would
 * satisfy `stream()` while reporting a provider identity, retry policy, and
 * catalog that describe a different service.
 *
 * @module
 */

import { LlmAdapter } from '@deepseek-ai/dsh-llm'
import type {
  ContentBlock,
  GenerateOptions,
  LlmModelInfo,
  LlmProviderInfo,
  LlmResolvedModelInfo,
  Message,
  StreamChunk,
  ToolSchema,
} from '@deepseek-ai/dsh-llm'

/** Connection facts resolved per request, never frozen at plugin load. */
export interface OllamaConnectionOptions {
  baseURL: string
  /** Per-request wall clock budget. Ollama cold-loads a model on first call. */
  requestTimeoutMs: number
  /**
   * Ollama's default context is often far below what a model supports; the
   * server silently truncates rather than erroring. Sent as `options.num_ctx`
   * when set so long agent conversations are not quietly clipped.
   */
  numCtx?: number
  keepAlive?: string
}

export interface OllamaAdapterOptions {
  options: () => OllamaConnectionOptions
}

/** Ollama's `/api/tags` entry. Every field but `name` is best-effort. */
interface OllamaTag {
  name?: string
  model?: string
  digest?: string
  details?: { parameter_size?: string; quantization_level?: string; family?: string }
}

interface OllamaChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string
  tool_calls?: { function: { name: string; arguments: unknown } }[]
}

/**
 * One NDJSON line from `/api/chat`. Every field is optional because this is
 * parsed from the wire: a malformed or partial object must be skippable
 * rather than throwing, and `done` is the only field the loop truly depends
 * on. `thinking` is present on reasoning models (qwen3) and absent elsewhere.
 */
interface OllamaStreamEvent {
  message?: {
    content?: string
    thinking?: string
    tool_calls?: { function?: { name?: string; arguments?: unknown } }[]
  }
  done?: boolean
  done_reason?: string
  prompt_eval_count?: number
  eval_count?: number
}

const TEXT_BLOCK_TYPES = new Set(['text', 'reasoning'])

/**
 * Flatten harness content blocks into the single string Ollama's chat API
 * accepts. Tool-call and tool-result blocks are mapped structurally where
 * Ollama supports it and otherwise rendered deterministically, so a text-only
 * local model still sees that a tool ran rather than silently losing the turn.
 */
function flattenContent(content: readonly ContentBlock[]): string {
  const parts: string[] = []
  for (const block of content) {
    if (TEXT_BLOCK_TYPES.has(block.type) && 'text' in block) {
      parts.push(String((block as { text: string }).text))
    } else if (block.type === 'tool-result' && 'content' in block) {
      const inner = (block as { content?: readonly ContentBlock[] }).content
      parts.push(inner ? flattenContent(inner) : '')
    } else if (block.type === 'image') {
      // Deterministic placeholder: this adapter declares no image modality, so
      // a reference must not be dropped without a trace.
      parts.push('[image omitted: the ollama route is text-only]')
    }
  }
  return parts.join('')
}

function toOllamaMessages(system: string | undefined, messages: readonly Message[]): OllamaChatMessage[] {
  const out: OllamaChatMessage[] = []
  if (system !== undefined && system.length > 0) out.push({ role: 'system', content: system })
  for (const message of messages) {
    const role = message.role === 'assistant' ? 'assistant' : 'user'
    const toolCalls = message.content.filter(b => b.type === 'tool-call')
    const entry: OllamaChatMessage = { role, content: flattenContent(message.content) }
    if (role === 'assistant' && toolCalls.length > 0) {
      entry.tool_calls = toolCalls.map((b) => {
        const call = b as unknown as { name: string; arguments: string }
        let parsed: unknown = {}
        try {
          parsed = JSON.parse(call.arguments)
        } catch {
          // A model that emitted unparsable arguments is a real event; forward
          // the raw string rather than dropping the call from history.
          parsed = { _raw: call.arguments }
        }
        return { function: { name: call.name, arguments: parsed } }
      })
    }
    out.push(entry)
  }
  return out
}

function toOllamaTools(tools: readonly ToolSchema[] | undefined) {
  if (tools === undefined || tools.length === 0) return undefined
  return tools.map(tool => ({
    type: 'function',
    function: { name: tool.name, description: tool.description, parameters: tool.parameters },
  }))
}

export class OllamaAdapter extends LlmAdapter {
  constructor(private readonly deps: OllamaAdapterOptions) {
    super()
  }

  override providerInfo(provider: string): LlmProviderInfo {
    return { id: provider, name: 'Ollama (local)' }
  }

  override async listModels(provider: string): Promise<readonly LlmModelInfo[]> {
    const { baseURL, requestTimeoutMs } = this.deps.options()
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), requestTimeoutMs)
    try {
      const response = await fetch(new URL('/api/tags', baseURL), { signal: controller.signal })
      if (!response.ok) return []
      const body = (await response.json()) as { models?: OllamaTag[] }
      const seen = new Set<string>()
      const models: LlmModelInfo[] = []
      for (const tag of body.models ?? []) {
        const id = tag.name ?? tag.model
        if (id === undefined || seen.has(id)) continue
        seen.add(id)
        const size = tag.details?.parameter_size
        const quant = tag.details?.quantization_level
        const suffix = [size, quant].filter(Boolean).join(', ')
        models.push({ provider, id, name: suffix.length > 0 ? `${id} (${suffix})` : id })
      }
      return models
    } catch {
      // A stopped ollama is an ordinary local condition, not a fault: the
      // catalog is advisory and consumers must not reject unlisted models.
      return []
    } finally {
      clearTimeout(timer)
    }
  }

  override async resolveModel(
    provider: string,
    model: string,
    signal?: AbortSignal,
  ): Promise<LlmResolvedModelInfo> {
    const { baseURL, requestTimeoutMs, numCtx } = this.deps.options()
    const controller = new AbortController()
    const abort = (): void => controller.abort()
    signal?.addEventListener('abort', abort, { once: true })
    const timer = setTimeout(() => controller.abort(), requestTimeoutMs)
    try {
      const response = await fetch(new URL('/api/show', baseURL), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model }),
        signal: controller.signal,
      })
      if (!response.ok) return { provider, id: model, name: model }
      const body = (await response.json()) as { model_info?: Record<string, unknown> }
      // Ollama namespaces the key by architecture (llama.context_length,
      // qwen3.context_length, ...), so find it by suffix rather than guessing.
      let context: number | undefined
      for (const [key, value] of Object.entries(body.model_info ?? {})) {
        if (key.endsWith('.context_length') && typeof value === 'number') {
          context = value
          break
        }
      }
      // A configured num_ctx is the real ceiling: the server truncates to it
      // regardless of what the architecture could address.
      const effective = numCtx !== undefined ? Math.min(numCtx, context ?? numCtx) : context
      return { provider, id: model, name: model, ...(effective !== undefined ? { context: { contextWindow: effective } } : {}) }
    } catch {
      return { provider, id: model, name: model }
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
    }
  }

  async *stream(options: GenerateOptions): AsyncIterable<StreamChunk> {
    const connection = this.deps.options()
    const controller = new AbortController()
    const abort = (): void => controller.abort()
    options.signal?.addEventListener('abort', abort, { once: true })
    const timer = setTimeout(() => controller.abort(), connection.requestTimeoutMs)

    // One text block per response, opened lazily: a response that is entirely
    // tool calls must not emit an empty text block.
    let index = 0
    let textOpen = false
    let text = ''
    let reasoning = ''
    let reasoningOpen = false

    try {
      const body: Record<string, unknown> = {
        model: options.model,
        messages: toOllamaMessages(options.system, options.messages),
        stream: true,
        options: {
          ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
          ...(options.maxTokens !== undefined ? { num_predict: options.maxTokens } : {}),
          ...(options.stop !== undefined ? { stop: options.stop } : {}),
          ...(connection.numCtx !== undefined ? { num_ctx: connection.numCtx } : {}),
        },
      }
      const tools = toOllamaTools(options.tools)
      if (tools !== undefined) body.tools = tools
      if (connection.keepAlive !== undefined) body.keep_alive = connection.keepAlive

      const response = await fetch(new URL('/api/chat', connection.baseURL), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      })

      if (!response.ok || response.body === null) {
        const detail = response.body === null ? 'no response body' : `HTTP ${response.status}`
        yield {
          type: 'finish',
          reason: { kind: 'error', failure: { code: 'PROVIDER_ERROR', message: `ollama: ${detail}` } },
        } as StreamChunk
        return
      }

      // Ollama streams NDJSON, one JSON object per line — not SSE. Buffer
      // across reads: a chunk boundary can land mid-line.
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let finished = false

      while (!finished) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        let newline = buffer.indexOf('\n')
        while (newline !== -1) {
          const line = buffer.slice(0, newline).trim()
          buffer = buffer.slice(newline + 1)
          newline = buffer.indexOf('\n')
          if (line.length === 0) continue

          let event: OllamaStreamEvent
          try {
            event = JSON.parse(line) as OllamaStreamEvent
          } catch {
            // A partial or malformed line is not fatal: Ollama emits one
            // object per line and the next read may carry a good one.
            continue
          }

          const delta: string | undefined = event?.message?.content
          const think: string | undefined = event?.message?.thinking
          if (typeof think === 'string' && think.length > 0) {
            if (!reasoningOpen) {
              yield { type: 'block-start', index, blockType: 'reasoning' } as StreamChunk
              reasoningOpen = true
            }
            reasoning += think
            yield { type: 'reasoning-delta', index, text: think } as StreamChunk
          }
          if (typeof delta === 'string' && delta.length > 0) {
            if (reasoningOpen) {
              yield { type: 'block-end', index, block: { type: 'reasoning', text: reasoning } as ContentBlock } as StreamChunk
              reasoningOpen = false
              index += 1
            }
            if (!textOpen) {
              yield { type: 'block-start', index, blockType: 'text' } as StreamChunk
              textOpen = true
            }
            text += delta
            yield { type: 'text-delta', index, text: delta } as StreamChunk
          }

          if (event?.done === true) {
            if (reasoningOpen) {
              yield { type: 'block-end', index, block: { type: 'reasoning', text: reasoning } as ContentBlock } as StreamChunk
              reasoningOpen = false
              index += 1
            }
            if (textOpen) {
              yield { type: 'block-end', index, block: { type: 'text', text } as ContentBlock } as StreamChunk
              textOpen = false
              index += 1
            }
            // Emit tool calls only at completion: Ollama sends them whole
            // rather than as deltas, so there is nothing to stream.
            for (const call of event?.message?.tool_calls ?? []) {
              const name = call?.function?.name ?? 'unknown'
              const args = JSON.stringify(call?.function?.arguments ?? {})
              const id = `${name}-${index}`
              yield { type: 'block-start', index, blockType: 'tool-call' } as StreamChunk
              yield { type: 'tool-call-delta', index, id, name, argumentsDelta: args } as StreamChunk
              yield {
                type: 'block-end',
                index,
                block: { type: 'tool-call', id, name, arguments: args } as unknown as ContentBlock,
              } as StreamChunk
              index += 1
            }
            if (typeof event.prompt_eval_count === 'number' || typeof event.eval_count === 'number') {
              yield {
                type: 'usage',
                usage: {
                  inputTokens: event.prompt_eval_count ?? 0,
                  outputTokens: event.eval_count ?? 0,
                },
              } as StreamChunk
            }
            // Ollama reports truncation as done_reason "length".
            const reason = event.done_reason === 'length' ? { kind: 'max-tokens' as const } : { kind: 'stop' as const }
            yield { type: 'finish', reason } as StreamChunk
            finished = true
            break
          }
        }
      }

      if (!finished) {
        // The stream ended without a done event — a killed server or dropped
        // connection. Close any open block so consumers are not left mid-block.
        if (reasoningOpen) yield { type: 'block-end', index, block: { type: 'reasoning', text: reasoning } as ContentBlock } as StreamChunk
        if (textOpen) yield { type: 'block-end', index, block: { type: 'text', text } as ContentBlock } as StreamChunk
        yield {
          type: 'finish',
          reason: { kind: 'error', failure: { code: 'PROVIDER_ERROR', message: 'ollama: stream ended without a done event' } },
        } as StreamChunk
      }
    } catch (cause) {
      const aborted = controller.signal.aborted
      yield {
        type: 'finish',
        reason: aborted
          ? { kind: 'aborted' as const, failure: { code: 'ABORTED', message: 'ollama: request aborted' } }
          : { kind: 'error' as const, failure: { code: 'PROVIDER_ERROR', message: `ollama: ${String(cause)}` } },
      } as StreamChunk
    } finally {
      clearTimeout(timer)
      options.signal?.removeEventListener('abort', abort)
    }
  }
}
