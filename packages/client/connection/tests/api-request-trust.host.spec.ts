/** Behavior of the /api browser-trust fence (rebinding + cross-site defense). */

import { describe, expect, it } from 'vitest'
import type { ApiTrustRefusal } from '../src/api-request-trust.ts'
import { assertTrustedAuthority, describeApiRequestTrust } from '../src/api-request-trust.ts'

function request(headers: Record<string, string | undefined>): { headers: Record<string, string | undefined> } {
  return { headers }
}

function trusted(req: ReturnType<typeof request>, trustedHosts: readonly string[]): boolean {
  return describeApiRequestTrust(req, trustedHosts).trusted
}

function refusal(req: ReturnType<typeof request>, trustedHosts: readonly string[]): ApiTrustRefusal | undefined {
  const verdict = describeApiRequestTrust(req, trustedHosts)
  return verdict.trusted ? undefined : verdict.refusal
}

function reason(req: ReturnType<typeof request>, trustedHosts: readonly string[]): string {
  const verdict = describeApiRequestTrust(req, trustedHosts)
  return verdict.trusted ? '' : verdict.reason
}

describe('describeApiRequestTrust', () => {
  it('holds markerless requests to the same Host fence — a plain-HTTP browser read carries no markers', () => {
    // Over plain HTTP a browser attaches neither Origin nor Fetch-Metadata to
    // reads (EventSource, images, navigations), so a rebound-origin GET is
    // markerless and its response readable: no marker shortcut may exist.
    expect(trusted(request({ host: '127.0.0.1:3080' }), [])).toBe(true)
    expect(trusted(request({ host: '192.168.1.5:3080' }), ['192.168.1.5'])).toBe(true)
    expect(trusted(request({ host: '192.168.1.5:3080' }), [])).toBe(false)
    expect(trusted(request({ host: 'harness.example' }), [])).toBe(false)
    expect(trusted(request({}), [])).toBe(false)
  })

  it('accepts loopback Hosts in every spelling, with and without ports, for browser requests', () => {
    for (const host of ['localhost', 'localhost:3080', '127.0.0.1', '127.0.0.1:3080', '127.8.9.10:80', '[::1]', '[::1]:3080', 'LOCALHOST:3080']) {
      expect(trusted(request({ host, origin: `http://${host}` }), [])).toBe(true)
    }
  })

  it('refuses a rebound Host: the attacker domain names the socket it did not expect', () => {
    expect(trusted(request({
      host: 'evil.example:3080',
      origin: 'http://evil.example:3080',
      'sec-fetch-site': 'same-origin',
    }), [])).toBe(false)
  })

  it('accepts a declared public authority: exact on host:port entries, any port on port-less entries', () => {
    const headers = { host: 'harness.internal:3080', origin: 'http://harness.internal:3080' }
    expect(trusted(request(headers), ['harness.internal:3080'])).toBe(true)
    expect(trusted(request(headers), ['harness.internal'])).toBe(true)
    expect(trusted(request(headers), ['harness.internal:9999'])).toBe(false)
    expect(trusted(request(headers), [])).toBe(false)
  })

  it('matches Host, Origin, and trusted entries through WHATWG normalization (case, default port)', () => {
    expect(trusted(request({ host: 'Harness.INTERNAL:3080', origin: 'http://harness.internal:3080' }), ['harness.internal:3080'])).toBe(true)
    expect(trusted(request({ host: 'harness.internal', origin: 'http://harness.internal' }), ['HARNESS.internal:80'])).toBe(true)
    // An unparsable entry never matches; it must not poison the rest of the list.
    expect(trusted(request({ host: 'harness.internal', origin: 'http://harness.internal' }), ['bad entry', 'harness.internal'])).toBe(true)
    expect(trusted(request({ host: 'harness.internal', origin: 'http://harness.internal' }), ['bad entry'])).toBe(false)
  })

  it('refuses cross-origin browser markers even on a loopback Host', () => {
    // Origin present and different → cross-site request that survived preflight rules.
    expect(trusted(request({ host: '127.0.0.1:3080', origin: 'http://evil.example' }), [])).toBe(false)
    // Explicit cross-site label → refused regardless of Origin.
    expect(trusted(request({ host: '127.0.0.1:3080', 'sec-fetch-site': 'cross-site' }), [])).toBe(false)
    // Opaque origin (sandboxed iframe, file: page) parses to no authority.
    expect(trusted(request({ host: '127.0.0.1:3080', origin: 'null' }), [])).toBe(false)
  })

  it('accepts a same-origin browser request, with or without an Origin header', () => {
    expect(trusted(request({
      host: 'localhost:3080',
      origin: 'http://localhost:3080',
      'sec-fetch-site': 'same-origin',
    }), [])).toBe(true)
    // Origin-less browser shapes (same-origin GETs) still carry sec-fetch-site.
    expect(trusted(request({ host: 'localhost:3080', 'sec-fetch-site': 'same-origin' }), [])).toBe(true)
  })

  it('reads the default port under the scheme the Origin names, so a TLS terminator writing :443 still matches', () => {
    // A proxy that spells the default port out in full sends `Host: name:443`
    // while the browser's https Origin drops it. Both name one authority.
    expect(trusted(request({ host: '127.0.0.1:443', origin: 'https://127.0.0.1' }), [])).toBe(true)
    expect(trusted(request({ host: 'harness.internal:443', origin: 'https://harness.internal' }), ['harness.internal:443'])).toBe(true)
    // The http default is read the same way from the other side.
    expect(trusted(request({ host: '127.0.0.1:80', origin: 'http://127.0.0.1' }), [])).toBe(true)
    expect(trusted(request({ host: '127.0.0.1', origin: 'https://127.0.0.1:443' }), [])).toBe(true)
  })

  it('still lets a non-default port decide trust under either scheme', () => {
    // Only the default port normalizes away: an extension or proxy that drops
    // a real port leaves two different authorities, and cross-port stays shut.
    expect(trusted(request({ host: '127.0.0.1:3080', origin: 'http://127.0.0.1' }), [])).toBe(false)
    expect(trusted(request({ host: '127.0.0.1:3080', origin: 'https://127.0.0.1' }), [])).toBe(false)
    expect(trusted(request({ host: '127.0.0.1:443', origin: 'http://127.0.0.1' }), [])).toBe(false)
    expect(trusted(request({ host: '127.0.0.1:80', origin: 'https://127.0.0.1' }), [])).toBe(false)
  })

  it('refuses an Origin outside the two HTTP schemes, whatever authority it claims', () => {
    // A page this server served is always http(s); anything else is another
    // kind of context naming our authority, and parses unnormalized besides.
    expect(trusted(request({ host: '127.0.0.1:3080', origin: 'app://127.0.0.1:3080' }), [])).toBe(false)
    expect(trusted(request({ host: '127.0.0.1:3080', origin: 'file://127.0.0.1:3080' }), [])).toBe(false)
  })

  it('names the refusing check and quotes only headers the caller sent', () => {
    expect(refusal(request({}), [])).toBe('no-host')
    expect(refusal(request({ host: 'bad host' }), [])).toBe('bad-host')
    expect(refusal(request({ host: 'harness.example' }), [])).toBe('untrusted-host')
    expect(refusal(request({ host: '127.0.0.1:3080', 'sec-fetch-site': 'cross-site' }), [])).toBe('cross-site')
    expect(refusal(request({ host: '127.0.0.1:3080', origin: 'null' }), [])).toBe('bad-origin')
    expect(refusal(request({ host: '127.0.0.1:3080', origin: 'http://evil.example' }), [])).toBe('origin-mismatch')
    expect(refusal(request({ host: '127.0.0.1:3080', origin: 'http://127.0.0.1:3080' }), [])).toBeUndefined()
    // The diagnosis carries the compared authorities so a 403 is actionable,
    // and a configured entry never appears in it.
    expect(reason(request({ host: '127.0.0.1:3080', origin: 'http://127.0.0.1' }), []))
      .toContain('compared as 127.0.0.1 against 127.0.0.1:3080')
    expect(reason(request({ host: 'harness.example', origin: 'http://harness.example' }), ['harness.internal']))
      .not.toContain('harness.internal')
  })

  it('assertTrustedAuthority accepts bare authorities and throws on anything more', () => {
    for (const entry of ['harness.internal', 'harness.internal:3080', 'HARNESS.internal:80', '10.0.0.9', '[::1]:3080']) {
      expect(() => { assertTrustedAuthority(entry) }).not.toThrow()
    }
    // WHATWG parsing would quietly read a hostname out of each of these; the
    // config boundary must refuse them instead of authorizing the prefix.
    for (const entry of ['harness.internal/path', 'harness.internal/', 'user@harness.internal', 'harness.internal?x', 'harness.internal#f', 'harness.internal\\path', 'bad entry', '']) {
      expect(() => { assertTrustedAuthority(entry) }).toThrow(/not a bare host\[:port\] authority/)
    }
    // WHATWG trimming would silently strip these; the entry must fail instead.
    for (const entry of ['harness.internal:3080 ', ' harness.internal', 'harness.internal:30\t80']) {
      expect(() => { assertTrustedAuthority(entry) }).toThrow(/not a bare host\[:port\] authority/)
    }
    // WHATWG parsing would silently rewrite these — a dangling colon or
    // zero-padded port would broaden an intended exact-port grant to every
    // port, and non-canonical host spellings would not read back as written.
    for (const entry of ['harness.internal:', '[::1]:', 'harness.internal:0080', '0x7f.0.0.1', '[0:0:0:0:0:0:0:1]']) {
      expect(() => { assertTrustedAuthority(entry) }).toThrow(/not a bare host\[:port\] authority/)
    }
  })

  it('never lets stray whitespace broaden an exact-port entry to every port', () => {
    // Defense in depth below the load-time assert: the explicit-port judgment
    // reads the parsed URL, so a trimmed `host:port ` entry stays exact.
    const entries = ['harness.internal:3080 ']
    expect(trusted(request({ host: 'harness.internal:9999', origin: 'http://harness.internal:9999' }), entries)).toBe(false)
    expect(trusted(request({ host: 'harness.internal:3080', origin: 'http://harness.internal:3080' }), entries)).toBe(true)
  })

  it('refuses malformed or untrusted authorities on browser requests', () => {
    const markers = { 'sec-fetch-site': 'same-origin' }
    expect(trusted(request({ ...markers }), [])).toBe(false)
    expect(trusted(request({ ...markers, host: '' }), [])).toBe(false)
    expect(trusted(request({ ...markers, host: 'bad host' }), [])).toBe(false)
    expect(trusted(request({ ...markers, host: '127.0.0.999' }), [])).toBe(false)
    expect(trusted(request({ ...markers, host: '128.0.0.1' }), [])).toBe(false)
  })
})
