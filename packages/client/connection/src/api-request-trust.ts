/**
 * Browser-trust fence for every /api request. Defends the two confused-deputy
 * paths a browser opens against a local HTTP API — DNS rebinding (Host names
 * the attacker's domain while the socket reaches this server) and cross-site
 * requests fired from a malicious page. The Host fence binds every request,
 * browser-looking or not: over plain HTTP a browser attaches neither Origin
 * nor Fetch-Metadata to reads (images and navigations — those
 * headers go only to trustworthy destinations), so an unmarked request may
 * still be a rebound browser read and Host is the one header rebinding cannot
 * forge. Non-browser and remote clients pass the same fence via loopback,
 * deployment-derived LAN IP literals, or a declared `trustedHosts` authority.
 * Network reachability and authentication stay out of scope: binding policy
 * belongs to the webserver config, and this fence is not an auth layer.
 */

import type { IncomingHttpHeaders } from 'node:http'
import { isLoopbackHostname } from './loopback-hostname.ts'

/** The request facts the fence reads from either HTTP representation. */
interface ApiTrustRequest {
  headers: IncomingHttpHeaders | Headers
}

function header(headers: IncomingHttpHeaders | Headers, name: string): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined
  const value = headers[name]
  return typeof value === 'string' ? value : undefined
}

/** Normalized URL of a Host-header authority (hostname lowercased, default port stripped, IPv6 bracketed), or undefined when unparsable. */
function parseAuthority(authority: string): URL | undefined {
  try {
    // http: is a WHATWG "special scheme": parsing yields a non-empty hostname or throws.
    return new URL(`http://${authority}`)
  } catch {
    return undefined
  }
}

/**
 * Assert one configured `trustedHosts` entry is a bare authority (`host` or
 * `host:port`) in canonical form: it must survive WHATWG parsing unchanged
 * (case aside). Anything parsing would silently rewrite is refused as a typo
 * that must fail the load loudly instead of being ignored until requests 403
 * or quietly changing the grant: URL parts beyond the authority
 * (`harness.internal/path`, `user@harness.internal` — which would authorize
 * the embedded hostname), stripped whitespace, a dangling colon or
 * zero-padded port (which would broaden an intended exact-port grant to every
 * port), and non-canonical host spellings (`0x7f.0.0.1`, percent-encoding,
 * unbracketed IPv6; IDN hosts are declared in punycode, the form the wire
 * carries).
 * @param entry - the configured value, verbatim.
 */
export function assertTrustedAuthority(entry: string): void {
  const entryUrl = parseAuthority(entry)
  if (entryUrl !== undefined && canonicalAuthority(entry, entryUrl) === entry.toLowerCase()) return
  throw new Error(`client-connection: trustedHosts entry ${JSON.stringify(entry)} is not a bare host[:port] authority`)
}

/**
 * Canonical form of a parsed authority: `hostname` when no port was written,
 * else `hostname:port`. The port is judged from URL parses under both special
 * schemes (their default ports differ, so `:80` and `:443` still count as
 * explicit), never from the raw string, where WHATWG trimming would misread
 * shapes like `host:port ` as port-less.
 */
function canonicalAuthority(entry: string, entryUrl: URL): string {
  // An authority that parsed under http cannot fail under https.
  const port = entryUrl.port !== '' ? entryUrl.port : new URL(`https://${entry}`).port
  return port === '' ? entryUrl.hostname : `${entryUrl.hostname}:${port}`
}

/**
 * Whether the request authority matches a `trustedHosts` entry. An entry with
 * an explicit port matches that exact authority; a port-less entry matches the
 * hostname on any port (the shape the CLI derives for IP-literal LAN serving,
 * where the bound port may be OS-assigned). Both sides compare through WHATWG
 * normalization, so case and a redundant `:80` never decide trust.
 */
function isTrustedAuthority(hostUrl: URL, trustedHosts: readonly string[]): boolean {
  return trustedHosts.some((entry) => {
    const entryUrl = parseAuthority(entry)
    if (entryUrl === undefined) return false
    return canonicalAuthority(entry, entryUrl) === entryUrl.hostname
      ? entryUrl.hostname === hostUrl.hostname
      : entryUrl.host === hostUrl.host
  })
}

/**
 * Why the fence refused, in terms of the headers the caller itself sent.
 * A 403 body carrying this is not a disclosure: every value quoted came from
 * the request, and no configured `trustedHosts` entry is ever named.
 */
export type ApiTrustRefusal =
  /** No Host header at all — the fence has nothing to bind the request to. */
  | 'no-host'
  /** Host present but not a parsable authority. */
  | 'bad-host'
  /** Host parsed, but is neither loopback nor a declared `trustedHosts` authority. */
  | 'untrusted-host'
  /** The browser labelled the request cross-site. */
  | 'cross-site'
  /** Origin present but not an http(s) authority (opaque `null`, `file:`, a custom scheme). */
  | 'bad-origin'
  /** Origin is a real authority, but not this one. */
  | 'origin-mismatch'

/** Fence verdict: `trusted`, or the refusal with a single-line diagnosis. */
export type ApiTrustVerdict =
  | { trusted: true }
  | { trusted: false; refusal: ApiTrustRefusal; reason: string }

function refuse(refusal: ApiTrustRefusal, reason: string): ApiTrustVerdict {
  return { trusted: false, refusal, reason }
}

/**
 * Parse an Origin header into the authority it names. Only the two special
 * HTTP schemes count: a page this server served is always http(s), so any
 * other scheme is some other kind of context (`file:`, a packaged-app or
 * extension scheme) claiming our authority, and the WHATWG parser leaves
 * non-special schemes unnormalized besides.
 * @param origin - the Origin header, verbatim (`null` for an opaque origin).
 */
function parseOrigin(origin: string): URL | undefined {
  try {
    const url = new URL(origin)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url : undefined
  } catch {
    return undefined
  }
}

/**
 * Decide whether one /api request may reach the RPC bridge, and say why not.
 * @param request - Node HTTP or Fetch request facts (headers).
 * @param trustedHosts - non-loopback authorities this deployment serves: exact `host:port`, or port-less `host` matching any port.
 * @returns the verdict; refusals carry a diagnosis built only from request headers.
 */
export function describeApiRequestTrust(
  request: ApiTrustRequest,
  trustedHosts: readonly string[],
): ApiTrustVerdict {
  // Host fence (DNS-rebinding defense), applied to every request: the browser
  // fills Host from the URL it believes it is talking to, so a rebound page
  // carries the attacker's domain here even though the socket lands on this
  // server. There is no marker shortcut — a browser read over plain HTTP
  // (images and navigations) arrives with neither Origin nor
  // Fetch-Metadata, indistinguishable from curl, and its response is readable
  // by the rebound page.
  const host = header(request.headers, 'host')
  if (host === undefined) return refuse('no-host', 'request carried no Host header')
  const hostUrl = parseAuthority(host)
  if (hostUrl === undefined) return refuse('bad-host', `Host ${JSON.stringify(host)} is not a parsable authority`)
  if (!isLoopbackHostname(hostUrl.hostname) && !isTrustedAuthority(hostUrl, trustedHosts)) {
    return refuse(
      'untrusted-host',
      `Host ${JSON.stringify(host)} is neither loopback nor a declared authority`
      + ' — serve this deployment over loopback, or name the authority with --trusted-host',
    )
  }
  // Cross-site fence: modern browsers label the initiator relationship on
  // every fetch; an explicit cross-site marker is refused regardless of Origin.
  if (header(request.headers, 'sec-fetch-site') === 'cross-site') {
    return refuse('cross-site', 'request is labelled sec-fetch-site: cross-site')
  }
  // Origin fence: when a browser attaches an Origin it must name exactly this
  // authority. Absent Origin is fine — the Host fence above already bound the
  // request.
  const origin = header(request.headers, 'origin')
  if (origin === undefined) return { trusted: true }
  const originUrl = parseOrigin(origin)
  if (originUrl === undefined) {
    return refuse('bad-origin', `Origin ${JSON.stringify(origin)} is not an http(s) authority`)
  }
  // Normalize both sides under the Origin's scheme. A Host header names an
  // authority with no scheme of its own, so which port is the default one is
  // knowable only from the Origin beside it: read under a fixed `http:`, an
  // explicit `:443` survives on the Host while the browser's https Origin
  // drops it, and a genuinely same-origin request from behind a TLS
  // terminator that writes the default port out in full is refused. Ports
  // still decide trust — only the default port, under the scheme that makes
  // it default, normalizes away.
  // An authority that parsed under http cannot fail under https.
  const scopedHostUrl = originUrl.protocol === 'http:' ? hostUrl : new URL(`https://${host}`)
  if (originUrl.host !== scopedHostUrl.host) {
    return refuse(
      'origin-mismatch',
      `Origin ${JSON.stringify(origin)} does not name Host ${JSON.stringify(host)}`
      + ` (compared as ${originUrl.host} against ${scopedHostUrl.host})`
      + ' — a browser extension or proxy rewriting Origin is the usual cause',
    )
  }
  return { trusted: true }
}
