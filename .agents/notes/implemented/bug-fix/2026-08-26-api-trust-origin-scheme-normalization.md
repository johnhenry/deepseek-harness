# Agent Note: Read the Origin's scheme when normalizing the `/api` Host, and say which check refused

Status: implemented

English | [中文](2026-08-26-api-trust-origin-scheme-normalization.zh.md)

## Problem

The `/api` authority fence ([the api browser-trust boundary](../architecture/2026-07-28-api-browser-trust-boundary.md)) compared an attached `Origin` against the `Host` by parsing both through WHATWG normalization — but it always read the `Host` under a fixed `http:`. A `Host` header names an authority with no scheme of its own, so which port is that authority's default one is knowable only from the `Origin` beside it. Under a fixed `http:`, `:443` is not the default and survives normalization, while the browser's `https` `Origin` drops it: any TLS terminator that writes the default port out in full sends `Host: name:443` with `Origin: https://name` and had every `/api` request refused, including the WebSocket handshakes the UI needs to show anything at all.

The refusal was also undiagnosable. Every failure answered a bare `forbidden`, so an operator saw only `transport failure for /api/host.pickDirectory: HTTP 403` and could not tell a rewritten `Origin` from an undeclared authority from the privileged-method loopback pin — three different causes with three different fixes, one of which (`--trusted-host`) cannot lift the pin at all. The pin's symptom is especially misleading: the rest of `/api` works, so the deployment reads as healthy and only the folder picker looks broken.

## Decision

Normalize both authorities under the scheme the `Origin` names. The `Host` is re-read under `https:` exactly when the `Origin` is https, so the default port for the scheme in play never decides trust while every non-default port still does; `127.0.0.1:3080` against `http://127.0.0.1` stays refused, and cross-port stays shut in both directions. An `Origin` outside `http:`/`https:` is now refused outright rather than compared: a page this server served is always one of the two, the WHATWG parser leaves non-special schemes unnormalized, and the old comparison would accept `app://127.0.0.1:3080` against that `Host`.

The fence answers with a verdict rather than a boolean. `describeApiRequestTrust` returns the refusing check as a closed `ApiTrustRefusal` tag plus a one-line diagnosis, and every 403 — HTTP route, shared-channel interceptor, and WebSocket upgrade rejection alike — carries it. A privileged method refused by the loopback pin says that, instead of repeating the generic advice to declare the authority with `--trusted-host`, which does not widen the privileged set. The predicate `isTrustedApiRequest` had no caller left and is gone.

Diagnoses quote only headers the caller itself sent. No configured `trustedHosts` entry appears in a 403 body: a refused caller learns which of its own headers lost, never what the deployment trusts.

## Alternatives considered

- **Compare the authorities port-insensitively when the Host is loopback.** Rejected: it would accept an `Origin` of `http://127.0.0.1` (a page served on port 80) against a `Host` of `127.0.0.1:3080`, opening exactly the cross-port hole on the loopback interface that the reports blame on a rewritten `Origin`. The rewrite is the client's bug; loosening the fence to tolerate it trades a real boundary for a workaround.
- **Trust `X-Forwarded-Proto` to pick the scheme.** Rejected: that header is attacker-controllable wherever no proxy strips it, and the `Origin` already states the scheme authoritatively for the only requests this comparison runs on.
- **Log the refusal host-side and keep the bare body.** Rejected: the operator reading the browser's transport error is usually not the one reading the server's stdout, and the fence's plugin has no logger injection today. The body already reaches whoever can reproduce the request.
- **Lift the privileged loopback pin for declared authorities.** Rejected: out of scope here and unchanged by this note — the pin waits on a real authentication layer, exactly as the owning architecture note records. This change only makes the pin say what it is.

## Consequences

- A deployment behind a TLS terminator that spells out `:443` now works instead of 403-ing every `/api` request; nothing that previously passed the fence stops passing.
- `Origin` schemes beyond `http:`/`https:` are refused where they were previously compared. No shipped client sends one — the browser carrier is served over http(s), and the in-process carrier does not cross this fence.
- 403 bodies are now variable text. `packages/client/connection/tests/node-half.host.spec.ts` asserts the exact diagnoses rather than the old literal `forbidden`, since the body is the fence's user-visible contract for a self-diagnosable refusal.
- `rejectWebSocketUpgrade` takes the diagnosis as a required parameter, so both transports refuse with one wording.
