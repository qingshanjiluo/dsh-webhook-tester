# dsh-webhook-tester

DeepSeek Harness plugin: offline webhook fixtures and HMAC signature maths, exposed as three
model-callable tools.

The plugin never binds a socket, never starts a listener, and never sends a request. It generates
deterministic sample deliveries, verifies `HMAC-SHA256` signatures over the exact bytes received,
and parses captured raw HTTP request text back into its parts — so a webhook receiver can be
exercised and debugged entirely from a transcript.

## Install

```bash
npx -y @deepseek-ai/dsh plugin --profile web add @qingshanjiluo/dsh-webhook-tester
```

## Tools

| Tool | Arguments | Returns |
| --- | --- | --- |
| `webhook_generate_sample` | `eventType` (string, required), `overrides` (JSON object, optional) | `requestedType`, `eventType`, `known`, `wireEvent`, `targetUrl`, `payload`, `payloadJson` (2-space), `bodyToPost` (compact), `headers`, `curl`, `byteLength`, `warnings` |
| `webhook_verify_signature` | `payload`, `secret`, `signatureHeader` (all required), `tolerance` (number, optional) | `valid`, `scheme`, `reason` |
| `webhook_parse_request` | `rawHttp` (string, required) | `method`, `path`, `httpVersion`, `headers`, `body`, `bodyJson`, `parseError`, `warnings` |

All three are pure and report `isConcurrencySafe: true`, so a model may fan them out in parallel.

### `webhook_generate_sample`

Built-in shapes: `push`, `pull_request` (aliases `pr`, `pull-request`), `issue` (alias `issues`),
`ping`, `generic`. Payloads are fixed (identical ids, SHAs, and timestamps on every call), so a
sample can be committed as a fixture. `overrides` is deep-merged onto the payload — objects merge
key by key, arrays and scalars replace the sample value. The returned `curl` command is POSIX shell
text with backslash continuations and single-quoted arguments (`'` escaped as `'\''`), and it posts
`bodyToPost` — the same string to sign and verify against.

Set `signingSecret` to have the sample ship a matching `X-Hub-Signature-256` header. An unknown
event name falls back to the `generic` envelope and says so in `warnings`.

### `webhook_verify_signature`

Recognised header formats (`scheme` reports the one detected):

| `scheme` | Header shape | Signed message |
| --- | --- | --- |
| `github-sha256` | `sha256=<hex>` (`X-Hub-Signature-256`) | the payload |
| `stripe-timestamped` | `t=<unix-seconds>,v1=<hex>` (several `v1=` allowed for key rotation) | `t=<unix-seconds>` + `.` + payload |
| `raw-sha256` | bare 64-character hex digest | the payload |
| `unknown` | anything else, including `sha1=` | rejected with a reason |

A pasted header line (`X-Hub-Signature-256: sha256=...`) is accepted; a leading field name is
stripped. Hex is compared case-insensitively over equal-length buffers with `timingSafeEqual`.
`tolerance` bounds how far `t=` may sit from the current time in seconds and defaults to
`defaultToleranceSeconds`; pass `0` to skip the freshness check. Pass `payload` byte-for-byte as it
arrived — re-serialised JSON will not verify. Anything that fails (empty secret or header,
non-hex digest, mixed schemes, stale timestamp, mismatch) returns `valid: false` plus a reason
rather than throwing.

### `webhook_parse_request`

Splits on the first blank line (`\r\n\r\n` or `\n\n`). The request line yields `method`, `path`
(including query), and `httpVersion` without the `HTTP/` prefix. Header names are lowercased,
folded continuation lines are joined with a single space, repeated headers are joined with `", "`.
`body` is preserved exactly — no newline normalisation, no trimming — so it can be handed straight
to `webhook_verify_signature`. `bodyJson` holds the parsed body when it is valid JSON, otherwise
`null` and `parseError` explains why. `warnings` covers a missing header/body separator, a missing
or unusual version token, malformed header lines, `Content-Length` drift, `Transfer-Encoding:
chunked` (reported, not decoded), and a JSON `Content-Type` with an empty body.

## Configuration

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `sampleUrl` | string | `http://127.0.0.1:3080/api/webhooks/github` | Target URL for generated `curl` commands and the `ping` sample's `hook.config.url`. |
| `signingSecret` | string | `''` | When non-empty, samples carry `X-Hub-Signature-256` computed over `bodyToPost`. |
| `defaultToleranceSeconds` | number | `300` | Freshness window for Stripe-style `t=` timestamps. |

## Development

```bash
npm install --no-audit --no-fund
npx tsc --noEmit
npm run build          # lib/index.js + lib/index.d.ts
npx vitest run
node scripts/load-smoke.mjs
```

## License

MIT
