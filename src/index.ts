/**
 * Offline webhook fixtures and HMAC signature maths for DeepSeek Harness.
 * `webhook_generate_sample` builds a deterministic sample payload for one of five
 * built-in event shapes plus a ready-to-run curl command; `webhook_verify_signature`
 * checks a GitHub-style `sha256=<hex>` or Stripe-style `t=<ts>,v1=<hex>` HMAC-SHA256
 * header against the exact bytes that were sent; `webhook_parse_request` splits raw
 * HTTP request text into method, path, headers (folded lines joined, keys lowered)
 * and body. Every tool is pure and in-process: no socket is bound, no listener is
 * started, no request is sent, and no subprocess is run, so a webhook receiver can
 * be exercised entirely from the model transcript.
 * @module @qingshanjiluo/dsh-webhook-tester
 */
import { createHmac, timingSafeEqual } from 'node:crypto'

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import z from '@deepseek-ai/schemastery'

export const name = 'dsh-webhook-tester'
export const inject = ['tools']

/** Deployment defaults for the webhook tester. */
export interface Config {
  /** Absolute URL the generated `curl` command posts to. */
  sampleUrl: string
  /** HMAC-SHA256 secret used to sign generated samples; empty means "do not sign". */
  signingSecret: string
  /** Freshness window applied to Stripe-style `t=` timestamps, in seconds. */
  defaultToleranceSeconds: number
}

/** Schemastery configuration for the webhook tester. */
export const Config: z<Config> = z.object({
  sampleUrl: z.string().default('http://127.0.0.1:3080/api/webhooks/github'),
  signingSecret: z.string().default(''),
  defaultToleranceSeconds: z.number().default(300),
})

/* -------------------------------------------------------------------------- */
/* Shared JSON helpers                                                          */
/* -------------------------------------------------------------------------- */

/** Any lossless JSON value a sample payload or override map may hold. */
type Json = string | number | boolean | null | Json[] | JsonRecord
/** A JSON object with string keys. */
interface JsonRecord {
  [key: string]: Json
}

/** Whether one JSON value is an object (arrays and null excluded). */
function isJsonObject(value: Json): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Keys of a JSON object value; empty for arrays, null, and scalars. Used by the
 * renderers, which see unconstrained `json` output nodes as loose JSON values.
 * @param value - any JSON value.
 * @returns Own enumerable string keys in insertion order.
 */
function objectKeys(value: unknown): string[] {
  if (value === null || value === undefined) return []
  if (typeof value !== 'object' || Array.isArray(value)) return []
  return Object.keys(value as Record<string, unknown>)
}

/**
 * Re-materialise an untrusted value as own-realm, JSON-safe data.
 * @param value - caller-supplied argument, however shaped.
 * @returns A detached copy, or `undefined` when the value is not JSON data.
 */
function jsonClone(value: unknown): Json | undefined {
  if (value === undefined) return undefined
  let text: string | undefined
  try {
    text = JSON.stringify(value)
  } catch {
    return undefined
  }
  if (text === undefined) return undefined
  try {
    return JSON.parse(text) as Json
  } catch {
    return undefined
  }
}

/**
 * Recursively overlay one sample object with caller overrides. Objects merge key by
 * key; arrays and scalars replace the sample value outright.
 * @param base - built-in sample object.
 * @param overrides - caller overlay with the same shape.
 * @returns A new object; neither input is mutated.
 */
function deepMerge(base: JsonRecord, overrides: JsonRecord): JsonRecord {
  const merged: JsonRecord = { ...base }
  for (const key of Object.keys(overrides)) {
    const incoming = overrides[key] as Json
    const current: Json | undefined = merged[key]
    merged[key] = current !== undefined && isJsonObject(current) && isJsonObject(incoming)
      ? deepMerge(current, incoming)
      : incoming
  }
  return merged
}

/** POSIX-shell single-quote wrapping so JSON bodies survive pasting into a shell. */
function shellQuote(value: string): string {
  return `'${value.split(`'`).join(`'\\''`)}'`
}

/** Lower-case hex HMAC-SHA256 of `message` under `secret`. */
function hmacSha256Hex(secret: string, message: string): string {
  return createHmac('sha256', secret).update(message, 'utf8').digest('hex')
}

/* -------------------------------------------------------------------------- */
/* Sample payloads                                                             */
/* -------------------------------------------------------------------------- */

const BUILT_IN_EVENTS = ['push', 'pull_request', 'issue', 'ping', 'generic'] as const
type BuiltInEvent = (typeof BUILT_IN_EVENTS)[number]

/** Header value a real provider would use for each built-in shape. */
const WIRE_EVENT: Record<BuiltInEvent, string> = {
  push: 'push',
  pull_request: 'pull_request',
  issue: 'issues',
  ping: 'ping',
  generic: 'generic',
}

/** Accepted spellings folded onto a built-in shape. */
const EVENT_ALIASES: Record<string, BuiltInEvent> = {
  push: 'push',
  push_event: 'push',
  pull_request: 'pull_request',
  pullrequest: 'pull_request',
  pull: 'pull_request',
  pr: 'pull_request',
  issue: 'issue',
  issues: 'issue',
  ping: 'ping',
  hook_ping: 'ping',
  generic: 'generic',
  custom: 'generic',
  unknown: 'generic',
}

const DELIVERY_ID = '6f1c2a34-56b7-4c8d-9e0f-1a2b3c4d5e6f'
const SAMPLE_TIME = '2024-05-17T09:30:00Z'
const SHA_BEFORE = '0d1f7c3a5b8e4c2d9a6f1b3e5c7d9a1b3c5d7e9f'
const SHA_AFTER = '4f8a2c6d0e1b3a5c7d9e1f3b5c7d9e1f3a5b7c9d'

function sampleRepository(): JsonRecord {
  return {
    id: 135493200,
    node_id: 'R_kgDOBy6zSA',
    name: 'hello-webhooks',
    full_name: 'octocat/hello-webhooks',
    private: false,
    owner: { login: 'octocat', id: 1, node_id: 'MDQ6VXNlcjE', type: 'User', site_admin: false },
    html_url: 'https://example.invalid/octocat/hello-webhooks',
    url: 'https://example.invalid/api/repositories/135493200',
    branch: 'main',
    language: 'TypeScript',
    visibility: 'public',
    default_branch: 'main',
  }
}

function sampleSender(): JsonRecord {
  return { login: 'octocat', id: 1, node_id: 'MDQ6VXNlcjE', type: 'User', site_admin: false }
}

function sampleCommit(index: number): JsonRecord {
  return {
    id: index === 0 ? SHA_AFTER : SHA_BEFORE,
    tree_id: 'b6d0c6e4f2a14d8e9c0d1e2f3a4b5c6d7e8f9012',
    message: index === 0 ? 'feat(webhook): verify signatures offline' : 'chore: seed fixture data',
    timestamp: SAMPLE_TIME,
    url: `https://example.invalid/octocat/hello-webhooks/commit/${index === 0 ? SHA_AFTER : SHA_BEFORE}`,
    author: { name: 'The Octocat', email: 'octocat@example.invalid', username: 'octocat' },
    committer: { name: 'The Octocat', email: 'octocat@example.invalid', username: 'octocat' },
    added: index === 0 ? ['src/webhook.ts'] : [],
    removed: index === 0 ? [] : ['docs/old-notes.md'],
    modified: index === 0 ? ['README.md'] : ['package.json'],
  }
}

function buildSample(event: BuiltInEvent, wireEvent: string, hookUrl: string): JsonRecord {
  if (event === 'push') {
    return {
      ref: 'refs/heads/main',
      before: SHA_BEFORE,
      after: SHA_AFTER,
      created: false,
      deleted: false,
      forced: false,
      base_url: 'https://example.invalid/octocat/hello-webhooks',
      html_url: 'https://example.invalid/octocat/hello-webhooks',
      url: 'https://example.invalid/octocat/hello-webhooks',
      compare: `https://example.invalid/octocat/hello-webhooks/compare/${SHA_BEFORE.slice(0, 7)}...${SHA_AFTER.slice(0, 7)}`,
      commits: [sampleCommit(0), sampleCommit(1)],
      head_commit: sampleCommit(0),
      repository: sampleRepository(),
      pusher: { name: 'octocat', email: 'octocat@example.invalid' },
      sender: sampleSender(),
    }
  }

  if (event === 'pull_request') {
    return {
      action: 'opened',
      number: 42,
      pull_request: {
        id: 1800000001,
        node_id: 'PR_kwDOBy6zSM5hvXQ9',
        number: 42,
        state: 'open',
        locked: false,
        title: 'feat(webhook): verify signatures offline',
        body: 'Adds a deterministic fixture and an HMAC-SHA256 check. No listener is required.',
        draft: false,
        user: sampleSender(),
        url: 'https://example.invalid/api/repos/octocat/hello-webhooks/pulls/42',
        html_url: 'https://example.invalid/octocat/hello-webhooks/pull/42',
        created_at: SAMPLE_TIME,
        updated_at: SAMPLE_TIME,
        closed_at: null,
        merged_at: null,
        mergeable_state: 'clean',
        draft_comment: null,
        additions: 128,
        deletions: 12,
        changed_files: 5,
        commits: 3,
        review_comments: 0,
        head: {
          label: 'octocat:feat/webhook-fixtures',
          ref: 'feat/webhook-fixtures',
          sha: SHA_AFTER,
          repo: sampleRepository(),
        },
        base: { label: 'octocat:main', ref: 'main', sha: SHA_BEFORE, repo: sampleRepository() },
        labels: [{ id: 208045946, name: 'enhancement', color: '84b6eb', default: true }],
        requested_reviewers: [],
        requested_reviewers_teams: [],
      },
      repository: sampleRepository(),
      sender: sampleSender(),
      installation: { id: 30791006, account: sampleSender() },
    }
  }

  if (event === 'issue') {
    return {
      action: 'opened',
      number: 128,
      issue: {
        id: 2300000001,
        node_id: 'I_kwDOBy6zSM6AaBcD',
        number: 128,
        state: 'open',
        state_reason: null,
        locked: false,
        title: 'Signature check fails on UTF-8 request bodies',
        body: 'Hash the raw bytes that arrived, before any JSON round trip, or non-ASCII payloads will not match.',
        user: sampleSender(),
        labels: [{ id: 208045946, name: 'bug', color: 'd73a4a', default: true }],
        assignees: [],
        milestone: null,
        comments: 0,
        created_at: SAMPLE_TIME,
        updated_at: SAMPLE_TIME,
        closed_at: null,
        url: 'https://example.invalid/api/repos/octocat/hello-webhooks/issues/128',
        html_url: 'https://example.invalid/octocat/hello-webhooks/issues/128',
        repository_url: 'https://example.invalid/api/repos/octocat/hello-webhooks',
      },
      repository: sampleRepository(),
      sender: sampleSender(),
      installation: { id: 30791006, account: sampleSender() },
    }
  }

  if (event === 'ping') {
    return {
      zen: 'Practicality beats purity.',
      hook_id: 135493200,
      hook: {
        type: 'Repository',
        id: 135493200,
        name: 'web',
        active: true,
        events: ['push', 'pull_request', 'issues'],
        config: { content_type: 'json', insecure_ssl: '0', url: hookUrl },
        updated_at: SAMPLE_TIME,
        created_at: SAMPLE_TIME,
        url: 'https://example.invalid/api/repos/octocat/hello-webhooks/hooks/135493200',
      },
      repository: sampleRepository(),
      sender: sampleSender(),
    }
  }

  // Provider-agnostic envelope, also the fallback for unrecognised event names.
  return {
    event: wireEvent,
    id: 'whevt_000000000000000000000000',
    delivery: DELIVERY_ID,
    timestamp: SAMPLE_TIME,
    apiVersion: '2024-05-17',
    data: {
      message: 'Hello from dsh-webhook-tester',
      attempt: 1,
      items: ['alpha', 'beta', 'gamma'],
      nested: { flag: true, count: 3, note: null },
    },
    sender: { name: 'sample-sender', id: 7 },
  }
}

/** Outcome of {@link makeSample}. */
interface SampleResult {
  requestedType: string
  eventType: string
  known: boolean
  wireEvent: string
  targetUrl: string
  payload: JsonRecord
  payloadJson: string
  bodyToPost: string
  headers: JsonRecord
  curl: string
  byteLength: number
  warnings: string[]
}

/**
 * Build one deterministic sample delivery: payload, headers, and a POSIX curl.
 * @param requestedType - event name supplied by the caller.
 * @param overrides - JSON overlay merged onto the built-in shape, if any.
 * @param config - deployment defaults for URL and signing secret.
 * @returns Every projection the receiver-under-test needs.
 */
function makeSample(requestedType: string, overrides: unknown, config: Config): SampleResult {
  const warnings: string[] = []
  const cleaned = requestedType.trim().toLowerCase().replace(/[\s-]+/g, '_')
  // Own-property lookup only, so names like "constructor" never resolve to inherited values.
  const aliasHit = Object.prototype.hasOwnProperty.call(EVENT_ALIASES, cleaned)
    ? EVENT_ALIASES[cleaned]
    : undefined
  const known = aliasHit !== undefined
  const event: BuiltInEvent = aliasHit ?? 'generic'
  const wireEvent = known ? WIRE_EVENT[event] : cleaned === '' ? 'generic' : cleaned

  if (!known) {
    warnings.push(
      `"${requestedType}" is not a built-in shape; generated the generic envelope with ` +
      `event "${wireEvent}". Built-ins: ${BUILT_IN_EVENTS.join(', ')}.`,
    )
  }

  let payload = buildSample(event, wireEvent, config.sampleUrl)
  const cloned = jsonClone(overrides)
  if (cloned === undefined) {
    if (overrides !== undefined) warnings.push('overrides were ignored: not JSON data.')
  } else if (!isJsonObject(cloned)) {
    warnings.push('overrides were ignored: expected a JSON object.')
  } else {
    payload = deepMerge(payload, cloned)
  }

  const bodyToPost = JSON.stringify(payload)
  const payloadJson = JSON.stringify(payload, null, 2)
  const byteLength = Buffer.byteLength(bodyToPost, 'utf8')

  const headers: JsonRecord = event === 'generic'
    ? {
        'Content-Type': 'application/json; charset=utf-8',
        'User-Agent': 'dsh-webhook-tester/0.1',
        'X-Webhook-Event': wireEvent,
        'X-Webhook-Delivery': DELIVERY_ID,
      }
    : {
        'Content-Type': 'application/json; charset=utf-8',
        'User-Agent': 'GitHub-Hookshot/dsh-webhook-tester',
        'X-GitHub-Event': wireEvent,
        'X-GitHub-Delivery': DELIVERY_ID,
      }
  headers['Content-Length'] = String(byteLength)

  if (config.signingSecret.length === 0) {
    warnings.push('config signingSecret is empty, so the sample is unsigned.')
  } else {
    headers['X-Hub-Signature-256'] = `sha256=${hmacSha256Hex(config.signingSecret, bodyToPost)}`
  }

  const lines = [`curl -sS -X POST ${shellQuote(config.sampleUrl)}`]
  for (const [name, value] of Object.entries(headers)) {
    lines.push(`  -H ${shellQuote(`${name}: ${String(value)}`)}`)
  }
  lines.push(`  --data-raw ${shellQuote(bodyToPost)}`)

  return {
    requestedType,
    eventType: event,
    known,
    wireEvent,
    targetUrl: config.sampleUrl,
    payload,
    payloadJson,
    bodyToPost,
    headers,
    curl: lines.join(' \\\n'),
    byteLength,
    warnings,
  }
}

/* -------------------------------------------------------------------------- */
/* Signature verification                                                      */
/* -------------------------------------------------------------------------- */

/** Outcome of {@link verifySignature}. */
interface VerifyResult {
  valid: boolean
  scheme: string
  reason: string
}

const SCHEME_GITHUB = 'github-sha256'
const SCHEME_STRIPE = 'stripe-timestamped'
const SCHEME_RAW = 'raw-sha256'
const SCHEME_UNKNOWN = 'unknown'
const HEX64 = /^[0-9a-f]{64}$/i

/**
 * Drop a pasted header name so `X-Hub-Signature-256: sha256=abc` and `sha256=abc`
 * behave identically.
 * @param header - raw header value, optionally prefixed with its field name.
 * @returns The value portion, trimmed.
 */
function stripHeaderName(header: string): string {
  const match = /^[ \t]*[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*[ \t]*:[ \t]*([\s\S]*)$/.exec(header)
  return (match ? match[1] : header).trim()
}

/**
 * Constant-time-ish comparison of one computed digest against every candidate the
 * header offered (providers may send two signatures during key rotation).
 * @param secret - shared HMAC key.
 * @param message - exact bytes the sender signed.
 * @param candidates - lowercase hex digests claimed by the header.
 * @returns Whether any candidate equals the computed digest.
 */
function digestMatches(secret: string, message: string, candidates: readonly string[]): boolean {
  const computed = Buffer.from(hmacSha256Hex(secret, message), 'utf8')
  let matched = false
  for (const candidate of candidates) {
    const buffer = Buffer.from(candidate.toLowerCase(), 'utf8')
    if (buffer.length === computed.length && timingSafeEqual(computed, buffer)) matched = true
  }
  return matched
}

/**
 * Verify a webhook signature header over the exact payload text.
 * @param payload - raw request body, byte-for-byte as received.
 * @param secret - endpoint signing secret.
 * @param header - signature header value as received.
 * @param tolerance - freshness window in seconds; `<= 0` skips the `t=` check.
 * @param nowSeconds - current unix seconds, injected for determinism.
 * @returns Validity, the recognised scheme, and a one-line reason.
 */
function verifySignature(
  payload: string,
  secret: string,
  header: string,
  tolerance: number,
  nowSeconds: number,
): VerifyResult {
  const fail = (scheme: string, reason: string): VerifyResult => ({ valid: false, scheme, reason })

  if (secret.trim().length === 0) return fail(SCHEME_UNKNOWN, 'secret is empty')
  const value = stripHeaderName(header)
  if (value.length === 0) return fail(SCHEME_UNKNOWN, 'signature header is empty')

  const segments = value.split(',').map(segment => segment.trim()).filter(segment => segment.length > 0)
  const stamps: string[] = []
  const github: string[] = []
  const stripe: string[] = []
  const bare: string[] = []
  const foreign: string[] = []
  for (const segment of segments) {
    const eq = segment.indexOf('=')
    if (eq === -1) {
      bare.push(segment)
      continue
    }
    const key = segment.slice(0, eq).trim().toLowerCase()
    const rest = segment.slice(eq + 1).trim()
    if (key === 't') stamps.push(rest)
    else if (key === 'v1') stripe.push(rest)
    else if (key === 'sha256') github.push(rest)
    else foreign.push(key)
  }

  const isStripe = stripe.length > 0 || stamps.length > 0
  const scheme = isStripe ? SCHEME_STRIPE : github.length > 0 ? SCHEME_GITHUB : bare.length > 0 ? SCHEME_RAW : SCHEME_UNKNOWN

  if (scheme === SCHEME_UNKNOWN) {
    return foreign.length > 0
      ? fail(SCHEME_UNKNOWN, `unsupported signature parameter "${foreign[0]}"; this tool verifies HMAC-SHA256 only (sha256=<hex> or t=<ts>,v1=<hex>)`)
      : fail(SCHEME_UNKNOWN, 'signature header holds no sha256=<hex>, v1=<hex>, or bare hex digest')
  }

  if (isStripe) {
    if (stamps.length === 0) return fail(SCHEME_STRIPE, 'timestamped signature has no t= segment')
    if (stripe.length === 0) return fail(SCHEME_STRIPE, 'timestamped signature has no v1= digest')
    if (stamps.length > 1 || github.length > 0 || bare.length > 0) {
      return fail(SCHEME_STRIPE, 'timestamped signature header mixes segments from more than one scheme')
    }
  }

  const digests = isStripe ? stripe : github.length > 0 ? github : bare
  for (const digest of digests) {
    if (!HEX64.test(digest)) return fail(scheme, 'signature digest is not 64 hexadecimal characters')
  }

  const message = isStripe ? `${stamps[0]}.${payload}` : payload
  if (!digestMatches(secret, message, digests)) {
    return fail(scheme, 'signature does not match the payload and secret')
  }

  if (isStripe) {
    const stamp = Number(stamps[0])
    if (!Number.isFinite(stamp) || !/^\d+$/.test(stamps[0] as string)) {
      return fail(SCHEME_STRIPE, `t=${stamps[0]} is not a unix-seconds timestamp`)
    }
    if (Number.isFinite(tolerance) && tolerance > 0) {
      const age = Math.abs(Math.floor(nowSeconds) - stamp)
      if (age > tolerance) {
        return fail(SCHEME_STRIPE, `timestamp is ${age}s away, outside the ${tolerance}s tolerance`)
      }
    }
  }

  return { valid: true, scheme, reason: 'signature matches the payload and secret' }
}

/* -------------------------------------------------------------------------- */
/* Raw HTTP request parsing                                                    */
/* -------------------------------------------------------------------------- */

/** Outcome of {@link parseRawRequest}. */
interface ParsedRequest {
  method: string
  path: string
  httpVersion: string
  headers: Record<string, string>
  body: string
  bodyJson: Json | null
  parseError: string
  warnings: string[]
}

/**
 * Parse raw HTTP request text into its parts. Header names are lowercased, folded
 * (continuation) lines are joined, repeated headers are comma-joined, and the body
 * is preserved byte-for-byte so it can be re-verified with `webhook_verify_signature`.
 * @param raw - the whole request, request line through final body byte.
 * @returns Method, path, HTTP version, headers, body, parsed body JSON, and notes.
 */
function parseRawRequest(raw: string): ParsedRequest {
  const warnings: string[] = []
  const headers: Record<string, string> = {}
  const empty: ParsedRequest = {
    method: '', path: '', httpVersion: '', headers, body: '', bodyJson: null, parseError: '', warnings,
  }
  if (raw.trim().length === 0) {
    empty.parseError = 'raw HTTP request is empty'
    return empty
  }

  const separator = /\r?\n\r?\n/.exec(raw)
  const head = separator ? raw.slice(0, separator.index) : raw
  const body = separator ? raw.slice(separator.index + separator[0].length) : ''
  if (!separator) warnings.push('no blank line separated the headers from the body; treated all text as headers')

  const lines = head.split(/\r?\n/)
  const requestLine = (lines.shift() ?? '').trim()
  if (requestLine.length === 0) {
    empty.parseError = 'request line is missing'
  } else {
    const parts = requestLine.split(/\s+/)
    empty.method = parts[0] as string
    empty.path = parts[1] ?? ''
    if (parts.length < 2) {
      empty.parseError = `request line "${requestLine}" is not "<method> <path> <version>"`
      empty.path = ''
    } else if (parts.length === 2) {
      warnings.push('request line carries no HTTP version token')
    } else {
      const version = parts.slice(2).join(' ')
      if (/^HTTP\/\d+(\.\d+)?$/i.test(version)) {
        empty.httpVersion = version.slice(version.indexOf('/') + 1)
      } else {
        empty.httpVersion = version
        warnings.push(`request line version token "${version}" is not HTTP/x.y`)
      }
    }
  }

  let folded = 0
  let lastIndex: string | null = null
  for (const line of lines) {
    if (line.length === 0) continue
    if (/^[ \t]/.test(line)) {
      if (lastIndex === null) {
        warnings.push(`ignored leading continuation line "${line.trim()}"`)
        continue
      }
      headers[lastIndex] = `${headers[lastIndex] ?? ''} ${line.trim()}`.replace(/^ +/, '')
      folded += 1
      continue
    }
    const colon = line.indexOf(':')
    if (colon === -1) {
      warnings.push(`ignored malformed header line "${line.trim()}"`)
      lastIndex = null
      continue
    }
    const key = line.slice(0, colon).trim().toLowerCase()
    const value = line.slice(colon + 1).trim()
    if (key.length === 0) {
      warnings.push(`ignored header line without a field name "${line.trim()}"`)
      lastIndex = null
      continue
    }
    if (Object.prototype.hasOwnProperty.call(headers, key)) {
      headers[key] = `${headers[key]}, ${value}`
      warnings.push(`repeated "${key}" header joined with ", "`)
    } else {
      headers[key] = value
    }
    lastIndex = key
  }
  if (folded > 0) warnings.push(`${folded} folded header line(s) joined into their predecessors`)

  const declared = headers['content-length']
  if (declared !== undefined) {
    const expected = Number(declared.split(',')[0]?.trim())
    if (!Number.isFinite(expected) || expected < 0) {
      warnings.push(`Content-Length "${declared}" is not a byte count`)
    } else if (expected !== Buffer.byteLength(body, 'utf8')) {
      warnings.push(`body is ${Buffer.byteLength(body, 'utf8')} bytes but Content-Length says ${expected}`)
    }
  }
  if (headers['transfer-encoding']?.toLowerCase().includes('chunked')) {
    warnings.push('Transfer-Encoding: chunked is reported as received, not decoded')
  }

  empty.body = body
  const trimmedBody = body.trim()
  const isJsonType = headers['content-type']?.toLowerCase().includes('json')
  if (trimmedBody.length === 0) {
    if (isJsonType) warnings.push('Content-Type claims JSON but the body is empty')
    return empty
  }
  try {
    empty.bodyJson = jsonClone(JSON.parse(trimmedBody) as Json) ?? null
  } catch (error) {
    empty.bodyJson = null
    empty.parseError = `body is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
  }
  return empty
}

/* -------------------------------------------------------------------------- */
/* Registration                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Register the three webhook tools on `ctx.tools`.
 * @param ctx - registrant context carrying the tool registry.
 * @param config - deployment's explicit defaults.
 */
export function apply(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'webhook_generate_sample',
    description:
      'Generate a deterministic sample webhook delivery for one built-in event shape ' +
      '(push, pull_request, issue, ping, generic). Returns the payload object, its ' +
      'pretty JSON, the exact compact body to post, realistic headers, byte count, and ' +
      'a ready-to-run POSIX curl command. Optionally pass overrides: a JSON object ' +
      'merged recursively onto the sample (arrays and scalars replace sample values). ' +
      'Nothing is sent — copy the curl command to reach your own receiver. Unknown event ' +
      'names fall back to the generic envelope and are noted in warnings.',
    parameters: {
      eventType: {
        type: 'string',
        required: true,
        description: 'Event shape: push, pull_request (pr, pull-request), issue (issues), ping, or generic. Other names use the generic envelope.',
      },
      overrides: {
        type: 'json',
        description: 'JSON object deep-merged onto the sample payload, e.g. {"number":7,"repository":{"full_name":"acme/api"}}.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          requestedType: { type: 'string', required: true, description: 'Event name exactly as the caller asked for it.' },
          eventType: { type: 'string', required: true, description: 'Built-in shape actually generated.' },
          known: { type: 'boolean', required: true, description: 'Whether the request matched a built-in shape.' },
          wireEvent: { type: 'string', required: true, description: 'Value used for the provider event header and generic envelope.' },
          targetUrl: { type: 'string', required: true, description: 'URL the curl command posts to.' },
          payload: { type: 'json', required: true, description: 'The sample payload as a JSON object.' },
          payloadJson: { type: 'string', required: true, description: 'Two-space-indented JSON text of the payload.' },
          bodyToPost: { type: 'string', required: true, description: 'Compact JSON bytes the curl command sends; sign and verify against this exact string.' },
          headers: { type: 'json', required: true, description: 'Realistic delivery headers, including Content-Length and any signature.' },
          curl: { type: 'string', required: true, description: 'POSIX curl command with backslash continuations.' },
          byteLength: { type: 'integer', required: true, description: 'UTF-8 byte length of bodyToPost.' },
          warnings: { type: 'array', required: true, description: 'Advisories; empty for a clean built-in sample.', items: { type: 'string' } },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: [
          `POST ${value.targetUrl} — ${value.eventType} sample, ${value.byteLength} bytes`,
          '',
          value.curl,
          '',
          `Payload (${value.requestedType}${value.known ? '' : ', unknown type, generic envelope'}):`,
          value.payloadJson,
          ...(value.warnings.length === 0 ? [] : ['', `Warnings: ${value.warnings.join(' ')}`]),
        ].join('\n'),
      }],
    },
    isConcurrencySafe: () => true,
    execute(args) {
      return Promise.resolve(makeSample(args.eventType, args.overrides, config))
    },
  }))

  ctx.tools.register(defineTool({
    name: 'webhook_verify_signature',
    description:
      'Verify a webhook HMAC-SHA256 signature over the exact payload bytes received. ' +
      'Accepts GitHub-style `sha256=<hex>` (X-Hub-Signature-256), a bare 64-character hex ' +
      'digest, or Stripe-style `t=<ts>,v1=<hex>` with a freshness tolerance. The whole ' +
      'header line may be pasted; a leading header name is ignored. Returns { valid, ' +
      'scheme, reason }. Pass payload verbatim (never re-serialised JSON), and pass ' +
      'tolerance 0 to skip the timestamp check.',
    parameters: {
      payload: { type: 'string', required: true, description: 'Raw request body exactly as it arrived.' },
      secret: { type: 'string', required: true, description: 'Shared webhook signing secret.' },
      signatureHeader: { type: 'string', required: true, description: 'Signature header value, e.g. sha256=<hex> or t=<ts>,v1=<hex>.' },
      tolerance: {
        type: 'number',
        description: 'Freshness window in seconds for t= timestamps; defaults to config defaultToleranceSeconds, 0 or less disables the check.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          valid: { type: 'boolean', required: true, description: 'Whether the signature is authentic and fresh.' },
          scheme: { type: 'string', required: true, description: 'github-sha256, stripe-timestamped, raw-sha256, or unknown.' },
          reason: { type: 'string', required: true, description: 'One-line verdict or the first failure found.' },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.valid
          ? `Signature VALID (${value.scheme}): ${value.reason}`
          : `Signature INVALID (${value.scheme}): ${value.reason}`,
      }],
    },
    isConcurrencySafe: () => true,
    execute(args) {
      const tolerance = args.tolerance === undefined ? config.defaultToleranceSeconds : args.tolerance
      return Promise.resolve(verifySignature(
        args.payload, args.secret, args.signatureHeader, tolerance, Math.floor(Date.now() / 1000),
      ))
    },
  }))

  ctx.tools.register(defineTool({
    name: 'webhook_parse_request',
    description:
      'Parse raw HTTP request text (request line, headers, blank line, body) into parts: ' +
      'method, path, httpVersion, headers with lowercased keys (folded continuation lines ' +
      'joined, repeats comma-joined), the untouched body, and bodyJson when the body is ' +
      'valid JSON. Use it on a captured delivery to inspect or replay it offline; warnings ' +
      'report Content-Length mismatches, chunked bodies, and malformed lines, and ' +
      'parseError reports an empty request or a body that is not JSON.',
    parameters: {
      rawHttp: {
        type: 'string',
        required: true,
        description: 'The complete request text, e.g. "POST /hook HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n{\\"a\\":1}".',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          method: { type: 'string', required: true, description: 'Request-line method, or empty when absent.' },
          path: { type: 'string', required: true, description: 'Request-line target (path and query), or empty when absent.' },
          httpVersion: { type: 'string', required: true, description: 'Version number without the HTTP/ prefix, e.g. 1.1.' },
          headers: { type: 'json', required: true, description: 'Lowercased header names mapped to their joined values.' },
          body: { type: 'string', required: true, description: 'Body bytes exactly as received, past the first blank line.' },
          bodyJson: { type: 'json', required: true, description: 'Parsed body when it is valid JSON, otherwise null.' },
          parseError: { type: 'string', required: true, description: 'Empty when nothing failed; otherwise the blocking defect.' },
          warnings: { type: 'array', required: true, description: 'Advisories about the request; empty when it is well formed.', items: { type: 'string' } },
        },
      },
      render: (_args, value) => {
        const body = value.bodyJson
        const shape = body === null
          ? ''
          : Array.isArray(body) ? 'array' : typeof body === 'object' ? objectKeys(body).join(', ') : String(body)
        const text = [
          `${value.method || '(no method)'} ${value.path || '(no path)'} HTTP/${value.httpVersion || '?'}`,
          `${objectKeys(value.headers).length} header(s), ${Buffer.byteLength(value.body, 'utf8')} body byte(s)`,
          ...(shape === '' ? [] : [`bodyJson: ${shape}`]),
          ...(value.parseError.length === 0 ? [] : [`error: ${value.parseError}`]),
          ...(value.warnings.length === 0 ? [] : [`warnings: ${value.warnings.join(' | ')}`]),
        ].join('\n')
        return [{ type: 'text', text }]
      },
    },
    isConcurrencySafe: () => true,
    execute(args) {
      return Promise.resolve(parseRawRequest(args.rawHttp))
    },
  }))
}
