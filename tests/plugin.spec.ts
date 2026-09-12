import { describe, expect, it } from 'vitest'

import { apply, Config, inject, name } from '../src/index.ts'

interface RegisteredTool {
  name: string
  parameters: { properties: Record<string, unknown>; required?: string[] }
  isConcurrencySafe(args: Record<string, unknown>): boolean
  execute(args: never, exec: never): Promise<unknown>
}

type Rec = Record<string, unknown>

const DEFAULTS = {
  sampleUrl: 'http://127.0.0.1:3080/api/webhooks/github',
  signingSecret: '',
  defaultToleranceSeconds: 300,
}

function mount(overrides: Partial<typeof DEFAULTS> = {}): RegisteredTool[] {
  const registered: RegisteredTool[] = []
  const ctx = { tools: { register: (def: RegisteredTool) => registered.push(def) } }
  // The plugin only reads ctx.tools, so this stub is the whole registrant surface it touches.
  apply(ctx as never, { ...DEFAULTS, ...overrides } as never)
  return registered
}

function tool(toolName: string, overrides: Partial<typeof DEFAULTS> = {}): RegisteredTool {
  const found = mount(overrides).find(candidate => candidate.name === toolName)
  if (!found) throw new Error(`${toolName} was not registered`)
  return found
}

function run(registered: RegisteredTool, args: Record<string, unknown>): Promise<Rec> {
  return registered.execute(args as never, {} as never) as Promise<Rec>
}

/* Known HMAC-SHA256 vectors, computed independently with node:crypto. */
const GH_PAYLOAD = '{"action":"opened","number":42}'
const GH_SECRET = 'my-webhook-secret'
const GH_SHA256 = 'sha256=3b00763535ea06e5c6a202b740b839d95d4540d29eeab983f68fe672d4b1574f'
const GH_SHA1_ONLY = 'sha1=443f996885395c9bfc3e625c52e9fdaaf0d9eeb3'
const STRIPE_PAYLOAD = '{"id":"evt_1h6Zu2Q7v8xYz","type":"account.updated"}'
const STRIPE_SECRET = 'whsec_test_2f6b1c8d9e'
const STRIPE_T = '1700000000'
const STRIPE_V1 = 'ec2f81a50788f19b7afc684dd5172d789e57b190925b1a0d49a0dfbb9fe56102'
const STRIPE_V1_ROTATING = '2596ced43cfcf3c0180813eff5d19b3f2a497a2d718719db4735c6438a86fb58'
const STRIPE_V1_WRONG = '10e033175557d7e152e44985a6ea196eb7d3fb879e0bb38f28c5c0de3c615308'

describe('dsh-webhook-tester plugin contract', () => {
  it('exports the Cordis function-plugin face', () => {
    expect(name).toBe('dsh-webhook-tester')
    expect(inject).toEqual(['tools'])
    expect(typeof apply).toBe('function')
    expect(Config).toBeInstanceOf(Object)
  })

  it('registers exactly the three documented tools, all concurrency-safe', () => {
    const registered = mount()
    expect(registered.map(entry => entry.name)).toEqual([
      'webhook_generate_sample', 'webhook_verify_signature', 'webhook_parse_request',
    ])
    // defineTool only reports concurrency safety for schema-valid arguments.
    const sampleArgs: Record<string, unknown> = {
      webhook_generate_sample: { eventType: 'push' },
      webhook_verify_signature: {
        payload: GH_PAYLOAD, secret: GH_SECRET, signatureHeader: GH_SHA256,
      },
      webhook_parse_request: { rawHttp: `POST /hook HTTP/1.1\r\n\r\n${GH_PAYLOAD}` },
    }
    for (const entry of registered) {
      expect(entry.isConcurrencySafe(sampleArgs[entry.name] as Record<string, unknown>), entry.name).toBe(true)
      expect(entry.isConcurrencySafe({}), entry.name).toBe(false)
    }
  })

  it('declares only the truly required parameters as required', () => {
    expect(tool('webhook_generate_sample').parameters.required ?? []).toEqual(['eventType'])
    expect(tool('webhook_verify_signature').parameters.required ?? []).toEqual([
      'payload', 'secret', 'signatureHeader',
    ])
    expect(tool('webhook_parse_request').parameters.required ?? []).toEqual(['rawHttp'])
  })
})

describe('webhook_generate_sample', () => {
  it('generates the push shape with realistic headers and a runnable curl', async () => {
    const result = await run(tool('webhook_generate_sample'), { eventType: 'push' })
    expect(result.known).toBe(true)
    expect(result.eventType).toBe('push')
    const payload = result.payload as Rec
    expect(payload.ref).toBe('refs/heads/main')
    expect((payload.repository as Rec).full_name).toBe('octocat/hello-webhooks')
    expect((payload.commits as unknown[]).length).toBe(2)
    const headers = result.headers as Rec
    expect(headers['X-GitHub-Event']).toBe('push')
    expect(headers['Content-Length']).toBe(String(result.byteLength))
    expect(headers['X-GitHub-Delivery']).toBeTruthy()
    const curl = result.curl as string
    expect(curl.startsWith('curl -sS -X POST ')).toBe(true)
    expect(curl).toContain(`'${DEFAULTS.sampleUrl}'`)
    expect(curl).toContain('--data-raw')
    expect(curl).toContain('-H \'Content-Type: application/json; charset=utf-8\'')
  })

  it('emits payload JSON that round-trips and matches the byte count', async () => {
    const result = await run(tool('webhook_generate_sample'), { eventType: 'ping' })
    expect(JSON.parse(result.payloadJson as string)).toEqual(result.payload)
    expect(result.byteLength).toBe(Buffer.byteLength(result.bodyToPost as string, 'utf8'))
    expect((result.payload as Rec).zen).toBe('Practicality beats purity.')
    expect((result.payload as Rec).hook).toBeTruthy()
    expect(((result.payload as Rec).hook as Rec).config).toBeTruthy()
  })

  it('deep-merges overrides without dropping sibling sample keys', async () => {
    const result = await run(tool('webhook_generate_sample'), {
      eventType: 'pull_request',
      overrides: {
        number: 7,
        repository: { full_name: 'acme/api' },
        pull_request: { title: 'fix: fold headers', head: { ref: 'hotfix' } },
      },
    })
    const payload = result.payload as Rec
    expect(payload.number).toBe(7)
    const repository = payload.repository as Rec
    expect(repository.full_name).toBe('acme/api')
    expect(repository.name).toBe('hello-webhooks')
    const pullRequest = payload.pull_request as Rec
    expect(pullRequest.title).toBe('fix: fold headers')
    expect(pullRequest.state).toBe('open')
    expect((pullRequest.head as Rec).ref).toBe('hotfix')
    expect((pullRequest.base as Rec).ref).toBe('main')
    expect((pullRequest.head as Rec).sha).toBeTruthy()
  })

  it('lets arrays replace sample values outright', async () => {
    const result = await run(tool('webhook_generate_sample'), {
      eventType: 'push',
      overrides: { commits: [{ id: 'deadbeef' }] },
    })
    const commits = (result.payload as Rec).commits as unknown[]
    expect(commits.length).toBe(1)
    expect((commits[0] as Rec).id).toBe('deadbeef')
  })

  it('falls back to the generic envelope for unknown event names', async () => {
    const result = await run(tool('webhook_generate_sample'), { eventType: 'deployment' })
    expect(result.known).toBe(false)
    expect(result.eventType).toBe('generic')
    expect(result.wireEvent).toBe('deployment')
    expect((result.payload as Rec).event).toBe('deployment')
    expect((result.headers as Rec)['X-Webhook-Event']).toBe('deployment')
    expect((result.warnings as string[]).some(warning => warning.includes('not a built-in shape'))).toBe(true)
  })

  it('treats every built-in name and alias as known', async () => {
    const registered = tool('webhook_generate_sample')
    for (const request of ['push', 'PR', 'pull-request', 'issues', 'ping', 'GENERIC']) {
      const result = await run(registered, { eventType: request })
      expect(result.known, request).toBe(true)
      expect((result.warnings as string[]).filter(warning => warning.includes('not a built-in shape'))).toEqual([])
    }
    expect((await run(registered, { eventType: 'issue' })).wireEvent).toBe('issues')
    expect((await run(registered, { eventType: 'pr' })).eventType).toBe('pull_request')
  })

  it('ignores overrides that are not JSON objects and rejects inherited keys', async () => {
    const registered = tool('webhook_generate_sample')
    const arrayy = await run(registered, { eventType: 'generic', overrides: [1, 2, 3] })
    expect((arrayy.warnings as string[]).some(warning => warning.includes('expected a JSON object'))).toBe(true)
    expect((arrayy.payload as Rec).data).toBeTruthy()
    const proto = await run(registered, { eventType: 'constructor' })
    expect(proto.known).toBe(false)
    expect((proto.payload as Rec).event).toBe('constructor')
  })

  it('is deterministic and reports the unsigned default', async () => {
    const registered = tool('webhook_generate_sample')
    const first = await run(registered, { eventType: 'issue' })
    const second = await run(registered, { eventType: 'issue' })
    expect(first.payloadJson).toBe(second.payloadJson)
    expect(first.curl).toBe(second.curl)
    expect((first.warnings as string[]).some(warning => warning.includes('unsigned'))).toBe(true)
  })

  it('quotes shell-hostile characters in the curl body', async () => {
    const result = await run(tool('webhook_generate_sample'), {
      eventType: 'generic',
      overrides: { data: { note: "it's fine" } },
    })
    expect(result.curl as string).toContain(`it'\\''s fine`)
    expect(result.bodyToPost as string).toContain("it's fine")
  })

  it('signs the exact bytes it tells the caller to post when a secret is configured', async () => {
    const signed = await run(tool('webhook_generate_sample', { signingSecret: GH_SECRET }), { eventType: 'ping' })
    const signature = (signed.headers as Rec)['X-Hub-Signature-256'] as string
    expect(signature.startsWith('sha256=')).toBe(true)
    const verdict = await run(tool('webhook_verify_signature', { signingSecret: GH_SECRET }), {
      payload: signed.bodyToPost,
      secret: GH_SECRET,
      signatureHeader: signature,
    })
    expect(verdict.valid).toBe(true)
    expect(verdict.scheme).toBe('github-sha256')
    const tampered = await run(tool('webhook_verify_signature'), {
      payload: `${signed.bodyToPost} `,
      secret: GH_SECRET,
      signatureHeader: signature,
    })
    expect(tampered.valid).toBe(false)
  })
})

describe('webhook_verify_signature', () => {
  it('accepts the known GitHub X-Hub-Signature-256 vector', async () => {
    const result = await run(tool('webhook_verify_signature'), {
      payload: GH_PAYLOAD,
      secret: GH_SECRET,
      signatureHeader: GH_SHA256,
    })
    expect(result).toEqual({
      valid: true,
      scheme: 'github-sha256',
      reason: 'signature matches the payload and secret',
    })
  })

  it('accepts a pasted header line and uppercase hex', async () => {
    const withName = await run(tool('webhook_verify_signature'), {
      payload: GH_PAYLOAD,
      secret: GH_SECRET,
      signatureHeader: `X-Hub-Signature-256: ${GH_SHA256}`,
    })
    expect(withName.valid).toBe(true)
    const upper = await run(tool('webhook_verify_signature'), {
      payload: GH_PAYLOAD,
      secret: GH_SECRET,
      signatureHeader: `sha256=${GH_SHA256.slice(7).toUpperCase()}`,
    })
    expect(upper.valid).toBe(true)
  })

  it('rejects a wrong secret, a mutated payload, and a bare-hex mismatch', async () => {
    const wrongSecret = await run(tool('webhook_verify_signature'), {
      payload: GH_PAYLOAD, secret: 'other-secret', signatureHeader: GH_SHA256,
    })
    expect(wrongSecret.valid).toBe(false)
    expect(wrongSecret.reason).toContain('does not match')
    const mutated = await run(tool('webhook_verify_signature'), {
      payload: '{"action":"closed","number":42}', secret: GH_SECRET, signatureHeader: GH_SHA256,
    })
    expect(mutated.valid).toBe(false)
    const hex = GH_SHA256.slice(7)
    const bare = await run(tool('webhook_verify_signature'), {
      payload: GH_PAYLOAD, secret: GH_SECRET, signatureHeader: hex,
    })
    expect(bare).toMatchObject({ valid: true, scheme: 'raw-sha256' })
    const bareBad = await run(tool('webhook_verify_signature'), {
      payload: GH_PAYLOAD, secret: GH_SECRET, signatureHeader: `${hex.slice(0, 62)}00`,
    })
    expect(bareBad.valid).toBe(false)
  })

  it('verifies the known Stripe vector and honours the freshness tolerance', async () => {
    const header = `t=${STRIPE_T},v1=${STRIPE_V1}`
    const skip = await run(tool('webhook_verify_signature'), {
      payload: STRIPE_PAYLOAD, secret: STRIPE_SECRET, signatureHeader: header, tolerance: 0,
    })
    expect(skip).toMatchObject({ valid: true, scheme: 'stripe-timestamped' })
    const generous = await run(tool('webhook_verify_signature'), {
      payload: STRIPE_PAYLOAD, secret: STRIPE_SECRET, signatureHeader: header, tolerance: 1_000_000_000_000,
    })
    expect(generous.valid).toBe(true)
    const stale = await run(tool('webhook_verify_signature'), {
      payload: STRIPE_PAYLOAD, secret: STRIPE_SECRET, signatureHeader: header, tolerance: 300,
    })
    expect(stale.valid).toBe(false)
    expect(stale.reason).toContain('outside the 300s tolerance')
    const configured = await run(tool('webhook_verify_signature', { defaultToleranceSeconds: 5 }), {
      payload: STRIPE_PAYLOAD, secret: STRIPE_SECRET, signatureHeader: header,
    })
    expect(configured.valid).toBe(false)
    expect(configured.reason).toContain('outside the 5s tolerance')
  })

  it('accepts either v1 digest during key rotation and rejects unknown digests', async () => {
    const rotated = `t=${STRIPE_T},v1=${STRIPE_V1_WRONG},v1=${STRIPE_V1}`
    const accepted = await run(tool('webhook_verify_signature'), {
      payload: STRIPE_PAYLOAD, secret: STRIPE_SECRET, signatureHeader: rotated, tolerance: 0,
    })
    expect(accepted.valid).toBe(true)
    const rejected = await run(tool('webhook_verify_signature'), {
      payload: STRIPE_PAYLOAD, secret: STRIPE_SECRET, signatureHeader: `t=${STRIPE_T},v1=${STRIPE_V1_WRONG}`, tolerance: 0,
    })
    expect(rejected.valid).toBe(false)
    expect(rejected.scheme).toBe('stripe-timestamped')
    const wrongKey = await run(tool('webhook_verify_signature'), {
      payload: STRIPE_PAYLOAD, secret: STRIPE_SECRET, signatureHeader: `t=${STRIPE_T},v1=${STRIPE_V1}`, tolerance: 0,
    })
    expect(wrongKey.valid).toBe(true)
    const rotatedOnly = await run(tool('webhook_verify_signature'), {
      payload: STRIPE_PAYLOAD, secret: STRIPE_SECRET, signatureHeader: `t=${STRIPE_T},v1=${STRIPE_V1_ROTATING}`, tolerance: 0,
    })
    expect(rotatedOnly.valid).toBe(false)
    expect(rotatedOnly.reason).toContain('does not match')
    const otherKey = await run(tool('webhook_verify_signature'), {
      payload: STRIPE_PAYLOAD, secret: 'whsec_nope', signatureHeader: `t=${STRIPE_T},v1=${STRIPE_V1}`, tolerance: 0,
    })
    expect(otherKey).toMatchObject({ valid: false, scheme: 'stripe-timestamped' })
  })

  it('reports malformed, unsupported, and empty input without throwing', async () => {
    const registered = tool('webhook_verify_signature')
    const sha1 = await run(registered, {
      payload: GH_PAYLOAD, secret: GH_SECRET, signatureHeader: GH_SHA1_ONLY,
    })
    expect(sha1.valid).toBe(false)
    expect(sha1.reason).toContain('unsupported signature parameter "sha1"')
    const truncated = await run(registered, {
      payload: GH_PAYLOAD, secret: GH_SECRET, signatureHeader: 'sha256=deadbeef',
    })
    expect(truncated.reason).toContain('not 64 hexadecimal characters')
    const emptyHeader = await run(registered, { payload: GH_PAYLOAD, secret: GH_SECRET, signatureHeader: '   ' })
    expect(emptyHeader).toMatchObject({ valid: false, scheme: 'unknown' })
    const emptySecret = await run(registered, { payload: GH_PAYLOAD, secret: '', signatureHeader: GH_SHA256 })
    expect(emptySecret.reason).toContain('secret is empty')
    const noV1 = await run(registered, { payload: GH_PAYLOAD, secret: GH_SECRET, signatureHeader: 't=1700000000' })
    expect(noV1.reason).toContain('no v1= digest')
  })
})

describe('webhook_parse_request', () => {
  it('parses a CRLF request whose header value is folded across lines', async () => {
    const raw = [
      'POST /hook?source=push HTTP/1.1',
      'Host: example.invalid',
      'User-Agent: curl/8.5.0',
      '\t-sS --data-binary',
      `X-Hub-Signature-256: ${GH_SHA256}`,
      'Content-Type: application/json',
      'Content-Length: 31',
      '',
      GH_PAYLOAD,
    ].join('\r\n')
    const result = await run(tool('webhook_parse_request'), { rawHttp: raw })
    expect(result.method).toBe('POST')
    expect(result.path).toBe('/hook?source=push')
    expect(result.httpVersion).toBe('1.1')
    expect(result.parseError).toBe('')
    const headers = result.headers as Rec
    expect(headers['user-agent']).toBe('curl/8.5.0 -sS --data-binary')
    expect(headers['x-hub-signature-256']).toBe(GH_SHA256)
    expect(headers['content-type']).toBe('application/json')
    expect(result.body).toBe(GH_PAYLOAD)
    expect(result.bodyJson).toEqual({ action: 'opened', number: 42 })
    expect((result.warnings as string[]).some(warning => warning.includes('folded header line'))).toBe(true)
  })

  it('joins repeated headers and reports Content-Length drift', async () => {
    const raw = [
      'POST /hook HTTP/1.1',
      'Set-Cookie: a=1',
      'set-cookie: b=2',
      'Content-Length: 999',
      '',
      GH_PAYLOAD,
    ].join('\n')
    const result = await run(tool('webhook_parse_request'), { rawHttp: raw })
    expect((result.headers as Rec)['set-cookie']).toBe('a=1, b=2')
    expect(result.httpVersion).toBe('1.1')
    const warnings = result.warnings as string[]
    expect(warnings.some(warning => warning.includes('repeated "set-cookie" header'))).toBe(true)
    expect(warnings.some(warning => warning.includes('Content-Length says 999'))).toBe(true)
  })

  it('keeps the body byte-for-byte so a signature can be re-checked', async () => {
    const raw = `PUT /jobs HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"note":"unicode ✓ and spaces   "}\r\n`
    const result = await run(tool('webhook_parse_request'), { rawHttp: raw })
    expect(result.body).toBe('{"note":"unicode ✓ and spaces   "}\r\n')
    expect((result.bodyJson as Rec).note).toBe('unicode ✓ and spaces   ')
    // The trailing CRLF and the multi-byte check mark both survive the split.
    expect(Buffer.byteLength(result.body as string, 'utf8')).toBeGreaterThan((result.body as string).length)
    const verdict = await run(tool('webhook_verify_signature'), {
      payload: result.body as string,
      secret: GH_SECRET,
      signatureHeader: `sha256=${'0'.repeat(64)}`,
    })
    expect(verdict.valid).toBe(false)
    expect(verdict.reason).toContain('does not match')
  })

  it('surfaces a body that is not JSON as parseError with null bodyJson', async () => {
    const result = await run(tool('webhook_parse_request'), {
      rawHttp: 'POST /hook HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"broken":',
    })
    expect(result.bodyJson).toBeNull()
    expect(result.parseError as string).toContain('body is not valid JSON')
    expect(result.body).toBe('{"broken":')
  })

  it('handles LF-only requests, empty bodies, and a missing header/body separator', async () => {
    const noBody = await run(tool('webhook_parse_request'), { rawHttp: 'DELETE /hook/1 HTTP/1.1\r\nAccept: */*\r\n\r\n' })
    expect(noBody.method).toBe('DELETE')
    expect(noBody.path).toBe('/hook/1')
    expect(noBody.body).toBe('')
    expect(noBody.bodyJson).toBeNull()
    expect(noBody.parseError).toBe('')
    const noSeparator = await run(tool('webhook_parse_request'), { rawHttp: 'GET /health HTTP/1.1' })
    expect(noSeparator.body).toBe('')
    expect((noSeparator.warnings as string[]).some(warning => warning.includes('no blank line'))).toBe(true)
  })

  it('reports empty input, malformed request lines, and junk header lines', async () => {
    const registered = tool('webhook_parse_request')
    const empty = await run(registered, { rawHttp: '   \r\n  ' })
    expect(empty.parseError).toBe('raw HTTP request is empty')
    expect(empty.method).toBe('')
    const oneToken = await run(registered, { rawHttp: 'BROKEN\r\nX: 1\r\n\r\n{}' })
    expect(oneToken.method).toBe('BROKEN')
    expect(oneToken.path).toBe('')
    expect(oneToken.parseError as string).toContain('is not "<method> <path> <version>"')
    const noVersion = await run(registered, { rawHttp: 'POST /hook\r\n\r\n{}' })
    expect(noVersion.httpVersion).toBe('')
    expect((noVersion.warnings as string[]).some(warning => warning.includes('no HTTP version token'))).toBe(true)
    const junk = await run(registered, { rawHttp: 'POST /hook HTTP/1.1\r\nnot-a-header\r\nTransfer-Encoding: chunked\r\n\r\n{"a":1}' })
    const warnings = junk.warnings as string[]
    expect(warnings.some(warning => warning.includes('ignored malformed header line'))).toBe(true)
    expect(warnings.some(warning => warning.includes('not decoded'))).toBe(true)
    expect((junk.headers as Rec)['transfer-encoding']).toBe('chunked')
    expect(junk.bodyJson).toEqual({ a: 1 })
  })
})
