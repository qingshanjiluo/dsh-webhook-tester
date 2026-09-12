/**
 * Loads the built artifact and asserts it exports the Cordis function-plugin face
 * the harness loader requires, then exercises one call per tool end to end.
 * Run after `npm run build`.
 * @module
 */
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'

const mod = await import(new URL('../lib/index.js', import.meta.url).href)

assert.equal(mod.name, 'dsh-webhook-tester', 'plugin name export')
assert.deepEqual(mod.inject, ['tools'], 'inject declares the tools service')
assert.equal(typeof mod.apply, 'function', 'apply is a function')
assert.ok(mod.Config, 'Config schema export present')

const registered = []
mod.apply({ tools: { register: def => registered.push(def) } }, {
  sampleUrl: 'http://127.0.0.1:3080/api/webhooks/github',
  signingSecret: '',
  defaultToleranceSeconds: 300,
})
assert.deepEqual(
  registered.map(t => t.name).sort(),
  ['webhook_generate_sample', 'webhook_parse_request', 'webhook_verify_signature'],
  'all three tools register',
)

const byName = new Map(registered.map(t => [t.name, t]))
const secret = 'smoke-secret'
const secretHeader = `sha256=${createHmac('sha256', secret).update('{"action":"opened"}', 'utf8').digest('hex')}`

const sample = await byName.get('webhook_generate_sample').execute({ eventType: 'push' }, {})
assert.equal(sample.eventType, 'push', 'sample reports the built-in shape')
assert.equal(sample.payload.ref, 'refs/heads/main', 'sample carries the push fields')
assert.match(sample.curl, /^curl -sS -X POST /, 'curl command is runnable POSIX text')
assert.equal(sample.known, true, 'push is a built-in shape')

const verified = await byName.get('webhook_verify_signature').execute(
  { payload: '{"action":"opened"}', secret, signatureHeader: secretHeader }, {},
)
assert.equal(verified.valid, true, 'a correct HMAC-SHA256 signature verifies')
assert.equal(verified.scheme, 'github-sha256', 'github scheme detected')

const rejected = await byName.get('webhook_verify_signature').execute(
  { payload: '{"action":"closed"}', secret, signatureHeader: secretHeader }, {},
)
assert.equal(rejected.valid, false, 'a tampered payload is rejected')

const parsed = await byName.get('webhook_parse_request').execute(
  { rawHttp: 'POST /hook HTTP/1.1\r\nHost: x\r\nX-Long: a\r\n  b\r\n\r\n{"ok":true}' }, {},
)
assert.equal(parsed.method, 'POST', 'request line parsed')
assert.equal(parsed.headers['x-long'], 'a b', 'folded header joined')
assert.deepEqual(parsed.bodyJson, { ok: true }, 'json body parsed')

console.log('load-smoke: ok —', registered.length, 'tools registered from built artifact')
