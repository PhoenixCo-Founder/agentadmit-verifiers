#!/usr/bin/env node
/**
 * Regenerates every fixture in this directory with fresh synthetic material.
 * Nothing here comes from a real AgentAdmit account: the passkey is a P-256
 * key generated on the spot, identifiers are placeholders, and chain inputs
 * are assembled the same way the service's database trigger assembles them.
 *
 *   node fixtures/generate.mjs
 *
 * Fixture matrix (expected verifier outcome):
 *   audit-export-valid.json           verify_audit_chain.py      PASS (genesis)
 *   audit-export-anchored.json        verify_audit_chain.py      PASS (anchored start reported)
 *   audit-export-deleted-row.json     verify_audit_chain.py      FAIL (chain break)
 *   audit-export-altered-row.json     verify_audit_chain.py      FAIL (row_hash mismatch)
 *   consent-export-valid.json         verify_consent_chain.py    PASS
 *   consent-export-valid.json         verify-consent-evidence.mjs PASS (2 evidence objects)
 *   consent-export-deleted-row.json   verify_consent_chain.py    FAIL (chain break)
 *   evidence-consent-grant.json       verify-consent-evidence.mjs PASS (evidence endpoint shape)
 *   evidence-action-confirmation.json verify-consent-evidence.mjs PASS (bare evidence object)
 *   evidence-tampered.json            verify-consent-evidence.mjs FAIL (preimage altered after signing)
 *   trust-valid.json                  --trust flag                PASS (matching COSE key)
 *   trust-wrong-key.json              --trust flag                FAIL (different P-256 key)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const RP_ID = 'agentadmit.com';
const ORIGIN = 'https://agentadmit.com';
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const write = (name, obj) => fs.writeFileSync(path.join(here, name), JSON.stringify(obj, null, 2) + '\n');

// ---------- minimal CBOR encoder (enough for a COSE EC2 key) ----------
function cborInt(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b;
}
function cborEncode(v) {
  if (typeof v === 'number') return v >= 0 ? cborInt(0, v) : cborInt(1, -1 - v);
  if (Buffer.isBuffer(v)) return Buffer.concat([cborInt(2, v.length), v]);
  if (typeof v === 'string') { const s = Buffer.from(v, 'utf8'); return Buffer.concat([cborInt(3, s.length), s]); }
  if (v instanceof Map) {
    const parts = [cborInt(5, v.size)];
    for (const [k, val] of v) parts.push(cborEncode(k), cborEncode(val));
    return Buffer.concat(parts);
  }
  throw new Error('cbor: unsupported value');
}

// ---------- synthetic passkey ----------
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = publicKey.export({ format: 'jwk' });
const coseKey = b64u(cborEncode(new Map([
  [1, 2], [3, -7], [-1, 1],
  [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')],
])));
const credentialId = b64u(crypto.randomBytes(16));

/** Sign a commitment preimage exactly the way a user-verified WebAuthn
 *  assertion over the hosted page would. */
function assertion(preimage, counter) {
  const challenge = b64u(sha256(Buffer.from(preimage, 'utf8')));
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false }), 'utf8');
  const authData = Buffer.alloc(37);
  sha256(Buffer.from(RP_ID, 'utf8')).copy(authData, 0);
  authData[32] = 0x05; // UP | UV
  authData.writeUInt32BE(counter, 33);
  const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientData)]), { key: privateKey, dsaEncoding: 'der' });
  return {
    v: 2,
    ceremony: 'authentication',
    assurance: { policy: 'consumer', authenticator: 'user_verified_unattested', attestation_format: null, aaguid: null },
    credential_id: credentialId,
    public_key: coseKey,
    challenge,
    commitment_preimage: preimage,
    response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(signature) },
    uv: true,
    verified_at: '2026-09-19T17:00:00.000Z',
  };
}

// ---------- preimages, built the way lib/*-evidence.ts builds them ----------
const grantPreimage = '{' + [
  '"v":3',
  '"app_id":"app_fixture"',
  '"app_user_id":"user_fixture"',
  '"scopes":["read:profile","read:workouts"]',
  '"duration":"30d"',
  '"purpose":"Weekly training summary"',
  '"user_intent":"Summarize my workouts every Sunday"',
  '"bounds":null',
  '"session_id":"csess_fixture0001"',
  '"issued_at":"2026-09-19T16:59:00.000Z"',
].join(',') + '}';

const actionPreimage = '{' + [
  '"v":1',
  '"kind":"action_confirmation"',
  '"app_id":"app_fixture"',
  '"connection_id":"conn_fixture0001"',
  '"app_user_id":"user_fixture"',
  '"scope":"manage:subscription"',
  '"method":"POST"',
  '"endpoint":"/api/recurring-payments/subscribe-to-trainer"',
  `"request_digest":"${sha256hex('{"trainer_id":"tr_fixture","package_id":"pk_fixture"}')}"`,
  '"summary":"Subscribe to Alex, $50/month"',
  '"session_id":"asess_fixture0001"',
  '"issued_at":"2026-09-19T17:05:00.000Z"',
].join(',') + '}';

const grantEvidence = assertion(grantPreimage, 7);
const actionEvidence = assertion(actionPreimage, 8);

// ---------- audit export (per-call chain, migration 057 shape) ----------
function auditRows(n, { anchor = '', app = 'app_fixture', env = 'live' } = {}) {
  const rows = [];
  let prev = anchor;
  for (let i = 1; i <= n; i++) {
    const id = `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`;
    const ts = `2026-09-19T17:10:${String(i).padStart(2, '0')}.000000Z`;
    const scope = i % 2 ? 'read:profile' : 'read:workouts';
    const fields = ['v1', id, String(i), app, 'user_fixture', 'conn_fixture0001', scope, '/api/profile', 'GET', 'Coach', 'Weekly training summary', 'Summarize my workouts every Sunday', 'success', `jti_${i}`, '', env, '', ts, prev];
    const chain_input = fields.join('\n');
    const row_hash = sha256hex(chain_input);
    rows.push({ id, chain_seq: i, app_id: app, app_user_id: 'user_fixture', connection_id: 'conn_fixture0001', scope_used: scope, endpoint: '/api/profile', method: 'GET', agent_label: 'Coach', purpose: 'Weekly training summary', user_intent: 'Summarize my workouts every Sunday', status: 'success', jti: `jti_${i}`, granted_event_id: null, environment: env, metadata: null, timestamp: ts, prev_hash: prev || null, row_hash, chain_input });
    prev = row_hash;
  }
  return rows;
}
const auditDoc = (rows) => ({ format_version: 1, app_id: 'app_fixture', rows, count: rows.length, next_cursor: null, verifier: 'https://github.com/PhoenixCo-Founder/agentadmit-verifiers' });
write('audit-export-valid.json', auditDoc(auditRows(6)));
write('audit-export-anchored.json', auditDoc(auditRows(4, { anchor: sha256hex('pruned history') })));
{ const rows = auditRows(6); rows.splice(2, 1); write('audit-export-deleted-row.json', auditDoc(rows)); }
{ const rows = auditRows(6); rows[3].chain_input = rows[3].chain_input.replace('read:workouts', 'write:workouts'); rows[3].scope_used = 'write:workouts'; write('audit-export-altered-row.json', auditDoc(rows)); }

// ---------- consent export (decision-event chain, migration 042 shape) ----------
function consentEvents() {
  const events = [];
  let prev = null;
  let n = 0;
  const push = (event, metadata, chained = true) => {
    n += 1;
    const id = `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
    const created_at = `2026-09-19T17:0${n % 10}:00.000000Z`;
    const row = { id, app_id: 'app_fixture', app_user_id: 'user_fixture', caller_class: 'external_agent', scope_group: null, event, actor: 'user', environment: 'live', terms_version: 'v1', metadata, created_at, prev_hash: null, row_hash: null, chain_input: null };
    if (chained) {
      const chain_input = ['v1', id, 'app_fixture', 'user_fixture', 'external_agent', '', event, 'user', 'live', 'v1', JSON.stringify(metadata), created_at, prev ?? ''].join('\n');
      row.prev_hash = prev;
      row.row_hash = sha256hex(chain_input);
      row.chain_input = chain_input;
      prev = row.row_hash;
    }
    events.push(row);
  };
  push('presence_verified', { session_id: 'csess_fixture0001', connection_id: 'conn_fixture0001', method: 'webauthn', evidence: grantEvidence });
  push('connection_granted', { connection_id: 'conn_fixture0001', scopes: ['read:profile', 'read:workouts'], agent_label: 'Coach', purpose: 'Weekly training summary', user_intent: 'Summarize my workouts every Sunday' });
  push('evaluated_allow', { connection_id: 'conn_fixture0001', scope: 'read:profile' }, false);
  push('presence_verified_action', { session_id: 'asess_fixture0001', connection_id: 'conn_fixture0001', scope: 'manage:subscription', evidence: actionEvidence });
  push('evaluated_allow', { connection_id: 'conn_fixture0001', scope: 'read:workouts' }, false);
  push('connection_revoked', { connection_id: 'conn_fixture0001', reason: 'user_revoked' });
  return events;
}
const consentDoc = (events) => ({ format_version: 1, app_id: 'app_fixture', events, count: events.length, next_cursor: null, verifier: 'https://github.com/PhoenixCo-Founder/agentadmit-verifiers' });
write('consent-export-valid.json', consentDoc(consentEvents()));
{ const events = consentEvents(); events.splice(1, 1); write('consent-export-deleted-row.json', consentDoc(events)); }

// ---------- evidence endpoint shape (GET /api/v1/connections/{id}/evidence?include_raw=true) ----------
write('evidence-consent-grant.json', {
  connection_id: 'conn_fixture0001',
  status: 'active',
  evidence_available: true,
  tier: 'hosted_vce',
  ceremony: { verified_at: grantEvidence.verified_at, method: 'webauthn', uv: true, provenance: 'hosted_witnessed' },
  authenticator_assurance: { policy: 'consumer', tier: 'user_verified_unattested', attestation_format: null, aaguid: null },
  commitment: { sha256: sha256hex(grantPreimage), preimage_version: 3, preimage: grantPreimage },
  ledger: { granted_event_present: true, tamper_evident: true },
  claim: 'A user-verified passkey ceremony signed a commitment to these recorded grant parameters.',
  evidence: grantEvidence,
});
write('evidence-action-confirmation.json', actionEvidence);
{
  const tampered = JSON.parse(JSON.stringify(actionEvidence));
  tampered.commitment_preimage = tampered.commitment_preimage.replace('$50/month', '$5,000/month');
  write('evidence-tampered.json', tampered);
}
// ---------- trust fixtures for --trust flag tests ----------
// trust-valid.json: the same COSE key used to sign the evidence fixtures
write('trust-valid.json', [{ credential_id: credentialId, public_key: coseKey }]);
// trust-wrong-key.json: a different P-256 key (signature must fail)
const { publicKey: wrongPub } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const wrongJwk = wrongPub.export({ format: 'jwk' });
const wrongCoseKey = b64u(cborEncode(new Map([
  [1, 2], [3, -7], [-1, 1],
  [-2, Buffer.from(wrongJwk.x, 'base64url')], [-3, Buffer.from(wrongJwk.y, 'base64url')],
])));
write('trust-wrong-key.json', [{ credential_id: credentialId, public_key: wrongCoseKey }]);

console.log('fixtures regenerated with a fresh synthetic passkey');
