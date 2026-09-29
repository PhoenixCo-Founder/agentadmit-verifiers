#!/usr/bin/env node
/**
 * verify-consent-evidence.mjs — offline verifier for AgentAdmit verifiable
 * consent evidence (VCE). Plain Node.js crypto, no dependencies, no network.
 *
 * Proves, from the exported record alone, that a user-verified passkey
 * signed a commitment to exactly the recorded parameters: a grant (scopes,
 * duration, purpose, the user's own intent, ceilings), a confirm-each-time
 * action, a relationship or self-consent switch change, or a protective
 * boundary change.
 *
 * Usage:
 *   node verify-consent-evidence.mjs <file.json> [--expect '<json>'] [--rp-id agentadmit.com] [--origin https://agentadmit.com] [--trust trust.json]
 *
 * <file.json> may be any of:
 *   - GET /api/v1/connections/{id}/evidence?include_raw=true  (evidence endpoint body)
 *   - GET /api/v1/consent/export                             (every event carrying evidence is verified)
 *   - a bare evidence object (the `evidence` member itself)
 *   - { rp_id, origin, session: { evidence }, authenticator: { credential_id, public_key } }
 *
 * --expect binds the signed commitment to values you already know (for
 * example the scopes your app recorded). Every key you pass must equal the
 * same key inside the signed preimage.
 *
 * --trust <file.json> supplies one or more authenticator public keys held
 * independently by the auditor, removing the dependency on the public_key
 * field in the export itself. Each entry may carry a credential_id to select
 * the right key when an export contains multiple credentials; if omitted the
 * first entry is used. Keys are EC P-256 (ES256) in either COSE b64url or
 * JWK object form. Format:
 *   [{ "credential_id": "...", "public_key": "<COSE b64url>" }]
 *   [{ "public_key": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } }]
 * or wrap in { "rp_id", "origin", "authenticators": [...] } to override rp/origin too.
 *
 * Ceiling, stated plainly: this proves what the authenticator signed and
 * that a user-verified ceremony produced the signature over that exact
 * commitment. It cannot prove what the screen rendered, and it is a
 * review-time record, never an enforcement input.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const file = args.find((a, i) => !a.startsWith('--') && (i === 0 || !args[i - 1].startsWith('--')));
if (!file) { console.error('usage: node verify-consent-evidence.mjs <file.json> [--expect json] [--rp-id id] [--origin url] [--trust trust.json]'); process.exit(2); }
const expected = opt('--expect', null) ? JSON.parse(opt('--expect')) : null;
let RP_ID = opt('--rp-id', null);
let ORIGIN = opt('--origin', null);

const b64u = (s) => Buffer.from(s, 'base64url');
const b64uEnc = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();

// --- minimal CBOR decoder (maps, arrays, byte/text strings, ints, negatives, simple values) ---
function cbor(buf) {
  let i = 0;
  const readLen = (ai) => {
    if (ai < 24) return ai;
    if (ai === 24) return buf[i++];
    if (ai === 25) { const v = buf.readUInt16BE(i); i += 2; return v; }
    if (ai === 26) { const v = buf.readUInt32BE(i); i += 4; return v; }
    throw new Error('cbor: unsupported length');
  };
  const item = () => {
    const b = buf[i++]; const major = b >> 5; const ai = b & 31;
    if (major === 0) return readLen(ai);
    if (major === 1) return -1 - readLen(ai);
    if (major === 2) { const n = readLen(ai); const v = buf.subarray(i, i + n); i += n; return v; }
    if (major === 3) { const n = readLen(ai); const v = buf.subarray(i, i + n).toString('utf8'); i += n; return v; }
    if (major === 4) { const n = readLen(ai); const a = []; for (let k = 0; k < n; k++) a.push(item()); return a; }
    if (major === 5) { const n = readLen(ai); const m = new Map(); for (let k = 0; k < n; k++) { const key = item(); m.set(key, item()); } return m; }
    if (major === 7) { if (ai === 20) return false; if (ai === 21) return true; if (ai === 22) return null; }
    throw new Error(`cbor: unsupported major ${major}`);
  };
  return item();
}

// Parse --trust file (after cbor/b64u are defined)
// Format: array or { rp_id?, origin?, authenticators: [] }
// Each entry: { credential_id?, public_key: <COSE b64url string | JWK object> }
let trustAuthenticators = null;
const trustArg = opt('--trust', null);
if (trustArg) {
  const raw = JSON.parse(fs.readFileSync(trustArg, 'utf8'));
  const entries = Array.isArray(raw) ? raw : (raw.authenticators ?? []);
  if (entries.length === 0) { console.error(`--trust: no authenticators found in ${trustArg}`); process.exit(2); }
  if (!Array.isArray(raw)) {
    if (raw.rp_id && RP_ID === null) RP_ID = raw.rp_id;
    if (raw.origin && ORIGIN === null) ORIGIN = raw.origin;
  }
  trustAuthenticators = entries.map((e, idx) => {
    const pk = Object.prototype.hasOwnProperty.call(e, 'public_key') ? e.public_key : e;
    let x, y, keyObj;
    if (typeof pk === 'string') {
      let coseMap;
      try { coseMap = cbor(b64u(pk)); } catch (err) { throw new Error(`--trust entry [${idx}]: COSE parse error: ${err.message}`); }
      const kty = coseMap.get(1), alg = coseMap.get(3), crv = coseMap.get(-1);
      x = coseMap.get(-2); y = coseMap.get(-3);
      if (kty !== 2 || crv !== 1 || alg !== -7) throw new Error(`--trust entry [${idx}]: expected EC2/P-256/ES256, got kty=${kty} crv=${crv} alg=${alg}`);
    } else if (pk && typeof pk === 'object' && pk.kty === 'EC') {
      x = b64u(pk.x); y = b64u(pk.y);
    } else {
      throw new Error(`--trust entry [${idx}]: public_key must be a COSE b64url string or a JWK object`);
    }
    try { keyObj = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64uEnc(x), y: b64uEnc(y) }, format: 'jwk' }); }
    catch (err) { throw new Error(`--trust entry [${idx}]: key import failed: ${err.message}`); }
    return { credential_id: e.credential_id ?? null, keyObj, x: Buffer.from(x), y: Buffer.from(y) };
  });
}

/** Verify one evidence object. Returns [ok, name, detail][] */
function verifyEvidence(ev, ctx = {}) {
  const results = [];
  const check = (name, ok, detail = '') => results.push([Boolean(ok), name, detail]);
  const resp = ev.response ?? {};
  const preimage = ev.commitment_preimage;
  check('commitment_preimage present (not the legacy random-challenge path)', typeof preimage === 'string' && preimage.length > 0);
  let pre = null; try { pre = JSON.parse(preimage); } catch { pre = null; }
  const kind = pre?.kind ?? (pre && 'scopes' in pre ? 'consent_grant' : 'unknown');
  check('preimage parses; kind + version', pre !== null, pre ? `kind=${kind} v=${pre.v}` : 'unparseable');
  if (ctx.sessionPreimage !== undefined) check('evidence preimage == stored commitment preimage', preimage === ctx.sessionPreimage);
  if (ctx.commitmentSha256) check('commitment.sha256 == SHA-256(preimage)', sha256(Buffer.from(preimage ?? '', 'utf8')).toString('hex') === ctx.commitmentSha256);
  if (expected && pre) {
    const bad = Object.keys(expected).filter((k) => JSON.stringify(pre[k]) !== JSON.stringify(expected[k]));
    check('preimage binds every --expect field', bad.length === 0, bad.length ? `mismatch: ${bad.join(', ')}` : `${Object.keys(expected).length} fields bound`);
  }
  const challenge = b64uEnc(sha256(Buffer.from(preimage ?? '', 'utf8')));
  check('challenge == base64url(SHA-256(preimage))', challenge === ev.challenge);
  let clientData = null;
  try { clientData = JSON.parse(b64u(resp.clientDataJSON).toString('utf8')); } catch { clientData = null; }
  check('clientDataJSON parses', clientData !== null);
  check('clientDataJSON.challenge == committed challenge', clientData?.challenge === challenge);
  check('clientDataJSON.origin == expected origin', clientData?.origin === ORIGIN, clientData?.origin ?? '');
  if (ev.ceremony === 'registration' && resp.attestationObject && !resp.signature) {
    // Legacy v1 record where the enrollment itself was the evidence. The
    // challenge is bound inside clientDataJSON, but with attestation format
    // 'none' nothing signs it: structure is checkable, a signature is not.
    check('clientDataJSON.type == webauthn.create (legacy registration-only evidence)', clientData?.type === 'webauthn.create', clientData?.type ?? '');
    let fmt = null;
    try {
      const att = cbor(b64u(resp.attestationObject));
      fmt = att.get('fmt'); const regAuth = att.get('authData');
      check('attestationObject.authData.rpIdHash == SHA-256(rpId)', regAuth.subarray(0, 32).equals(sha256(Buffer.from(RP_ID, 'utf8'))), RP_ID);
      const rf = regAuth[32];
      check('flags: user present (UP)', (rf & 0x01) === 0x01);
      check('flags: user verified (UV)', (rf & 0x04) === 0x04);
      check('evidence.uv recorded true', ev.uv === true);
      const credIdLen = regAuth.readUInt16BE(53); const credId = regAuth.subarray(55, 55 + credIdLen);
      check('attested credential id == evidence.credential_id', b64uEnc(credId) === ev.credential_id);
      const cosePub = regAuth.subarray(55 + credIdLen);
      check('attested COSE public key == evidence.public_key', b64uEnc(cosePub) === ev.public_key);
      const cose = cbor(cosePub);
      check('COSE key: EC2 (kty=2), P-256 (crv=1), ES256 (alg=-7)', cose.get(1) === 2 && cose.get(-1) === 1 && cose.get(3) === -7);
    } catch (e) { check('attestationObject parses', false, String(e.message)); }
    check(`NOTE: no assertion signature in this record (attestation format ${fmt}); legacy registration-only evidence is structurally bound to the commitment, not signed over it`, true);
    return { results, kind, pre, legacyRegistration: true };
  }
  check('clientDataJSON.type == webauthn.get (assertion)', clientData?.type === 'webauthn.get', clientData?.type ?? '');
  const authData = resp.authenticatorData ? b64u(resp.authenticatorData) : Buffer.alloc(0);
  check('authenticatorData present (>= 37 bytes)', authData.length >= 37, `${authData.length} bytes`);
  check('authenticatorData.rpIdHash == SHA-256(rpId)', authData.length >= 32 && authData.subarray(0, 32).equals(sha256(Buffer.from(RP_ID, 'utf8'))), RP_ID);
  const flags = authData[32] ?? 0;
  check('flags: user present (UP)', (flags & 0x01) === 0x01);
  check('flags: user verified (UV)', (flags & 0x04) === 0x04);
  check('evidence.uv recorded true', ev.uv === true);
  let cose = null; try { cose = cbor(b64u(ev.public_key)); } catch { cose = null; }
  const kty = cose?.get(1), alg = cose?.get(3), crv = cose?.get(-1), x = cose?.get(-2), y = cose?.get(-3);
  check('COSE key: EC2 (kty=2), P-256 (crv=1), ES256 (alg=-7)', kty === 2 && crv === 1 && alg === -7, `kty=${kty} crv=${crv} alg=${alg}`);
  if (ctx.enrolled) {
    check('evidence.public_key == enrolled authenticator key', ev.public_key === ctx.enrolled.public_key);
    check('evidence.credential_id == enrolled credential', ev.credential_id === ctx.enrolled.credential_id);
  }
  let verifyKey;
  if (ctx.trust) {
    const tx = ctx.trust.x, ty = ctx.trust.y;
    const coordsMatch = x && y && tx && ty && Buffer.from(x).equals(tx) && Buffer.from(y).equals(ty);
    check('evidence.public_key x,y == auditor-supplied trusted key', coordsMatch);
    verifyKey = ctx.trust.keyObj;
  } else {
    try { verifyKey = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64uEnc(x), y: b64uEnc(y) }, format: 'jwk' }); }
    catch { verifyKey = null; }
  }
  let sigOk = false;
  try {
    const signed = Buffer.concat([authData, sha256(b64u(resp.clientDataJSON))]);
    sigOk = verifyKey !== null && crypto.verify('sha256', signed, { key: verifyKey, dsaEncoding: 'der' }, b64u(resp.signature));
  } catch { sigOk = false; }
  const sigLabel = ctx.trust ? 'ECDSA P-256 signature verifies with the auditor-supplied trusted key' : 'ECDSA P-256 signature verifies with the recorded public key';
  check(sigLabel, sigOk);
  if (ev.registration) {
    let rcd = null; try { rcd = JSON.parse(b64u(ev.registration.response.clientDataJSON).toString('utf8')); } catch { rcd = null; }
    check('registration clientDataJSON: type webauthn.create, same challenge + origin', rcd?.type === 'webauthn.create' && rcd?.challenge === challenge && rcd?.origin === ORIGIN);
    try {
      const att = cbor(b64u(ev.registration.response.attestationObject));
      const fmt = att.get('fmt'); const regAuth = att.get('authData');
      const credIdLen = regAuth.readUInt16BE(53); const credId = regAuth.subarray(55, 55 + credIdLen);
      check('registration attestationObject: credential id + rpIdHash match', b64uEnc(credId) === ev.credential_id && regAuth.subarray(0, 32).equals(sha256(Buffer.from(RP_ID, 'utf8'))), `fmt=${fmt}`);
    } catch (e) { check('registration attestationObject parses', false, String(e.message)); }
    check('ceremony recorded as registration_then_authentication', ev.ceremony === 'registration_then_authentication', ev.ceremony ?? '');
  }
  if (ev.v === 2) {
    const a = ev.assurance ?? {};
    const consistent =
      (a.policy === 'consumer' || a.policy === 'trusted') &&
      ['user_verified_unattested', 'attested_unverified', 'trusted_attestation'].includes(a.authenticator) &&
      (a.policy !== 'trusted' || a.authenticator === 'trusted_attestation');
    check('assurance record internally consistent (policy vs authenticator tier)', consistent, JSON.stringify(a));
    if (a.authenticator === 'user_verified_unattested') check('assurance honestly labeled: consumer tier, unattested authenticator', a.attestation_format === null || a.attestation_format === 'none');
  } else {
    check('legacy v1 evidence (no assurance record; treat as consumer tier)', ev.v === 1, `v=${ev.v}`);
  }
  return { results, kind, pre };
}

const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
// Relying party: explicit flags win, then a bundle that declares its own rp_id/origin
// (private rigs, previews), then the hosted service.
RP_ID = RP_ID ?? doc?.rp_id ?? 'agentadmit.com';
ORIGIN = ORIGIN ?? doc?.origin ?? 'https://agentadmit.com';
console.log(`relying party: rp_id=${RP_ID} origin=${ORIGIN}`);
const targets = [];
if (Array.isArray(doc?.rows)) { console.error('This is a per-call audit export. Use verify_audit_chain.py for the chain; audit rows carry no passkey evidence.'); process.exit(2); }
if (Array.isArray(doc?.events)) {
  for (const e of doc.events) {
    const ev = e?.metadata?.evidence;
    if (ev && typeof ev === 'object') targets.push({ label: `${e.event} ${e.id ?? ''}`.trim(), ev, ctx: {} });
  }
  if (targets.length === 0) { console.error('No events with metadata.evidence in this export (only hosted ceremonies produce evidence).'); process.exit(2); }
} else if (doc?.session?.evidence) {
  targets.push({ label: 'bundle', ev: doc.session.evidence, ctx: { sessionPreimage: doc.session.commitment_preimage, enrolled: doc.authenticator } });
} else if (doc?.evidence && doc?.tier !== undefined) {
  if (doc.tier !== 'hosted_vce') { console.error(`Evidence tier is "${doc.tier}", not hosted_vce: no independently verifiable evidence exists for this record (reason: ${doc.reason ?? 'n/a'}).`); process.exit(2); }
  targets.push({ label: `connection ${doc.connection_id}`, ev: doc.evidence, ctx: { sessionPreimage: doc.commitment?.preimage, commitmentSha256: doc.commitment?.sha256 } });
} else if (doc?.evidence?.response && doc?.commitment_preimage !== undefined) {
  targets.push({ label: 'evidence', ev: doc.evidence, ctx: { sessionPreimage: doc.commitment_preimage } });
} else if (doc?.response && doc?.challenge) {
  targets.push({ label: 'evidence', ev: doc, ctx: {} });
} else {
  console.error('Unrecognized input. Pass an evidence endpoint body (include_raw=true), a consent export, or a bare evidence object.');
  process.exit(2);
}

let allPass = true;
let anyLegacy = false;
if (trustAuthenticators) console.log(`trust: ${trustAuthenticators.length} auditor-supplied authenticator key(s) loaded from ${trustArg}`);
for (const t of targets) {
  let trust = null;
  if (trustAuthenticators) {
    trust = trustAuthenticators.find((a) => !a.credential_id || a.credential_id === t.ev.credential_id)
          ?? trustAuthenticators[0];
  }
  const { results, kind, pre, legacyRegistration } = verifyEvidence(t.ev, { ...t.ctx, trust });
  if (legacyRegistration) anyLegacy = true;
  const pass = results.filter((r) => r[0]).length;
  console.log(`== ${t.label}  (${kind})`);
  for (const [ok, name, detail] of results) console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`);
  if (pre) {
    const shown = Object.fromEntries(Object.entries(pre).filter(([k]) => !['v', 'kind'].includes(k)));
    console.log('signed commitment:', JSON.stringify(shown));
  }
  console.log(`${pass}/${results.length} ${pass === results.length ? 'PASS' : 'FAIL'}\n`);
  if (pass !== results.length) allPass = false;
}
if (allPass && anyLegacy) console.log(`EVIDENCE CHECKED - ${targets.length} record(s); at least one is legacy registration-only evidence (commitment-bound, unsigned)`);
else console.log(allPass ? `EVIDENCE VALID - ${targets.length} ceremony record(s) verified offline` : 'EVIDENCE INVALID - at least one check failed');
process.exit(allPass ? 0 : 1);
