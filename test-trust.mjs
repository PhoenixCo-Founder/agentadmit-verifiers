import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-trust-'));
const evidence = JSON.parse(fs.readFileSync('fixtures/evidence-consent-grant.json'));
const valid = JSON.parse(fs.readFileSync('fixtures/trust-valid.json'));
const wrong = JSON.parse(fs.readFileSync('fixtures/trust-wrong-key.json'));
const cose = Buffer.from(valid[0].public_key, 'base64url');
const coordinate = (tag) => { const start = cose.indexOf(Buffer.from([tag, 0x58, 0x20])) + 3; return cose.subarray(start, start + 32).toString('base64url'); };
const jwk = { kty: 'EC', crv: 'P-256', x: coordinate(0x21), y: coordinate(0x22) };
let count = 0;
function check(name, trust, pass, doc = evidence, extra = []) {
  const file = path.join(temp, 'evidence.json');
  const config = path.join(temp, 'trust.json');
  fs.writeFileSync(file, JSON.stringify(doc));
  fs.writeFileSync(config, JSON.stringify(trust));
  const args = ['verify-consent-evidence.mjs', file, '--trust', ...(trust === undefined ? [] : [config]), ...extra];
  const result = spawnSync(process.execPath, args, {encoding:'utf8'});
  assert.equal(result.status === 0, pass, `${name}: ${result.stdout} ${result.stderr}`);
  console.log(`ok ${++count}: ${name}`);
}
try {
  check('COSE key', valid, true);
  check('JWK key', [{public_key:jwk}], true);
  check('second unscoped key', [{public_key:wrong[0].public_key},{public_key:jwk}], true);
  check('explicit credential mismatch', [{...valid[0],credential_id:'other'}], false);
  check('wrong key', wrong, false);
  check('wrong JWK curve', [{public_key:{...jwk,crv:'P-384'}}], false);
  check('wrong JWK algorithm', [{public_key:{...jwk,alg:'ES384'}}], false);
  check('empty keys', [], false);
  check('malformed key set', {authenticators:{}}, false);
  check('independent RP', {rp_id:'wrong.example',authenticators:valid}, false);
  check('independent origin', {origin:'https://wrong.example',authenticators:valid}, false);
  // Keep a structurally valid unsigned legacy record, so this detects the old bypass.
  const legacy = structuredClone(evidence);
  const ev = legacy.evidence;
  ev.ceremony = 'registration';
  const client = JSON.parse(Buffer.from(ev.response.clientDataJSON, 'base64url'));
  client.type = 'webauthn.create';
  const id = Buffer.from(ev.credential_id, 'base64url');
  const auth = Buffer.from(ev.response.authenticatorData, 'base64url');
  const length = Buffer.alloc(2); length.writeUInt16BE(id.length);
  const regAuth = Buffer.concat([auth, Buffer.alloc(16), length, id, cose]);
  const att = Buffer.concat([Buffer.from('a263666d74646e6f6e6568617574684461746158', 'hex'), Buffer.from([regAuth.length]), regAuth]);
  ev.response = {clientDataJSON:Buffer.from(JSON.stringify(client)).toString('base64url'),attestationObject:att.toString('base64url')};
  delete ev.registration;
  fs.writeFileSync(path.join(temp, 'legacy.json'), JSON.stringify(legacy));
  assert.equal(spawnSync(process.execPath, ['verify-consent-evidence.mjs',path.join(temp, 'legacy.json')]).status, 0);
  check('legacy unsigned evidence cannot satisfy trust', valid, false, legacy);
  const result = spawnSync(process.execPath, ['verify-consent-evidence.mjs','fixtures/evidence-consent-grant.json','--trust']);
  assert.equal(result.status, 2);
  console.log(`ok ${++count}: missing trust file fails closed`);
} finally { fs.rmSync(temp, {recursive:true,force:true}); }
