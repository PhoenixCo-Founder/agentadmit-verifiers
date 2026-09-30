# Export and evidence formats

This file is the contract the verifiers implement. If you would rather not run our code, everything needed to re-implement each check is here.

`format_version` is carried on every JSON export body (and as `X-Export-Format-Version` on CSV responses). Current: **2** for the per-call audit export and **1** for the consent export. Additive fields never bump the version. A renamed, removed, or re-defined field, or a change to how `chain_input` is assembled, does.

## 1. Per-call audit export (`GET /api/v1/audit/export`)

Body: `{ format_version, app_id, rows[], count, next_cursor, verifier }`. CSV uses the same columns, one row per line, continuation in `X-Next-Cursor`.

Each row is one verified call. Fields:

| Field | Meaning |
| --- | --- |
| `id` | Row id. |
| `chain_seq` | Position in the chain for this `(app_id, environment)`. Strictly increasing. NULL on pre-chain legacy rows. |
| `app_id`, `app_user_id`, `connection_id` | The app, the pseudonymous user, and the agent connection. |
| `scope_used`, `endpoint`, `method` | What the call exercised (endpoint and method as declared by the app, may be null). |
| `agent_label`, `purpose`, `user_intent` | Agent label chosen by the user; the app's declared purpose; the user's own stated intent. Review-time context. |
| `status` | `success`, `test`, `scope_denied`, `bound_exceeded`, `consent_denied`, `consent_unavailable`, `confirmation_required`, `outcome_reported`. |
| `jti` | The access token identifier the call carried. |
| `granted_event_id` | The consent-trail event the call relied on, when known. |
| `environment` | `live` or `test`. |
| `outcome`, `outcome_for`, `status_class` | Format 2 only. On `outcome_reported` rows, the app-reported result (`executed`, `failed`, or `unknown`), the source audit row id it reports on, and optional HTTP class (`1xx`..`5xx` or null). These copies must match the hash-covered `metadata` object. Non-outcome rows must not carry reported outcome values. |
| `timestamp` | Database server time at insert (UTC, microseconds). |
| `prev_hash` | `row_hash` of the previous chained row in the same chain, or NULL at genesis. Non-NULL on the first exported row means the chain continues from rows outside this export (an anchor). |
| `row_hash` | `hex(SHA-256(chain_input))`. |
| `chain_input` | The exact string that was hashed: the row's content, its timestamp, and `prev_hash`, newline-joined in a fixed field order. Treat it as opaque; verify it, do not rebuild it. |

Checks:

1. **Integrity.** For every row with a non-NULL `row_hash`: `hex(SHA-256(utf8(chain_input))) == row_hash`.
2. **Order.** Within one `(app_id, environment)`, `chain_seq` strictly increases in export order.
3. **Continuity.** Within one chain, each row's `prev_hash` equals the previous chained row's `row_hash`.
4. **Anchor.** The first exported row of a chain may carry a non-NULL `prev_hash`. Report it; do not fail. Rows are pruned oldest-first by the retention window, so the anchor points at pruned history or at rows before your `from` bound.
5. **Legacy.** Rows with NULL `row_hash` predate the chain. Report them; fail only if one appears after its chain has started.
6. **Outcome binding.** Format 2 outcome rows are chained as their own rows. The verifier checks that `outcome`, `outcome_for`, and `status_class` match the values in hash-covered `metadata`, that the outcome row has `status = outcome_reported`, and that non-outcome rows do not carry outcome copies.

## 2. Consent export (`GET /api/v1/consent/export`)

Body: `{ format_version, app_id, events[], count, next_cursor, verifier }`.

Event types: `granted`, `revoked`, `connection_granted`, `connection_revoked`, `presence_verified`, `presence_verified_action`, `policy_updated`, and the relationship and self-consent switch events, plus the evaluation events `evaluated_allow` and `evaluated_deny`.

| Field | Meaning |
| --- | --- |
| `id`, `app_id`, `app_user_id`, `environment` | Identity of the event. |
| `caller_class`, `scope_group` | Which caller class and scope group the decision concerned. |
| `event`, `actor` | What happened and who acted (`user`, `app`, `system`). |
| `terms_version` | Terms shown at the time. |
| `metadata` | Event payload: scopes, agent label, purpose, intent, connection id, and for `presence_verified*` events an `evidence` object (section 3). |
| `created_at` | Database server time. |
| `prev_hash`, `row_hash`, `chain_input` | As in section 1. NULL on evaluation events and pre-chain legacy rows. |

Checks:

1. **Integrity.** `hex(SHA-256(utf8(chain_input))) == row_hash` for every chained event.
2. **Continuity.** Within one `(app_id, environment)`, each chained event's `prev_hash` equals the previous chained event's `row_hash`.
3. **Genesis.** The first chained event of each chain has `prev_hash` NULL. Decision events are never pruned, so a consent chain always starts at genesis.
4. **Unchained by design.** `evaluated_allow` and `evaluated_deny` are never chained (they age out under retention). Any other event unchained after its chain has started is a failure.

## 3. Verifiable consent evidence

Produced by every hosted passkey ceremony. Found in `presence_verified*` events (`metadata.evidence`) and returned by `GET /api/v1/connections/{id}/evidence?include_raw=true` (`evidence`, with `commitment.preimage` and `commitment.sha256` alongside).

| Field | Meaning |
| --- | --- |
| `v` | Evidence record version: `1` (legacy, no assurance record) or `2`. |
| `ceremony` | `authentication`, or `registration_then_authentication` when a new credential was enrolled and then immediately signed the same commitment. Legacy v1 records may carry `registration` alone: the enrollment's `clientDataJSON` binds the challenge, but with attestation format `none` nothing signs it, so such a record is commitment-bound and unsigned. |
| `assurance` (v2) | `{ policy: consumer \| trusted, authenticator: user_verified_unattested \| attested_unverified \| trusted_attestation, attestation_format, aaguid }`. `trusted` policy requires `trusted_attestation`. |
| `credential_id`, `public_key` | The authenticator credential and its COSE public key (base64url CBOR; EC2 / P-256 / ES256). |
| `commitment_preimage` | The canonical string that was committed to (section 4). |
| `challenge` | `base64url(SHA-256(utf8(commitment_preimage)))`. |
| `response` | The WebAuthn assertion: `clientDataJSON`, `authenticatorData`, `signature` (all base64url). |
| `registration` | Present only for `registration_then_authentication`: the enrollment `clientDataJSON` and `attestationObject`. |
| `uv`, `verified_at` | User-verification flag as recorded, and the server time. |

Checks (standard WebAuthn assertion verification, with the challenge pinned to the commitment):

1. `challenge == base64url(SHA-256(commitment_preimage))`.
2. Decode `clientDataJSON`: `type == "webauthn.get"`, `challenge` equals step 1, `origin == "https://agentadmit.com"`.
3. Decode `authenticatorData`: first 32 bytes equal `SHA-256("agentadmit.com")`; flag bits UP (0x01) and UV (0x04) are set; `uv` is recorded `true`.
4. Decode the COSE key: `kty=2, crv=1, alg=-7`. Verify the ECDSA P-256 / SHA-256 signature over `authenticatorData || SHA-256(clientDataJSON)`.
5. If `registration` is present: its `clientDataJSON` has `type == "webauthn.create"` with the same challenge and origin, and the attested credential id and rpIdHash match.
6. The `assurance` record is internally consistent, and the tier is reported, never upgraded.
7. Optionally bind the parsed preimage to values you already hold (`--expect`).

## 4. Commitment preimages

Each preimage is a JSON object serialized by the service in a fixed key order (never re-serialize it; hash the string as exported). The `v` key is the preimage version; `kind` names the ceremony (absent on grant commitments).

| Kind | Keys, in order |
| --- | --- |
| grant (no `kind`) | `v`(3), `app_id`, `app_user_id`, `scopes` (sorted), `duration`, `purpose`, `user_intent`, `bounds`, `session_id`, `issued_at`. v1 lacks `user_intent`; v1 and v2 lack `bounds`. |
| `action_confirmation` | `v`(1), `kind`, `app_id`, `connection_id`, `app_user_id`, `scope`, `method`, `endpoint`, `request_digest`, `summary`, `session_id`, `issued_at`. |
| `relationship_consent` | `v`, `kind`, `app_id`, `subject_user_id`, `grantee_user_id`, `relationship_type`, `grantee_label`, `relationship_label`, `changes[]`, `session_id`, `issued_at`. |
| `self_consent` | `v`, `kind`, `app_id`, `app_user_id`, `environment`, `app_label`, `changes[]`, `session_id`, `issued_at`. |
| `protective_boundaries` | `v`, `kind`, `app_id`, `connection_id`, `app_user_id`, `actor_kind`, `changes[]`, `session_id`, `issued_at`. |

A grant commitment binds the scopes, the duration, the app's declared purpose, the user's own words, and the user's chosen call ceilings. An action commitment binds the scope, HTTP method, endpoint, a digest of the request body computed by the app, and the summary the human saw. What the digest covers is the app's declaration; the verifier proves the signature is over that declaration.
