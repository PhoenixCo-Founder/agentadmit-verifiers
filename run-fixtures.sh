#!/usr/bin/env bash
# Self-test: every fixture must produce the expected outcome. Exit 0 only if
# the whole matrix matches. Run from the repository root.
set -u
cd "$(dirname "$0")"
fail=0
expect() { # expect <0|1> <description> <command...>
  local want="$1"; shift; local desc="$1"; shift
  if "$@" >/tmp/agentadmit-verifiers-out.txt 2>&1; then got=0; else got=$?; fi
  if [ "$got" -eq "$want" ]; then echo "ok    exit=$got  $desc"; else echo "WRONG exit=$got (wanted $want)  $desc"; cat /tmp/agentadmit-verifiers-out.txt; fail=1; fi
}
expect 0 "audit chain: valid from genesis"            python3 verify_audit_chain.py fixtures/audit-export-valid.json
expect 0 "audit chain: anchored start reported"        python3 verify_audit_chain.py fixtures/audit-export-anchored.json
expect 1 "audit chain: deleted middle row detected"    python3 verify_audit_chain.py fixtures/audit-export-deleted-row.json
expect 1 "audit chain: altered row detected"           python3 verify_audit_chain.py fixtures/audit-export-altered-row.json
tmpdir="$(mktemp -d)"
python3 - "$tmpdir" <<'PY'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
source = "00000000-0000-4000-8000-000000000001"
row_id = "00000000-0000-4000-8000-000000000002"
metadata = {"outcome": "executed", "outcome_for": source, "status_class": "2xx"}
ts = "2026-09-29T20:00:00.000000Z"
fields = ["v1", row_id, "2", "app_1", "user_1", "conn_1", "write:item", "/item", "POST", "agent", "purpose", "intent", "outcome_reported", "test-jti", "", "live", json.dumps(metadata, separators=(",", ":")), ts, ""]
row = {
    "id": row_id, "chain_seq": 2, "app_id": "app_1", "app_user_id": "user_1",
    "connection_id": "conn_1", "scope_used": "write:item", "endpoint": "/item",
    "method": "POST", "agent_label": "agent", "purpose": "purpose",
    "user_intent": "intent", "status": "outcome_reported", "jti": "test-jti",
    "granted_event_id": None, "environment": "live", "metadata": metadata,
    "outcome": "executed", "outcome_for": source, "status_class": "2xx",
    "timestamp": ts, "prev_hash": None,
}
row["chain_input"] = "\n".join(fields)
row["row_hash"] = hashlib.sha256(row["chain_input"].encode()).hexdigest()
doc = {"format_version": 2, "rows": [row]}
(out / "audit-outcome-valid.json").write_text(json.dumps(doc))
tampered = json.loads(json.dumps(doc))
tampered["rows"][0]["outcome"] = "failed"
(out / "audit-outcome-tampered-copy.json").write_text(json.dumps(tampered))
tampered_status = json.loads(json.dumps(doc))
tampered_status["rows"][0]["status_class"] = "5xx"
(out / "audit-outcome-tampered-status.json").write_text(json.dumps(tampered_status))
PY
expect 0 "audit outcome: format2 valid outcome row"    python3 verify_audit_chain.py "$tmpdir/audit-outcome-valid.json"
expect 1 "audit outcome: tampered outcome copy"        python3 verify_audit_chain.py "$tmpdir/audit-outcome-tampered-copy.json"
expect 1 "audit outcome: tampered status class copy"   python3 verify_audit_chain.py "$tmpdir/audit-outcome-tampered-status.json"
rm -rf "$tmpdir"
expect 0 "consent chain: valid"                        python3 verify_consent_chain.py fixtures/consent-export-valid.json
expect 1 "consent chain: deleted row detected"         python3 verify_consent_chain.py fixtures/consent-export-deleted-row.json
expect 0 "evidence: grant (evidence endpoint shape)"   node verify-consent-evidence.mjs fixtures/evidence-consent-grant.json --expect '{"scopes":["read:profile","read:workouts"],"duration":"30d"}'
expect 0 "evidence: action confirmation (bare object)" node verify-consent-evidence.mjs fixtures/evidence-action-confirmation.json --expect '{"scope":"manage:subscription","method":"POST"}'
expect 0 "evidence: every ceremony in a consent export" node verify-consent-evidence.mjs fixtures/consent-export-valid.json
expect 1 "evidence: preimage altered after signing"    node verify-consent-evidence.mjs fixtures/evidence-tampered.json
expect 1 "evidence: --expect mismatch detected"        node verify-consent-evidence.mjs fixtures/evidence-action-confirmation.json --expect '{"summary":"Subscribe to Alex, $5,000/month"}'
expect 0 "evidence: --trust valid COSE key passes"     node verify-consent-evidence.mjs fixtures/evidence-consent-grant.json --trust fixtures/trust-valid.json
expect 1 "evidence: --trust wrong key fails"           node verify-consent-evidence.mjs fixtures/evidence-consent-grant.json --trust fixtures/trust-wrong-key.json
exit $fail
