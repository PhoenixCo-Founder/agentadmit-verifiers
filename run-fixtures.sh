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
expect 0 "consent chain: valid"                        python3 verify_consent_chain.py fixtures/consent-export-valid.json
expect 1 "consent chain: deleted row detected"         python3 verify_consent_chain.py fixtures/consent-export-deleted-row.json
expect 0 "evidence: grant (evidence endpoint shape)"   node verify-consent-evidence.mjs fixtures/evidence-consent-grant.json --expect '{"scopes":["read:profile","read:workouts"],"duration":"30d"}'
expect 0 "evidence: action confirmation (bare object)" node verify-consent-evidence.mjs fixtures/evidence-action-confirmation.json --expect '{"scope":"manage:subscription","method":"POST"}'
expect 0 "evidence: every ceremony in a consent export" node verify-consent-evidence.mjs fixtures/consent-export-valid.json
expect 1 "evidence: preimage altered after signing"    node verify-consent-evidence.mjs fixtures/evidence-tampered.json
expect 1 "evidence: --expect mismatch detected"        node verify-consent-evidence.mjs fixtures/evidence-action-confirmation.json --expect '{"summary":"Subscribe to Alex, $5,000/month"}'
exit $fail
