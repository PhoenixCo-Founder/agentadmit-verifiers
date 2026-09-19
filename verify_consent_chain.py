#!/usr/bin/env python3
"""
verify_consent_chain.py - third-party verifier for the AgentAdmit consent
trail's tamper-evident hash chain. Standard library only; no network.

Usage:
  python3 verify_consent_chain.py consent-export.json
  curl -s "https://agentadmit.com/api/v1/consent/export?environment=live&format=json" \
    -H "Authorization: Bearer $AGENTADMIT_API_KEY" | python3 verify_consent_chain.py -

Input: the JSON body of GET /api/v1/consent/export (an object with "events"),
or a bare JSON array of events. Combine pages in export order first.

What it proves, from the export contents alone:
  1. INTEGRITY: SHA-256(chain_input) == row_hash for every chained row.
  2. CONTINUITY: within each (app_id, environment), each decision event's
     prev_hash equals the previous decision event's row_hash (export order).
  3. GENESIS: the first chained row of each chain has prev_hash NULL.

Every event is chained except the evaluation events (evaluated_allow /
evaluated_deny), which age out under the plan's retention window and are
unchained by design. Unchained rows are reported, never failures, unless a
non-evaluation event appears unchained AFTER its chain has started.

Passkey evidence inside presence_verified* events is verified separately by
verify-consent-evidence.mjs.

Ceiling: tamper-EVIDENT, never tamper-proof. A self-consistent export cannot
prove completeness, and an operator rewriting and re-chaining history is
detectable only by comparing exports taken at different times.
"""

import hashlib
import json
import sys

SUPPORTED_FORMAT_VERSION = 1
UNCHAINED_BY_DESIGN = {"evaluated_allow", "evaluated_deny"}


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    raw = sys.stdin.read() if src == "-" else open(src, encoding="utf-8").read()
    data = json.loads(raw)
    if isinstance(data, dict):
        events = data.get("events")
        if events is None:
            print("FAIL: no 'events' member; is this an audit export? use verify_audit_chain.py")
            return 2
        fv = data.get("format_version")
        if fv is not None and fv > SUPPORTED_FORMAT_VERSION:
            print(f"WARNING: export format_version {fv} is newer than this verifier supports ({SUPPORTED_FORMAT_VERSION}); update the verifier")
        elif fv is not None:
            print(f"export format_version: {fv}")
    else:
        events = data

    failures = []
    chained = unchained = 0
    heads = {}  # (app_id, environment) -> previous row_hash

    for e in events:
        key = (e["app_id"], e.get("environment") or "unknown")
        row_hash = e.get("row_hash")
        if row_hash is None:
            unchained += 1
            if e["event"] not in UNCHAINED_BY_DESIGN and key in heads:
                # A chained decision event can never be followed by an
                # unchained one; pre-chain legacy rows come first.
                failures.append(f"unchained {e['event']} event {e['id']} AFTER chain started")
            continue

        chained += 1
        if hashlib.sha256(e["chain_input"].encode("utf-8")).hexdigest() != row_hash:
            failures.append(f"row_hash mismatch at {e['id']} (content altered?)")
        prev = e.get("prev_hash")
        if key not in heads:
            if prev is not None:
                failures.append(f"genesis row {e['id']} has non-NULL prev_hash")
        elif prev != heads[key]:
            failures.append(
                f"chain break at {e['id']}: prev_hash {str(prev)[:16]}... != prior row_hash {heads[key][:16]}... (row deleted or reordered?)"
            )
        heads[key] = row_hash

    print(f"chained rows verified: {chained} | unchained (evaluation/legacy): {unchained} | chains: {len(heads)}")
    if failures:
        print("FAIL:")
        for f in failures:
            print(" -", f)
        return 1
    print("CONSENT CHAIN VALID - no deletion, alteration, or reordering detected within the export")
    return 0


if __name__ == "__main__":
    sys.exit(main())
