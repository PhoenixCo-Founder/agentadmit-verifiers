#!/usr/bin/env python3
"""
verify_audit_chain.py - third-party verifier for the AgentAdmit per-call audit
trail's tamper-evident hash chain. Standard library only; no network.

Usage:
  python3 verify_audit_chain.py audit-export.json
  curl -s "https://agentadmit.com/api/v1/audit/export?environment=live&format=json" \
    -H "Authorization: Bearer $AGENTADMIT_API_KEY" | python3 verify_audit_chain.py -

Input: the JSON body of GET /api/v1/audit/export (an object with "rows"), or a
bare JSON array of rows. Combine pages in export order before verifying; for
continuity checks export the full app/environment segment without
connection_id or app_user_id filters (those filters skip interleaved rows).

What it proves, from the export contents alone:
  1. INTEGRITY: SHA-256(chain_input) == row_hash for every chained row.
  2. ORDER: chain_seq strictly increases within each (app_id, environment).
  3. CONTINUITY: each row's prev_hash equals the previous chained row's
     row_hash. Any deleted, altered, or reordered MIDDLE row breaks this.
  4. ANCHOR: the first exported row of a chain may carry a non-NULL
     prev_hash. That is the fingerprint of history outside this export,
     pruned by the retention window (oldest rows first) or before the
     `from` bound. It is reported, never a failure. A NULL prev_hash on the
     first row is genesis.

Unchained rows (pre-chain legacy, NULL row_hash) are reported, never failures,
unless one appears AFTER its chain has started.

Ceiling: tamper-EVIDENT, never tamper-proof. A self-consistent export cannot
prove completeness, and an operator rewriting and re-chaining history is
detectable only by comparing exports taken at different times.
"""

import hashlib
import json
import sys

SUPPORTED_FORMAT_VERSION = 1


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    raw = sys.stdin.read() if src == "-" else open(src, encoding="utf-8").read()
    data = json.loads(raw)
    if isinstance(data, dict):
        rows = data.get("rows")
        if rows is None:
            print("FAIL: no 'rows' member; is this a consent export? use verify_consent_chain.py")
            return 2
        fv = data.get("format_version")
        if fv is not None and fv > SUPPORTED_FORMAT_VERSION:
            print(f"WARNING: export format_version {fv} is newer than this verifier supports ({SUPPORTED_FORMAT_VERSION}); update the verifier")
        elif fv is not None:
            print(f"export format_version: {fv}")
    else:
        rows = data

    failures = []
    chained = unchained = anchored = 0
    heads = {}  # (app_id, environment) -> previous row_hash
    last_seq = {}

    for r in rows:
        key = (r["app_id"], r.get("environment") or "unknown")
        row_hash = r.get("row_hash")
        if row_hash is None:
            unchained += 1
            if key in heads:
                failures.append(f"unchained row {r['id']} AFTER chain started")
            continue

        chained += 1
        if hashlib.sha256(r["chain_input"].encode("utf-8")).hexdigest() != row_hash:
            failures.append(f"row_hash mismatch at {r['id']} (content altered?)")
        seq = r.get("chain_seq")
        if key in last_seq and seq is not None and seq <= last_seq[key]:
            failures.append(f"chain_seq not increasing at {r['id']} (reordered export?)")
        if seq is not None:
            last_seq[key] = seq
        prev = r.get("prev_hash")
        if key not in heads:
            if prev is not None:
                anchored += 1  # continues history outside this export
        elif prev != heads[key]:
            failures.append(
                f"chain break at {r['id']}: prev_hash {str(prev)[:16]}... != prior row_hash {heads[key][:16]}... (row deleted or reordered?)"
            )
        heads[key] = row_hash

    print(f"chained rows verified: {chained} | unchained (legacy): {unchained} | chains: {len(heads)} | anchored starts: {anchored}")
    if failures:
        print("FAIL:")
        for f in failures:
            print(" -", f)
        return 1
    print("AUDIT CHAIN VALID - no deletion, alteration, or reordering detected within the export")
    return 0


if __name__ == "__main__":
    sys.exit(main())
