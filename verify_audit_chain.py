#!/usr/bin/env python3
"""
PUBLISHED COPY: https://github.com/PhoenixCo-Founder/agentadmit-verifiers
(keep this file and the public one identical; the test suite runs this copy).

verify_audit_chain.py - third-party verifier for the AgentAdmit per-call audit
trail's tamper-evident hash chain. Standard library only; no network for audit
chain verification. Anchor signature verification requires `cryptography`:
  pip install cryptography

Usage:
  python3 verify_audit_chain.py audit-export.json
  curl -s "https://agentadmit.com/api/v1/audit/export?environment=live&format=json" \
    -H "Authorization: Bearer $AGENTADMIT_API_KEY" | python3 verify_audit_chain.py -

  # Verify a signed daily chain-head anchor (requires `cryptography`):
  python3 verify_audit_chain.py --verify-anchor anchor.json --public-key app_public_key.pem
    where anchor.json is the body of GET /api/v1/audit/chain-head
    and   app_public_key.pem is the SPKI PEM from GET /api/v1/apps/{app_id} field public_key

Input: the JSON body of GET /api/v1/audit/export (an object with "rows"), or a
bare JSON array of rows. Combine pages in export order before verifying; for
continuity checks export the full app/environment segment without
connection_id or app_user_id filters (those filters skip interleaved rows).

What it proves, from the export contents alone:
  1. INTEGRITY: SHA-256(chain_input) == row_hash for every chained row.
  2. ORDER: chain_seq strictly increases within each (app_id, environment).
  3. CONTINUITY: each row's prev_hash equals the previous chained row's
     row_hash. Any deleted, altered, or reordered MIDDLE row breaks this.
  4. OUTCOMES: reported outcome copies agree with hash-covered metadata.
     These record what the app reported happened, not proof of execution.
  5. ANCHOR: the first exported row of a chain may carry a non-NULL
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
import uuid

SUPPORTED_FORMAT_VERSION = 2
ANCHOR_TYPE = "agentadmit.audit.chain_head.v1"


def verify_anchor(anchor_path: str, public_key_path: str) -> int:
    """Verify a signed daily chain-head anchor from GET /api/v1/audit/chain-head.

    Requires: pip install cryptography
    The canonical payload is JSON.stringify(payload) with the exact key order
    returned by the endpoint (sorted lexicographically, RFC 8785 JCS subset).
    The signature is base64url(RSA-SHA256(UTF-8(canonical_json))).
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        print("FAIL: anchor signature verification requires `cryptography` (pip install cryptography)")
        return 2

    import base64

    raw = sys.stdin.read() if anchor_path == "-" else open(anchor_path, encoding="utf-8").read()
    anchor = json.loads(raw)
    payload = anchor.get("payload")
    signature_b64 = anchor.get("signature")
    kid = anchor.get("kid")
    if not payload or not signature_b64 or not kid:
        print("FAIL: anchor JSON must contain payload, signature, and kid")
        return 1

    expected_type = payload.get("type")
    if expected_type != ANCHOR_TYPE:
        print(f"FAIL: unexpected anchor type {expected_type!r}; expected {ANCHOR_TYPE!r}")
        return 1

    # Verify the key order matches lexicographic sort (JCS).
    keys = list(payload.keys())
    if keys != sorted(keys):
        print(f"FAIL: payload keys are not in lexicographic order: {keys}")
        return 1

    canonical_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    # Pad the base64url to a multiple of 4 before decoding.
    sig_bytes = base64.urlsafe_b64decode(signature_b64 + "==")

    pub_pem = open(public_key_path, "rb").read()
    public_key = serialization.load_pem_public_key(pub_pem)

    try:
        public_key.verify(sig_bytes, canonical_bytes, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        print("FAIL: RSA-SHA256 signature verification failed — anchor may have been tampered with")
        return 1
    except Exception as exc:
        print(f"FAIL: signature verification error: {exc}")
        return 1

    app_id = payload.get("app_id", "?")
    environment = payload.get("environment", "?")
    head_hash = payload.get("head_hash", "?")
    head_seq = payload.get("head_seq", "?")
    anchored_at = payload.get("anchored_at", "?")
    print(f"ANCHOR VALID  kid={kid}  app={app_id}  env={environment}")
    print(f"  anchored_at={anchored_at}  head_seq={head_seq}  head_hash={str(head_hash)[:32]}...")
    print("  RSA-SHA256 signature verified against provided public key.")
    print("  Cross-check: export rows after this anchor should have this hash as prev_hash on the first retained row.")
    return 0


def check_outcome_binding(row):
    """Validate exported copies against the metadata inside the hashed preimage.

    Split from the right: earlier free-text fields can contain LF, whereas
    PostgreSQL JSONB text escapes newlines inside strings. Do not parse the
    exported metadata and assume that it was what the trigger hashed.
    """
    preamble, metadata_text, _timestamp, hashed_prev = row["chain_input"].rsplit("\n", 3)
    version, row_id, seq, app_id, _rest = preamble.split("\n", 4)
    if version != "v1":
        raise ValueError("unsupported chain preimage version")
    for field, actual in (("id", row_id), ("chain_seq", seq), ("app_id", app_id)):
        if str(row.get(field)) != actual:
            raise ValueError(f"{field} differs from hash-covered value")
    if (row.get("prev_hash") or "") != hashed_prev:
        raise ValueError("prev_hash differs from hash-covered value")
    hashed_env = preamble.rsplit("\n", 1)[1]
    if (row.get("environment") or "unknown") != hashed_env:
        raise ValueError("environment differs from hash-covered value")
    metadata = json.loads(metadata_text) if metadata_text else None
    if "metadata" in row and row["metadata"] != metadata:
        raise ValueError("metadata differs from hash-covered value")
    protected = metadata if isinstance(metadata, dict) else {}
    is_report = (row.get("status") == "outcome_reported"
                 or protected.get("outcome_for") is not None
                 or row.get("outcome_for") is not None
                 or row.get("outcome") in ("executed", "failed", "unknown"))
    if not is_report:
        if row.get("outcome") not in (None, "unreported") or row.get("status_class") is not None:
            raise ValueError("unexpected outcome fields on non-outcome row")
        return
    for field in ("outcome", "outcome_for", "status_class"):
        if row.get(field) != protected.get(field):
            raise ValueError(f"{field} differs from hash-covered metadata")
    if protected.get("outcome") not in ("executed", "failed", "unknown"):
        raise ValueError("invalid reported outcome")
    target = protected.get("outcome_for")
    if not isinstance(target, str):
        raise ValueError("outcome_for must be a UUID")
    uuid.UUID(target)
    if target == row_id:
        raise ValueError("outcome row cannot refer to itself")
    if protected.get("status_class") not in (None, "1xx", "2xx", "3xx", "4xx", "5xx"):
        raise ValueError("invalid status_class")
    # Outcome rows use these fixed trailing fields in migration 057. Validate
    # against exported copies by reconstruction, so embedded LF in a jti is
    # not mistaken for a field boundary.
    tail_fields = ("status", "jti", "granted_event_id", "environment")
    if row.get("status") != "outcome_reported":
        raise ValueError("outcome report must have outcome_reported status")
    expected_tail = "\n" + "\n".join(str(row.get(k) or "") for k in tail_fields)
    if not preamble.endswith(expected_tail):
        raise ValueError("outcome status/linkage differs from hash-covered value")


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--verify-anchor":
        anchor_path = args[1] if len(args) > 1 else "-"
        public_key_path = None
        for i, a in enumerate(args):
            if a == "--public-key" and i + 1 < len(args):
                public_key_path = args[i + 1]
        if public_key_path is None:
            print("Usage: verify_audit_chain.py --verify-anchor anchor.json --public-key app_public_key.pem")
            return 2
        return verify_anchor(anchor_path, public_key_path)

    src = args[0] if args else "-"
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
            # Outcome reporting postdates chaining; an outcome cannot be
            # presented as an unverifiable legacy row by stripping its hash.
            metadata = r.get("metadata")
            if (r.get("status") == "outcome_reported"
                    or r.get("outcome_for") is not None
                    or r.get("outcome") in ("executed", "failed", "unknown")
                    or (isinstance(metadata, dict) and metadata.get("outcome_for") is not None)):
                failures.append(f"unchained outcome report at {r['id']}")
            unchained += 1
            if key in heads:
                failures.append(f"unchained row {r['id']} AFTER chain started")
            continue

        chained += 1
        if hashlib.sha256(r["chain_input"].encode("utf-8")).hexdigest() != row_hash:
            failures.append(f"row_hash mismatch at {r['id']} (content altered?)")
        try:
            check_outcome_binding(r)
        except (ValueError, TypeError, KeyError) as exc:
            failures.append(f"invalid outcome/preimage binding at {r['id']}: {exc}")
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
