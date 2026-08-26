#!/usr/bin/env bash
# CipherSettle end-to-end test suite (local ICP replica).
# Reinstalls the canister first, so it always runs against clean state and is
# safe to re-run back-to-back.
set -u
CAN=ciphersettle_backend
PASS=0; FAIL=0

echo "=== 0. Fresh canister state (reinstall) ==="
dfx canister install --mode reinstall "$CAN" -y >/dev/null || {
  echo "reinstall failed — is the replica running and the canister deployed?"; exit 1
}
echo "  ok: canister state reset"

BANK=$(dfx --identity bank identity get-principal)
STRANGER=$(dfx --identity stranger identity get-principal)
REGULATOR=$(dfx --identity regulator identity get-principal)

# valid 48-byte BLS12-381 G1 compressed point (G1 generator) as transport key
TPK=$(python3 -c "print(';'.join(str(b) for b in bytes.fromhex('97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb')))")

call() { # call <identity> <method> [args] -> flattened output
  local id="$1"; shift
  dfx ${id:+--identity "$id"} canister call "$CAN" "$@" 2>&1 | tr '\n' ' '
}

callc() { # callc <identity> <cycles> <method> <args> -- call with attached cycles
  # --with-cycles requires --wallet on the local network; each identity owns one.
  local id="$1" cycles="$2"; shift 2
  local w
  w=$(dfx ${id:+--identity "$id"} identity get-wallet 2>/dev/null)
  dfx ${id:+--identity "$id"} canister call --wallet "$w" --with-cycles "$cycles" "$CAN" "$@" 2>&1 | tr '\n' ' '
}

expect() { # expect <name> <expected-substring> <output>
  local name="$1" want="$2" out="$3"
  if printf '%s' "$out" | grep -qF "$want"; then
    PASS=$((PASS+1)); echo "  PASS: $name"
  else
    FAIL=$((FAIL+1)); echo "  FAIL: $name"
    echo "        wanted: $want"
    echo "        got   : $(printf '%s' "$out" | head -c 220)"
  fi
}

echo "=== A. Admin / regulator management ==="
expect "A1 non-admin cannot register regulator" "only the canister admin" \
  "$(call bank register_regulator "(principal \"$REGULATOR\")")"
expect "A2 admin registers regulator" "(variant { Ok })" \
  "$(call '' register_regulator "(principal \"$REGULATOR\")")"
expect "A3 revoke unknown regulator errors" "not a registered regulator" \
  "$(call '' revoke_regulator "(principal \"$STRANGER\")")"

echo "=== B. vetKD public key ==="
# NOTE: .did declares get_vetkd_public_key : () -> (blob) -- a bare blob, NOT a variant.
PK=$(call '' get_vetkd_public_key)
NB=$(printf '%s' "$PK" | grep -oE '\\[0-9a-f]{2}' | wc -l)
if printf '%s' "$PK" | grep -qF 'blob "' && [ "$NB" -eq 96 ]; then
  PASS=$((PASS+1)); echo "  PASS: B1 get_vetkd_public_key returns 96-byte blob (BLS12-381 G2)"
else
  FAIL=$((FAIL+1)); echo "  FAIL: B1 get_vetkd_public_key"; echo "        got: $(printf '%s' "$PK" | head -c 220)"; echo "        byte count: $NB"
fi

echo "=== C. Invoice registration + double-financing guard ==="
CT_BLOB='blob "\89\95\40\16\5a"'  # bytes 137;149;64;22;90
expect "C1 issuer registers INV-001" "(variant { Ok })" \
  "$(call '' register_invoice '("INV-001", "NULL-A", vec{137; 149; 64; 22; 90})')"
expect "C2 duplicate invoice_id rejected" "invoice_id already exists" \
  "$(call '' register_invoice '("INV-001", "NULL-B", vec{1})')"
expect "C3 same nullifier on new invoice rejected (double financing)" "nullifier already registered" \
  "$(call '' register_invoice '("INV-002", "NULL-A", vec{2})')"

python3 -c "
blob = ';'.join(['1']*65537)
open('/tmp/opencode/big.args','w').write(f'(\"INV-BIG\", \"NULL-BIG\", vec{{{blob}}})')"
expect "C4 oversized payload (>64KiB) rejected" "exceeds the 65536-byte limit" \
  "$(dfx canister call $CAN register_invoice --argument-file /tmp/opencode/big.args 2>&1 | tr '\n' ' ')"
expect "C5 invalid invoice_id format rejected" "invoice_id may only contain" \
  "$(call '' register_invoice '("INV 001 BAD", "NULL-FMT", vec{1})')"
expect "C6 empty nullifier rejected" "nullifier_hash must not be empty" \
  "$(call '' register_invoice '("INV-FMT2", "", vec{1})')"

echo "=== D. Confidential retrieval / access control ==="
expect "D1 bank denied before grant" "not authorized to view this invoice" \
  "$(call bank get_encrypted_invoice '("INV-001")')"
expect "D2 stranger denied" "not authorized to view this invoice" \
  "$(call stranger get_encrypted_invoice '("INV-001")')"
expect "D3 issuer reads own ciphertext" "$CT_BLOB" \
  "$(call '' get_encrypted_invoice '("INV-001")')"
expect "D4 non-issuer cannot grant access" "only the issuer can grant settlement access" \
  "$(call bank grant_settlement_access "(\"INV-001\", principal \"$BANK\")")"
expect "D5 issuer grants bank" "(variant { Ok })" \
  "$(call '' grant_settlement_access "(\"INV-001\", principal \"$BANK\")")"
expect "D6 bank reads ciphertext after grant" "$CT_BLOB" \
  "$(call bank get_encrypted_invoice '("INV-001")')"
expect "D7 unknown invoice errors" "invoice not found" \
  "$(call '' get_encrypted_invoice '("NOPE")')"

echo "=== E. vetKD key derivation ==="
# Authorization runs BEFORE the cycles fee is accepted, so denied callers are
# never charged; only successful-derivation paths need --with-cycles.
expect "E1 stranger cannot derive key (and pays nothing)" "not authorized to derive a decryption key" \
  "$(call stranger derive_invoice_key "(\"INV-001\", vec{$TPK})")"
LAST=""
for i in 2 3 4 5 6; do LAST=$(call stranger derive_invoice_key "(\"INV-001\", vec{$TPK})"); done
expect "E2 rate limit trips at call 6 (5/60s)" "rate limit exceeded for key derivation" "$LAST"
expect "E3 underfunded derivation rejected" "insufficient cycles attached" \
  "$(call bank derive_invoice_key "(\"INV-001\", vec{$TPK})")"

# dfx implements --with-cycles by relaying through the identity's wallet
# canister, so the canister sees the WALLET principal as msg_caller. That is
# the correct IC semantic for relayed calls: the relayer pays and signs.
# Paid derivation is therefore exercised on a dedicated invoice granted to
# the bank's wallet principal, mirroring how a wallet-relayed client integrates.
BANKW=$(dfx --identity bank identity get-wallet 2>/dev/null)
REGW=$(dfx --identity regulator identity get-wallet 2>/dev/null)
call '' register_invoice '("INV-PAID", "NULL-PAID", vec{9; 9})' >/dev/null
call '' grant_settlement_access "(\"INV-PAID\", principal \"$BANKW\")" >/dev/null
call '' register_regulator "(principal \"$REGW\")" >/dev/null

expect "E4 bank (via wallet, paying fee) derives key successfully" "Ok = blob" \
  "$(callc bank 2000000000 derive_invoice_key "(\"INV-PAID\", vec{$TPK})")"
expect "E5 regulator (via wallet, paying fee) derives key successfully (disclosure)" "Ok = blob" \
  "$(callc regulator 2000000000 derive_invoice_key "(\"INV-PAID\", vec{$TPK})")"
# Denied (E1/E2) and underfunded (E3) derivations must leave NO audit entries:
# no success actions, no disclosure requests, no failure records.
if [ -z "$(call '' get_audit_log '(opt "INV-001")' | grep -oE 'key_derived_bank|disclosure_request|key_derivation_failed')" ]; then
  PASS=$((PASS+1)); echo "  PASS: E6 denied/underfunded derivations leave no derivation audit entries"
else
  FAIL=$((FAIL+1)); echo "  FAIL: E6 INV-001 audit unexpectedly contains derivation actions"
fi
AUDIT_PAID=$(call '' get_audit_log '(opt "INV-PAID")')
if printf '%s' "$AUDIT_PAID" | grep -qF 'key_derived_bank' && printf '%s' "$AUDIT_PAID" | grep -qF 'disclosure_request'; then
  PASS=$((PASS+1)); echo "  PASS: E7 paid derivations logged once each (success actions only)"
else
  FAIL=$((FAIL+1)); echo "  FAIL: E7 paid derivations logged once each"; echo "        got: $(printf '%s' "$AUDIT_PAID" | grep -oE 'action = "[a-z_]+"' | tr '\n' ' ')"
fi

echo "=== F. Disputes ==="
expect "F1 stranger cannot raise dispute" "registered regulator can raise a dispute" \
  "$(call stranger raise_dispute '("INV-001")')"
expect "F2 issuer raises dispute" "(variant { Ok })" \
  "$(call '' raise_dispute '("INV-001")')"
expect "F3 double dispute rejected" "a dispute is already open" \
  "$(call '' raise_dispute '("INV-001")')"
expect "F4 unknown invoice dispute errors" "invoice not found" \
  "$(call '' raise_dispute '("NOPE")')"

echo "=== G. Settlement lifecycle ==="
expect "G1 stranger cannot settle" "only the issuer or the granted bank" \
  "$(call stranger mark_settled '("INV-001")')"
expect "G2 bank settles invoice" "(variant { Ok })" \
  "$(call bank mark_settled '("INV-001")')"
expect "G3 double-settle rejected" "invoice is already settled" \
  "$(call bank mark_settled '("INV-001")')"
expect "G4 dispute flag persists after settlement (audit)" "dispute_raised" \
  "$(call '' get_audit_log '(opt "INV-001")' | grep -oF 'dispute_raised')"
expect "G5 issuer revokes bank access" "(variant { Ok })" \
  "$(call '' revoke_settlement_access '("INV-001")')"
expect "G6 second revoke errors (nothing granted)" "no settlement access is currently granted" \
  "$(call '' revoke_settlement_access '("INV-001")')"

echo "=== H. Pruning guard (admin-only) ==="
expect "H1 non-admin prune denied even when invoice is theirs" "only the admin can prune ciphertext" \
  "$(call bank prune_ciphertext '("INV-001")')"
expect "H2 admin prune blocked before retention window" "not yet eligible for pruning" \
  "$(call '' prune_ciphertext '("INV-001")')"

echo "=== I. Regulator lifecycle ==="
expect "I1 non-admin cannot revoke regulator" "only the canister admin" \
  "$(call bank revoke_regulator "(principal \"$REGULATOR\")")"
expect "I2 admin revokes regulator" "(variant { Ok })" \
  "$(call '' revoke_regulator "(principal \"$REGULATOR\")")"
expect "I3 revoked regulator loses derivation access" "not authorized to derive a decryption key" \
  "$(call regulator derive_invoice_key "(\"INV-001\", vec{$TPK})")"
expect "I4 revoked regulator cannot raise dispute" "registered regulator can raise a dispute" \
  "$(call regulator raise_dispute '("INV-001")')"

echo "=== J. Audit trail completeness ==="
AUDIT=$(call '' get_audit_log '(null)')
for action in invoice_registered settlement_access_granted key_derived_bank disclosure_request \
              regulator_registered invoice_settled dispute_raised \
              settlement_access_revoked regulator_revoked; do
  if printf '%s' "$AUDIT" | grep -qF "action = \"$action\""; then
    PASS=$((PASS+1)); echo "  PASS: J audit contains $action"
  else
    FAIL=$((FAIL+1)); echo "  FAIL: J audit missing $action"
  fi
done

echo
echo "==================================="
echo "RESULT: $PASS passed, $FAIL failed"
exit $([ $FAIL -eq 0 ] && echo 0 || echo 1)
