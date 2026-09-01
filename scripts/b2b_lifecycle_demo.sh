#!/usr/bin/env bash
#
# VetKeys-Powered Invoice Settlement Canister -- B2B lifecycle demo against a real deployed canister.
#
# Mirrors examples/b2b_lifecycle_simulation.rs (in ciphersettle_core) call
# for call, but drives the actual `ciphersettle_backend` canister via `dfx`
# instead of the in-memory ProtocolState spec. Use the Rust example to
# verify the *logic* without any deployment; use this script against a
# real `dfx start` replica (or a testnet/mainnet deployment, with the
# network flag changed) to verify the *canister* behaves the same way.
#
# NOT executed as part of this repository's automated verification: this
# sandbox has no `dfx` and no network path to fetch it (see the project
# README's "Confirmed in this session" / "Still not verified" notes). Every
# step below corresponds to an assertion that *was* actually run and
# checked in examples/b2b_lifecycle_simulation.rs -- treat this script as
# the operational reference translation of that verified logic into real
# `dfx canister call` invocations, not as independently-tested in its own
# right. Review it against ciphersettle_backend.did and lib.rs before
# relying on it, the same way you should for any infrastructure script.
#
# Usage:
#   dfx start --background
#   dfx deploy
#   ./scripts/b2b_lifecycle_demo.sh
#
# Requires: dfx, and jq for readable output (optional -- falls back to raw
# candid text if jq isn't installed).

set -euo pipefail

CANISTER=ciphersettle_backend
NETWORK="${DFX_NETWORK:-local}"

call() {
  dfx canister call "$CANISTER" --network "$NETWORK" "$@"
}

section() {
  echo ""
  echo "=================================================================="
  echo " $1"
  echo "=================================================================="
}

# ---------------------------------------------------------------------
section "[01] Platform setup: identify the actors"
# ---------------------------------------------------------------------
# In a real deployment each of these is a distinct authenticated Principal
# -- typically one dfx identity per organization for a demo like this one,
# or per-service-account keys held by each counterparty's backend in
# production. Swap `dfx identity` for whatever key-management your
# integrators actually use; the canister only ever sees the Principal.
ADMIN_PRINCIPAL=$(dfx identity get-principal)
echo "Admin (platform operator) principal: $ADMIN_PRINCIPAL"

# For a real multi-organization demo you'd create separate dfx identities
# (`dfx identity new acme-mfg`, `dfx identity new meridian-tf`, etc.) and
# switch between them with `dfx identity use <name>` before each call that
# should be attributed to that organization. This script assumes you've
# already created and noted the principals for:
#   ACME_PRINCIPAL        -- Acme Manufacturing Ltd (issuer)
#   MERIDIAN_PRINCIPAL     -- Meridian Trade Finance (bank)
#   BRIDGEPORT_PRINCIPAL   -- Bridgeport Capital (replacement bank)
#   NORTHBRIDGE_PRINCIPAL  -- Northbridge Compliance Partners (regulator)
: "${ACME_PRINCIPAL:?set this to Acme's dfx identity principal}"
: "${MERIDIAN_PRINCIPAL:?set this to Meridian's dfx identity principal}"
: "${BRIDGEPORT_PRINCIPAL:?set this to Bridgeport's dfx identity principal}"
: "${NORTHBRIDGE_PRINCIPAL:?set this to Northbridge's dfx identity principal}"

# ---------------------------------------------------------------------
section "[02] Platform setup: admin onboards the regulator"
# ---------------------------------------------------------------------
call register_regulator "(principal \"$NORTHBRIDGE_PRINCIPAL\")"
echo "-> expect: (variant { Ok })"

echo ""
echo "Confirming a non-admin can't do the same (expect an Err):"
dfx identity use acme-mfg 2>/dev/null || true
call register_regulator "(principal \"rogue-regulator-principal\")" || true
dfx identity use default 2>/dev/null || true

# ---------------------------------------------------------------------
section "[03] Registration: Acme registers a real invoice (as Acme)"
# ---------------------------------------------------------------------
dfx identity use acme-mfg
INVOICE_1_ID="ACME-2026-Q3-00231"
# Candid blob literals are backslash-escaped byte pairs, e.g. \00\01\02\03
# -- this is a placeholder; substitute your client's real ciphertext bytes.
call register_invoice "(
  \"$INVOICE_1_ID\",
  \"ACME-TAXID-4471\",
  \"INV-100231\",
  \"USD\",
  4_850_000 : nat64,
  1_798_761_600 : nat64,
  blob \"\\00\\01\\02\\03\"
)"
echo "-> expect: (variant { Ok = \"<64-char hex nullifier receipt>\" })"

# ---------------------------------------------------------------------
section "[04] Rejection: the same invoice cannot be double-financed"
# ---------------------------------------------------------------------
# Same declared fields, different invoice_id and a different (unrelated)
# caller -- must be rejected with the generic message, not a message that
# reveals *why* (see the round-3/round-5 review notes on the
# register_invoice oracle finding).
dfx identity use unrelated-third-party 2>/dev/null || dfx identity use default
call register_invoice "(
  \"some-other-invoice-id\",
  \"ACME-TAXID-4471\",
  \"INV-100231\",
  \"USD\",
  4_850_000 : nat64,
  1_798_761_600 : nat64,
  blob \"\\00\\01\\02\\03\"
)" || true
echo "-> expect: (variant { Err = \"registration was not completed\" })"

# ---------------------------------------------------------------------
section "[05] Verification setup: Acme grants Meridian settlement access"
# ---------------------------------------------------------------------
dfx identity use acme-mfg
call grant_settlement_access "(\"$INVOICE_1_ID\", principal \"$MERIDIAN_PRINCIPAL\")"
echo "-> expect: (variant { Ok })"

# ---------------------------------------------------------------------
section "[06] Verification: Meridian derives a decryption key (vetKD)"
# ---------------------------------------------------------------------
# Real client flow: fetch the transport keypair's public key locally,
# call get_vetkd_public_key once per canister (cacheable), then call
# derive_invoice_key with your transport public key bytes. This script
# shows the shape of the calls; a real client uses @dfinity/vetkeys to
# generate the transport keypair and decrypt the returned encrypted_key
# client-side -- that part never touches dfx directly.
dfx identity use meridian-tf 2>/dev/null || true
call get_vetkd_public_key "()"
# Real transport public key bytes come from your vetkeys client library
# (e.g. TransportSecretKey.publicKeyBytes() via @dfinity/vetkeys), encoded
# as a Candid blob literal (\XX per byte). Placeholder length shown only.
TRANSPORT_PUBLIC_KEY_BLOB="blob \"\\00\\01...\\XX\"  # 32-256 bytes, see MIN/MAX_TRANSPORT_KEY_BYTES in lib.rs"
call derive_invoice_key "(\"$INVOICE_1_ID\", $TRANSPORT_PUBLIC_KEY_BLOB)"
echo "-> expect: (variant { Ok = blob \"<encrypted key material>\" })"

echo ""
echo "Confirming an unrelated party is denied the same request:"
dfx identity use default 2>/dev/null || true
call derive_invoice_key "(\"$INVOICE_1_ID\", $TRANSPORT_PUBLIC_KEY_BLOB)" || true
echo "-> expect: (variant { Err = \"not authorized to derive a decryption key for this invoice\" })"

# ---------------------------------------------------------------------
section "[07] Verification: regulator disclosure, distinctly logged"
# ---------------------------------------------------------------------
dfx identity use northbridge-compliance 2>/dev/null || true
call derive_invoice_key "(\"$INVOICE_1_ID\", $TRANSPORT_PUBLIC_KEY_BLOB)"
echo "-> expect: (variant { Ok = ... }); logged as a disclosure_request event, not key_derived_bank"

# ---------------------------------------------------------------------
section "[08] Access change: Acme revokes Meridian, grants Bridgeport instead"
# ---------------------------------------------------------------------
dfx identity use acme-mfg
call revoke_settlement_access "(\"$INVOICE_1_ID\")"
echo "-> expect: (variant { Ok })"
call grant_settlement_access "(\"$INVOICE_1_ID\", principal \"$BRIDGEPORT_PRINCIPAL\")"
echo "-> expect: (variant { Ok })"
echo ""
echo "NB: this only blocks Meridian's *future* key derivations. A key"
echo "Meridian already derived in step 6 is not retroactively invalidated"
echo "-- see the project README's 'Still open' item 3."

# ---------------------------------------------------------------------
section "[09] Execution: settlement"
# ---------------------------------------------------------------------
dfx identity use bridgeport-capital 2>/dev/null || true
call mark_settled "(\"$INVOICE_1_ID\")"
echo "-> expect: (variant { Ok })"
call mark_settled "(\"$INVOICE_1_ID\")" || true
echo "-> expect (second call): (variant { Err = \"invoice is already settled\" })"

# ---------------------------------------------------------------------
section "[10] Verification: audit trail, scoped and unscoped"
# ---------------------------------------------------------------------
dfx identity use acme-mfg
call get_audit_log "(opt \"$INVOICE_1_ID\", null, null)"
echo "-> expect: Acme's own invoice's full event history"

dfx identity use unrelated-third-party 2>/dev/null || dfx identity use default
call get_audit_log "(opt \"$INVOICE_1_ID\", null, null)" || true
echo "-> expect: (variant { Err = \"not authorized to view the audit log for this invoice\" })"

dfx identity use default
call get_audit_log "(null, null, opt (500 : nat64))"
echo "-> expect: the full cross-invoice log (admin-only), including the"
echo "   step-04 rejection filed under invoice_id \"*\""

# ---------------------------------------------------------------------
section "[11] Wind-down: ciphertext pruning, once eligible"
# ---------------------------------------------------------------------
# prune_ciphertext is deliberately callable by anyone -- it's gated purely
# by the eligibility check (settled + past the ~180-day retention window),
# not by caller identity. In a real deployment this is typically triggered
# by a scheduled job, not manually.
call prune_ciphertext "(\"$INVOICE_1_ID\")" || true
echo "-> expect (immediately after settlement): (variant { Err = \"invoice is not yet eligible for pruning ...\" })"
echo "   (would succeed once ~180 days past settlement)"

echo ""
echo "=================================================================="
echo " Demo complete. Cross-check every '-> expect' line above against"
echo " the actual response your replica returned."
echo "=================================================================="
