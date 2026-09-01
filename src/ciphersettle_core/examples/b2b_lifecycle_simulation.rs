//! B2B lifecycle simulation for VetKeys-Powered Invoice Settlement Canister.
//!
//! Runs entirely against `ciphersettle_core::ProtocolState` -- the same
//! pure-logic "executable spec" the canister is built from (see the
//! project README's "Treat ProtocolState as the executable spec" note).
//! This means the simulation below exercises the *exact* access-control,
//! nullifier, and audit-logging rules the real canister enforces, without
//! needing `dfx` or a live replica.
//!
//! Run it with:
//!   cargo run --example b2b_lifecycle_simulation -p ciphersettle_core
//!
//! Narrates a realistic B2B invoice-financing scenario end to end:
//! platform setup, successful registration, both flavors of rejected
//! registration (the double-financing check and the oracle-closing fix
//! from the round-3/round-5 reviews), settlement-access grant and
//! revocation, key-derivation ("verification") by an authorized bank and
//! by a regulator, unauthorized-access rejection, settlement, and
//! ciphertext-pruning eligibility. Every step's actual `Result` is checked
//! with `assert!`/`assert_eq!` -- this isn't just a script that prints
//! things and hopes; a change to the protocol's rules that alters any of
//! these outcomes will make this example panic, not silently produce
//! different output.

use ciphersettle_core::{InvoiceFingerprint, ProtocolState};

/// Small helper so each step's narration and outcome are easy to scan.
fn step(n: u32, title: &str) {
    println!("\n[{n:02}] {title}");
    println!("{}", "-".repeat(4 + title.len()));
}

fn fingerprint(issuer: &str, invoice_number: &str, currency: &str, amount: u64, due_date: u64) -> InvoiceFingerprint {
    InvoiceFingerprint {
        issuer_identifier: issuer.to_string(),
        invoice_number: invoice_number.to_string(),
        currency_code: currency.to_string(),
        amount_minor_units: amount,
        due_date_unix: due_date,
    }
}

fn main() {
    println!("=====================================================");
    println!(" VetKeys-Powered Invoice Settlement Canister -- B2B invoice-financing lifecycle demo");
    println!("=====================================================");
    println!(
        "Cast: Acme Manufacturing Ltd (issuer), Meridian Trade\n\
         Finance (bank), Northbridge Compliance Partners (regulator),\n\
         and the canister's platform operator (admin)."
    );

    // Principals: in the real canister these are IC Principals; ProtocolState
    // uses plain strings so this crate has zero IC dependencies (see its
    // module doc). A B2B integrator's client would substitute each of these
    // with the counterparty's actual authenticated Principal.
    let admin = "platform-operator".to_string();
    let acme = "issuer-acme-mfg".to_string();
    let meridian = "bank-meridian-tf".to_string();
    let northbridge = "regulator-northbridge".to_string();
    let random_competitor = "unrelated-third-party".to_string();

    // ---------------------------------------------------------------
    step(1, "Platform setup: admin onboards a compliance regulator");
    // ---------------------------------------------------------------
    // In production this is a one-time (or periodic) admin action per
    // regulator relationship -- e.g. a compliance team the platform
    // operator has a standing legal arrangement with.
    let mut state = ProtocolState::new(admin.clone());
    state
        .register_regulator(&admin, northbridge.clone())
        .expect("admin should be able to register a regulator");
    println!("Registered regulator: {northbridge}");

    // A non-admin trying the same action must be rejected -- this is the
    // access-control boundary a B2B platform operator relies on to keep
    // "who can see disclosure-worthy metadata" a deliberate decision, not
    // whoever calls first.
    let rejected = state.register_regulator(&acme, "rogue-regulator".to_string());
    assert!(rejected.is_err(), "a non-admin must not be able to register a regulator");
    println!("Confirmed: non-admin regulator registration correctly rejected ({:?})", rejected.unwrap_err());

    // ---------------------------------------------------------------
    step(2, "Registration: Acme registers a real invoice");
    // ---------------------------------------------------------------
    // Acme's own back-office system encrypts the invoice content client-side
    // (out of scope for this crate -- see the project README's "still open"
    // list) and submits the ciphertext alongside five declared identifying
    // fields. The canister derives the nullifier itself; ProtocolState
    // mirrors that exactly.
    let invoice_1_id = "ACME-2026-Q3-00231".to_string();
    let invoice_1_fp = fingerprint("ACME-TAXID-4471", "INV-100231", "USD", 4_850_000, 1_798_761_600); // $48,500.00 in minor units
    let nullifier_1 = state
        .register_invoice(&acme, invoice_1_id.clone(), &invoice_1_fp, 1_735_689_600)
        .expect("a fresh, valid invoice should register");
    println!(
        "Registered {invoice_1_id} for Acme -- nullifier receipt: {}",
        nullifier_1.to_hex()
    );

    // ---------------------------------------------------------------
    step(3, "Rejection: the same invoice cannot be double-financed");
    // ---------------------------------------------------------------
    // A second, uncoordinated submission of the *same* declared fields --
    // whether an honest duplicate submission or an attempted second
    // financing of the same invoice at a different bank -- must collide on
    // the same nullifier and be rejected, regardless of what invoice_id or
    // which caller is used.
    let duplicate_attempt = state.register_invoice(
        &random_competitor,
        "some-other-invoice-id".to_string(),
        &invoice_1_fp, // identical fields, different id and caller
        1_735_689_600,
    );
    assert!(duplicate_attempt.is_err(), "a duplicate fingerprint must be rejected");
    let duplicate_err = duplicate_attempt.unwrap_err();
    println!("Confirmed: double-financing attempt rejected -- \"{duplicate_err}\"");

    // ---------------------------------------------------------------
    step(4, "Rejection: the error message doesn't leak which reason applied");
    // ---------------------------------------------------------------
    // Round 3/5 finding: an unauthenticated caller must not be able to
    // distinguish "this exact invoice is already registered" from "you
    // picked a taken invoice_id" -- otherwise register_invoice becomes an
    // oracle a competitor could use to fingerprint-and-guess which
    // invoices already exist. Both rejection reasons must produce the
    // identical message.
    let duplicate_id_attempt = state.register_invoice(
        &acme,
        invoice_1_id.clone(), // reuse the same invoice_id
        &fingerprint("ACME-TAXID-4471", "INV-999999", "USD", 1, 1), // different fields
        1_735_689_600,
    );
    let duplicate_id_err = duplicate_id_attempt.unwrap_err();
    assert_eq!(
        duplicate_err, duplicate_id_err,
        "duplicate-fingerprint and duplicate-invoice_id rejections must be indistinguishable"
    );
    println!("Confirmed: both rejection reasons produce the same caller-facing message");
    println!("(the specific reason is still in the audit log -- see step 10)");

    // ---------------------------------------------------------------
    step(5, "Verification setup: Acme grants Meridian settlement access");
    // ---------------------------------------------------------------
    state
        .grant_settlement_access(&acme, &invoice_1_id, meridian.clone())
        .expect("issuer should be able to grant settlement access");
    println!("Acme granted settlement access on {invoice_1_id} to Meridian");

    // ---------------------------------------------------------------
    step(6, "Verification: Meridian derives a decryption key");
    // ---------------------------------------------------------------
    // In the real canister this triggers a vetKD threshold key derivation;
    // ProtocolState models the access-decision half of that (who's allowed
    // to ask), which is the part actually enforceable in software.
    let role = state
        .request_key_access(&meridian, &invoice_1_id)
        .expect("the granted bank should be authorized to derive a key");
    println!("Meridian's access resolved to role: {role:?}");
    assert_eq!(role, ciphersettle_core::AccessRole::Bank);

    // An unrelated third party must be denied the same request.
    let denied = state.request_key_access(&random_competitor, &invoice_1_id);
    assert!(denied.is_err(), "an unrelated party must not be able to derive a key");
    println!("Confirmed: unrelated party's key-derivation request correctly denied");

    // ---------------------------------------------------------------
    step(7, "Verification: regulator disclosure, distinctly logged");
    // ---------------------------------------------------------------
    // Northbridge has standing disclosure access to every invoice, not
    // just this one -- but every such access is logged distinctly as a
    // "disclosure" event, not conflated with ordinary counterparty access.
    let regulator_role = state
        .request_key_access(&northbridge, &invoice_1_id)
        .expect("a registered regulator should be authorized to derive a key");
    assert_eq!(regulator_role, ciphersettle_core::AccessRole::Regulator);
    println!("Northbridge's access resolved to role: {regulator_role:?} (logged as a disclosure event)");

    // ---------------------------------------------------------------
    step(8, "Access change: Acme revokes Meridian's access mid-lifecycle");
    // ---------------------------------------------------------------
    // A realistic B2B scenario: the financing arrangement with Meridian
    // falls through before settlement, and Acme wants to pull access.
    state
        .revoke_settlement_access(&acme, &invoice_1_id)
        .expect("issuer should be able to revoke settlement access");
    println!("Acme revoked Meridian's settlement access on {invoice_1_id}");

    let after_revocation = state.request_key_access(&meridian, &invoice_1_id);
    assert!(
        after_revocation.is_err(),
        "revoked bank must not be able to derive a *new* key"
    );
    println!("Confirmed: Meridian can no longer derive a new key for this invoice");
    println!(
        "(NB: this only blocks *future* derivations -- a key already derived\n\
         in step 6 isn't retroactively invalidated; see the project README's\n\
         \"Still open\" item 3 on key-revocation semantics)"
    );

    // Re-grant to a different bank to show a fresh financing relationship
    // can proceed normally after the first one falls through.
    let bridgeport = "bank-bridgeport-capital".to_string();
    state
        .grant_settlement_access(&acme, &invoice_1_id, bridgeport.clone())
        .expect("issuer should be able to grant access to a new bank");
    println!("Acme granted settlement access on {invoice_1_id} to Bridgeport Capital instead");

    // ---------------------------------------------------------------
    step(9, "Execution: settlement");
    // ---------------------------------------------------------------
    // Actual fund movement happens entirely off-canister (see the README's
    // "don't touch the money" design constraint) -- this just records the
    // terminal state.
    state
        .mark_settled(&bridgeport, &invoice_1_id, 1_798_800_000)
        .expect("the granted bank should be able to mark the invoice settled");
    println!("Bridgeport Capital marked {invoice_1_id} as settled");

    let double_settle = state.mark_settled(&acme, &invoice_1_id, 1_798_800_001);
    assert!(double_settle.is_err(), "an already-settled invoice must reject a second settlement");
    println!("Confirmed: double-settlement attempt correctly rejected");

    // ---------------------------------------------------------------
    step(10, "Verification: full audit trail, and the admin-only view");
    // ---------------------------------------------------------------
    let acme_view = state
        .get_audit_log_authorized(&acme, Some(&invoice_1_id))
        .expect("the issuer should be able to read this invoice's own audit log");
    println!("Acme's view of {invoice_1_id}'s audit log ({} events):", acme_view.len());
    for event in &acme_view {
        println!("  - {:<28} actor={}", event.action, event.actor);
    }

    let stranger_view = state.get_audit_log_authorized(&random_competitor, Some(&invoice_1_id));
    assert!(stranger_view.is_err(), "an unrelated party must not be able to read this invoice's audit log");
    println!("Confirmed: unrelated party denied read access to this invoice's audit log");

    let admin_unscoped = state
        .get_audit_log_authorized(&admin, None)
        .expect("admin should be able to read the unscoped, cross-invoice audit log");
    println!(
        "\nAdmin's unscoped view sees all {} events across the platform, including\n\
         the two rejected-registration attempts from steps 3-4, filed under\n\
         invoice_id \"*\" since they never became real invoices:",
        admin_unscoped.len()
    );
    for event in admin_unscoped.iter().filter(|e| e.invoice_id == "*") {
        println!("  - {:<45} actor={}", event.action, event.actor);
    }
    let non_admin_unscoped = state.get_audit_log_authorized(&acme, None);
    assert!(non_admin_unscoped.is_err(), "only admin may read the unscoped, cross-invoice log");
    println!("Confirmed: non-admin denied the unscoped, cross-invoice audit log");

    // ---------------------------------------------------------------
    step(11, "Wind-down: ciphertext-pruning eligibility over time");
    // ---------------------------------------------------------------
    let settled_at = 1_798_800_000u64;
    let retention_nanos = 180 * 24 * 60 * 60 * 1_000_000_000u64; // ~180 days, matches the canister's default

    let too_soon = settled_at + 1_000_000_000; // 1 second after settlement
    assert!(
        !state.is_eligible_for_ciphertext_pruning(&invoice_1_id, too_soon, retention_nanos),
        "ciphertext must not be prune-eligible immediately after settlement"
    );
    println!("Confirmed: not prune-eligible immediately after settlement");

    let well_past_retention = settled_at + retention_nanos + 1_000_000_000;
    assert!(
        state.is_eligible_for_ciphertext_pruning(&invoice_1_id, well_past_retention, retention_nanos),
        "ciphertext must become prune-eligible once past the retention window"
    );
    println!("Confirmed: prune-eligible once past the ~180-day retention window");
    println!(
        "(the invoice record and its full audit trail are never pruned --\n\
         only the ciphertext payload is dropped once eligible)"
    );

    println!("\n=====================================================");
    println!(" All {} scenario steps completed and asserted correctly.", 11);
    println!("=====================================================");
}
