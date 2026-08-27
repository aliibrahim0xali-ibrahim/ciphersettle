//! Pure decision logic for the confidential settlement protocol, deliberately
//! kept free of any ic-cdk / candid dependency so it can be built and tested
//! on any Rust toolchain, independent of the Internet Computer SDK version.
//! The canister crate (ciphersettle_backend) should call into this module rather than
//! re-implementing these decisions inline, so the rules are tested once here
//! and simply wired up there.

pub mod nullifier;
pub mod sha256;

pub use nullifier::{compute_nullifier, FingerprintError, InvoiceFingerprint, Nullifier};

/// A caller identity. In the real canister this wraps `candid::Principal`;
/// here it's a plain string so this crate has zero IC dependencies.
pub type CallerId = String;

#[derive(Debug, PartialEq, Eq)]
pub enum NullifierError {
    AlreadyClaimed,
}

/// Double-financing check: a nullifier may be claimed exactly once.
/// `already_present` is the caller's lookup result against the registry.
/// The nullifier itself must come from `compute_nullifier` -- see
/// `nullifier.rs` for why a free-form, caller-chosen nullifier defeats the
/// entire point of this check.
pub fn check_nullifier(already_present: bool) -> Result<(), NullifierError> {
    if already_present {
        Err(NullifierError::AlreadyClaimed)
    } else {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccessRole {
    Issuer,
    Bank,
    Regulator,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccessError {
    NotAuthorized,
}

/// Decide whether `caller` may derive a decryption key for an invoice, and
/// which role that access should be logged under. Regulator access always
/// wins the label even if a regulator happens to also be the issuer or bank,
/// because the log's job is to flag every possible disclosure event, not to
/// pick the "most convenient" explanation for a given call.
pub fn resolve_access(
    caller: &CallerId,
    issuer: &CallerId,
    bank: &Option<CallerId>,
    regulators: &[CallerId],
) -> Result<AccessRole, AccessError> {
    if regulators.iter().any(|r| r == caller) {
        return Ok(AccessRole::Regulator);
    }
    if caller == issuer {
        return Ok(AccessRole::Issuer);
    }
    if bank.as_ref() == Some(caller) {
        return Ok(AccessRole::Bank);
    }
    Err(AccessError::NotAuthorized)
}

/// Maps an access role to the exact audit-log action string the canister
/// should record. Centralized here so the log vocabulary can't drift between
/// call sites.
pub fn audit_action_for(role: &AccessRole) -> &'static str {
    match role {
        AccessRole::Regulator => "disclosure_request",
        AccessRole::Bank => "key_derived_bank",
        AccessRole::Issuer => "key_derived_issuer",
    }
}

// ---------------------------------------------------------------------------
// Rate limiting / cycle-guard decision logic. Pure and clock-injected so it's
// testable without a live replica. The canister supplies "now" (ic_cdk::api::time,
// nanoseconds) and the caller's recent call timestamps; this module only
// decides whether the call should be allowed.
// ---------------------------------------------------------------------------

/// A fixed-window rate limit: at most `max_calls` calls per `window_nanos`
/// per caller, evaluated against that caller's own call history for the
/// gated endpoint (e.g. derive_invoice_key).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitPolicy {
    pub max_calls: usize,
    pub window_nanos: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RateLimitError {
    TooManyRequests,
}

/// Decide whether a new call is allowed given the caller's prior call
/// timestamps (nanoseconds, ascending or unordered -- order doesn't matter
/// here) and the current time. Timestamps outside the trailing window are
/// ignored, so this is a sliding window, not a hard reset-at-boundary window.
pub fn check_rate_limit(
    policy: &RateLimitPolicy,
    prior_call_times: &[u64],
    now: u64,
) -> Result<(), RateLimitError> {
    let window_start = now.saturating_sub(policy.window_nanos);
    let calls_in_window = prior_call_times
        .iter()
        .filter(|&&t| t >= window_start && t <= now)
        .count();
    if calls_in_window >= policy.max_calls {
        Err(RateLimitError::TooManyRequests)
    } else {
        Ok(())
    }
}

/// Payload-size guard: reject any caller-supplied byte/string field above a
/// configured cap. Used for ciphertext (storage-inflation defense) and for
/// bounded-length identifier fields like `invoice_id` (same defense,
/// different field) so a single size-check function has one tested home
/// rather than being duplicated per call site.
pub fn check_payload_size(payload_len: usize, max_bytes: usize) -> Result<(), String> {
    if payload_len > max_bytes {
        Err(format!(
            "payload of {payload_len} bytes exceeds the {max_bytes}-byte limit"
        ))
    } else {
        Ok(())
    }
}

/// Sanity-bounds a caller-supplied transport public key's length before it's
/// forwarded to the vetKD system API. This is intentionally a loose range
/// check, not an exact-length assertion: confirm the precise expected byte
/// length against the version of `@dfinity/vetkeys` / `ic_vetkd_sdk_utils`
/// you pin, and tighten `min`/`max` to that exact value once confirmed --
/// a loose bound still stops a wildly malformed or unbounded-size blob from
/// being forwarded, but an exact check catches malformed keys earlier and
/// more precisely.
pub fn check_transport_key_length(len: usize, min: usize, max: usize) -> Result<(), String> {
    if len < min || len > max {
        Err(format!(
            "transport public key length {len} is outside the expected [{min}, {max}] byte range"
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Full protocol state machine. This mirrors ciphersettle_backend's stable-structure
// logic exactly (nullifier set, invoice map, regulator set, append-only
// audit log) but uses plain std collections so it compiles and tests on any
// Rust toolchain. Treat this as the executable specification: if you change
// a rule in the canister, change it here first, get the test passing, then
// port the same change over.
// ---------------------------------------------------------------------------

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: u64,
    pub invoice_id: String,
    pub actor: CallerId,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvoiceStatus {
    Active,
    Settled,
}

#[derive(Debug, Clone)]
struct Invoice {
    issuer: CallerId,
    bank: Option<CallerId>,
    status: InvoiceStatus,
    // Kept for future use (e.g. reporting/expiry-of-unsettled-invoices
    // policies) even though no current rule reads it yet.
    #[allow(dead_code)]
    created_at: u64,
    settled_at: Option<u64>,
}

#[derive(Debug, Default)]
pub struct ProtocolState {
    admin: Option<CallerId>,
    nullifiers: HashSet<Nullifier>,
    invoices: HashMap<String, Invoice>,
    regulators: HashSet<CallerId>,
    audit_log: Vec<AuditEvent>,
    next_event_id: u64,
}

impl ProtocolState {
    pub fn new(admin: CallerId) -> Self {
        Self {
            admin: Some(admin),
            ..Default::default()
        }
    }

    fn log(&mut self, invoice_id: &str, actor: &CallerId, action: &'static str) {
        let event = AuditEvent {
            id: self.next_event_id,
            invoice_id: invoice_id.to_string(),
            actor: actor.clone(),
            action: action.to_string(),
        };
        self.next_event_id += 1;
        self.audit_log.push(event);
    }

    fn is_admin(&self, caller: &CallerId) -> bool {
        self.admin.as_ref() == Some(caller)
    }

    pub fn register_regulator(&mut self, caller: &CallerId, regulator: CallerId) -> Result<(), String> {
        if !self.is_admin(caller) {
            return Err("only the admin can register regulators".to_string());
        }
        self.regulators.insert(regulator);
        self.log("*", caller, "regulator_registered");
        Ok(())
    }

    /// Admin-only removal of a previously registered regulator. Errors if the
    /// principal was never registered, so callers can't get a silent no-op
    /// that looks like a successful revoke.
    pub fn revoke_regulator(&mut self, caller: &CallerId, regulator: &CallerId) -> Result<(), String> {
        if !self.is_admin(caller) {
            return Err("only the admin can revoke regulators".to_string());
        }
        if !self.regulators.remove(regulator) {
            return Err("that principal is not a registered regulator".to_string());
        }
        self.log("*", caller, "regulator_revoked");
        Ok(())
    }

    /// Admin-only rotation of the admin identity itself. Without this, a
    /// lost or compromised admin key is a permanent lockout on every
    /// admin-gated operation (registering/revoking regulators, and this
    /// rotation itself). Logged like any other privileged action, since
    /// "who controls this canister's admin role changed" is exactly the
    /// kind of event an auditor should be able to see.
    pub fn transfer_admin(&mut self, caller: &CallerId, new_admin: CallerId) -> Result<(), String> {
        if !self.is_admin(caller) {
            return Err("only the current admin can transfer adminship".to_string());
        }
        self.admin = Some(new_admin);
        self.log("*", caller, "admin_rotated");
        Ok(())
    }

    /// Registers an invoice under a nullifier *derived by this function*
    /// from the caller-declared `fingerprint`, not supplied directly by the
    /// caller. See `nullifier.rs` for why that distinction is the whole
    /// point: a caller-chosen nullifier can always be "fresh," which makes
    /// double-financing prevention meaningless. Returns the derived
    /// nullifier on success so the caller can be given a receipt/reference
    /// without the canister ever persisting the underlying fields.
    pub fn register_invoice(
        &mut self,
        caller: &CallerId,
        invoice_id: String,
        fingerprint: &InvoiceFingerprint,
        created_at: u64,
    ) -> Result<Nullifier, String> {
        let nullifier = compute_nullifier(fingerprint)
            .map_err(|e| format!("invalid invoice fingerprint: {e:?}"))?;

        let already_claimed = self.nullifiers.contains(&nullifier);
        check_nullifier(already_claimed).map_err(|_| {
            "an invoice with these identifying fields (issuer, invoice number, currency, \
             amount, due date) is already registered -- this is the double-financing check"
                .to_string()
        })?;
        if self.invoices.contains_key(&invoice_id) {
            return Err("invoice_id already exists".to_string());
        }
        self.nullifiers.insert(nullifier);
        self.invoices.insert(
            invoice_id.clone(),
            Invoice {
                issuer: caller.clone(),
                bank: None,
                status: InvoiceStatus::Active,
                created_at,
                settled_at: None,
            },
        );
        self.log(&invoice_id, caller, "invoice_registered");
        Ok(nullifier)
    }

    pub fn grant_settlement_access(
        &mut self,
        caller: &CallerId,
        invoice_id: &str,
        bank: CallerId,
    ) -> Result<(), String> {
        let invoice = self
            .invoices
            .get_mut(invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if &invoice.issuer != caller {
            return Err("only the issuer can grant settlement access".to_string());
        }
        invoice.bank = Some(bank);
        self.log(invoice_id, caller, "settlement_access_granted");
        Ok(())
    }

    /// Issuer-only revocation of a previously granted counterparty. This is
    /// the missing half of `grant_settlement_access`: a financing
    /// arrangement falling through, or a bank's access needing to be pulled,
    /// no longer requires waiting for the invoice to reach a terminal state.
    /// Errors rather than silently no-op'ing if there was nothing to revoke,
    /// so a caller can't mistake "nothing happened" for "access removed".
    pub fn revoke_settlement_access(
        &mut self,
        caller: &CallerId,
        invoice_id: &str,
    ) -> Result<(), String> {
        let invoice = self
            .invoices
            .get_mut(invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if &invoice.issuer != caller {
            return Err("only the issuer can revoke settlement access".to_string());
        }
        if invoice.bank.take().is_none() {
            return Err("no settlement access is currently granted for this invoice".to_string());
        }
        self.log(invoice_id, caller, "settlement_access_revoked");
        Ok(())
    }

    pub fn request_key_access(
        &mut self,
        caller: &CallerId,
        invoice_id: &str,
    ) -> Result<AccessRole, String> {
        let invoice = self
            .invoices
            .get(invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        let regulators: Vec<CallerId> = self.regulators.iter().cloned().collect();
        let role = resolve_access(caller, &invoice.issuer, &invoice.bank, &regulators)
            .map_err(|_| "not authorized to derive a decryption key for this invoice".to_string())?;
        self.log(invoice_id, caller, audit_action_for(&role));
        Ok(role)
    }

    /// Issuer or the currently-granted bank may mark an invoice settled.
    /// Settlement itself (moving money) happens off-canister, per the
    /// project's "don't touch the money" design constraint -- this just
    /// records the terminal state so pruning eligibility can be evaluated.
    pub fn mark_settled(
        &mut self,
        caller: &CallerId,
        invoice_id: &str,
        settled_at: u64,
    ) -> Result<(), String> {
        let invoice = self
            .invoices
            .get_mut(invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        let is_participant = &invoice.issuer == caller || invoice.bank.as_ref() == Some(caller);
        if !is_participant {
            return Err("only the issuer or the granted bank can mark an invoice settled".to_string());
        }
        if invoice.status == InvoiceStatus::Settled {
            return Err("invoice is already settled".to_string());
        }
        invoice.status = InvoiceStatus::Settled;
        invoice.settled_at = Some(settled_at);
        self.log(invoice_id, caller, "invoice_settled");
        Ok(())
    }

    /// Pruning eligibility for an invoice's *ciphertext payload* -- not the
    /// audit log, which stays append-only forever regardless of pruning,
    /// since the audit trail is the compliance artifact and is metadata-only
    /// (no ciphertext, no plaintext) so it doesn't carry the same storage-cost
    /// pressure that raw ciphertext blobs do. An invoice is eligible once it
    /// is Settled AND has sat past `retention_nanos` since settlement.
    /// Active invoices are never eligible, regardless of age, since pruning
    /// an unsettled invoice would destroy data a bank or regulator may still
    /// need.
    pub fn is_eligible_for_ciphertext_pruning(
        &self,
        invoice_id: &str,
        now: u64,
        retention_nanos: u64,
    ) -> bool {
        match self.invoices.get(invoice_id) {
            Some(inv) => match (&inv.status, inv.settled_at) {
                (InvoiceStatus::Settled, Some(settled_at)) => {
                    now.saturating_sub(settled_at) >= retention_nanos
                }
                _ => false,
            },
            None => false,
        }
    }

    /// Unchecked accessor -- returns every matching event regardless of who
    /// is asking. Kept `pub(crate)` (not exported) so nothing outside this
    /// crate can bypass `get_audit_log_authorized` by mistake; use that
    /// instead from the canister.
    fn audit_log(&self, invoice_id: Option<&str>) -> Vec<&AuditEvent> {
        self.audit_log
            .iter()
            .filter(|e| invoice_id.map_or(true, |id| e.invoice_id == id))
            .collect()
    }

    /// Access-checked audit log read.
    ///
    /// - Per-invoice (`invoice_id = Some(..)`): the admin, the invoice's
    ///   issuer, its currently-granted bank, or any registered regulator may
    ///   read that invoice's events. Everyone else is denied -- an
    ///   unauthenticated global broadcast of "who granted access to whom,
    ///   and when a regulator investigated which invoice" is exactly the
    ///   metadata leak this method exists to close.
    /// - Unscoped (`invoice_id = None`): admin only. A full cross-invoice
    ///   listing reveals the entire relationship graph (every issuer/bank
    ///   pairing, every disclosure event, across every invoice at once),
    ///   which is a strictly bigger leak than any single invoice's log and
    ///   isn't needed by any role other than the operator.
    pub fn get_audit_log_authorized(
        &self,
        caller: &CallerId,
        invoice_id: Option<&str>,
    ) -> Result<Vec<&AuditEvent>, String> {
        if self.is_admin(caller) {
            return Ok(self.audit_log(invoice_id));
        }
        match invoice_id {
            None => Err(
                "only the admin can read the unscoped audit log; request a specific invoice_id instead"
                    .to_string(),
            ),
            Some(id) => {
                let invoice = self
                    .invoices
                    .get(id)
                    .ok_or_else(|| "invoice not found".to_string())?;
                let regulators: Vec<CallerId> = self.regulators.iter().cloned().collect();
                resolve_access(caller, &invoice.issuer, &invoice.bank, &regulators)
                    .map_err(|_| "not authorized to view the audit log for this invoice".to_string())?;
                Ok(self.audit_log(Some(id)))
            }
        }
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;

    fn fp(issuer: &str, invoice_number: &str) -> InvoiceFingerprint {
        InvoiceFingerprint {
            issuer_identifier: issuer.to_string(),
            invoice_number: invoice_number.to_string(),
            currency_code: "USD".to_string(),
            amount_minor_units: 10_000,
            due_date_unix: 1_800_000_000,
        }
    }

    #[test]
    fn full_lifecycle_issuer_registers_grants_and_bank_derives() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        let role = state
            .request_key_access(&"bank-1".to_string(), "inv-1")
            .unwrap();
        assert_eq!(role, AccessRole::Bank);

        let log = state.audit_log(Some("inv-1"));
        let actions: Vec<&str> = log.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(
            actions,
            vec!["invoice_registered", "settlement_access_granted", "key_derived_bank"]
        );
    }

    #[test]
    fn duplicate_fingerprint_blocks_second_invoice_even_under_a_different_id() {
        // Same declared identifying fields, submitted under two different
        // invoice_ids and by two different callers -- this is exactly the
        // double-financing pattern the nullifier exists to catch.
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let result = state.register_invoice(
            &"issuer-2".to_string(),
            "inv-2".to_string(),
            &fp("issuer-1", "INV-1"),
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_invoice_id_is_rejected_even_with_a_different_fingerprint() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let result = state.register_invoice(
            &"issuer-1".to_string(),
            "inv-1".to_string(),
            &fp("issuer-1", "INV-2"),
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn invalid_fingerprint_is_rejected_before_any_state_changes() {
        let mut state = ProtocolState::new("admin".to_string());
        let bad = InvoiceFingerprint {
            issuer_identifier: "".to_string(), // empty -> invalid
            invoice_number: "INV-1".to_string(),
            currency_code: "USD".to_string(),
            amount_minor_units: 1,
            due_date_unix: 1,
        };
        let result = state.register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &bad, 0);
        assert!(result.is_err());
        // and it must not have partially registered anything
        assert!(state.audit_log(None).is_empty());
    }

    #[test]
    fn non_issuer_cannot_grant_settlement_access() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let result =
            state.grant_settlement_access(&"attacker".to_string(), "inv-1", "bank-1".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn non_admin_cannot_register_regulator() {
        let mut state = ProtocolState::new("admin".to_string());
        let result = state.register_regulator(&"not-admin".to_string(), "fake-reg".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn regulator_access_is_logged_as_disclosure_in_full_flow() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_regulator(&"admin".to_string(), "regulator-1".to_string())
            .unwrap();
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let role = state
            .request_key_access(&"regulator-1".to_string(), "inv-1")
            .unwrap();
        assert_eq!(role, AccessRole::Regulator);
        let log = state.audit_log(Some("inv-1"));
        assert!(log.iter().any(|e| e.action == "disclosure_request"));
    }

    #[test]
    fn unrelated_invoice_events_are_excluded_by_filter() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state
            .register_invoice(&"issuer-2".to_string(), "inv-2".to_string(), &fp("issuer-2", "INV-1"), 0)
            .unwrap();
        let log = state.audit_log(Some("inv-1"));
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].invoice_id, "inv-1");
    }

    // ---- Access revocation ----

    #[test]
    fn issuer_can_revoke_previously_granted_bank_access() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        state
            .revoke_settlement_access(&"issuer-1".to_string(), "inv-1")
            .unwrap();

        // the revoked bank can no longer derive a key
        let result = state.request_key_access(&"bank-1".to_string(), "inv-1");
        assert!(result.is_err());
    }

    #[test]
    fn revoking_settlement_access_with_nothing_granted_is_an_error_not_a_noop() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let result = state.revoke_settlement_access(&"issuer-1".to_string(), "inv-1");
        assert!(result.is_err());
    }

    #[test]
    fn non_issuer_cannot_revoke_settlement_access() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        let result = state.revoke_settlement_access(&"bank-1".to_string(), "inv-1");
        assert!(result.is_err());
    }

    #[test]
    fn issuer_can_regrant_after_revoking() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        state
            .revoke_settlement_access(&"issuer-1".to_string(), "inv-1")
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-2".to_string())
            .unwrap();
        let role = state
            .request_key_access(&"bank-2".to_string(), "inv-1")
            .unwrap();
        assert_eq!(role, AccessRole::Bank);
    }

    #[test]
    fn admin_can_revoke_a_registered_regulator() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_regulator(&"admin".to_string(), "regulator-1".to_string())
            .unwrap();
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state
            .revoke_regulator(&"admin".to_string(), &"regulator-1".to_string())
            .unwrap();
        // revoked regulator no longer gets disclosure access
        let result = state.request_key_access(&"regulator-1".to_string(), "inv-1");
        assert!(result.is_err());
    }

    #[test]
    fn revoking_an_unregistered_regulator_is_an_error() {
        let mut state = ProtocolState::new("admin".to_string());
        let result = state.revoke_regulator(&"admin".to_string(), &"never-registered".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn non_admin_cannot_revoke_regulator() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_regulator(&"admin".to_string(), "regulator-1".to_string())
            .unwrap();
        let result = state.revoke_regulator(&"not-admin".to_string(), &"regulator-1".to_string());
        assert!(result.is_err());
    }

    // ---- Admin rotation ----

    #[test]
    fn admin_can_transfer_adminship() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .transfer_admin(&"admin".to_string(), "new-admin".to_string())
            .unwrap();
        // old admin can no longer perform admin-only actions
        let result = state.register_regulator(&"admin".to_string(), "regulator-1".to_string());
        assert!(result.is_err());
        // new admin can
        state
            .register_regulator(&"new-admin".to_string(), "regulator-1".to_string())
            .unwrap();
    }

    #[test]
    fn non_admin_cannot_transfer_adminship() {
        let mut state = ProtocolState::new("admin".to_string());
        let result = state.transfer_admin(&"attacker".to_string(), "attacker".to_string());
        assert!(result.is_err());
        // admin is unchanged
        assert!(state.register_regulator(&"admin".to_string(), "regulator-1".to_string()).is_ok());
    }

    // ---- Settlement lifecycle & pruning eligibility ----

    #[test]
    fn issuer_or_bank_can_mark_settled() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        state.mark_settled(&"bank-1".to_string(), "inv-1", 1_000).unwrap();
        let log = state.audit_log(Some("inv-1"));
        assert!(log.iter().any(|e| e.action == "invoice_settled"));
    }

    #[test]
    fn stranger_cannot_mark_settled() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let result = state.mark_settled(&"stranger".to_string(), "inv-1", 1_000);
        assert!(result.is_err());
    }

    #[test]
    fn double_settlement_is_rejected() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state.mark_settled(&"issuer-1".to_string(), "inv-1", 1_000).unwrap();
        let result = state.mark_settled(&"issuer-1".to_string(), "inv-1", 2_000);
        assert!(result.is_err());
    }

    #[test]
    fn active_invoice_is_never_prune_eligible_regardless_of_age() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let far_future = 999_999_999_999u64;
        assert!(!state.is_eligible_for_ciphertext_pruning("inv-1", far_future, 1));
    }

    #[test]
    fn settled_invoice_is_prune_eligible_only_after_retention_window() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state.mark_settled(&"issuer-1".to_string(), "inv-1", 1_000).unwrap();

        let retention = 500u64;
        assert!(!state.is_eligible_for_ciphertext_pruning("inv-1", 1_200, retention)); // too soon
        assert!(state.is_eligible_for_ciphertext_pruning("inv-1", 1_500, retention)); // right at boundary
        assert!(state.is_eligible_for_ciphertext_pruning("inv-1", 5_000, retention)); // well past
    }

    #[test]
    fn unknown_invoice_is_not_prune_eligible() {
        let state = ProtocolState::new("admin".to_string());
        assert!(!state.is_eligible_for_ciphertext_pruning("does-not-exist", 1_000_000, 1));
    }

    // ---- Gated audit log access ----

    #[test]
    fn issuer_can_read_their_own_invoices_audit_log() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let log = state
            .get_audit_log_authorized(&"issuer-1".to_string(), Some("inv-1"))
            .unwrap();
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn granted_bank_can_read_the_invoices_audit_log() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        let log = state
            .get_audit_log_authorized(&"bank-1".to_string(), Some("inv-1"))
            .unwrap();
        assert!(!log.is_empty());
    }

    #[test]
    fn registered_regulator_can_read_any_invoices_audit_log() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_regulator(&"admin".to_string(), "regulator-1".to_string())
            .unwrap();
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let log = state
            .get_audit_log_authorized(&"regulator-1".to_string(), Some("inv-1"))
            .unwrap();
        assert!(!log.is_empty());
    }

    #[test]
    fn unrelated_caller_cannot_read_an_invoices_audit_log() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let result = state.get_audit_log_authorized(&"stranger".to_string(), Some("inv-1"));
        assert!(result.is_err());
    }

    #[test]
    fn admin_can_read_any_invoices_audit_log() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        let log = state
            .get_audit_log_authorized(&"admin".to_string(), Some("inv-1"))
            .unwrap();
        assert!(!log.is_empty());
    }

    #[test]
    fn only_admin_can_read_the_unscoped_audit_log() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(&"issuer-1".to_string(), "inv-1".to_string(), &fp("issuer-1", "INV-1"), 0)
            .unwrap();
        assert!(state.get_audit_log_authorized(&"admin".to_string(), None).is_ok());
        assert!(state.get_audit_log_authorized(&"issuer-1".to_string(), None).is_err());
    }

    #[test]
    fn reading_audit_log_for_unknown_invoice_is_an_error() {
        let state = ProtocolState::new("admin".to_string());
        let result = state.get_audit_log_authorized(&"issuer-1".to_string(), Some("does-not-exist"));
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_allows_first_claim() {
        assert_eq!(check_nullifier(false), Ok(()));
    }

    #[test]
    fn nullifier_rejects_second_claim() {
        assert_eq!(check_nullifier(true), Err(NullifierError::AlreadyClaimed));
    }

    #[test]
    fn issuer_is_granted_access() {
        let issuer = "issuer-1".to_string();
        let role = resolve_access(&issuer, &issuer, &None, &[]).unwrap();
        assert_eq!(role, AccessRole::Issuer);
        assert_eq!(audit_action_for(&role), "key_derived_issuer");
    }

    #[test]
    fn granted_bank_is_granted_access() {
        let issuer = "issuer-1".to_string();
        let bank = "bank-1".to_string();
        let role = resolve_access(&bank, &issuer, &Some(bank.clone()), &[]).unwrap();
        assert_eq!(role, AccessRole::Bank);
        assert_eq!(audit_action_for(&role), "key_derived_bank");
    }

    #[test]
    fn ungranted_bank_is_denied() {
        let issuer = "issuer-1".to_string();
        let granted_bank = "bank-1".to_string();
        let other_bank = "bank-2".to_string();
        let result = resolve_access(&other_bank, &issuer, &Some(granted_bank), &[]);
        assert_eq!(result, Err(AccessError::NotAuthorized));
    }

    #[test]
    fn stranger_is_denied() {
        let issuer = "issuer-1".to_string();
        let stranger = "stranger".to_string();
        let result = resolve_access(&stranger, &issuer, &None, &[]);
        assert_eq!(result, Err(AccessError::NotAuthorized));
    }

    #[test]
    fn registered_regulator_is_granted_access_and_flagged_as_disclosure() {
        let issuer = "issuer-1".to_string();
        let regulator = "regulator-1".to_string();
        let role = resolve_access(&regulator, &issuer, &None, &[regulator.clone()]).unwrap();
        assert_eq!(role, AccessRole::Regulator);
        assert_eq!(audit_action_for(&role), "disclosure_request");
    }

    #[test]
    fn regulator_who_is_also_issuer_is_still_logged_as_disclosure() {
        // A regulator principal that happens to equal the issuer must still
        // be flagged as a disclosure event, not silently treated as routine
        // issuer access -- the log's purpose is to never under-report.
        let dual_role_principal = "dual-1".to_string();
        let role = resolve_access(
            &dual_role_principal,
            &dual_role_principal,
            &None,
            &[dual_role_principal.clone()],
        )
        .unwrap();
        assert_eq!(role, AccessRole::Regulator);
    }

    #[test]
    fn unregistered_caller_claiming_to_be_regulator_is_denied() {
        let issuer = "issuer-1".to_string();
        let fake_regulator = "not-actually-registered".to_string();
        let real_regulators = vec!["regulator-1".to_string()];
        let result = resolve_access(&fake_regulator, &issuer, &None, &real_regulators);
        assert_eq!(result, Err(AccessError::NotAuthorized));
    }

    // ---- Rate limiting ----

    #[test]
    fn rate_limit_allows_calls_under_the_cap() {
        let policy = RateLimitPolicy { max_calls: 3, window_nanos: 1_000_000_000 };
        let prior = vec![100, 200];
        assert_eq!(check_rate_limit(&policy, &prior, 300), Ok(()));
    }

    #[test]
    fn rate_limit_blocks_calls_at_the_cap() {
        let policy = RateLimitPolicy { max_calls: 3, window_nanos: 1_000_000_000 };
        let prior = vec![100, 200, 300];
        assert_eq!(check_rate_limit(&policy, &prior, 400), Err(RateLimitError::TooManyRequests));
    }

    #[test]
    fn rate_limit_ignores_calls_outside_the_window() {
        let policy = RateLimitPolicy { max_calls: 2, window_nanos: 1_000 };
        // two calls happened, but both are far outside the trailing window
        let prior = vec![0, 1];
        assert_eq!(check_rate_limit(&policy, &prior, 100_000), Ok(()));
    }

    #[test]
    fn rate_limit_boundary_timestamp_counts_as_inside_the_window() {
        let policy = RateLimitPolicy { max_calls: 1, window_nanos: 1_000 };
        let now = 5_000u64;
        let prior = vec![now - 1_000]; // exactly at the window edge
        assert_eq!(check_rate_limit(&policy, &prior, now), Err(RateLimitError::TooManyRequests));
    }

    // ---- Payload size guard ----

    #[test]
    fn payload_within_limit_is_accepted() {
        assert_eq!(check_payload_size(100, 1_000), Ok(()));
    }

    #[test]
    fn payload_at_exact_limit_is_accepted() {
        assert_eq!(check_payload_size(1_000, 1_000), Ok(()));
    }

    #[test]
    fn payload_over_limit_is_rejected() {
        assert!(check_payload_size(1_001, 1_000).is_err());
    }

    // ---- Transport key length guard ----

    #[test]
    fn transport_key_within_bounds_is_accepted() {
        assert_eq!(check_transport_key_length(48, 32, 128), Ok(()));
    }

    #[test]
    fn transport_key_below_minimum_is_rejected() {
        assert!(check_transport_key_length(4, 32, 128).is_err());
    }

    #[test]
    fn transport_key_above_maximum_is_rejected() {
        assert!(check_transport_key_length(4096, 32, 128).is_err());
    }

    #[test]
    fn transport_key_at_exact_bounds_is_accepted() {
        assert_eq!(check_transport_key_length(32, 32, 128), Ok(()));
        assert_eq!(check_transport_key_length(128, 32, 128), Ok(()));
    }
}
