use candid::{CandidType, Decode, Encode, Principal};
use ic_cdk::management_canister::{
    vetkd_derive_key, vetkd_public_key, VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId,
    VetKDPublicKeyArgs,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{storable::Bound, DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;

type Memory = VirtualMemory<DefaultMemoryImpl>;

const DOMAIN_SEPARATOR: &[u8] = b"ciphersettle-invoice-v1";

// Storage-inflation guard: caps a single ciphertext upload. Sized generously
// for an invoice document; tune to whatever the real client payload needs.
const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;

// Cycle-drain guard on the expensive vetKD call: at most this many
// derive_invoice_key calls per caller per window.
const DERIVE_KEY_RATE_LIMIT: ciphersettle_core::RateLimitPolicy = ciphersettle_core::RateLimitPolicy {
    max_calls: 5,
    window_nanos: 60_000_000_000, // 60 seconds, in nanoseconds (ic_cdk::api::time() units)
};

// Ciphertext is only eligible for pruning once an invoice has been Settled
// and sat past this retention window. The audit log (metadata only) is never
// pruned -- see ciphersettle_core::is_eligible_for_ciphertext_pruning's doc
// comment for why that split is deliberate.
const CIPHERTEXT_RETENTION_NANOS: u64 = 180 * 24 * 60 * 60 * 1_000_000_000; // ~180 days

// Anti-Sybil fee attached to every key-derivation attempt (accepted only
// after authorization passes; complements the per-principal rate limit,
// which fresh principals could otherwise bypass for free).
const DERIVE_KEY_FEE_CYCLES: u128 = ciphersettle_core::MIN_DERIVE_KEY_FEE_CYCLES;

// ---------- Data model ----------

#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Eq)]
enum InvoiceStatus {
    Active,
    Settled,
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
struct InvoiceRecord {
    issuer: Principal,
    bank: Option<Principal>,
    ciphertext: Vec<u8>, // encrypted client-side before submission; canister never sees plaintext
    created_at: u64,
    status: InvoiceStatus,
    settled_at: Option<u64>,
    // Set by raise_dispute; permanent metadata (resolution is out of scope).
    disputed: bool,
    // true once ciphertext has been pruned; the record and audit trail
    // remain, only the (already-settled, already-retention-expired) blob is
    // dropped.
    ciphertext_pruned: bool,
}

impl Storable for InvoiceRecord {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
struct AuditEvent {
    id: u64,
    invoice_id: String,
    actor: Principal,
    action: String, // "invoice_registered" | "settlement_access_granted" | "settlement_access_revoked" | "invoice_settled" | "dispute_raised" | "ciphertext_pruned" | "key_derived_bank" | "key_derived_issuer" | "key_derivation_failed" | "disclosure_request" | "regulator_registered" | "regulator_revoked"
    timestamp: u64,
}

impl Storable for AuditEvent {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

// Wrapper so Principal can be stored in a StableCell (needs Storable + Default)
#[derive(CandidType, Serialize, Deserialize, Clone, Default)]
struct PrincipalWrapper(Option<Principal>);

impl Storable for PrincipalWrapper {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

// Per-caller recent call timestamps for the derive_invoice_key rate limit.
// Wrapped so it can live in a StableBTreeMap.
#[derive(CandidType, Serialize, Deserialize, Clone, Default)]
struct CallTimes(Vec<u64>);

impl Storable for CallTimes {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

// ---------- Stable storage ----------

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // nullifier_hash -> 1  (a set: presence = already claimed/financed)
    static NULLIFIERS: RefCell<StableBTreeMap<String, u8, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))))
    );

    // invoice_id -> InvoiceRecord
    static INVOICES: RefCell<StableBTreeMap<String, InvoiceRecord, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))))
    );

    // regulator_principal -> 1 (a set of principals allowed to trigger disclosure)
    static REGULATORS: RefCell<StableBTreeMap<Principal, u8, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))))
    );

    // append-only audit log, keyed by incrementing event id
    static AUDIT_LOG: RefCell<StableBTreeMap<u64, AuditEvent, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))))
    );

    static NEXT_EVENT_ID: RefCell<u64> = const { RefCell::new(0) };

    // canister deployer / admin, set once at init
    static ADMIN: RefCell<StableCell<PrincipalWrapper, Memory>> = RefCell::new(
        StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))), PrincipalWrapper::default())
            .expect("failed to init admin cell")
    );

    // caller principal -> recent derive_invoice_key call timestamps, for rate limiting
    static DERIVE_CALL_TIMES: RefCell<StableBTreeMap<Principal, CallTimes, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5))))
    );
}

fn log_event(invoice_id: &str, actor: Principal, action: &str) {
    let id = NEXT_EVENT_ID.with(|c| {
        let mut c = c.borrow_mut();
        let id = *c;
        *c += 1;
        id
    });
    let event = AuditEvent {
        id,
        invoice_id: invoice_id.to_string(),
        actor,
        action: action.to_string(),
        timestamp: ic_cdk::api::time(),
    };
    AUDIT_LOG.with(|log| log.borrow_mut().insert(id, event));
}

fn vetkd_key_id() -> VetKDKeyId {
    // "dfx_test_key" works on local replica; swap for the mainnet key name at deploy time.
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "dfx_test_key".to_string(),
    }
}

// ---------- Lifecycle ----------

#[ic_cdk::init]
fn init() {
    let caller = ic_cdk::api::msg_caller();
    ADMIN.with(|a| {
        a.borrow_mut()
            .set(PrincipalWrapper(Some(caller)))
            .expect("failed to set admin");
    });
}

fn is_admin(p: Principal) -> bool {
    ADMIN.with(|a| a.borrow().get().0 == Some(p))
}

// ---------- Admin: register / revoke regulator principals ----------

#[ic_cdk::update]
fn register_regulator(regulator: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if !is_admin(caller) {
        return Err("only the canister admin can register regulators".to_string());
    }
    REGULATORS.with(|r| r.borrow_mut().insert(regulator, 1));
    log_event("*", caller, "regulator_registered");
    Ok(())
}

/// Admin-only. Pulls a previously registered regulator's standing disclosure
/// access, e.g. once an audit window has closed. Errors (rather than
/// silently no-op'ing) if the principal wasn't registered, so a caller can't
/// mistake a typo'd principal for a successful revoke.
#[ic_cdk::update]
fn revoke_regulator(regulator: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if !is_admin(caller) {
        return Err("only the canister admin can revoke regulators".to_string());
    }
    let was_present = REGULATORS.with(|r| r.borrow_mut().remove(&regulator).is_some());
    if !was_present {
        return Err("that principal is not a registered regulator".to_string());
    }
    log_event("*", caller, "regulator_revoked");
    Ok(())
}

fn is_regulator(p: Principal) -> bool {
    REGULATORS.with(|r| r.borrow().contains_key(&p))
}

// ---------- Core flow: submit -> nullifier check -> encrypted store ----------

#[ic_cdk::update]
fn register_invoice(
    invoice_id: String,
    nullifier_hash: String,
    ciphertext: Vec<u8>,
) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();

    ciphersettle_core::validate_identifier(&invoice_id, "invoice_id", ciphersettle_core::MAX_INVOICE_ID_LEN)?;
    ciphersettle_core::validate_identifier(&nullifier_hash, "nullifier_hash", ciphersettle_core::MAX_NULLIFIER_LEN)?;
    ciphersettle_core::check_payload_size(ciphertext.len(), MAX_CIPHERTEXT_BYTES)?;

    let already_claimed = NULLIFIERS.with(|n| n.borrow().contains_key(&nullifier_hash));
    ciphersettle_core::check_nullifier(already_claimed)
        .map_err(|_| "nullifier already registered: invoice already submitted elsewhere".to_string())?;
    if INVOICES.with(|i| i.borrow().contains_key(&invoice_id)) {
        return Err("invoice_id already exists".to_string());
    }

    NULLIFIERS.with(|n| n.borrow_mut().insert(nullifier_hash, 1));
    INVOICES.with(|i| {
        i.borrow_mut().insert(
            invoice_id.clone(),
            InvoiceRecord {
                issuer: caller,
                bank: None,
                ciphertext,
                created_at: ic_cdk::api::time(),
                status: InvoiceStatus::Active,
                settled_at: None,
                disputed: false,
                ciphertext_pruned: false,
            },
        )
    });
    log_event(&invoice_id, caller, "invoice_registered");
    Ok(())
}

#[ic_cdk::update]
fn grant_settlement_access(invoice_id: String, bank: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    INVOICES.with(|i| {
        let mut i = i.borrow_mut();
        let mut record = i
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if record.issuer != caller {
            return Err("only the issuer can grant settlement access".to_string());
        }
        record.bank = Some(bank);
        i.insert(invoice_id.clone(), record);
        Ok(())
    })?;
    log_event(&invoice_id, caller, "settlement_access_granted");
    Ok(())
}

/// Issuer-only. Pulls a previously granted counterparty's access -- e.g. a
/// financing arrangement fell through, or the bank's access needs to be
/// pulled before the invoice reaches a terminal state. Errors if nothing was
/// granted, so "revoked" always means something actually changed.
#[ic_cdk::update]
fn revoke_settlement_access(invoice_id: String) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    INVOICES.with(|i| {
        let mut i = i.borrow_mut();
        let mut record = i
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if record.issuer != caller {
            return Err("only the issuer can revoke settlement access".to_string());
        }
        if record.bank.take().is_none() {
            return Err("no settlement access is currently granted for this invoice".to_string());
        }
        i.insert(invoice_id.clone(), record);
        Ok(())
    })?;
    log_event(&invoice_id, caller, "settlement_access_revoked");
    Ok(())
}

/// Issuer or the currently-granted bank may mark an invoice settled. Actual
/// fund movement happens off-canister (see README: "don't touch the money");
/// this just records the terminal state so ciphertext-pruning eligibility
/// can be evaluated later.
#[ic_cdk::update]
fn mark_settled(invoice_id: String) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    let now = ic_cdk::api::time();
    INVOICES.with(|i| {
        let mut i = i.borrow_mut();
        let mut record = i
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        let is_participant = record.issuer == caller || record.bank == Some(caller);
        if !is_participant {
            return Err("only the issuer or the granted bank can mark an invoice settled".to_string());
        }
        if record.status == InvoiceStatus::Settled {
            return Err("invoice is already settled".to_string());
        }
        record.status = InvoiceStatus::Settled;
        record.settled_at = Some(now);
        i.insert(invoice_id.clone(), record);
        Ok(())
    })?;
    log_event(&invoice_id, caller, "invoice_settled");
    Ok(())
}

/// Raises an on-chain dispute flag over an invoice's content. Callable by
/// protocol participants (issuer, currently-granted bank) or a registered
/// regulator -- not arbitrary callers, so the flag can't be spammed by
/// strangers. The flag is permanent metadata recorded in the invoice record
/// and the audit log; resolving a dispute is out of scope for this canister.
#[ic_cdk::update]
fn raise_dispute(invoice_id: String) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    INVOICES.with(|i| {
        let mut i = i.borrow_mut();
        let mut record = i
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        let is_participant = record.issuer == caller || record.bank == Some(caller);
        if !is_participant && !is_regulator(caller) {
            return Err(
                "only the issuer, the granted bank, or a registered regulator can raise a dispute"
                    .to_string(),
            );
        }
        if record.disputed {
            return Err("a dispute is already open for this invoice".to_string());
        }
        record.disputed = true;
        i.insert(invoice_id.clone(), record);
        Ok(())
    })?;
    log_event(&invoice_id, caller, "dispute_raised");
    Ok(())
}

/// Admin-only drop of the ciphertext blob for an invoice that is Settled and
/// past the retention window, freeing paid stable-memory storage. Identity is
/// checked first so unauthorized callers get a clear denial regardless of
/// eligibility. The invoice record and its full audit trail are kept
/// permanently -- only the payload bytes are cleared -- so `get_audit_log`
/// remains a complete history even after pruning.
#[ic_cdk::update]
fn prune_ciphertext(invoice_id: String) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if !is_admin(caller) {
        return Err("only the admin can prune ciphertext".to_string());
    }
    let now = ic_cdk::api::time();
    INVOICES.with(|i| {
        let mut i = i.borrow_mut();
        let mut record = i
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if record.ciphertext_pruned {
            return Err("ciphertext already pruned for this invoice".to_string());
        }
        let eligible = record.status == InvoiceStatus::Settled
            && record
                .settled_at
                .map(|settled_at| now.saturating_sub(settled_at) >= CIPHERTEXT_RETENTION_NANOS)
                .unwrap_or(false);
        if !eligible {
            return Err(
                "invoice is not yet eligible for pruning (must be settled and past the retention window)"
                    .to_string(),
            );
        }
        record.ciphertext = Vec::new();
        record.ciphertext_pruned = true;
        i.insert(invoice_id.clone(), record);
        Ok(())
    })?;
    log_event(&invoice_id, caller, "ciphertext_pruned");
    Ok(())
}

// ---------- Confidential retrieval (ciphertext only; decryption happens client-side) ----------

#[ic_cdk::query]
fn get_encrypted_invoice(invoice_id: String) -> Result<Vec<u8>, String> {
    let caller = ic_cdk::api::msg_caller();
    INVOICES.with(|i| {
        let record = i
            .borrow()
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        let allowed = record.issuer == caller
            || record.bank == Some(caller)
            || is_regulator(caller);
        if !allowed {
            return Err("not authorized to view this invoice".to_string());
        }
        if record.ciphertext_pruned {
            return Err("ciphertext has been pruned for this invoice (past settlement retention window)".to_string());
        }
        Ok(record.ciphertext.clone())
    })
}

// ---------- vetKD: key derivation gated by role + rate limit, with disclosure logging ----------

#[ic_cdk::update]
async fn get_vetkd_public_key() -> Vec<u8> {
    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context: DOMAIN_SEPARATOR.to_vec(),
        key_id: vetkd_key_id(),
    };
    let reply = vetkd_public_key(&request)
        .await
        .expect("failed to fetch vetKD public key");
    reply.public_key
}

/// Records this call's timestamp against `caller` and prunes anything
/// outside the rate-limit window while we're at it, so DERIVE_CALL_TIMES
/// doesn't grow unbounded per caller over the canister's lifetime.
fn record_and_check_rate_limit(caller: Principal) -> Result<(), String> {
    let now = ic_cdk::api::time();
    DERIVE_CALL_TIMES.with(|m| {
        let mut m = m.borrow_mut();
        let mut times = m.get(&caller).unwrap_or_default();

        ciphersettle_core::check_rate_limit(&DERIVE_KEY_RATE_LIMIT, &times.0, now)
            .map_err(|_| "rate limit exceeded for key derivation; please wait before retrying".to_string())?;

        let window_start = now.saturating_sub(DERIVE_KEY_RATE_LIMIT.window_nanos);
        times.0.retain(|&t| t >= window_start);
        times.0.push(now);
        m.insert(caller, times);
        Ok(())
    })
}

#[ic_cdk::update]
async fn derive_invoice_key(
    invoice_id: String,
    transport_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let caller = ic_cdk::api::msg_caller();

    record_and_check_rate_limit(caller)?;

    let record = INVOICES.with(|i| i.borrow().get(&invoice_id)).ok_or("invoice not found".to_string())?;

    let registered_regulators: Vec<String> = REGULATORS.with(|r| {
        r.borrow().iter().map(|(p, _)| p.to_text()).collect()
    });
    // Authorization happens *before* any side effect (fee acceptance, vetKD
    // round-trip, audit write), so a denied caller leaves no trace at all.
    let role = ciphersettle_core::resolve_access(
        &caller.to_text(),
        &record.issuer.to_text(),
        &record.bank.map(|b| b.to_text()),
        &registered_regulators,
    )
    .map_err(|_| "not authorized to derive a decryption key for this invoice".to_string())?;

    // Selective disclosure: resolve_access always labels regulator access as
    // such, even if the same principal also happens to be the issuer -- see
    // ciphersettle_core's tests for why that priority order is enforced, not just
    // asserted here.
    let success_action = ciphersettle_core::audit_action_for(&role);

    // Economic Sybil guard: reject underfunded requests before accepting
    // anything, then take the fee up front -- it pays for the attempt itself
    // (including a failed vetKD round-trip), so it is not refunded.
    ciphersettle_core::check_cycles_fee(
        ic_cdk::api::msg_cycles_available(),
        DERIVE_KEY_FEE_CYCLES,
    )?;
    ic_cdk::api::msg_cycles_accept(DERIVE_KEY_FEE_CYCLES);

    let request = VetKDDeriveKeyArgs {
        input: invoice_id.as_bytes().to_vec(),
        context: DOMAIN_SEPARATOR.to_vec(),
        transport_public_key,
        key_id: vetkd_key_id(),
    };
    // The audit event is written only once the derivation outcome is known,
    // so the log reflects what actually happened rather than what was merely
    // attempted: successes use the role's action, failures get their own
    // distinct action and never over-report completed disclosures.
    match vetkd_derive_key(&request).await {
        Ok(reply) => {
            log_event(&invoice_id, caller, success_action);
            Ok(reply.encrypted_key)
        }
        Err(e) => {
            log_event(&invoice_id, caller, "key_derivation_failed");
            Err(format!("vetkd_derive_key failed: {e:?}"))
        }
    }
}

// ---------- Public audit log: metadata only, never ciphertext or plaintext ----------

#[ic_cdk::query]
fn get_audit_log(invoice_id: Option<String>) -> Vec<AuditEvent> {
    AUDIT_LOG.with(|log| {
        log.borrow()
            .iter()
            .filter(|(_, e)| match &invoice_id {
                Some(id) => &e.invoice_id == id,
                None => true,
            })
            .map(|(_, e)| e)
            .collect()
    })
}
