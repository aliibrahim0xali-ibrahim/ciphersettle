//! Canonical invoice fingerprinting and nullifier derivation.
//!
//! # Why this module exists
//!
//! In the original design, `nullifier_hash` was an arbitrary client-chosen
//! string with no binding to the invoice it claimed to represent. That made
//! the double-financing check meaningless against anyone who didn't feel
//! like cooperating with it: an issuer could submit the same real invoice
//! twice under two different nullifiers, and nothing would catch it.
//!
//! This module fixes the *minimum-bar* version of that problem: the
//! canister -- not the client -- computes the nullifier, as a deterministic
//! hash of a small set of caller-declared invoice-identifying fields. This
//! means:
//!   - The nullifier is no longer a free choice; it's a pure function of
//!     what the caller declares the invoice to be.
//!   - Two submissions that declare the same identifying fields collide,
//!     exactly as a working double-financing check requires.
//!   - The raw fields themselves are never persisted anywhere (see
//!     `InvoiceFingerprint`'s doc comment) -- only their hash is stored, so
//!     this doesn't add a new metadata leak.
//!
//! # What this does *not* fix
//!
//! A caller can still lie about the fields (e.g. declare a different
//! invoice number for what is actually the same real invoice) and get a
//! fresh nullifier. Closing that gap fully requires one of:
//!   - an external authority (e.g. an e-invoicing/tax registry) signing
//!     off on the declared fields, verified by the canister before
//!     accepting them (this module's `InvoiceFingerprint` is designed to be
//!     the exact payload such a signature would cover, so adding this later
//!     is additive, not a redesign), or
//!   - a zero-knowledge proof that the fields correspond to a previously
//!     committed, undisclosed invoice.
//! Neither exists yet. Treat this module as closing the "nullifier is pure
//! noise" bug, not as a claim that the system resists a fully adversarial,
//! unattested issuer.

use crate::sha256::sha256;

/// The canonical, jurisdiction-agnostic set of fields that identify an
/// invoice for double-financing purposes. Deliberately narrow: this is the
/// minimum needed to detect "this is the same invoice, submitted again,"
/// not a general invoice schema. Extend it only if your deployment's
/// definition of "the same invoice" actually needs more fields --- adding
/// fields changes what counts as a collision.
///
/// These fields are used only transiently, inside the canister call that
/// computes the nullifier from them (see `Nullifier`). They are not stored
/// anywhere; only the resulting 32-byte hash persists. That is deliberate:
/// several of these fields (amount, due date) are exactly the kind of
/// business detail this project's confidentiality model is trying to keep
/// out of the public audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceFingerprint {
    /// Issuer's external identifier (e.g. a tax/business-registration
    /// number). Deliberately not the IC principal: the principal identifies
    /// *who is calling the canister*, not *which real-world business issued
    /// the invoice*, and those are different facts.
    pub issuer_identifier: String,
    /// The invoice number as assigned by the issuer's own system of record.
    pub invoice_number: String,
    /// ISO 4217 currency code (e.g. "USD"), kept separate from the amount
    /// so "100 USD" and "100 EUR" don't collide.
    pub currency_code: String,
    /// Amount in the currency's minor unit (e.g. cents), to avoid any
    /// floating-point or locale-formatting ambiguity in what "the same
    /// amount" means.
    pub amount_minor_units: u64,
    /// Due date as a Unix timestamp (seconds), rather than a
    /// locale-dependent string, for the same reason.
    pub due_date_unix: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FingerprintError {
    /// A field was empty where a non-empty identifier is required. Accepting
    /// empty strings here would let every "unset" issuer/invoice-number
    /// collide with every other, which defeats the point. This is also what
    /// catches a whitespace-only field: canonicalization trims first, so
    /// `"   "` becomes `""` and is caught right here, not silently accepted
    /// as a distinct value.
    EmptyRequiredField(&'static str),
    /// A field exceeded the configured maximum length, checked *after*
    /// canonicalization (trimming), not before -- so trailing padding on an
    /// otherwise-valid field doesn't wrongly reject it. Bounded so a
    /// fingerprint field can't be used to smuggle an unbounded amount of
    /// data through what's supposed to be a fixed-shape identifier -- these
    /// fields are transient (never stored) but still pass through
    /// candid-decoded, caller-controlled `String`s in the canister, so the
    /// bound matters for message-size hygiene even though nothing here is
    /// persisted long-term.
    FieldTooLong { field: &'static str, max: usize },
    /// A field contained a byte outside the ASCII range. Deliberately a hard
    /// rejection rather than an attempt at partial Unicode canonicalization:
    /// this crate has no access to a real Unicode normalization table, and
    /// pretending to handle NFC/NFD normalization, confusable characters, or
    /// right-to-left overrides without actually doing it correctly would be
    /// worse than refusing the input outright. A real limitation for
    /// deployments whose issuer identifiers or invoice numbers are
    /// legitimately non-Latin -- not a bug, but worth surfacing, not just a
    /// code comment.
    NonAsciiField(&'static str),
    /// `currency_code` didn't match the expected shape of exactly three
    /// ASCII letters after trimming and upper-casing. This is a *shape*
    /// check only (it confirms "looks like an ISO 4217 code"), not a real
    /// membership check against the actual ISO 4217 list.
    InvalidCurrencyCodeShape,
}

const MAX_FIELD_LEN: usize = 256;

impl InvoiceFingerprint {
    /// Produces a canonicalized copy of this fingerprint so that two
    /// declarations of "the same invoice" that differ only in
    /// case/whitespace collide onto the same nullifier, instead of silently
    /// producing two different ones. Concretely:
    ///   - every string field is trimmed of leading/trailing whitespace,
    ///   - `currency_code` is additionally upper-cased and shape-validated
    ///     as exactly three ASCII letters (a shape check, not a real
    ///     ISO-4217 membership check),
    ///   - every field is rejected outright if it contains any non-ASCII
    ///     byte (see `FingerprintError::NonAsciiField` for why).
    ///
    /// Deliberately does **not** case-fold `issuer_identifier` or
    /// `invoice_number`: unlike a 3-letter currency code, there's no
    /// universal rule for "the same" tax ID or invoice number across
    /// jurisdictions and issuer systems, so this crate doesn't invent one.
    /// If a deployment's registry has a canonical form (e.g. "tax IDs are
    /// always numeric, dashes stripped"), apply it before constructing the
    /// `InvoiceFingerprint` in the first place -- this is a documented
    /// extension point, not something this function tries to guess at.
    ///
    /// `compute_nullifier` always canonicalizes before hashing; this is
    /// exposed separately so callers can canonicalize-then-inspect before
    /// deciding to submit, if useful.
    pub fn canonicalize(&self) -> Result<InvoiceFingerprint, FingerprintError> {
        let issuer_identifier = self.issuer_identifier.trim().to_string();
        let invoice_number = self.invoice_number.trim().to_string();
        let currency_code = self.currency_code.trim().to_ascii_uppercase();

        for (name, value) in [
            ("issuer_identifier", issuer_identifier.as_str()),
            ("invoice_number", invoice_number.as_str()),
            ("currency_code", currency_code.as_str()),
        ] {
            if !value.is_ascii() {
                return Err(FingerprintError::NonAsciiField(name));
            }
        }

        // Currency shape (exactly three ASCII letters) is intentionally
        // *not* checked here. An empty currency_code must surface as
        // `EmptyRequiredField`, not `InvalidCurrencyCodeShape` -- that check
        // happens in `validate`, after the emptiness check, so the two
        // error variants don't race for a currency-code-shaped complaint
        // about a field the caller simply left blank.

        Ok(InvoiceFingerprint {
            issuer_identifier,
            invoice_number,
            currency_code,
            amount_minor_units: self.amount_minor_units,
            due_date_unix: self.due_date_unix,
        })
    }

    /// Validates an *already-canonicalized* fingerprint: required fields are
    /// non-empty, and no field exceeds the length bound. Called on the
    /// output of `canonicalize`, never on raw caller input directly, so
    /// "empty" correctly catches whitespace-only input (trimmed to `""`
    /// first) and the length bound is measured after trimming, not before.
    fn validate(&self) -> Result<(), FingerprintError> {
        if self.issuer_identifier.is_empty() {
            return Err(FingerprintError::EmptyRequiredField("issuer_identifier"));
        }
        if self.invoice_number.is_empty() {
            return Err(FingerprintError::EmptyRequiredField("invoice_number"));
        }
        if self.currency_code.is_empty() {
            return Err(FingerprintError::EmptyRequiredField("currency_code"));
        }
        for (name, value) in [
            ("issuer_identifier", &self.issuer_identifier),
            ("invoice_number", &self.invoice_number),
            ("currency_code", &self.currency_code),
        ] {
            if value.len() > MAX_FIELD_LEN {
                return Err(FingerprintError::FieldTooLong {
                    field: name,
                    max: MAX_FIELD_LEN,
                });
            }
        }
        // Shape-validate currency_code only once we know it's non-empty and
        // within bounds -- an empty or overlong currency_code should report
        // as such, not as "wrong shape".
        if self.currency_code.len() != 3
            || !self.currency_code.bytes().all(|b| b.is_ascii_alphabetic())
        {
            return Err(FingerprintError::InvalidCurrencyCodeShape);
        }
        Ok(())
    }

    /// Serializes the fingerprint into an unambiguous byte string, ready
    /// for hashing. Every variable-length field is length-prefixed (as a
    /// big-endian u64) before its bytes, which is what actually prevents
    /// concatenation ambiguity: without this, the fields
    /// `("ab", "c")` and `("a", "bc")` would serialize to the identical
    /// byte string `"abc"` and silently collide. See
    /// `length_prefixing_prevents_concatenation_ambiguity` in the tests
    /// below for a worked example of exactly that case.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for field in [
            self.issuer_identifier.as_bytes(),
            self.invoice_number.as_bytes(),
            self.currency_code.as_bytes(),
        ] {
            buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
            buf.extend_from_slice(field);
        }
        buf.extend_from_slice(&self.amount_minor_units.to_be_bytes());
        buf.extend_from_slice(&self.due_date_unix.to_be_bytes());
        buf
    }
}

/// A derived nullifier: a 32-byte SHA-256 digest of a validated, canonically
/// serialized `InvoiceFingerprint`. Opaque on purpose -- nothing about the
/// underlying fields can be recovered from it, which is exactly what lets
/// the canister store and compare it publicly without leaking the fields
/// themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    pub fn to_hex(&self) -> String {
        crate::sha256::to_hex(&self.0)
    }
}

/// Domain separator mixed into every nullifier hash, so a hash collision
/// with some *other* SHA-256 usage elsewhere in the system (or in a future
/// version of this protocol) can't accidentally or maliciously be
/// engineered into a nullifier collision. Distinct from the vetKD
/// `DOMAIN_SEPARATOR` in the canister -- this one scopes hash-based
/// commitments, that one scopes key derivation; conflating the two would
/// undo the isolation both are meant to provide.
const NULLIFIER_DOMAIN: &[u8] = b"ciphersettle-nullifier-v1";

/// Computes the nullifier for a set of declared invoice-identifying fields.
/// This is the only way a nullifier should ever be produced -- see the
/// module doc for why letting a caller supply one directly defeats the
/// entire point.
///
/// Always canonicalizes the fingerprint first (see `InvoiceFingerprint::canonicalize`):
/// without this, `"USD"` vs `"usd"`, or `"INV-001"` vs `" INV-001 "`, would
/// produce *different* nullifiers for what is obviously the same invoice --
/// letting anyone dodge the double-financing check just by varying case or
/// whitespace on resubmission. Validation (non-empty, length bound) then
/// runs against the canonicalized fields, not the raw input.
pub fn compute_nullifier(fingerprint: &InvoiceFingerprint) -> Result<Nullifier, FingerprintError> {
    let canonical = fingerprint.canonicalize()?;
    canonical.validate()?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&(NULLIFIER_DOMAIN.len() as u64).to_be_bytes());
    buf.extend_from_slice(NULLIFIER_DOMAIN);
    buf.extend_from_slice(&canonical.canonical_bytes());
    Ok(Nullifier(sha256(&buf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(issuer: &str, invoice_number: &str, currency: &str, amount: u64, due: u64) -> InvoiceFingerprint {
        InvoiceFingerprint {
            issuer_identifier: issuer.to_string(),
            invoice_number: invoice_number.to_string(),
            currency_code: currency.to_string(),
            amount_minor_units: amount,
            due_date_unix: due,
        }
    }

    #[test]
    fn same_fields_always_produce_the_same_nullifier() {
        let a = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        let b = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_invoice_number_produces_a_different_nullifier() {
        let a = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        let b = compute_nullifier(&fp("issuer-1", "INV-002", "USD", 10_000, 1_800_000_000)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_amount_produces_a_different_nullifier() {
        let a = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        let b = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_001, 1_800_000_000)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_currency_produces_a_different_nullifier() {
        let a = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        let b = compute_nullifier(&fp("issuer-1", "INV-001", "EUR", 10_000, 1_800_000_000)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_due_date_produces_a_different_nullifier() {
        let a = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        let b = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_900_000_000)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_issuer_produces_a_different_nullifier() {
        // Two different issuers both submitting "INV-001" for 100.00 USD
        // must NOT collide -- invoice numbers are only unique per issuer in
        // the real world.
        let a = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        let b = compute_nullifier(&fp("issuer-2", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefixing_prevents_concatenation_ambiguity() {
        // Without length-prefixing, ("ab", "c", ...) and ("a", "bc", ...)
        // would serialize to the same bytes ("abc...") and collide. This is
        // exactly the bug length-prefixing exists to prevent.
        let a = compute_nullifier(&fp("ab", "c", "USD", 1, 1)).unwrap();
        let b = compute_nullifier(&fp("a", "bc", "USD", 1, 1)).unwrap();
        assert_ne!(a, b, "length-prefixing must prevent field-boundary collisions");
    }

    #[test]
    fn empty_issuer_identifier_is_rejected() {
        let result = compute_nullifier(&fp("", "INV-001", "USD", 1, 1));
        assert_eq!(
            result,
            Err(FingerprintError::EmptyRequiredField("issuer_identifier"))
        );
    }

    #[test]
    fn empty_invoice_number_is_rejected() {
        let result = compute_nullifier(&fp("issuer-1", "", "USD", 1, 1));
        assert_eq!(
            result,
            Err(FingerprintError::EmptyRequiredField("invoice_number"))
        );
    }

    #[test]
    fn empty_currency_code_is_rejected() {
        let result = compute_nullifier(&fp("issuer-1", "INV-001", "", 1, 1));
        assert_eq!(
            result,
            Err(FingerprintError::EmptyRequiredField("currency_code"))
        );
    }

    #[test]
    fn overly_long_field_is_rejected() {
        let too_long = "x".repeat(MAX_FIELD_LEN + 1);
        let result = compute_nullifier(&fp(&too_long, "INV-001", "USD", 1, 1));
        assert_eq!(
            result,
            Err(FingerprintError::FieldTooLong {
                field: "issuer_identifier",
                max: MAX_FIELD_LEN
            })
        );
    }

    #[test]
    fn field_at_exact_max_length_is_accepted() {
        let exactly_max = "x".repeat(MAX_FIELD_LEN);
        assert!(compute_nullifier(&fp(&exactly_max, "INV-001", "USD", 1, 1)).is_ok());
    }

    #[test]
    fn nullifier_hex_is_64_lowercase_hex_chars() {
        let n = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 1, 1)).unwrap();
        let hex = n.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // ---- Canonicalization (round 2: closes the case/whitespace bypass) ----

    #[test]
    fn currency_code_is_case_insensitive() {
        let a = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        let b = compute_nullifier(&fp("issuer-1", "INV-001", "usd", 10_000, 1_800_000_000)).unwrap();
        assert_eq!(a, b, "USD and usd must collide -- same currency, different case");
    }

    #[test]
    fn identifier_fields_are_whitespace_trimmed() {
        let a = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        let b = compute_nullifier(&fp(" issuer-1 ", " INV-001 ", "USD", 10_000, 1_800_000_000)).unwrap();
        assert_eq!(a, b, "surrounding whitespace must not produce a distinct nullifier");
    }

    #[test]
    fn currency_code_is_trimmed_before_case_folding() {
        let a = compute_nullifier(&fp("issuer-1", "INV-001", "USD", 10_000, 1_800_000_000)).unwrap();
        let b = compute_nullifier(&fp("issuer-1", "INV-001", " usd ", 10_000, 1_800_000_000)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn whitespace_only_field_is_treated_as_empty_and_rejected() {
        let result = compute_nullifier(&fp("   ", "INV-001", "USD", 1, 1));
        assert_eq!(
            result,
            Err(FingerprintError::EmptyRequiredField("issuer_identifier"))
        );
    }

    #[test]
    fn length_bound_is_checked_after_trimming_not_before() {
        // Padded with whitespace so the raw field is over MAX_FIELD_LEN, but
        // the trimmed content is well within bounds -- this must be accepted,
        // not rejected for a length that only existed before trimming.
        let padded = format!("  {}  ", "x".repeat(MAX_FIELD_LEN));
        assert!(padded.len() > MAX_FIELD_LEN);
        assert!(compute_nullifier(&fp(&padded, "INV-001", "USD", 1, 1)).is_ok());
    }

    #[test]
    fn currency_code_wrong_length_is_rejected() {
        let result = compute_nullifier(&fp("issuer-1", "INV-001", "US", 1, 1));
        assert_eq!(result, Err(FingerprintError::InvalidCurrencyCodeShape));
    }

    #[test]
    fn currency_code_with_non_letters_is_rejected() {
        let result = compute_nullifier(&fp("issuer-1", "INV-001", "US1", 1, 1));
        assert_eq!(result, Err(FingerprintError::InvalidCurrencyCodeShape));
    }

    #[test]
    fn non_ascii_issuer_identifier_is_rejected() {
        let result = compute_nullifier(&fp("issuer-\u{00e9}1", "INV-001", "USD", 1, 1));
        assert_eq!(result, Err(FingerprintError::NonAsciiField("issuer_identifier")));
    }

    #[test]
    fn non_ascii_invoice_number_is_rejected() {
        let result = compute_nullifier(&fp("issuer-1", "INV-\u{4e2d}001", "USD", 1, 1));
        assert_eq!(result, Err(FingerprintError::NonAsciiField("invoice_number")));
    }
}
