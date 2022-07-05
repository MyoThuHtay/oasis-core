//! SGX-specific functionality.

pub mod egetkey;
pub mod ias;
pub mod pcs;
pub mod seal;

use anyhow::Result;
use chrono::prelude::*;
#[cfg(target_env = "sgx")]
use sgx_isa::Report;

use crate::common::time::insecure_posix_time;

impl_bytes!(MrEnclave, 32, "Enclave hash (MRENCLAVE).");
impl_bytes!(MrSigner, 32, "Enclave signer hash (MRSIGNER).");

/// Enclave identity.
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq, cbor::Encode, cbor::Decode)]
pub struct EnclaveIdentity {
    pub mr_enclave: MrEnclave,
    pub mr_signer: MrSigner,
}

impl EnclaveIdentity {
    pub fn current() -> Option<Self> {
        #[cfg(target_env = "sgx")]
        {
            let report = Report::for_self();
            Some(EnclaveIdentity {
                mr_enclave: MrEnclave(report.mrenclave),
                mr_signer: MrSigner(report.mrsigner),
            })
        }

        // TODO: There should be a mechanism for setting mock values for
        // the purpose of testing.
        #[cfg(not(target_env = "sgx"))]
        None
    }

    pub fn fortanix_test(mr_enclave: MrEnclave) -> Self {
        Self {
            mr_enclave,
            mr_signer: MrSigner::from(
                "9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a",
            ),
        }
    }
}

/// An unverified SGX remote attestation quote, depending on the attestation scheme.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub enum Quote {
    #[cbor(rename = "ias")]
    Ias(ias::AVR),

    #[cbor(rename = "pcs")]
    Pcs(pcs::QuoteBundle),
}

impl Quote {
    /// Verify the remote attestation quote.
    pub fn verify(&self) -> Result<VerifiedQuote> {
        // TODO: Add QuotePolicy argument.
        match self {
            Quote::Ias(avr) => ias::verify(avr),
            Quote::Pcs(qb) => {
                let now = Utc.timestamp(insecure_posix_time(), 0);
                Ok(qb.verify(now)?)
            }
        }
    }

    /// Whether the quote is considered fresh.
    pub fn is_fresh(&self, now: i64, ts: i64, policy: &QuotePolicy) -> bool {
        match (self, policy) {
            (Quote::Ias(_), QuotePolicy::Ias(_)) => ias::timestamp_is_fresh(now, ts),
            (Quote::Pcs(_), QuotePolicy::Pcs(qp)) => qp.is_fresh(now, ts),
            _ => false,
        }
    }
}

/// Quote validity policy.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub enum QuotePolicy {
    #[cbor(rename = "ias")]
    Ias(ias::QuotePolicy),

    #[cbor(rename = "pcs")]
    Pcs(pcs::QuotePolicy),
}

impl QuotePolicy {
    /// Return a sane default policy for the given quote type.
    pub fn default_for(quote: &Quote) -> Self {
        match quote {
            Quote::Ias(_) => QuotePolicy::Ias(ias::QuotePolicy {
                allowed_quote_statuses: vec![],
            }),
            Quote::Pcs(_) => QuotePolicy::Pcs(pcs::QuotePolicy {
                tcb_validity_period: 30,
                min_tcb_evaluation_data_number: 1,
            }),
        }
    }
}

/// A remote attestation quote that has undergone verification.
#[derive(Debug, Default, Clone)]
pub struct VerifiedQuote {
    pub report_data: Vec<u8>,
    pub identity: EnclaveIdentity,
    pub timestamp: i64,
    pub nonce: Vec<u8>,
}
