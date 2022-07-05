package node

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
)

const (
	// LatestSGXConstraintsVersion is the latest SGX constraints structure version that should be
	// used for all new descriptors.
	LatestSGXConstraintsVersion = 1
)

// SGXConstraints are the Intel SGX TEE constraints.
type SGXConstraints struct {
	cbor.Versioned

	// Enclaves is the allowed MRENCLAVE/MRSIGNER pairs.
	Enclaves []sgx.EnclaveIdentity `json:"enclaves,omitempty"`

	// Policy is the quote policy.
	Policy *quote.QuotePolicy `json:"policy,omitempty"`
}

// UnmarshalCBOR is a custom deserializer that handles different structure versions.
func (sc *SGXConstraints) UnmarshalCBOR(data []byte) error {
	// Determine Entity structure version.
	v, err := cbor.GetVersion(data)
	if err != nil {
		v = 0 // Previous SGXConstraints structures were not versioned.
	}
	switch v {
	case 0:
		// Old version only supported the IAS-related constraints.
		type sgxConstraintsV0 struct {
			Enclaves             []sgx.EnclaveIdentity       `json:"enclaves,omitempty"`
			AllowedQuoteStatuses []ias.ISVEnclaveQuoteStatus `json:"allowed_quote_statuses,omitempty"`
		}
		var scv0 sgxConstraintsV0
		if err = cbor.Unmarshal(data, &scv0); err != nil {
			return err
		}

		// Convert into new format.
		sc.Versioned = cbor.NewVersioned(0)
		sc.Enclaves = scv0.Enclaves
		sc.Policy = &quote.QuotePolicy{
			IAS: &ias.QuotePolicy{
				AllowedQuoteStatuses: scv0.AllowedQuoteStatuses,
			},
		}
		return nil
	case 1:
		// New version, call the default unmarshaler.
		type scv2 SGXConstraints
		return cbor.Unmarshal(data, (*scv2)(sc))
	default:
		return fmt.Errorf("invalid SGX constraints version: %d", v)
	}
}

func (sc *SGXConstraints) ValidateBasic(cfg *TEEFeatures) error {
	// Before the PCS feature only v0 of SGX constraints is supported.
	if !cfg.SGX.PCS && sc.V != 0 {
		return fmt.Errorf("unsupported SGX constraints version: %d", sc.V)
	}
	return nil
}

func (sc *SGXConstraints) ContainsEnclave(eid sgx.EnclaveIdentity) bool {
	for _, e := range sc.Enclaves {
		if eid == e {
			return true
		}
	}
	return false
}

// TODO: Move to quote verification part (based on policy).
func (sc *SGXConstraints) quoteStatusAllowed(avr *ias.AttestationVerificationReport) bool {
	status := avr.ISVEnclaveQuoteStatus

	// Always allow "OK" and "SW_HARDENING_NEEDED".
	if status == ias.QuoteOK || status == ias.QuoteSwHardeningNeeded {
		return true
	}

	if sc.Policy == nil || sc.Policy.IAS == nil {
		return false
	}

	// Search through the constraints to see if the AVR quote status is
	// explicitly allowed.
	for _, v := range sc.Policy.IAS.AllowedQuoteStatuses {
		if v == status {
			return true
		}
	}

	return false
}
