package quote

import (
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
)

// Quote is an unverified SGX remote attestation quote, depending on the attestation scheme.
type Quote struct {
	IAS *ias.AVRBundle   `json:"ias,omitempty"`
	PCS *pcs.QuoteBundle `json:"pcs,omitempty"`
}

// QuotePolicy is the quote validity policy.
type QuotePolicy struct {
	IAS *ias.QuotePolicy `json:"ias,omitempty"`
	PCS *pcs.QuotePolicy `json:"pcs,omitempty"`
}
