package api

import (
	"testing"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
)

// TODO - this test will keep evolving as we expand the state interference checks
func TestCcheckTxAndSenderValidity(t *testing.T) {
	cases := []struct {
		description   string
		txs           []*gethtypes.Transaction
		requiredError string
	}{
		{
			description:   "no txs sent",
			txs:           []*gethtypes.Transaction{},
			requiredError: "we require a payment tx along with the TOB txs",
		},
	}
}
