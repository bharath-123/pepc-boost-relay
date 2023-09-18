package api

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/mev-boost-relay/common"
)

type MockTracer struct {
	tracerError string
}

func NewMockTracer(tracerError string) *MockTracer {
	return &MockTracer{
		tracerError: tracerError,
	}
}

func (t *MockTracer) TraceTx(context context.Context, tx *types.Transaction) (*common.CallTrace, error, error) {
	return nil, nil, fmt.Errorf(t.tracerError)
}
