package api

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/mev-boost-relay/common"
)

type MockTracer struct {
	tracerError string
	callTrace   *common.CallTrace
}

func NewMockTracer(tracerError string, callTrace *common.CallTrace) *MockTracer {
	return &MockTracer{
		tracerError: tracerError,
		callTrace:   callTrace,
	}
}

func (t *MockTracer) TraceTx(context context.Context, tx *types.Transaction) (*common.CallTraceResponse, error) {
	if t.tracerError == "" {
		return &common.CallTraceResponse{Result: *t.callTrace}, nil
	}
	return &common.CallTraceResponse{Result: *t.callTrace}, fmt.Errorf(t.tracerError)
}
