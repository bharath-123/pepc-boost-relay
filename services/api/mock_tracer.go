package api

import (
	"context"
	"fmt"

	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/mev-boost-relay/common"
)

type MockTracer struct {
	tracerError  string
	callTraceMap map[common2.Hash]*common.CallTrace
}

func NewMockTracer(tracerError string, callTraceMap map[common2.Hash]*common.CallTrace) *MockTracer {
	return &MockTracer{
		tracerError:  tracerError,
		callTraceMap: callTraceMap,
	}
}

func (t *MockTracer) TraceTx(context context.Context, tx *types.Transaction) (*common.CallTraceResponse, error) {
	if t.tracerError == "" {
		callTrace, ok := t.callTraceMap[tx.Hash()]
		if !ok {
			return nil, fmt.Errorf("test: no call trace found for tx hash %v", tx.Hash())
		}
		return &common.CallTraceResponse{Result: *callTrace}, nil
	}
	return nil, fmt.Errorf(t.tracerError)
}
