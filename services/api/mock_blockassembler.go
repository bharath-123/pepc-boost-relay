package api

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/mev-boost-relay/common"
)

type MockBlockAssembler struct {
	assemblerError error
}

func (m *MockBlockAssembler) Send(context context.Context, payload *common.BlockAssemblerRequest) (*capella.ExecutionPayload, error, error) {
	if m.assemblerError != nil {
		return nil, nil, m.assemblerError
	}

	finalTxList := []bellatrix.Transaction{}
	for _, tx := range payload.TobTxs.Transactions {
		finalTxList = append(finalTxList, tx)
	}
	for _, tx := range payload.RobPayload.Capella.ExecutionPayload.Transactions {
		finalTxList = append(finalTxList, tx)
	}

	finalPayload := &capella.ExecutionPayload{
		Transactions: finalTxList,
		Withdrawals:  payload.RobPayload.Withdrawals(),
		ParentHash:   payload.RobPayload.Capella.Message.ParentHash,
		FeeRecipient: payload.RobPayload.Capella.Message.ProposerFeeRecipient,
		BlockHash:    payload.RobPayload.Capella.Message.BlockHash,
	}

	return finalPayload, nil, m.assemblerError
}
