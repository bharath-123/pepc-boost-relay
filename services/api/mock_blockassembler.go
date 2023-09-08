package api

import (
	"context"

	"github.com/flashbots/mev-boost-relay/common"
)

type MockBlockAssembler struct {
	assemblerError error
}

func (m *MockBlockAssembler) Send(context context.Context, payload *common.BlockAssemblerRequest) (error, error) {
	return nil, m.assemblerError
}
