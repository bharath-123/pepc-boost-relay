package api

import (
	"context"

	"github.com/flashbots/mev-boost-relay/common"
)

type MockBlockSimulationRateLimiter struct {
	simulationError    error
	tobSimulationError error
}

func (m *MockBlockSimulationRateLimiter) Send(context context.Context, payload *common.BuilderBlockValidationRequest, isHighPrio, fastTrack bool) (error, error) {
	return nil, m.simulationError
}

func (m *MockBlockSimulationRateLimiter) TobSim(context context.Context, tobValidationRequest *common.TobValidationRequest) (error, error) {
	return nil, m.tobSimulationError
}

func (m *MockBlockSimulationRateLimiter) CurrentCounter() int64 {
	return 0
}
