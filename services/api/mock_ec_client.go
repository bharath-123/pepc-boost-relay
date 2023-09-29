package api

import "math/big"

type MockEcClient struct {
	nonceMap   map[string]uint64
	balanceMap map[string]*big.Int
}

func NewMockEcClient(nonceMap map[string]uint64, balanceMap map[string]*big.Int) *MockEcClient {
	return &MockEcClient{
		nonceMap:   nonceMap,
		balanceMap: balanceMap,
	}
}

func (ec *MockEcClient) GetLatestNonce(address string) (uint64, error) {
	return ec.nonceMap[address], nil
}

func (ec *MockEcClient) GetLatestBalance(address string) (*big.Int, error) {
	return ec.balanceMap[address], nil
}
