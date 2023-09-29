package api

import "math/big"

type MockEcClient struct {
	Nonce   uint64
	Balance *big.Int
}

func NewMockEcClient(nonce uint64, balance *big.Int) *MockEcClient {
	return &MockEcClient{
		Nonce:   nonce,
		Balance: balance,
	}
}

func (ec *MockEcClient) GetLatestNonce(address string) (uint64, error) {
	return ec.Nonce, nil
}

func (ec *MockEcClient) GetLatestBalance(address string) (*big.Int, error) {
	return ec.Balance, nil
}
