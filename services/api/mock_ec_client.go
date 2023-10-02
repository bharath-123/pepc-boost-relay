package api

import (
	"math/big"

	common2 "github.com/ethereum/go-ethereum/common"
)

type MockEcClient struct {
	nonceMap   map[string]uint64
	balanceMap map[string]*big.Int
	sender     common2.Address
}

func NewMockEcClient(nonceMap map[string]uint64, balanceMap map[string]*big.Int, sender common2.Address) *MockEcClient {
	return &MockEcClient{
		nonceMap:   nonceMap,
		balanceMap: balanceMap,
		sender:     sender,
	}
}

func (ec *MockEcClient) GetLatestNonce(address string) (uint64, error) {
	return ec.nonceMap[address], nil
}

func (ec *MockEcClient) GetLatestBalance(address string) (*big.Int, error) {
	return ec.balanceMap[address], nil
}

func (ec *MockEcClient) GetSigner() (common2.Address, error) {
	return ec.sender, nil
}
