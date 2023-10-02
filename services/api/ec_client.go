package api

import (
	"context"
	"math/big"

	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type IEcClient interface {
	GetLatestNonce(address common2.Address) (uint64, error)
	GetLatestBalance(address common2.Address) (*big.Int, error)
	GetSigner(tx *types.Transaction) (common2.Address, error)
}

type EcClient struct {
	ecClient *ethclient.Client
}

func NewEcClient(ecUrl string) (*EcClient, error) {
	ecClient, err := ethclient.Dial(ecUrl)
	if err != nil {
		return nil, err
	}
	return &EcClient{ecClient: ecClient}, nil
}

func (ec *EcClient) GetLatestNonce(address common2.Address) (uint64, error) {
	return ec.ecClient.NonceAt(context.Background(), address, nil)
}

func (ec *EcClient) GetLatestBalance(address common2.Address) (*big.Int, error) {
	return ec.ecClient.BalanceAt(context.Background(), address, nil)
}

func (ec *EcClient) GetSigner(tx *types.Transaction) (common2.Address, error) {
	return types.Sender(types.NewCancunSigner(tx.ChainId()), tx)
}
