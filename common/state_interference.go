package common

import (
	"bytes"

	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/mev-boost-relay/contracts"
)

var (
	DaiToken        = "dai"
	WethToken       = "weth"
	DaiWethPair1    = "dai_weth_pair_1"
	DaiWethPair2    = "dai_weth_pair_2"
	UniswapFactory1 = "uniswap_factory_1"
	UniswapFactory2 = "uniswap_factory_2"
)

// just check if it goes to the DaiWethPair with a swap tx
func IsTxWEthDaiSwap(traces *CallTraceResponse, defiAddresses map[string]common2.Address) (bool, error) {
	rootCallTrace := traces.Result
	stack := []CallTrace{rootCallTrace}

	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		res, err := IsTraceToWEthDaiPair(current, defiAddresses)
		if err != nil {
			return false, err
		}
		// we found a weth/dai swap
		if res {
			return true, nil
		}

		for _, call := range current.Calls {
			stack = append(stack, call)
		}
	}

	return false, nil
}

func IsTraceToWEthDaiPair(callTrace CallTrace, defiAddresses map[string]common2.Address) (bool, error) {
	if callTrace.To == nil {
		return false, nil
	}

	uniswapDaiWethAddress1 := defiAddresses[DaiWethPair1].String()
	uniswapDaiWethAddress2 := defiAddresses[DaiWethPair2].String()
	if !(callTrace.To.String() == uniswapDaiWethAddress1 && callTrace.To.String() == uniswapDaiWethAddress2) {
		return false, nil
	}

	if len(callTrace.Input) < 4 {
		return false, nil
	}

	uniswapPairAbi, err := contracts.UniswapPairMetaData.GetAbi()
	if err != nil {
		return false, err
	}
	swapId := uniswapPairAbi.Methods["swap"].ID
	if !bytes.Equal(callTrace.Input[:4], swapId) {
		return false, nil
	}

	return true, nil
}
