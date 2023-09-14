package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	bellatrixUtil "github.com/attestantio/go-eth2-client/util/bellatrix"
	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	boosttypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/stretchr/testify/require"
)

// TODO - this test will keep evolving as we expand the state interference checks
func TestCheckTxAndSenderValidity(t *testing.T) {
	_, _, backend := startTestBackend(t)
	randomAddress := common2.BytesToAddress([]byte("0xabc"))
	uniswapV2Address := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	cases := []struct {
		description   string
		txs           []*gethtypes.Transaction
		requiredError string
	}{
		{
			description:   "no txs sent",
			txs:           []*gethtypes.Transaction{},
			requiredError: "Empty TOB tx request sent!",
		},
		{
			description: "only 1 tx sent",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			requiredError: "We require a payment tx along with the TOB txs!",
		},
		{
			description: "payout not addresses to relayer",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &uniswapV2Address,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &randomAddress,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			requiredError: "We require a payment tx to the relayer along with the TOB txs!",
		},
		{
			description: "zero value payout",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &uniswapV2Address,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(0),
					Data:     []byte(""),
				}),
			},
			requiredError: "The relayer payment tx is non-zero!",
		},
		{
			description: "malformed payout",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &uniswapV2Address,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(110),
					Data:     []byte("tx2"),
				}),
			},
			requiredError: "The relayer payment tx has malformed data!",
		},
		{
			description: "More than 2 txs sent",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       nil,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       nil,
					Value:    big.NewInt(2),
					Data:     []byte("tx2"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			requiredError: "we support only 1 tx on the TOB currently, got 3",
		},
		{
			description: "First tx is a contract creation",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       nil,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			requiredError: "contract creation cannot be a TOB tx",
		},
		{
			description: "ToB tx is not part of whitelist",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &randomAddress,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			requiredError: "TOB tx can only be sent to uniswap v2 router",
		},
		{
			description: "Valid ToB txs",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &uniswapV2Address,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			requiredError: "",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			err := backend.relay.checkTxAndSenderValidity(c.txs)
			if c.requiredError != "" {
				require.Contains(t, err.Error(), c.requiredError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TODO - refactor these tests into a TDT
func TestSubmitTobTxsOverrideTxsWithHigherValue(t *testing.T) {
	path := "/relay/v1/builder/tob_txs"
	backend := newTestBackend(t, 1)

	headSlot := uint64(32)
	submissionSlot := headSlot + 1
	//submissionTimestamp := 1606824419

	addr1 := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	// Payload attributes
	parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
	feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
	require.NoError(t, err)
	withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
	require.NoError(t, err)
	prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"
	proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
	require.NoError(t, err)
	proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

	// Setup the test relay backend
	backend.relay.headSlot.Store(headSlot)
	backend.relay.capellaEpoch = 1
	backend.relay.proposerDutiesMap = make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	backend.relay.proposerDutiesMap[headSlot+1] = &common.BuilderGetValidatorsResponseEntry{
		Slot: headSlot,
		Entry: &types.SignedValidatorRegistration{
			Message: &types.RegisterValidatorRequestMessage{
				Pubkey:       boosttypes.PublicKey(proposerPubkey),
				FeeRecipient: feeRec,
			},
		},
	}
	backend.relay.payloadAttributes = make(map[string]payloadAttributesHelper)
	backend.relay.payloadAttributes[parentHash] = payloadAttributesHelper{
		slot:       submissionSlot,
		parentHash: parentHash,
		payloadAttributes: beaconclient.PayloadAttributes{
			PrevRandao: prevRandao,
		},
		withdrawalsRoot: phase0.Root(withdrawalsRoot),
	}

	// Test 1 : Happy path
	req := new(common.TobTxsSubmitRequest)

	tx1 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(1),
		Gas:      1,
		To:       &addr1,
		Value:    big.NewInt(1),
		Data:     []byte("tx1"),
	})
	tx2 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(2),
		Gas:      2,
		To:       &backend.relay.relayerPayoutAddress,
		Value:    big.NewInt(2),
		Data:     []byte(""),
	})
	tx1byte, err := tx1.MarshalBinary()
	require.NoError(t, err)
	tx2byte, err := tx2.MarshalBinary()
	require.NoError(t, err)
	txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx1byte, tx2byte}}
	req = &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     txs,
		Slot:       headSlot + 1,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err := req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr := backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusOK, rr.Code)

	tobTxValue, err := backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)
	fmt.Printf("tobTxValue in test is : %v\n", tobTxValue)
	require.Equal(t, tobTxValue, big.NewInt(2))

	tobtxs, err := backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)

	require.Equal(t, 2, len(tobtxs))

	firstTx := new(gethtypes.Transaction)
	err = firstTx.UnmarshalBinary(tobtxs[0])

	firstTxJson, err := firstTx.MarshalJSON()
	require.NoError(t, err)
	tx1Json, err := tx1.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, firstTxJson, tx1Json)

	secondTx := new(gethtypes.Transaction)
	err = secondTx.UnmarshalBinary(tobtxs[1])
	secondTxJson, err := secondTx.MarshalJSON()
	require.NoError(t, err)
	tx2Json, err := tx2.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, secondTxJson, tx2Json)

	// Test 2: Try adding txs with higher value
	req = new(common.TobTxsSubmitRequest)
	addr1 = common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	tx3 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(3),
		Gas:      3,
		To:       &addr1,
		Value:    big.NewInt(3),
		Data:     []byte("tx3"),
	})
	tx4 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    4,
		GasPrice: big.NewInt(5),
		Gas:      12,
		To:       &backend.relay.relayerPayoutAddress,
		Value:    big.NewInt(10),
		Data:     []byte(""),
	})
	tx3byte, err := tx3.MarshalBinary()
	require.NoError(t, err)
	tx4byte, err := tx4.MarshalBinary()
	require.NoError(t, err)
	txs = bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx3byte, tx4byte}}
	req = &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     txs,
		Slot:       headSlot + 1,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err = req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr = backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusOK, rr.Code)

	tobTxValue, err = backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)
	fmt.Printf("tobTxValue in test is : %v\n", tobTxValue)
	require.Equal(t, tobTxValue, big.NewInt(10))

	tobtxs, err = backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)

	require.Equal(t, 2, len(tobtxs))

	firstTx = new(gethtypes.Transaction)
	err = firstTx.UnmarshalBinary(tobtxs[0])

	firstTxJson, err = firstTx.MarshalJSON()
	require.NoError(t, err)
	tx1Json, err = tx3.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, firstTxJson, tx1Json)

	secondTx = new(gethtypes.Transaction)
	err = secondTx.UnmarshalBinary(tobtxs[1])
	secondTxJson, err = secondTx.MarshalJSON()
	require.NoError(t, err)
	tx2Json, err = tx4.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, secondTxJson, tx2Json)
}

func TestSubmitTobTxsLowerValueRequests(t *testing.T) {
	path := "/relay/v1/builder/tob_txs"
	backend := newTestBackend(t, 1)

	headSlot := uint64(32)
	submissionSlot := headSlot + 1
	//submissionTimestamp := 1606824419

	// Payload attributes
	parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
	feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
	require.NoError(t, err)
	withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
	require.NoError(t, err)
	prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"
	proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
	require.NoError(t, err)
	proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

	// Setup the test relay backend
	backend.relay.headSlot.Store(headSlot)
	backend.relay.capellaEpoch = 1
	backend.relay.proposerDutiesMap = make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	backend.relay.proposerDutiesMap[headSlot+1] = &common.BuilderGetValidatorsResponseEntry{
		Slot: headSlot,
		Entry: &types.SignedValidatorRegistration{
			Message: &types.RegisterValidatorRequestMessage{
				Pubkey:       boosttypes.PublicKey(proposerPubkey),
				FeeRecipient: feeRec,
			},
		},
	}
	backend.relay.payloadAttributes = make(map[string]payloadAttributesHelper)
	backend.relay.payloadAttributes[parentHash] = payloadAttributesHelper{
		slot:       submissionSlot,
		parentHash: parentHash,
		payloadAttributes: beaconclient.PayloadAttributes{
			PrevRandao: prevRandao,
		},
		withdrawalsRoot: phase0.Root(withdrawalsRoot),
	}

	// Test 1 : Happy path
	req := new(common.TobTxsSubmitRequest)
	addr1 := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	tx1 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(1),
		Gas:      1,
		To:       &addr1,
		Value:    big.NewInt(1),
		Data:     []byte("tx1"),
	})
	tx2 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(2),
		Gas:      2,
		To:       &backend.relay.relayerPayoutAddress,
		Value:    big.NewInt(2),
		Data:     []byte(""),
	})
	tx1byte, err := tx1.MarshalBinary()
	require.NoError(t, err)
	tx2byte, err := tx2.MarshalBinary()
	require.NoError(t, err)
	txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx1byte, tx2byte}}
	req = &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     txs,
		Slot:       headSlot + 1,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err := req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr := backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusOK, rr.Code)

	tobTxValue, err := backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)
	fmt.Printf("tobTxValue in test is : %v\n", tobTxValue)
	require.Equal(t, tobTxValue, big.NewInt(2))

	tobtxs, err := backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)

	require.Equal(t, 2, len(tobtxs))

	firstTx := new(gethtypes.Transaction)
	err = firstTx.UnmarshalBinary(tobtxs[0])

	firstTxJson, err := firstTx.MarshalJSON()
	require.NoError(t, err)
	tx1Json, err := tx1.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, firstTxJson, tx1Json)

	secondTx := new(gethtypes.Transaction)
	err = secondTx.UnmarshalBinary(tobtxs[1])
	secondTxJson, err := secondTx.MarshalJSON()
	require.NoError(t, err)
	tx2Json, err := tx2.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, secondTxJson, tx2Json)

	// Test 2: Try adding txs with higher value
	req = new(common.TobTxsSubmitRequest)
	addr1 = common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	tx3 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(3),
		Gas:      3,
		To:       &addr1,
		Value:    big.NewInt(3),
		Data:     []byte("tx3"),
	})
	tx4 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    4,
		GasPrice: big.NewInt(5),
		Gas:      12,
		To:       &backend.relay.relayerPayoutAddress,
		Value:    big.NewInt(10),
		Data:     []byte(""),
	})
	tx3byte, err := tx3.MarshalBinary()
	require.NoError(t, err)
	tx4byte, err := tx4.MarshalBinary()
	require.NoError(t, err)
	txs = bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx3byte, tx4byte}}
	req = &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     txs,
		Slot:       headSlot + 1,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err = req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr = backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusOK, rr.Code)

	tobTxValue, err = backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)
	fmt.Printf("tobTxValue in test is : %v\n", tobTxValue)
	require.Equal(t, tobTxValue, big.NewInt(10))

	tobtxs, err = backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)

	require.Equal(t, 2, len(tobtxs))

	firstTx = new(gethtypes.Transaction)
	err = firstTx.UnmarshalBinary(tobtxs[0])

	firstTxJson, err = firstTx.MarshalJSON()
	require.NoError(t, err)
	tx1Json, err = tx3.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, firstTxJson, tx1Json)

	secondTx = new(gethtypes.Transaction)
	err = secondTx.UnmarshalBinary(tobtxs[1])
	secondTxJson, err = secondTx.MarshalJSON()
	require.NoError(t, err)
	tx2Json, err = tx4.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, secondTxJson, tx2Json)
}

func TestSubmitTobTxsNoPayout(t *testing.T) {
	path := "/relay/v1/builder/tob_txs"
	backend := newTestBackend(t, 1)

	headSlot := uint64(32)
	submissionSlot := headSlot + 1
	//submissionTimestamp := 1606824419

	// Payload attributes
	parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
	feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
	require.NoError(t, err)
	withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
	require.NoError(t, err)
	prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"
	proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
	require.NoError(t, err)
	proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

	// Setup the test relay backend
	backend.relay.headSlot.Store(headSlot)
	backend.relay.capellaEpoch = 1
	backend.relay.proposerDutiesMap = make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	backend.relay.proposerDutiesMap[headSlot+1] = &common.BuilderGetValidatorsResponseEntry{
		Slot: headSlot,
		Entry: &types.SignedValidatorRegistration{
			Message: &types.RegisterValidatorRequestMessage{
				Pubkey:       boosttypes.PublicKey(proposerPubkey),
				FeeRecipient: feeRec,
			},
		},
	}
	backend.relay.payloadAttributes = make(map[string]payloadAttributesHelper)
	backend.relay.payloadAttributes[parentHash] = payloadAttributesHelper{
		slot:       submissionSlot,
		parentHash: parentHash,
		payloadAttributes: beaconclient.PayloadAttributes{
			PrevRandao: prevRandao,
		},
		withdrawalsRoot: phase0.Root(withdrawalsRoot),
	}

	// Test 3: No payout tx
	req := new(common.TobTxsSubmitRequest)
	addr1 := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	tx7 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(3),
		Gas:      3,
		To:       &addr1,
		Value:    big.NewInt(3),
		Data:     []byte("tx6"),
	})
	tx7byte, err := tx7.MarshalBinary()
	require.NoError(t, err)
	txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx7byte}}
	req = &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     txs,
		Slot:       headSlot + 1,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err := req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr := backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "We require a payment tx along with the TOB txs!")
}

func TestSubmitTobTxsPayoutToWrongAddress(t *testing.T) {
	path := "/relay/v1/builder/tob_txs"
	backend := newTestBackend(t, 1)

	headSlot := uint64(32)
	submissionSlot := headSlot + 1
	//submissionTimestamp := 1606824419

	// Payload attributes
	parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
	feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
	require.NoError(t, err)
	withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
	require.NoError(t, err)
	prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"
	proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
	require.NoError(t, err)
	proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

	// Setup the test relay backend
	backend.relay.headSlot.Store(headSlot)
	backend.relay.capellaEpoch = 1
	backend.relay.proposerDutiesMap = make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	backend.relay.proposerDutiesMap[headSlot+1] = &common.BuilderGetValidatorsResponseEntry{
		Slot: headSlot,
		Entry: &types.SignedValidatorRegistration{
			Message: &types.RegisterValidatorRequestMessage{
				Pubkey:       boosttypes.PublicKey(proposerPubkey),
				FeeRecipient: feeRec,
			},
		},
	}
	backend.relay.payloadAttributes = make(map[string]payloadAttributesHelper)
	backend.relay.payloadAttributes[parentHash] = payloadAttributesHelper{
		slot:       submissionSlot,
		parentHash: parentHash,
		payloadAttributes: beaconclient.PayloadAttributes{
			PrevRandao: prevRandao,
		},
		withdrawalsRoot: phase0.Root(withdrawalsRoot),
	}

	// Test 3: Payout tx is to the wrong address
	req := new(common.TobTxsSubmitRequest)
	addr1 := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	tx8 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(3),
		Gas:      3,
		To:       &addr1,
		Value:    big.NewInt(3),
		Data:     []byte("tx6"),
	})
	tx9 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    4,
		GasPrice: big.NewInt(5),
		Gas:      12,
		To:       &addr1,
		Value:    big.NewInt(5),
		Data:     []byte(""),
	})
	tx8byte, err := tx8.MarshalBinary()
	require.NoError(t, err)
	tx9byte, err := tx9.MarshalBinary()
	require.NoError(t, err)
	txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx8byte, tx9byte}}
	req = &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     txs,
		Slot:       headSlot + 1,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err := req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr := backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "We require a payment tx to the relayer along with the TOB txs!")

}

func TestSubmitTobTxsStateInterference(t *testing.T) {
	path := "/relay/v1/builder/tob_txs"
	backend := newTestBackend(t, 1)

	headSlot := uint64(32)
	submissionSlot := headSlot + 1
	//submissionTimestamp := 1606824419

	// Payload attributes
	parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
	feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
	require.NoError(t, err)
	withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
	require.NoError(t, err)
	prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"
	proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
	require.NoError(t, err)
	proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

	// Setup the test relay backend
	backend.relay.headSlot.Store(headSlot)
	backend.relay.capellaEpoch = 1
	backend.relay.proposerDutiesMap = make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	backend.relay.proposerDutiesMap[headSlot+1] = &common.BuilderGetValidatorsResponseEntry{
		Slot: headSlot,
		Entry: &types.SignedValidatorRegistration{
			Message: &types.RegisterValidatorRequestMessage{
				Pubkey:       boosttypes.PublicKey(proposerPubkey),
				FeeRecipient: feeRec,
			},
		},
	}
	backend.relay.payloadAttributes = make(map[string]payloadAttributesHelper)
	backend.relay.payloadAttributes[parentHash] = payloadAttributesHelper{
		slot:       submissionSlot,
		parentHash: parentHash,
		payloadAttributes: beaconclient.PayloadAttributes{
			PrevRandao: prevRandao,
		},
		withdrawalsRoot: phase0.Root(withdrawalsRoot),
	}

	// Test 3: Fail state interference checks
	req := new(common.TobTxsSubmitRequest)
	addr1 := common2.HexToAddress("0xB2D7a3554F221B34f49d7d3C61375E603aFb699e")

	tx1 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(3),
		Gas:      3,
		To:       &addr1,
		Value:    big.NewInt(3),
		Data:     []byte("tx6"),
	})
	tx2 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    4,
		GasPrice: big.NewInt(5),
		Gas:      12,
		To:       &backend.relay.relayerPayoutAddress,
		Value:    big.NewInt(5),
		Data:     []byte(""),
	})
	tx1byte, err := tx1.MarshalBinary()
	require.NoError(t, err)
	tx2byte, err := tx2.MarshalBinary()
	require.NoError(t, err)
	txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx1byte, tx2byte}}
	req = &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     txs,
		Slot:       headSlot + 1,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err := req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr := backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "TOB tx can only be sent to uniswap v2 router")

}

func TestSubmitTobTxsCheckSlots(t *testing.T) {
	path := "/relay/v1/builder/tob_txs"
	backend := newTestBackend(t, 1)

	headSlot := uint64(32)
	submissionSlot := headSlot + 1

	// Payload attributes
	parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
	feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
	require.NoError(t, err)
	withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
	require.NoError(t, err)
	prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"
	proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
	require.NoError(t, err)
	proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

	// Setup the test relay backend
	backend.relay.headSlot.Store(headSlot)
	backend.relay.capellaEpoch = 1
	backend.relay.proposerDutiesMap = make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	backend.relay.proposerDutiesMap[headSlot+1] = &common.BuilderGetValidatorsResponseEntry{
		Slot: headSlot,
		Entry: &types.SignedValidatorRegistration{
			Message: &types.RegisterValidatorRequestMessage{
				Pubkey:       boosttypes.PublicKey(proposerPubkey),
				FeeRecipient: feeRec,
			},
		},
	}
	backend.relay.payloadAttributes = make(map[string]payloadAttributesHelper)
	backend.relay.payloadAttributes[parentHash] = payloadAttributesHelper{
		slot:       submissionSlot,
		parentHash: parentHash,
		payloadAttributes: beaconclient.PayloadAttributes{
			PrevRandao: prevRandao,
		},
		withdrawalsRoot: phase0.Root(withdrawalsRoot),
	}

	// Test 4 : Slot to far ahead
	addr1 := common2.HexToAddress("0xB2D7a3554F221B34f49d7d3C61375E603aFb699e")
	tx1 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(3),
		Gas:      3,
		To:       &addr1,
		Value:    big.NewInt(3),
		Data:     []byte("tx6"),
	})
	tx2 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    4,
		GasPrice: big.NewInt(5),
		Gas:      12,
		To:       &backend.relay.relayerPayoutAddress,
		Value:    big.NewInt(5),
		Data:     []byte(""),
	})
	tx1byte, err := tx1.MarshalBinary()
	require.NoError(t, err)
	tx2byte, err := tx2.MarshalBinary()
	require.NoError(t, err)
	txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx1byte, tx2byte}}

	req := &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     txs,
		Slot:       headSlot + 2,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err := req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr := backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "Slot's TOB bid not yet started!!")

	// Test 5: No txs are sent
	req = &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}},
		Slot:       headSlot + 2,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err = req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr = backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "Empty TOB tx request sent")
}

func TestSubmitTobTxsHappyPath(t *testing.T) {
	path := "/relay/v1/builder/tob_txs"
	backend := newTestBackend(t, 1)

	headSlot := uint64(32)
	submissionSlot := headSlot + 1
	//submissionTimestamp := 1606824419

	// Payload attributes
	parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
	feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
	require.NoError(t, err)
	withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
	require.NoError(t, err)
	prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"
	proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
	require.NoError(t, err)
	proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

	// Setup the test relay backend
	backend.relay.headSlot.Store(headSlot)
	backend.relay.capellaEpoch = 1
	backend.relay.proposerDutiesMap = make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	backend.relay.proposerDutiesMap[headSlot+1] = &common.BuilderGetValidatorsResponseEntry{
		Slot: headSlot,
		Entry: &types.SignedValidatorRegistration{
			Message: &types.RegisterValidatorRequestMessage{
				Pubkey:       boosttypes.PublicKey(proposerPubkey),
				FeeRecipient: feeRec,
			},
		},
	}
	backend.relay.payloadAttributes = make(map[string]payloadAttributesHelper)
	backend.relay.payloadAttributes[parentHash] = payloadAttributesHelper{
		slot:       submissionSlot,
		parentHash: parentHash,
		payloadAttributes: beaconclient.PayloadAttributes{
			PrevRandao: prevRandao,
		},
		withdrawalsRoot: phase0.Root(withdrawalsRoot),
	}

	req := new(common.TobTxsSubmitRequest)
	addr1 := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	tx1 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(3),
		Gas:      3,
		To:       &addr1,
		Value:    big.NewInt(3),
		Data:     []byte("tx3"),
	})
	tx2 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    4,
		GasPrice: big.NewInt(5),
		Gas:      12,
		To:       &backend.relay.relayerPayoutAddress,
		Value:    big.NewInt(10),
		Data:     []byte(""),
	})
	tx1byte, err := tx1.MarshalBinary()
	require.NoError(t, err)
	tx2byte, err := tx2.MarshalBinary()
	require.NoError(t, err)
	txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx1byte, tx2byte}}
	txsHashRoot, err := txs.HashTreeRoot()
	require.NoError(t, err)
	req = &common.TobTxsSubmitRequest{
		ParentHash: parentHash,
		TobTxs:     txs,
		Slot:       headSlot + 1,
	}
	fmt.Printf("Marshalling request to json!!")
	jsonReq, err := req.MarshalJSON()
	require.NoError(t, err)
	fmt.Printf("Unmarshalling request from json!!")

	rr := backend.requestBytes(http.MethodPost, path, jsonReq, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusOK, rr.Code)

	tobTxValue, err := backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)
	fmt.Printf("tobTxValue in test is : %v\n", tobTxValue)
	require.Equal(t, tobTxValue, big.NewInt(10))

	tobtxs, err := backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), headSlot+1, parentHash)
	require.NoError(t, err)

	require.Equal(t, 2, len(tobtxs))

	firstTx := new(gethtypes.Transaction)
	err = firstTx.UnmarshalBinary(tobtxs[0])
	require.NoError(t, err)

	secondTx := new(gethtypes.Transaction)
	err = secondTx.UnmarshalBinary(tobtxs[1])
	require.NoError(t, err)

	firstTxBytes, err := firstTx.MarshalBinary()
	require.NoError(t, err)
	secondTxBytes, err := secondTx.MarshalBinary()
	require.NoError(t, err)

	txsPostStoringInRedis := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{firstTxBytes, secondTxBytes}}
	txsPostStoringInRedisHashRoot, err := txsPostStoringInRedis.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, txsHashRoot, txsPostStoringInRedisHashRoot)
}

func TestSubmitBuilderBlock(t *testing.T) {
	submitBlockPath := "/relay/v1/builder/blocks"
	submitTobTxsPath := "/relay/v1/builder/tob_txs"
	backend := newTestBackend(t, 1)
	uniswapV2Address := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	cases := []struct {
		description   string
		tobTxs        []*gethtypes.Transaction
		requiredError string
	}{
		{
			description:   "No ToB txs",
			tobTxs:        []*gethtypes.Transaction{},
			requiredError: "",
		},
		{
			description: "ToB txs of some value are present",
			tobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &uniswapV2Address,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			requiredError: "",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			backend = newTestBackend(t, 1)

			headSlot := uint64(32)
			submissionSlot := headSlot + 1
			submissionTimestamp := 1606824419

			// Payload attributes
			payloadJSONFilename := "../../testdata/submitBlockPayloadCapella_Goerli.json.gz"
			parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
			feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
			require.NoError(t, err)
			withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
			require.NoError(t, err)
			prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"

			// Setup the test relay backend
			backend.relay.headSlot.Store(headSlot)
			backend.relay.capellaEpoch = 1
			backend.relay.proposerDutiesMap = make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
			backend.relay.proposerDutiesMap[headSlot+1] = &common.BuilderGetValidatorsResponseEntry{
				Slot: headSlot,
				Entry: &types.SignedValidatorRegistration{
					Message: &types.RegisterValidatorRequestMessage{
						FeeRecipient: feeRec,
					},
				},
			}
			backend.relay.payloadAttributes = make(map[string]payloadAttributesHelper)
			backend.relay.payloadAttributes[parentHash] = payloadAttributesHelper{
				slot:       submissionSlot,
				parentHash: parentHash,
				payloadAttributes: beaconclient.PayloadAttributes{
					PrevRandao: prevRandao,
				},
				withdrawalsRoot: phase0.Root(withdrawalsRoot),
			}
			backend.relay.blockAssembler = &MockBlockAssembler{
				assemblerError: nil,
			}

			// create the ToB txs
			tobTxsValue := big.NewInt(0)
			if len(c.tobTxs) > 0 {
				req := new(common.TobTxsSubmitRequest)
				txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
				require.NoError(t, err)
				for _, tx := range c.tobTxs {
					txBytes, err := tx.MarshalBinary()
					require.NoError(t, err)
					txs.Transactions = append(txs.Transactions, txBytes)
				}
				txsHashRoot, err := txs.HashTreeRoot()
				req = &common.TobTxsSubmitRequest{
					ParentHash: parentHash,
					TobTxs:     txs,
					Slot:       headSlot + 1,
				}
				jsonReq, err := req.MarshalJSON()
				require.NoError(t, err)

				rr := backend.requestBytes(http.MethodPost, submitTobTxsPath, jsonReq, map[string]string{
					"Content-Type": "application/json",
				})
				require.Equal(t, http.StatusOK, rr.Code)

				tobTxValue, err := backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
				require.NoError(t, err)
				payoutTxs := c.tobTxs[len(c.tobTxs)-1]
				require.Equal(t, tobTxValue, payoutTxs.Value())
				tobTxsValue = payoutTxs.Value()

				tobTxs, err := backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), headSlot+1, parentHash)
				require.NoError(t, err)
				require.Equal(t, len(c.tobTxs), len(tobTxs))
				txOutOfRedis := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
				for _, tx := range tobTxs {
					txOutOfRedis.Transactions = append(txOutOfRedis.Transactions, tx)
				}
				txsOutOfRedisHash, err := txOutOfRedis.HashTreeRoot()
				require.NoError(t, err)
				require.Equal(t, txsHashRoot, txsOutOfRedisHash)
			}

			// Prepare the request payload
			req := new(common.BuilderSubmitBlockRequest)
			requestPayloadJSONBytes := common.LoadGzippedBytes(t, payloadJSONFilename)
			require.NoError(t, err)
			err = json.Unmarshal(requestPayloadJSONBytes, &req)
			require.NoError(t, err)

			// Update
			req.Capella.Message.Slot = submissionSlot
			req.Capella.ExecutionPayload.Timestamp = uint64(submissionTimestamp)
			fmt.Printf("DEBUG: payload value is %d\n", req.Value())
			// create valid builder keypairs
			// TODO - store a valid payload in testdata
			secretKey, publicKey, err := bls.GenerateNewKeypair()
			require.NoError(t, err)
			pKey, err := boosttypes.BlsPublicKeyToPublicKey(publicKey)
			require.NoError(t, err)
			req.Capella.Message.BuilderPubkey = phase0.BLSPubKey(pKey)
			// sign the payload with the builder keypair
			signature, err := boosttypes.SignMessage(req.Message(), backend.relay.opts.EthNetDetails.DomainBuilder, secretKey)
			require.NoError(t, err)
			req.Capella.Signature = phase0.BLSSignature(signature)
			totalExpectedBidValue := big.NewInt(0).Add(req.Message().Value.ToBig(), tobTxsValue)

			// Send JSON encoded request
			reqJSONBytes, err := req.Capella.MarshalJSON()
			require.NoError(t, err)
			require.Equal(t, 704810, len(reqJSONBytes))
			reqJSONBytes2, err := json.Marshal(req.Capella)
			require.NoError(t, err)
			require.Equal(t, reqJSONBytes, reqJSONBytes2)
			rr := backend.requestBytes(http.MethodPost, submitBlockPath, reqJSONBytes, nil)
			if c.requiredError != "" {
				require.Contains(t, rr.Body.String(), c.requiredError)
			} else {
				require.Equal(t, http.StatusOK, rr.Code)
			}
			// get the block stored in the db
			topBid, err := backend.redis.GetBestBid(headSlot+1, parentHash, req.ProposerPubkey())
			fmt.Printf("DEBUG: topBid value is %d\n", topBid.Value().Int64())
			fmt.Printf("DEBUG: totalExpectedBidValue is %d\n", totalExpectedBidValue.Int64())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, topBid.Value())
		})
	}
}
