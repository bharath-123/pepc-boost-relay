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

var (
	uniswapV2Addr   = common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")
	blockSubmitPath = "/relay/v1/builder/blocks"
	tobTxSubmitPath = "/relay/v1/builder/tob_txs"
)

// TODO - this test will keep evolving as we expand the state interference checks
func TestCheckTxAndSenderValidity(t *testing.T) {
	_, _, backend := startTestBackend(t)
	randomAddress := common2.BytesToAddress([]byte("0xabc"))

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
					To:       &uniswapV2Addr,
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
			requiredError: "we require a payment tx to the relayer along with the TOB txs",
		},
		{
			description: "zero value payout",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &uniswapV2Addr,
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
			requiredError: "the relayer payment tx is non-zero",
		},
		{
			description: "malformed payout",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &uniswapV2Addr,
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
			requiredError: "the relayer payment tx has malformed data",
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
					To:       &uniswapV2Addr,
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

func prepareBackend(backend *testBackend, slot uint64, parentHash string, feeRec types.Address, withdrawalsRoot []byte, prevRandao string, proposerPubkey phase0.BLSPubKey) {
	headSlot := slot
	submissionSlot := headSlot + 1

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
	backend.relay.blockAssembler = &MockBlockAssembler{
		assemblerError: nil,
	}
}

// tests when tob txs are sent in sequence
func TestSubmitTobTxsInSequence(t *testing.T) {
	backend := newTestBackend(t, 1)

	cases := []struct {
		description      string
		firstTobTxs      []*gethtypes.Transaction
		secondTobTxs     []*gethtypes.Transaction
		nextSentIsHigher bool
	}{
		{
			description: "second set of tob txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    1,
					GasPrice: big.NewInt(1),
					Gas:      1,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(1),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(3),
					Data:     []byte("tx3"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			nextSentIsHigher: true,
		},
		{
			description: "first set of txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    1,
					GasPrice: big.NewInt(1),
					Gas:      1,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(1),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(3),
					Data:     []byte("tx3"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(1),
					Data:     []byte(""),
				}),
			},
			nextSentIsHigher: false,
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {

			backend := newTestBackend(t, 1)

			headSlot := uint64(32)
			parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
			feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
			require.NoError(t, err)
			withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
			require.NoError(t, err)
			prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"
			proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
			require.NoError(t, err)
			proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

			prepareBackend(backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey)

			// submit first set of tob txs
			tobTxReqs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
			for _, tx := range c.firstTobTxs {
				txByte, err := tx.MarshalBinary()
				require.NoError(t, err)
				tobTxReqs.Transactions = append(tobTxReqs.Transactions, txByte)
			}
			firstSetTxHashRoot, err := tobTxReqs.HashTreeRoot()
			require.NoError(t, err)
			req := &common.TobTxsSubmitRequest{
				ParentHash: parentHash,
				TobTxs:     tobTxReqs,
				Slot:       headSlot + 1,
			}
			jsonReq, err := req.MarshalJSON()
			require.NoError(t, err)
			rr := backend.requestBytes(http.MethodPost, tobTxSubmitPath, jsonReq, map[string]string{
				"Content-Type": "application/json",
			})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, rr.Code)
			// first checks should check for the first set of tob txs
			tobTxValue, err := backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
			require.NoError(t, err)
			require.Equal(t, tobTxValue, c.firstTobTxs[len(c.firstTobTxs)-1].Value())

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
			require.Equal(t, firstSetTxHashRoot, txsPostStoringInRedisHashRoot)

			// submit second set of txs
			tobTxReqs = bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
			for _, tx := range c.secondTobTxs {
				txByte, err := tx.MarshalBinary()
				require.NoError(t, err)
				tobTxReqs.Transactions = append(tobTxReqs.Transactions, txByte)
			}
			secondSetTxHashRoot, err := tobTxReqs.HashTreeRoot()
			require.NoError(t, err)
			req = &common.TobTxsSubmitRequest{
				ParentHash: parentHash,
				TobTxs:     tobTxReqs,
				Slot:       headSlot + 1,
			}
			jsonReq, err = req.MarshalJSON()
			require.NoError(t, err)
			rr = backend.requestBytes(http.MethodPost, tobTxSubmitPath, jsonReq, map[string]string{
				"Content-Type": "application/json",
			})
			if !c.nextSentIsHigher {
				require.NoError(t, err)
				require.Equal(t, http.StatusBadRequest, rr.Code)
				require.Contains(t, rr.Body.String(), "TOB tx value is less than the current value!")
			} else {
				// the tob txs should be the second set
				tobTxValue, err = backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
				require.NoError(t, err)

				tobtxs, err = backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), headSlot+1, parentHash)
				require.NoError(t, err)
				require.Equal(t, 2, len(tobtxs))

				firstTx = new(gethtypes.Transaction)
				err = firstTx.UnmarshalBinary(tobtxs[0])
				require.NoError(t, err)

				secondTx = new(gethtypes.Transaction)
				err = secondTx.UnmarshalBinary(tobtxs[1])
				require.NoError(t, err)

				firstTxBytes, err = firstTx.MarshalBinary()
				require.NoError(t, err)
				secondTxBytes, err = secondTx.MarshalBinary()
				require.NoError(t, err)

				txsPostStoringInRedis = bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{firstTxBytes, secondTxBytes}}
				txsPostStoringInRedisHashRoot, err = txsPostStoringInRedis.HashTreeRoot()
				require.Equal(t, tobTxValue, c.secondTobTxs[len(c.secondTobTxs)-1].Value())
				require.Equal(t, txsPostStoringInRedisHashRoot, secondSetTxHashRoot)
			}
		})
	}
}

func TestSubmitTobTxs(t *testing.T) {
	backend := newTestBackend(t, 1)

	cases := []struct {
		description   string
		tobTxs        []*gethtypes.Transaction
		requiredError string
		slotDelta     uint64
	}{
		{
			description: "No payout",
			tobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(3),
					Data:     []byte("tx6"),
				}),
			},
			requiredError: "We require a payment tx along with the TOB txs!",
			slotDelta:     1,
		},
		{
			description: "payout to wrong address",
			tobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(3),
					Data:     []byte("tx6"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(5),
					Data:     []byte(""),
				}),
			},
			requiredError: "we require a payment tx to the relayer along with the TOB txs",
			slotDelta:     1,
		},
		{
			description: "ToB state interference",
			tobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(3),
					Data:     []byte("tx6"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(5),
					Data:     []byte(""),
				}),
			},
			requiredError: "TOB tx can only be sent to uniswap v2 router",
			slotDelta:     1,
		},
		{
			description: "req submitted too early",
			tobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(3),
					Data:     []byte("tx6"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(5),
					Data:     []byte(""),
				}),
			},
			requiredError: "Slot's TOB bid not yet started!!",
			slotDelta:     2,
		},
		{
			description:   "No txs sent",
			tobTxs:        []*gethtypes.Transaction{},
			requiredError: "Empty TOB tx request sent",
			slotDelta:     1,
		},
		{
			description: "Valid TobTxs sent",
			tobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(3),
					Data:     []byte("tx3"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			requiredError: "",
			slotDelta:     1,
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			backend := newTestBackend(t, 1)

			headSlot := uint64(32)

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

			prepareBackend(backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey)

			tobTxReqs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
			for _, tx := range c.tobTxs {
				txByte, err := tx.MarshalBinary()
				require.NoError(t, err)
				tobTxReqs.Transactions = append(tobTxReqs.Transactions, txByte)
			}
			txHashRoot, err := tobTxReqs.HashTreeRoot()
			require.NoError(t, err)
			req := &common.TobTxsSubmitRequest{
				ParentHash: parentHash,
				TobTxs:     tobTxReqs,
				Slot:       headSlot + c.slotDelta,
			}
			jsonReq, err := req.MarshalJSON()
			require.NoError(t, err)
			rr := backend.requestBytes(http.MethodPost, tobTxSubmitPath, jsonReq, map[string]string{
				"Content-Type": "application/json",
			})

			//err := backend.relay.checkTxAndSenderValidity(c.txs)
			if c.requiredError != "" {
				require.Contains(t, rr.Body.String(), c.requiredError)
			} else {
				require.NoError(t, err)
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
				require.Equal(t, txHashRoot, txsPostStoringInRedisHashRoot)

			}
		})
	}
}

func TestSubmitBuilderBlockInSequence(t *testing.T) {
	backend := newTestBackend(t, 1)

	cases := []struct {
		description      string
		firstTobTxs      []*gethtypes.Transaction
		secondTobTxs     []*gethtypes.Transaction
		nextSentIsHigher bool
	}{
		{
			description: "second set of tob txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    1,
					GasPrice: big.NewInt(1),
					Gas:      1,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(1),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(3),
					Data:     []byte("tx3"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			nextSentIsHigher: true,
		},
		{
			description: "first set of txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    1,
					GasPrice: big.NewInt(1),
					Gas:      1,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(1),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &uniswapV2Addr,
					Value:    big.NewInt(3),
					Data:     []byte("tx3"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &backend.relay.relayerPayoutAddress,
					Value:    big.NewInt(1),
					Data:     []byte(""),
				}),
			},
			nextSentIsHigher: false,
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			backend := newTestBackend(t, 1)

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
			proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
			require.NoError(t, err)
			proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

			prepareBackend(backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey)
			// submit the first ToB txs
			txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
			require.NoError(t, err)
			for _, tx := range c.firstTobTxs {
				txBytes, err := tx.MarshalBinary()
				require.NoError(t, err)
				txs.Transactions = append(txs.Transactions, txBytes)
			}
			txsHashRoot, err := txs.HashTreeRoot()
			req := &common.TobTxsSubmitRequest{
				ParentHash: parentHash,
				TobTxs:     txs,
				Slot:       headSlot + 1,
			}
			jsonReq, err := req.MarshalJSON()
			require.NoError(t, err)

			rr := backend.requestBytes(http.MethodPost, tobTxSubmitPath, jsonReq, map[string]string{
				"Content-Type": "application/json",
			})
			require.Equal(t, http.StatusOK, rr.Code)

			tobTxValue, err := backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
			require.NoError(t, err)
			payoutTxs := c.firstTobTxs[len(c.firstTobTxs)-1]
			require.Equal(t, tobTxValue, payoutTxs.Value())
			tobTxsValue := payoutTxs.Value()

			tobTxs, err := backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), headSlot+1, parentHash)
			require.NoError(t, err)
			require.Equal(t, len(c.firstTobTxs), len(tobTxs))
			txOutOfRedis := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
			for _, tx := range tobTxs {
				txOutOfRedis.Transactions = append(txOutOfRedis.Transactions, tx)
			}
			txsOutOfRedisHash, err := txOutOfRedis.HashTreeRoot()
			require.NoError(t, err)
			require.Equal(t, txsHashRoot, txsOutOfRedisHash)

			// Prepare the request payload
			blockSubmitReq := prepareBlockSubmitRequest(t, payloadJSONFilename, submissionSlot, uint64(submissionTimestamp), backend)

			totalExpectedBidValue := big.NewInt(0).Add(blockSubmitReq.Message().Value.ToBig(), tobTxsValue)

			// Send JSON encoded request
			reqJSONBytes, err := blockSubmitReq.Capella.MarshalJSON()
			require.NoError(t, err)
			require.Equal(t, 704810, len(reqJSONBytes))
			reqJSONBytes2, err := json.Marshal(blockSubmitReq.Capella)
			require.NoError(t, err)
			require.Equal(t, reqJSONBytes, reqJSONBytes2)
			rr = backend.requestBytes(http.MethodPost, blockSubmitPath, reqJSONBytes, nil)
			require.Equal(t, http.StatusOK, rr.Code)

			txPipeliner := backend.redis.NewPipeline()
			topBidValue, err := backend.redis.GetTopBidValue(context.Background(), txPipeliner, headSlot+1, parentHash, blockSubmitReq.ProposerPubkey())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, topBidValue)
			bestBid, err := backend.redis.GetBestBid(headSlot+1, parentHash, blockSubmitReq.ProposerPubkey())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, bestBid.Value())
			value, err := backend.redis.GetBuilderLatestValue(headSlot+1, blockSubmitReq.ParentHash(), blockSubmitReq.ProposerPubkey(), blockSubmitReq.BuilderPubkey().String())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, value)
			payload, err := backend.redis.GetExecutionPayloadCapella(headSlot+1, blockSubmitReq.ProposerPubkey(), blockSubmitReq.BlockHash())
			require.NoError(t, err)
			require.Equal(t, blockSubmitReq.NumTx()+len(c.firstTobTxs), payload.NumTx())
			payloadTxs := payload.Capella.Capella.Transactions
			payloadTobTxs := payloadTxs[:len(c.firstTobTxs)]
			payloadRobTxs := payloadTxs[len(c.firstTobTxs):]
			for i, tobtx := range payloadTobTxs {
				expectedTobTx := c.firstTobTxs[i]
				expectedTobTxBinary, err := expectedTobTx.MarshalBinary()

				require.NoError(t, err)
				require.Equal(t, bellatrix.Transaction(expectedTobTxBinary), tobtx)
			}
			for i, robtx := range payloadRobTxs {
				expectedRobTx := blockSubmitReq.Capella.ExecutionPayload.Transactions[i]
				require.Equal(t, expectedRobTx, robtx)
			}
			bid, err := backend.redis.GetBidTrace(headSlot+1, blockSubmitReq.ProposerPubkey(), blockSubmitReq.BlockHash())
			require.NoError(t, err)
			require.Equal(t, bid.Value.ToBig(), totalExpectedBidValue)
			require.Equal(t, bid.Slot, headSlot+1)
			require.Equal(t, int(bid.NumTx), blockSubmitReq.NumTx()+len(c.firstTobTxs))
			floorBid, err := backend.redis.GetFloorBidValue(context.Background(), txPipeliner, headSlot+1, parentHash, blockSubmitReq.ProposerPubkey())
			require.NoError(t, err)
			require.Equal(t, floorBid, totalExpectedBidValue)

			// submit the second set of ToB txs
			txs = bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
			require.NoError(t, err)
			for _, tx := range c.secondTobTxs {
				txBytes, err := tx.MarshalBinary()
				require.NoError(t, err)
				txs.Transactions = append(txs.Transactions, txBytes)
			}
			txsHashRoot, err = txs.HashTreeRoot()
			req = &common.TobTxsSubmitRequest{
				ParentHash: parentHash,
				TobTxs:     txs,
				Slot:       headSlot + 1,
			}
			jsonReq, err = req.MarshalJSON()
			require.NoError(t, err)

			rr = backend.requestBytes(http.MethodPost, tobTxSubmitPath, jsonReq, map[string]string{
				"Content-Type": "application/json",
			})

			if !c.nextSentIsHigher {
				require.Equal(t, http.StatusBadRequest, rr.Code)
				require.Contains(t, rr.Body.String(), "TOB tx value is less than the current value!")
				// we can stop the test here
				return
			}
			require.Equal(t, http.StatusOK, rr.Code)

			tobTxValue, err = backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), headSlot+1, parentHash)
			require.NoError(t, err)
			payoutTxs = c.secondTobTxs[len(c.secondTobTxs)-1]
			require.Equal(t, tobTxValue, payoutTxs.Value())
			tobTxsValue = payoutTxs.Value()

			tobTxs, err = backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), headSlot+1, parentHash)
			require.NoError(t, err)
			require.Equal(t, len(c.secondTobTxs), len(tobTxs))
			txOutOfRedis = bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
			for _, tx := range tobTxs {
				txOutOfRedis.Transactions = append(txOutOfRedis.Transactions, tx)
			}
			txsOutOfRedisHash, err = txOutOfRedis.HashTreeRoot()
			require.NoError(t, err)
			require.Equal(t, txsHashRoot, txsOutOfRedisHash)

			blockSubmitReq = prepareBlockSubmitRequest(t, payloadJSONFilename, submissionSlot, uint64(submissionTimestamp), backend)

			totalExpectedBidValue = big.NewInt(0).Add(blockSubmitReq.Message().Value.ToBig(), tobTxsValue)

			// Send JSON encoded request
			reqJSONBytes, err = blockSubmitReq.Capella.MarshalJSON()
			require.NoError(t, err)
			require.Equal(t, 704810, len(reqJSONBytes))
			reqJSONBytes2, err = json.Marshal(blockSubmitReq.Capella)
			require.NoError(t, err)
			require.Equal(t, reqJSONBytes, reqJSONBytes2)
			rr = backend.requestBytes(http.MethodPost, blockSubmitPath, reqJSONBytes, nil)
			require.Equal(t, http.StatusOK, rr.Code)

			txPipeliner = backend.redis.NewPipeline()
			topBidValue, err = backend.redis.GetTopBidValue(context.Background(), txPipeliner, headSlot+1, parentHash, blockSubmitReq.ProposerPubkey())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, topBidValue)
			bestBid, err = backend.redis.GetBestBid(headSlot+1, parentHash, blockSubmitReq.ProposerPubkey())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, bestBid.Value())
			value, err = backend.redis.GetBuilderLatestValue(headSlot+1, blockSubmitReq.ParentHash(), blockSubmitReq.ProposerPubkey(), blockSubmitReq.BuilderPubkey().String())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, value)
			payload, err = backend.redis.GetExecutionPayloadCapella(headSlot+1, blockSubmitReq.ProposerPubkey(), blockSubmitReq.BlockHash())
			require.NoError(t, err)
			require.Equal(t, blockSubmitReq.NumTx()+len(c.secondTobTxs), payload.NumTx())
			payloadTxs = payload.Capella.Capella.Transactions
			payloadTobTxs = payloadTxs[:len(c.secondTobTxs)]
			payloadRobTxs = payloadTxs[len(c.secondTobTxs):]
			for i, tobtx := range payloadTobTxs {
				expectedTobTx := c.secondTobTxs[i]
				expectedTobTxBinary, err := expectedTobTx.MarshalBinary()

				require.NoError(t, err)
				require.Equal(t, bellatrix.Transaction(expectedTobTxBinary), tobtx)
			}
			for i, robtx := range payloadRobTxs {
				expectedRobTx := blockSubmitReq.Capella.ExecutionPayload.Transactions[i]
				require.Equal(t, expectedRobTx, robtx)
			}
			bid, err = backend.redis.GetBidTrace(headSlot+1, blockSubmitReq.ProposerPubkey(), blockSubmitReq.BlockHash())
			require.NoError(t, err)
			require.Equal(t, bid.Value.ToBig(), totalExpectedBidValue)
			require.Equal(t, bid.Slot, headSlot+1)
			require.Equal(t, int(bid.NumTx), blockSubmitReq.NumTx()+len(c.secondTobTxs))
			floorBid, err = backend.redis.GetFloorBidValue(context.Background(), txPipeliner, headSlot+1, parentHash, blockSubmitReq.ProposerPubkey())
			require.NoError(t, err)
			require.Equal(t, floorBid, totalExpectedBidValue)
			blockSubmissionEntry, err := backend.relay.db.GetBlockSubmissionEntry(headSlot+1, blockSubmitReq.ProposerPubkey(), blockSubmitReq.BlockHash())
			require.NoError(t, err)
			blockSubmissionValue, ok := new(big.Int).SetString(blockSubmissionEntry.Value, 10)
			require.True(t, ok)
			require.Equal(t, totalExpectedBidValue, blockSubmissionValue)
			dbPayload, err := backend.datastore.GetGetPayloadResponse(common.TestLog, headSlot+1, blockSubmitReq.ProposerPubkey(), blockSubmitReq.BlockHash())
			require.NoError(t, err)
			require.Equal(t, blockSubmitReq.NumTx()+len(c.secondTobTxs), dbPayload.NumTx())
			payloadTxs = dbPayload.Capella.Capella.Transactions
			payloadTobTxs = payloadTxs[:len(c.secondTobTxs)]
			payloadRobTxs = payloadTxs[len(c.secondTobTxs):]
			for i, tobtx := range payloadTobTxs {
				expectedTobTx := c.secondTobTxs[i]
				expectedTobTxBinary, err := expectedTobTx.MarshalBinary()

				require.NoError(t, err)
				require.Equal(t, bellatrix.Transaction(expectedTobTxBinary), tobtx)
			}
			for i, robtx := range payloadRobTxs {
				expectedRobTx := blockSubmitReq.Capella.ExecutionPayload.Transactions[i]
				require.Equal(t, expectedRobTx, robtx)
			}
		})
	}

}

func prepareBlockSubmitRequest(t *testing.T, payloadJSONFilename string, submissionSlot, submissionTimestamp uint64, backend *testBackend) *common.BuilderSubmitBlockRequest {
	// Prepare the request payload
	req := new(common.BuilderSubmitBlockRequest)
	requestPayloadJSONBytes := common.LoadGzippedBytes(t, payloadJSONFilename)
	err := json.Unmarshal(requestPayloadJSONBytes, &req)
	require.NoError(t, err)

	// Update
	req.Capella.Message.Slot = submissionSlot
	req.Capella.ExecutionPayload.Timestamp = submissionTimestamp
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

	return req
}

func TestSubmitBuilderBlock(t *testing.T) {
	backend := newTestBackend(t, 1)

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
					To:       &uniswapV2Addr,
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
			proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
			require.NoError(t, err)
			proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

			prepareBackend(backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey)

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

				rr := backend.requestBytes(http.MethodPost, tobTxSubmitPath, jsonReq, map[string]string{
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
			req := prepareBlockSubmitRequest(t, payloadJSONFilename, submissionSlot, uint64(submissionTimestamp), backend)

			totalExpectedBidValue := big.NewInt(0).Add(req.Message().Value.ToBig(), tobTxsValue)

			// Send JSON encoded request
			reqJSONBytes, err := req.Capella.MarshalJSON()
			rr := backend.requestBytes(http.MethodPost, blockSubmitPath, reqJSONBytes, nil)
			if c.requiredError != "" {
				require.Contains(t, rr.Body.String(), c.requiredError)
			} else {
				require.Equal(t, http.StatusOK, rr.Code)
			}
			// get the block stored in the db
			txPipeliner := backend.redis.NewPipeline()
			topBidValue, err := backend.redis.GetTopBidValue(context.Background(), txPipeliner, headSlot+1, parentHash, req.ProposerPubkey())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, topBidValue)
			bestBid, err := backend.redis.GetBestBid(headSlot+1, parentHash, req.ProposerPubkey())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, bestBid.Value())
			value, err := backend.redis.GetBuilderLatestValue(headSlot+1, req.ParentHash(), req.ProposerPubkey(), req.BuilderPubkey().String())
			require.NoError(t, err)
			require.Equal(t, totalExpectedBidValue, value)
			payload, err := backend.redis.GetExecutionPayloadCapella(headSlot+1, req.ProposerPubkey(), req.BlockHash())
			require.NoError(t, err)
			require.Equal(t, req.NumTx()+len(c.tobTxs), payload.NumTx())
			payloadTxs := payload.Capella.Capella.Transactions
			tobTxs := payloadTxs[:len(c.tobTxs)]
			robTxs := payloadTxs[len(c.tobTxs):]
			for i, tobtx := range tobTxs {
				expectedTobTx := c.tobTxs[i]
				expectedTobTxBinary, err := expectedTobTx.MarshalBinary()

				require.NoError(t, err)
				require.Equal(t, bellatrix.Transaction(expectedTobTxBinary), tobtx)
			}
			for i, robtx := range robTxs {
				expectedRobTx := req.Capella.ExecutionPayload.Transactions[i]
				require.Equal(t, expectedRobTx, robtx)
			}
			bid, err := backend.redis.GetBidTrace(headSlot+1, req.ProposerPubkey(), req.BlockHash())
			require.NoError(t, err)
			require.Equal(t, bid.Value.ToBig(), totalExpectedBidValue)
			require.Equal(t, bid.Slot, headSlot+1)
			require.Equal(t, int(bid.NumTx), req.NumTx()+len(c.tobTxs))
			floorBid, err := backend.redis.GetFloorBidValue(context.Background(), txPipeliner, headSlot+1, parentHash, req.ProposerPubkey())
			require.NoError(t, err)
			require.Equal(t, floorBid, totalExpectedBidValue)
			blockSubmissionEntry, err := backend.relay.db.GetBlockSubmissionEntry(headSlot+1, req.ProposerPubkey(), req.BlockHash())
			require.NoError(t, err)
			blockSubmissionValue, ok := new(big.Int).SetString(blockSubmissionEntry.Value, 10)
			require.True(t, ok)
			require.Equal(t, totalExpectedBidValue, blockSubmissionValue)
			dbPayload, err := backend.datastore.GetGetPayloadResponse(common.TestLog, headSlot+1, req.ProposerPubkey(), req.BlockHash())
			require.NoError(t, err)
			require.Equal(t, req.NumTx()+len(c.tobTxs), dbPayload.NumTx())
			payloadTxs = dbPayload.Capella.Capella.Transactions
			tobTxs = payloadTxs[:len(c.tobTxs)]
			robTxs = payloadTxs[len(c.tobTxs):]
			for i, tobtx := range tobTxs {
				expectedTobTx := c.tobTxs[i]
				expectedTobTxBinary, err := expectedTobTx.MarshalBinary()

				require.NoError(t, err)
				require.Equal(t, bellatrix.Transaction(expectedTobTxBinary), tobtx)
			}
			for i, robtx := range robTxs {
				expectedRobTx := req.Capella.ExecutionPayload.Transactions[i]
				require.Equal(t, expectedRobTx, robtx)
			}
		})
	}
}
