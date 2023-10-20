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
	randomAddr           = common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")
	blockSubmitPath      = "/relay/v1/builder/rob_blocks"
	tobTxSubmitPath      = "/relay/v1/builder/tob_txs"
	payloadJSONFilename  = "../../testdata/submitBlockPayloadCapella_Goerli.json.gz"
	payloadJSONFilename2 = "../../testdata/submitBlockPayloadCapella_Goerli2.json.gz"
)

type GoerliTestTraces struct {
	ValidEthUsdcTx      *gethtypes.Transaction
	ValidEthUsdcTxTrace *common.CallTrace
	InvalidTx           *gethtypes.Transaction
	InvalidTxTrace      *common.CallTrace
	ValidEthWbtcTx      *gethtypes.Transaction
	ValidEthWbtcTxTrace *common.CallTrace
	ValidEthDaiTx       *gethtypes.Transaction
	ValidEthDaiTxTrace  *common.CallTrace
}

type DevnetTestTraces struct {
	ValidWethDaiTx      *gethtypes.Transaction
	ValidWethDaiTxTrace *common.CallTrace
	InvalidTx           *gethtypes.Transaction
	InvalidTxTrace      *common.CallTrace
}

func prepareBackend(t *testing.T, backend *testBackend, slot uint64, parentHash string, feeRec types.Address, withdrawalsRoot []byte, prevRandao string, proposerPubkey phase0.BLSPubKey, network string) {
	t.Helper()
	headSlot := slot
	submissionSlot := headSlot + 1

	backend.relay.opts.EthNetDetails.Name = network
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

func prepareBlockSubmitRequest(t *testing.T, payloadJSONFilename string, submissionSlot, submissionTimestamp uint64, backend *testBackend) *common.BuilderSubmitBlockRequest {
	t.Helper()
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

func assertTobTxs(t *testing.T, backend *testBackend, slot uint64, parentHash string, tobTxValue *big.Int, txHashRoot [32]byte, expectedNoOfTobs int) {
	tobTxValue, err := backend.redis.GetTobTxValue(context.Background(), backend.redis.NewPipeline(), slot, parentHash)
	require.NoError(t, err)
	require.Equal(t, tobTxValue, tobTxValue)

	tobtxs, err := backend.redis.GetTobTx(context.Background(), backend.redis.NewTxPipeline(), slot, parentHash)
	require.NoError(t, err)

	require.Equal(t, expectedNoOfTobs, len(tobtxs))

	txsPostStoringInRedis := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}

	for _, tobtx := range tobtxs {
		tx := new(gethtypes.Transaction)
		err = tx.UnmarshalBinary(tobtx)
		require.NoError(t, err)

		txBytes, err := tx.MarshalBinary()
		require.NoError(t, err)

		txsPostStoringInRedis.Transactions = append(txsPostStoringInRedis.Transactions, txBytes)
	}

	txsPostStoringInRedisHashRoot, err := txsPostStoringInRedis.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, txHashRoot, txsPostStoringInRedisHashRoot)

}

func GetCustomDevnetTracingRelatedTestData(t *testing.T) DevnetTestTraces {
	validWethDaiTxContents := common.LoadFileContents(t, "../../testdata/traces/custom/valid_weth_dai_tx.json")
	validWethDaiTx := new(gethtypes.Transaction)
	err := validWethDaiTx.UnmarshalJSON(validWethDaiTxContents)
	require.NoError(t, err)

	invalidWethDaiTxContents := common.LoadFileContents(t, "../../testdata/traces/custom/invalid_weth_dai_tx.json")
	invalidWethDaiTx := new(gethtypes.Transaction)
	err = invalidWethDaiTx.UnmarshalJSON(invalidWethDaiTxContents)
	require.NoError(t, err)

	validWethDaiTxTraceContents := common.LoadFileContents(t, "../../testdata/traces/custom/valid_weth_dai_tx_trace.json")
	validWethDaiTxTrace := new(common.CallTrace)
	err = json.Unmarshal(validWethDaiTxTraceContents, validWethDaiTxTrace)
	require.NoError(t, err)

	invalidWethDaiTraceContents := common.LoadFileContents(t, "../../testdata/traces/custom/invalid_weth_dai_tx_trace.json")
	invalidWethDaiTrace := new(common.CallTrace)
	err = json.Unmarshal(invalidWethDaiTraceContents, invalidWethDaiTrace)
	require.NoError(t, err)

	return DevnetTestTraces{
		ValidWethDaiTx:      validWethDaiTx,
		ValidWethDaiTxTrace: validWethDaiTxTrace,
		InvalidTx:           invalidWethDaiTx,
		InvalidTxTrace:      invalidWethDaiTrace,
	}
}

func GetGoerliTracingRelatedTestData(t *testing.T) GoerliTestTraces {
	validEthUsdcTxContents := common.LoadFileContents(t, "../../testdata/traces/goerli/valid_eth_usdc_tx.json")
	validEthUsdcTx := new(gethtypes.Transaction)
	err := validEthUsdcTx.UnmarshalJSON(validEthUsdcTxContents)
	require.NoError(t, err)

	invalidEthUsdcTxContents := common.LoadFileContents(t, "../../testdata/traces/goerli/invalid_tx.json")
	invalidEthUsdcTx := new(gethtypes.Transaction)
	err = invalidEthUsdcTx.UnmarshalJSON(invalidEthUsdcTxContents)
	require.NoError(t, err)

	validEthUsdcTxTraceContents := common.LoadFileContents(t, "../../testdata/traces/goerli/valid_eth_usdc_tx_trace.json")
	validEthUsdcTxTrace := new(common.CallTrace)
	err = json.Unmarshal(validEthUsdcTxTraceContents, validEthUsdcTxTrace)
	require.NoError(t, err)

	invalidEthUsdcTxTraceContents := common.LoadFileContents(t, "../../testdata/traces/goerli/invalid_tx_trace.json")
	invalidEthUsdcTxTrace := new(common.CallTrace)
	err = json.Unmarshal(invalidEthUsdcTxTraceContents, invalidEthUsdcTxTrace)
	require.NoError(t, err)

	validEthDaiTxContents := common.LoadFileContents(t, "../../testdata/traces/goerli/valid_eth_dai_tx.json")
	validEthDaiTx := new(gethtypes.Transaction)
	err = validEthDaiTx.UnmarshalJSON(validEthDaiTxContents)
	require.NoError(t, err)

	validEthDaiTxTraceContents := common.LoadFileContents(t, "../../testdata/traces/goerli/valid_eth_dai_tx_trace.json")
	validEthDaiTxTrace := new(common.CallTrace)
	err = json.Unmarshal(validEthDaiTxTraceContents, validEthDaiTxTrace)
	require.NoError(t, err)

	validEthWbtcTxContents := common.LoadFileContents(t, "../../testdata/traces/goerli/valid_eth_wbtc_tx.json")
	validEthWbtcTx := new(gethtypes.Transaction)
	err = validEthWbtcTx.UnmarshalJSON(validEthWbtcTxContents)
	require.NoError(t, err)

	validEthWbtcTxTraceContents := common.LoadFileContents(t, "../../testdata/traces/goerli/valid_eth_wbtc_tx_trace.json")
	validEthWbtcTxTrace := new(common.CallTrace)
	err = json.Unmarshal(validEthWbtcTxTraceContents, validEthWbtcTxTrace)
	require.NoError(t, err)

	return GoerliTestTraces{
		ValidEthUsdcTx:      validEthUsdcTx,
		ValidEthUsdcTxTrace: validEthUsdcTxTrace,
		InvalidTx:           invalidEthUsdcTx,
		InvalidTxTrace:      invalidEthUsdcTxTrace,
		ValidEthWbtcTx:      validEthWbtcTx,
		ValidEthWbtcTxTrace: validEthWbtcTxTrace,
		ValidEthDaiTx:       validEthDaiTx,
		ValidEthDaiTxTrace:  validEthDaiTxTrace,
	}
}

func GetTestPayloadAttributes(t *testing.T) (string, types.Address, []byte, string, phase0.BLSPubKey, uint64) {
	t.Helper()
	parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
	feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
	require.NoError(t, err)
	withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
	require.NoError(t, err)
	prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"
	proposerPubkeyByte, err := hexutil.Decode(testProposerKey)
	require.NoError(t, err)
	proposerPubkey := phase0.BLSPubKey(proposerPubkeyByte)

	return parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, uint64(32)
}

func TestStateInterference(t *testing.T) {
	devnetTraces := GetCustomDevnetTracingRelatedTestData(t)
	goerliTraces := GetGoerliTracingRelatedTestData(t)

	cases := []struct {
		description   string
		callTraces    *common.CallTrace
		tx            *gethtypes.Transaction
		isTxCorrect   bool
		network       string
		requiredError string
	}{
		{
			description:   "valid custom devnet tx",
			callTraces:    devnetTraces.ValidWethDaiTxTrace,
			tx:            devnetTraces.ValidWethDaiTx,
			isTxCorrect:   true,
			network:       common.EthNetworkCustom,
			requiredError: "",
		},
		{
			description:   "invalid custom devnet tx",
			callTraces:    devnetTraces.InvalidTxTrace,
			tx:            devnetTraces.InvalidTx,
			isTxCorrect:   false,
			network:       common.EthNetworkCustom,
			requiredError: "",
		},
		{
			description:   "valid goerli tx",
			callTraces:    goerliTraces.ValidEthUsdcTxTrace,
			tx:            goerliTraces.ValidEthUsdcTx,
			isTxCorrect:   true,
			network:       common.EthNetworkGoerli,
			requiredError: "",
		},
		{
			description:   "invalid goerli tx",
			callTraces:    goerliTraces.InvalidTxTrace,
			tx:            goerliTraces.InvalidTx,
			isTxCorrect:   false,
			network:       common.EthNetworkGoerli,
			requiredError: "",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			_, _, backend := startTestBackend(t, c.network)

			// Payload attributes
			parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

			prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, c.network)

			res, err := backend.relay.TobTxChecks(c.callTraces)
			if c.requiredError != "" {
				require.Contains(t, err.Error(), c.requiredError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.isTxCorrect, res)

		})
	}
}

func TestBaseTraceChecks(t *testing.T) {
	_, _, backend := startTestBackend(t, common.EthNetworkGoerli)

	cases := []struct {
		description    string
		callTrace      common.CallTrace
		isTraceCorrect bool
	}{
		{
			description: "Call to smart contract",
			callTrace: common.CallTrace{
				To: nil,
			},
			isTraceCorrect: false,
		},
		{
			description: "Call type is STATICCALL",
			callTrace: common.CallTrace{
				Type: "STATICCALL",
			},
			isTraceCorrect: false,
		},
		{
			description: "Call input is less then 4 bytes",
			callTrace: common.CallTrace{
				Input: []byte{0x01, 0x02, 0x03},
			},
			isTraceCorrect: false,
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			res, err := backend.relay.BaseTraceChecks(c.callTrace)
			require.NoError(t, err)
			require.Equal(t, c.isTraceCorrect, res)

		})
	}
}

// this is only for custom network
func TestIsTraceEthUsdcSwap(t *testing.T) {
	_, _, backend := startTestBackend(t, common.EthNetworkGoerli)

	// Payload attributes
	parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

	prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, common.EthNetworkGoerli)

	ethUsdcTraceContents := common.LoadFileContents(t, "../../testdata/traces/goerli/eth_usdc_trace.json")
	ethUsdcTrace := new(common.CallTrace)
	err := json.Unmarshal(ethUsdcTraceContents, ethUsdcTrace)
	require.NoError(t, err)

	pairToDifferentAddress := new(common.CallTrace)
	err = json.Unmarshal(ethUsdcTraceContents, pairToDifferentAddress)
	// some random address
	pairToDifferentAddress.To = &randomAddr

	ethUsdcTraceDifferentMethod := new(common.CallTrace)
	err = json.Unmarshal(ethUsdcTraceContents, ethUsdcTraceDifferentMethod)
	ethUsdcTraceDifferentMethod.Input = append([]byte("0x1234"), ethUsdcTrace.Input[4:]...)

	ethBtcTraceContents := common.LoadFileContents(t, "../../testdata/traces/goerli/eth_wbtc_trace.json")
	ethBtcTrace := new(common.CallTrace)
	err = json.Unmarshal(ethBtcTraceContents, ethBtcTrace)
	require.NoError(t, err)

	ethDaiTraceContents := common.LoadFileContents(t, "../../testdata/traces/goerli/eth_dai_trace.json")
	ethDaiTrace := new(common.CallTrace)
	err = json.Unmarshal(ethDaiTraceContents, ethDaiTrace)
	require.NoError(t, err)

	cases := []struct {
		description    string
		callTrace      common.CallTrace
		isTraceCorrect bool
		requiredError  string
	}{
		{
			description:    "valid eth usdc trace",
			callTrace:      *ethUsdcTrace,
			isTraceCorrect: true,
			requiredError:  "",
		},
		{
			description:    "valid eth wbtc trace",
			callTrace:      *ethBtcTrace,
			isTraceCorrect: true,
			requiredError:  "",
		},
		{
			description:    "valid eth dai trace",
			callTrace:      *ethDaiTrace,
			isTraceCorrect: true,
			requiredError:  "",
		},
		{
			description:    "valid eth dai trace",
			callTrace:      *ethUsdcTrace,
			isTraceCorrect: true,
			requiredError:  "",
		},
		{
			description:    "trace to different uniswap pair",
			callTrace:      *pairToDifferentAddress,
			isTraceCorrect: false,
			requiredError:  "",
		},
		{
			description:    "trace to correct uniswap pair but with different method",
			callTrace:      *ethUsdcTraceDifferentMethod,
			isTraceCorrect: false,
			requiredError:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			res, err := backend.relay.IsTraceUniV3EthUsdcSwap(c.callTrace)
			if c.requiredError != "" {
				require.Contains(t, err.Error(), c.requiredError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.isTraceCorrect, res)

		})
	}

}

// this is only for custom network
func TestIsTraceToWEthDaiPair(t *testing.T) {
	_, _, backend := startTestBackend(t, common.EthNetworkCustom)

	// Payload attributes
	parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

	prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, common.EthNetworkCustom)

	wethDaiTraceContents := common.LoadFileContents(t, "../../testdata/traces/custom/weth_dai_trace.json")
	wethDaiTrace := new(common.CallTrace)
	err := json.Unmarshal(wethDaiTraceContents, wethDaiTrace)
	require.NoError(t, err)

	pairToDifferentAddress := new(common.CallTrace)
	err = json.Unmarshal(wethDaiTraceContents, pairToDifferentAddress)
	// some random address
	pairToDifferentAddress.To = &randomAddr

	wethDaiTraceDifferentMethod := new(common.CallTrace)
	err = json.Unmarshal(wethDaiTraceContents, wethDaiTraceDifferentMethod)
	wethDaiTraceDifferentMethod.Input = append([]byte("0x1234"), wethDaiTrace.Input[4:]...)

	cases := []struct {
		description    string
		callTrace      common.CallTrace
		isTraceCorrect bool
		requiredError  string
	}{
		{
			description:    "valid trace",
			callTrace:      *wethDaiTrace,
			isTraceCorrect: true,
			requiredError:  "",
		},
		{
			description:    "trace to different uniswap pair",
			callTrace:      *pairToDifferentAddress,
			isTraceCorrect: false,
			requiredError:  "",
		},
		{
			description:    "trace to correct uniswap pair but with different method",
			callTrace:      *wethDaiTraceDifferentMethod,
			isTraceCorrect: false,
			requiredError:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			res, err := backend.relay.IsTraceToWEthDaiPair(c.callTrace)
			if c.requiredError != "" {
				require.Contains(t, err.Error(), c.requiredError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.isTraceCorrect, res)

		})
	}

}

func TestNetworkIndependentTobTxChecks(t *testing.T) {
	_, _, backend := startTestBackend(t, common.EthNetworkCustom)
	randomAddress := common2.BytesToAddress([]byte("0xabc"))

	// Payload attributes
	parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

	prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, common.EthNetworkCustom)

	headSlotProposerFeeRecipient := common2.HexToAddress(backend.relay.proposerDutiesMap[headSlot+1].Entry.Message.FeeRecipient.String())

	cases := []struct {
		description        string
		txs                []*gethtypes.Transaction
		callTraces         map[common2.Hash]*common.CallTrace
		tobSimulationError string
		requiredError      string
	}{
		{
			description:        "no txs sent",
			txs:                []*gethtypes.Transaction{},
			callTraces:         nil,
			tobSimulationError: "",
			requiredError:      "Empty TOB tx request sent!",
		},
		{
			description: "only 1 tx sent",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &randomAddress,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			callTraces:         nil,
			tobSimulationError: "",
			requiredError:      "We require a payment tx along with the TOB txs!",
		},
		{
			description: "More than 4 txs sent excluding payout tx",
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
					To:       nil,
					Value:    big.NewInt(2),
					Data:     []byte("tx2"),
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
					To:       &randomAddress,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			callTraces:    nil,
			requiredError: "we support only 3 txs on the TOB currently, got 5",
		},
		{
			description: "zero value payout",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &randomAddr,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(0),
					Data:     []byte(""),
				}),
			},
			callTraces:         nil,
			tobSimulationError: "payout tx value is zero",
			requiredError:      "payout tx value is zero",
		},
		{
			description: "malformed payout",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &randomAddr,
					Value:    big.NewInt(2),
					Data:     []byte("tx1"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte("tx2"),
				}),
			},
			callTraces:         nil,
			tobSimulationError: "payout tx data is malformed",
			requiredError:      "payout tx data is malformed",
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
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			callTraces:         nil,
			tobSimulationError: "contract creation txs are not allowed",
			requiredError:      "contract creation txs are not allowed",
		},
		{
			description: "payout not addressed to proposer",
			txs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &randomAddr,
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
			callTraces:         nil,
			tobSimulationError: "payout tx recipient does not match proposer fee recipient",
			requiredError:      "payout tx recipient does not match proposer fee recipient",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			backend.relay.tracer = &MockTracer{
				tracerError:  "",
				callTraceMap: c.callTraces,
			}
			if c.tobSimulationError != "" {
				backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
					tobSimulationError: fmt.Errorf(c.tobSimulationError),
				}
			}

			tobTxReqs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
			for _, tx := range c.txs {
				txByte, err := tx.MarshalBinary()
				require.NoError(t, err)
				tobTxReqs.Transactions = append(tobTxReqs.Transactions, txByte)
			}
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

			if c.requiredError != "" {
				require.Equal(t, http.StatusBadRequest, rr.Code)
				require.Contains(t, rr.Body.String(), c.requiredError)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestNetworkDependentCheckTxAndSenderValidity(t *testing.T) {
	_, _, backend := startTestBackend(t, common.EthNetworkCustom)

	devnetTraceData := GetCustomDevnetTracingRelatedTestData(t)
	goerliTraceData := GetGoerliTracingRelatedTestData(t)

	// Payload attributes
	parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

	prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, common.EthNetworkCustom)

	headSlotProposerFeeRecipient := common2.HexToAddress(backend.relay.proposerDutiesMap[headSlot+1].Entry.Message.FeeRecipient.String())

	cases := []struct {
		description   string
		txs           []*gethtypes.Transaction
		callTraces    map[common2.Hash]*common.CallTrace
		network       string
		requiredError string
	}{
		{
			description: "Invalid custom devnet ToB tx",
			txs: []*gethtypes.Transaction{
				devnetTraceData.InvalidTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			callTraces:    map[common2.Hash]*common.CallTrace{devnetTraceData.InvalidTx.Hash(): devnetTraceData.InvalidTxTrace},
			network:       common.EthNetworkCustom,
			requiredError: "not a valid tob tx",
		},
		{
			description: "Valid custom devnet ToB txs",
			txs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			callTraces:    map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			network:       common.EthNetworkCustom,
			requiredError: "",
		},
		{
			description: "Invalid goerli ToB tx",
			txs: []*gethtypes.Transaction{
				goerliTraceData.InvalidTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			callTraces:    map[common2.Hash]*common.CallTrace{goerliTraceData.InvalidTx.Hash(): goerliTraceData.InvalidTxTrace},
			network:       common.EthNetworkGoerli,
			requiredError: "not a valid tob tx",
		},
		{
			description: "1 valid goerli ToB tx",
			txs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			callTraces:    map[common2.Hash]*common.CallTrace{goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace},
			network:       common.EthNetworkGoerli,
			requiredError: "",
		},
		{
			description: "2 valid goerli ToB tx",
			txs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthWbtcTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			callTraces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthWbtcTx.Hash(): goerliTraceData.ValidEthWbtcTxTrace,
			},
			network:       common.EthNetworkGoerli,
			requiredError: "",
		},
		{
			description: "3 valid goerli ToB tx",
			txs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthWbtcTx,
				goerliTraceData.ValidEthDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			callTraces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthWbtcTx.Hash(): goerliTraceData.ValidEthWbtcTxTrace,
				goerliTraceData.ValidEthDaiTx.Hash():  goerliTraceData.ValidEthDaiTxTrace,
			},
			network:       common.EthNetworkGoerli,
			requiredError: "",
		},
		{
			description: "2 valid goerli ToB tx and 1 invalid tx",
			txs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthWbtcTx,
				goerliTraceData.InvalidTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			callTraces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthWbtcTx.Hash(): goerliTraceData.ValidEthWbtcTxTrace,
				goerliTraceData.InvalidTx.Hash():      goerliTraceData.InvalidTxTrace,
			},
			network:       common.EthNetworkGoerli,
			requiredError: "not a valid tob tx",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			_, _, backend := startTestBackend(t, c.network)

			backend.relay.tracer = &MockTracer{
				tracerError:  "",
				callTraceMap: c.callTraces,
			}

			parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

			prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, c.network)

			err := backend.relay.checkTobTxsStateInterference(c.txs, common.TestLog)
			if c.requiredError != "" {
				require.Contains(t, err.Error(), c.requiredError)
				return
			}
			require.NoError(t, err)

		})
	}
}

// tests when tob txs are sent in sequence
func TestSubmitTobTxsInSequence(t *testing.T) {
	backend := newTestBackend(t, 1, common.EthNetworkGoerli)

	devnetTraceData := GetCustomDevnetTracingRelatedTestData(t)
	goerliTraceData := GetGoerliTracingRelatedTestData(t)

	// Payload attributes
	parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

	prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, common.EthNetworkCustom)

	headSlotProposerFeeRecipient := common2.HexToAddress(backend.relay.proposerDutiesMap[headSlot+1].Entry.Message.FeeRecipient.String())

	cases := []struct {
		description        string
		firstTobTxs        []*gethtypes.Transaction
		firstTobTxsTraces  map[common2.Hash]*common.CallTrace
		secondTobTxs       []*gethtypes.Transaction
		secondTobTxsTraces map[common2.Hash]*common.CallTrace
		network            string
		nextSentIsHigher   bool
	}{
		{
			description: "second set of tob txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			firstTobTxsTraces:  map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			secondTobTxsTraces: map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			network:            common.EthNetworkCustom,
			nextSentIsHigher:   true,
		},
		{
			description: "first set of txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(1),
					Data:     []byte(""),
				}),
			},
			firstTobTxsTraces:  map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			secondTobTxsTraces: map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			network:            common.EthNetworkCustom,
			nextSentIsHigher:   false,
		},
		{
			description: "goerli first set of txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthWbtcTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(1),
					Data:     []byte(""),
				}),
			},
			firstTobTxsTraces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthWbtcTx.Hash(): goerliTraceData.ValidEthWbtcTxTrace,
			},
			secondTobTxsTraces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthDaiTx.Hash():  goerliTraceData.ValidEthDaiTxTrace,
			},
			network:          common.EthNetworkGoerli,
			nextSentIsHigher: false,
		},
		{
			description: "goerli second set of tob txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthWbtcTx,
				goerliTraceData.ValidEthDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			firstTobTxsTraces: map[common2.Hash]*common.CallTrace{goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace},
			secondTobTxsTraces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthWbtcTx.Hash(): goerliTraceData.ValidEthWbtcTxTrace,
				goerliTraceData.ValidEthDaiTx.Hash():  goerliTraceData.ValidEthDaiTxTrace,
			},
			network:          common.EthNetworkGoerli,
			nextSentIsHigher: true,
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			backend := newTestBackend(t, 1, c.network)

			parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

			prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, c.network)

			backend.relay.tracer = &MockTracer{
				tracerError:  "",
				callTraceMap: c.firstTobTxsTraces,
			}
			backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{tobSimulationError: nil}

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
			assertTobTxs(t, backend, headSlot+1, parentHash, c.firstTobTxs[len(c.firstTobTxs)-1].Value(), firstSetTxHashRoot, len(c.firstTobTxs))

			// submit second set of txs
			backend.relay.tracer = &MockTracer{
				tracerError:  "",
				callTraceMap: c.secondTobTxsTraces,
			}
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
				assertTobTxs(t, backend, headSlot+1, parentHash, c.secondTobTxs[len(c.secondTobTxs)-1].Value(), secondSetTxHashRoot, len(c.secondTobTxs))
			}
		})
	}
}

func TestSubmitTobTxs(t *testing.T) {
	backend := newTestBackend(t, 1, common.EthNetworkCustom)

	devnetTraceData := GetCustomDevnetTracingRelatedTestData(t)
	goerliTraceData := GetGoerliTracingRelatedTestData(t)

	// Payload attributes
	parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

	prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, common.EthNetworkCustom)

	headSlotProposerFeeRecipient := common2.HexToAddress(backend.relay.proposerDutiesMap[headSlot+1].Entry.Message.FeeRecipient.String())

	cases := []struct {
		description   string
		tobTxs        []*gethtypes.Transaction
		traces        map[common2.Hash]*common.CallTrace
		requiredError string
		network       string
		slotDelta     uint64
	}{
		{
			description: "custom devnet ToB state interference",
			tobTxs: []*gethtypes.Transaction{
				devnetTraceData.InvalidTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(5),
					Data:     []byte(""),
				}),
			},
			traces:        map[common2.Hash]*common.CallTrace{devnetTraceData.InvalidTx.Hash(): devnetTraceData.InvalidTxTrace},
			requiredError: "not a valid tob tx",
			network:       common.EthNetworkCustom,
			slotDelta:     1,
		},
		{
			description: "goerli ToB state interference",
			tobTxs: []*gethtypes.Transaction{
				goerliTraceData.InvalidTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(5),
					Data:     []byte(""),
				}),
			},
			traces:        map[common2.Hash]*common.CallTrace{goerliTraceData.InvalidTx.Hash(): goerliTraceData.InvalidTxTrace},
			requiredError: "not a valid tob tx",
			network:       common.EthNetworkGoerli,
			slotDelta:     1,
		},
		{
			description: "req submitted too early",
			tobTxs: []*gethtypes.Transaction{
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    3,
					GasPrice: big.NewInt(3),
					Gas:      3,
					To:       &randomAddr,
					Value:    big.NewInt(3),
					Data:     []byte("tx6"),
				}),
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(5),
					Data:     []byte(""),
				}),
			},
			traces:        nil,
			requiredError: "Slot's TOB bid not yet started!!",
			network:       common.EthNetworkCustom,
			slotDelta:     2,
		},
		{
			description: "custom devnet Valid TobTxs sent",
			tobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			traces:        map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			network:       common.EthNetworkCustom,
			requiredError: "",
			slotDelta:     1,
		},
		{
			description: "goerli 1 Valid TobTxs sent",
			tobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			traces:        map[common2.Hash]*common.CallTrace{goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace},
			network:       common.EthNetworkGoerli,
			requiredError: "",
			slotDelta:     1,
		},
		{
			description: "goerli 2 Valid TobTxs sent",
			tobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthWbtcTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			traces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthWbtcTx.Hash(): goerliTraceData.ValidEthWbtcTxTrace,
			},
			network:       common.EthNetworkGoerli,
			requiredError: "",
			slotDelta:     1,
		},
		{
			description: "goerli 3 Valid TobTxs sent",
			tobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthWbtcTx,
				goerliTraceData.ValidEthDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			traces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthWbtcTx.Hash(): goerliTraceData.ValidEthWbtcTxTrace,
				goerliTraceData.ValidEthDaiTx.Hash():  goerliTraceData.ValidEthDaiTxTrace,
			},
			network:       common.EthNetworkGoerli,
			requiredError: "",
			slotDelta:     1,
		},
		{
			description: "devnet Valid TobTxs sent with 3 tob txs",
			tobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				devnetTraceData.ValidWethDaiTx,
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			traces: map[common2.Hash]*common.CallTrace{
				devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace,
			},
			network:       common.EthNetworkCustom,
			requiredError: "",
			slotDelta:     1,
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			backend = newTestBackend(t, 1, c.network)

			parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot = GetTestPayloadAttributes(t)

			prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, c.network)
			if c.traces == nil {
				backend.relay.tracer = &MockTracer{tracerError: "no traces available", callTraceMap: nil}
			} else {
				backend.relay.tracer = &MockTracer{tracerError: "", callTraceMap: c.traces}
			}

			backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{tobSimulationError: nil}

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

			if c.requiredError != "" {
				require.Contains(t, rr.Body.String(), c.requiredError)
				return
			}
			assertTobTxs(t, backend, headSlot+1, parentHash, c.tobTxs[len(c.tobTxs)-1].Value(), txHashRoot, len(c.tobTxs))

		})
	}
}

func assertBlock(t *testing.T, backend *testBackend, headSlot uint64, parentHash string, blockSubmitReq *common.BuilderSubmitBlockRequest, totalExpectedBidValue *big.Int, tobTxs []*gethtypes.Transaction) {
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
	require.Equal(t, blockSubmitReq.NumTx()+len(tobTxs), payload.NumTx())
	payloadTxs := payload.Capella.Capella.Transactions
	payloadTobTxs := payloadTxs[:len(tobTxs)]
	payloadRobTxs := payloadTxs[len(tobTxs):]
	for i, tobtx := range payloadTobTxs {
		expectedTobTx := tobTxs[i]
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
	require.Equal(t, int(bid.NumTx), blockSubmitReq.NumTx()+len(tobTxs))
	floorBid, err := backend.redis.GetFloorBidValue(context.Background(), txPipeliner, headSlot+1, parentHash, blockSubmitReq.ProposerPubkey())
	require.NoError(t, err)
	require.Equal(t, floorBid, totalExpectedBidValue)
	blockSubmissionEntry, err := backend.relay.db.GetBlockSubmissionEntry(headSlot+1, blockSubmitReq.ProposerPubkey(), blockSubmitReq.BlockHash())
	require.NoError(t, err)
	blockSubmissionValue, ok := new(big.Int).SetString(blockSubmissionEntry.Value, 10)
	require.True(t, ok)
	require.Equal(t, totalExpectedBidValue, blockSubmissionValue)
	dbPayload, err := backend.datastore.GetGetPayloadResponse(common.TestLog, headSlot+1, blockSubmitReq.ProposerPubkey(), blockSubmitReq.BlockHash())
	require.NoError(t, err)
	require.Equal(t, blockSubmitReq.NumTx()+len(tobTxs), dbPayload.NumTx())
	payloadTxs = dbPayload.Capella.Capella.Transactions
	payloadTobTxs = payloadTxs[:len(tobTxs)]
	payloadRobTxs = payloadTxs[len(tobTxs):]
	for i, tobtx := range payloadTobTxs {
		expectedTobTx := tobTxs[i]
		expectedTobTxBinary, err := expectedTobTx.MarshalBinary()

		require.NoError(t, err)
		require.Equal(t, bellatrix.Transaction(expectedTobTxBinary), tobtx)
	}
	for i, robtx := range payloadRobTxs {
		expectedRobTx := blockSubmitReq.Capella.ExecutionPayload.Transactions[i]
		require.Equal(t, expectedRobTx, robtx)
	}
	if len(tobTxs) > 0 {
		includedTobTxs, err := backend.relay.db.GetIncludedTobTxsForGivenSlotAndParentHashAndBlockHash(headSlot+1, blockSubmitReq.ParentHash(), blockSubmitReq.BlockHash())
		require.NoError(t, err)
		require.Equal(t, len(tobTxs), len(includedTobTxs))
	}
}

func TestSubmitBuilderBlockInSequence(t *testing.T) {
	backend := newTestBackend(t, 1, common.EthNetworkCustom)

	devnetTraceData := GetCustomDevnetTracingRelatedTestData(t)
	goerliTraceData := GetGoerliTracingRelatedTestData(t)

	// Payload attributes
	parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

	prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, common.EthNetworkCustom)

	headSlotProposerFeeRecipient := common2.HexToAddress(backend.relay.proposerDutiesMap[headSlot+1].Entry.Message.FeeRecipient.String())

	cases := []struct {
		description        string
		firstTobTxs        []*gethtypes.Transaction
		firstTobTxsTraces  map[common2.Hash]*common.CallTrace
		secondTobTxs       []*gethtypes.Transaction
		secondTobTxsTraces map[common2.Hash]*common.CallTrace
		network            string
		nextSentIsHigher   bool
	}{
		{
			description: "second set of tob txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			firstTobTxsTraces:  map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			secondTobTxsTraces: map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			network:            common.EthNetworkCustom,
			nextSentIsHigher:   true,
		},
		{
			description: "first set of txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(1),
					Data:     []byte(""),
				}),
			},
			firstTobTxsTraces:  map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			secondTobTxsTraces: map[common2.Hash]*common.CallTrace{devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace},
			network:            common.EthNetworkCustom,
			nextSentIsHigher:   false,
		},
		{
			description: "goerli first set of txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthWbtcTx,
				goerliTraceData.ValidEthDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(1),
					Data:     []byte(""),
				}),
			},
			firstTobTxsTraces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthWbtcTx.Hash(): goerliTraceData.ValidEthWbtcTxTrace,
				goerliTraceData.ValidEthDaiTx.Hash():  goerliTraceData.ValidEthDaiTxTrace,
			},
			secondTobTxsTraces: map[common2.Hash]*common.CallTrace{goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace},
			network:            common.EthNetworkGoerli,
			nextSentIsHigher:   false,
		},
		{
			description: "goerli second set of tob txs is higher",
			firstTobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(2),
					Data:     []byte(""),
				}),
			},
			secondTobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    4,
					GasPrice: big.NewInt(5),
					Gas:      12,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(10),
					Data:     []byte(""),
				}),
			},
			firstTobTxsTraces: map[common2.Hash]*common.CallTrace{goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace},
			secondTobTxsTraces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthDaiTx.Hash():  goerliTraceData.ValidEthDaiTxTrace,
			},
			network:          common.EthNetworkGoerli,
			nextSentIsHigher: true,
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			backend = newTestBackend(t, 1, c.network)

			parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot = GetTestPayloadAttributes(t)

			submissionSlot := headSlot + 1
			submissionTimestamp := 1606824419

			prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, c.network)

			backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{tobSimulationError: nil}

			backend.relay.tracer = &MockTracer{
				tracerError:  "",
				callTraceMap: c.firstTobTxsTraces,
			}

			// submit the first ToB txs
			txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
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

			payoutTxs := c.firstTobTxs[len(c.firstTobTxs)-1]
			tobTxsValue := payoutTxs.Value()

			assertTobTxs(t, backend, headSlot+1, parentHash, tobTxsValue, txsHashRoot, len(c.firstTobTxs))

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

			assertBlock(t, backend, headSlot, parentHash, blockSubmitReq, totalExpectedBidValue, c.firstTobTxs)

			// submit the second set of ToB txs
			backend.relay.tracer = &MockTracer{
				tracerError:  "",
				callTraceMap: c.secondTobTxsTraces,
			}
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

			payoutTxs = c.secondTobTxs[len(c.secondTobTxs)-1]
			tobTxsValue = payoutTxs.Value()

			assertTobTxs(t, backend, headSlot+1, parentHash, c.secondTobTxs[len(c.secondTobTxs)-1].Value(), txsHashRoot, len(c.secondTobTxs))

			blockSubmitReq = prepareBlockSubmitRequest(t, payloadJSONFilename2, submissionSlot, uint64(submissionTimestamp), backend)

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

			assertBlock(t, backend, headSlot, parentHash, blockSubmitReq, totalExpectedBidValue, c.secondTobTxs)
		})
	}

}

func TestSubmitBuilderBlock(t *testing.T) {
	backend := newTestBackend(t, 1, common.EthNetworkCustom)

	devnetTraceData := GetCustomDevnetTracingRelatedTestData(t)
	goerliTraceData := GetGoerliTracingRelatedTestData(t)

	// Payload attributes
	parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

	prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, common.EthNetworkCustom)

	backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{tobSimulationError: nil}

	headSlotProposerFeeRecipient := common2.HexToAddress(backend.relay.proposerDutiesMap[headSlot+1].Entry.Message.FeeRecipient.String())

	cases := []struct {
		description   string
		tobTxs        []*gethtypes.Transaction
		traces        map[common2.Hash]*common.CallTrace
		network       string
		requiredError string
	}{
		{
			description:   "No ToB txs",
			tobTxs:        []*gethtypes.Transaction{},
			traces:        nil,
			network:       common.EthNetworkCustom,
			requiredError: "",
		},
		{
			description: "custom devnet ToB txs of some value are present",
			tobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			network: common.EthNetworkCustom,
			traces: map[common2.Hash]*common.CallTrace{
				devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace,
			},
			requiredError: "",
		},
		{
			description: "goerli ToB txs of some value are present",
			tobTxs: []*gethtypes.Transaction{
				goerliTraceData.ValidEthUsdcTx,
				goerliTraceData.ValidEthWbtcTx,
				goerliTraceData.ValidEthDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			network: common.EthNetworkGoerli,
			traces: map[common2.Hash]*common.CallTrace{
				goerliTraceData.ValidEthUsdcTx.Hash(): goerliTraceData.ValidEthUsdcTxTrace,
				goerliTraceData.ValidEthWbtcTx.Hash(): goerliTraceData.ValidEthWbtcTxTrace,
				goerliTraceData.ValidEthDaiTx.Hash():  goerliTraceData.ValidEthDaiTxTrace,
			},
			requiredError: "",
		},
		{
			description: "custom devnet 3 ToB txs are present",
			tobTxs: []*gethtypes.Transaction{
				devnetTraceData.ValidWethDaiTx,
				devnetTraceData.ValidWethDaiTx,
				devnetTraceData.ValidWethDaiTx,
				gethtypes.NewTx(&gethtypes.LegacyTx{
					Nonce:    2,
					GasPrice: big.NewInt(2),
					Gas:      2,
					To:       &headSlotProposerFeeRecipient,
					Value:    big.NewInt(110),
					Data:     []byte(""),
				}),
			},
			network: common.EthNetworkCustom,
			traces: map[common2.Hash]*common.CallTrace{
				devnetTraceData.ValidWethDaiTx.Hash(): devnetTraceData.ValidWethDaiTxTrace,
			},
			requiredError: "",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			backend = newTestBackend(t, 1, c.network)

			parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, headSlot := GetTestPayloadAttributes(t)

			submissionSlot := headSlot + 1
			submissionTimestamp := 1606824419

			prepareBackend(t, backend, headSlot, parentHash, feeRec, withdrawalsRoot, prevRandao, proposerPubkey, c.network)

			backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{tobSimulationError: nil}

			if c.traces != nil {
				backend.relay.tracer = &MockTracer{
					tracerError:  "",
					callTraceMap: c.traces,
				}
			} else {
				backend.relay.tracer = &MockTracer{
					tracerError:  "no traces available",
					callTraceMap: nil,
				}
			}

			// create the ToB txs
			tobTxsValue := big.NewInt(0)
			if len(c.tobTxs) > 0 {
				req := new(common.TobTxsSubmitRequest)
				txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{}}
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

				payoutTxs := c.tobTxs[len(c.tobTxs)-1]
				tobTxsValue = payoutTxs.Value()
				assertTobTxs(t, backend, headSlot+1, parentHash, tobTxsValue, txsHashRoot, len(c.tobTxs))
			} else {
				backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
					simulationError: nil,
				}
			}

			// Prepare the request payload
			req := prepareBlockSubmitRequest(t, payloadJSONFilename, submissionSlot, uint64(submissionTimestamp), backend)

			totalExpectedBidValue := big.NewInt(0).Add(req.Message().Value.ToBig(), tobTxsValue)

			// Send JSON encoded request
			reqJSONBytes, err := req.Capella.MarshalJSON()
			require.NoError(t, err)
			rr := backend.requestBytes(http.MethodPost, blockSubmitPath, reqJSONBytes, nil)
			if c.requiredError != "" {
				require.Contains(t, rr.Body.String(), c.requiredError)
				return
			}
			require.Equal(t, http.StatusOK, rr.Code)

			// get the block stored in the db
			assertBlock(t, backend, headSlot, parentHash, req, totalExpectedBidValue, c.tobTxs)
		})
	}
}
