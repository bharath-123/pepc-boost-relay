package common

import (
	"encoding/json"
	"math/big"
	"testing"

	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	bellatrixUtil "github.com/attestantio/go-eth2-client/util/bellatrix"
	common2 "github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

func TestBoostBidToBidTrace(t *testing.T) {
	bidTrace := boostTypes.BidTrace{
		Slot:                 uint64(25),
		ParentHash:           boostTypes.Hash{0x02, 0x03},
		BuilderPubkey:        boostTypes.PublicKey{0x04, 0x05},
		ProposerPubkey:       boostTypes.PublicKey{0x06, 0x07},
		ProposerFeeRecipient: boostTypes.Address{0x08, 0x09},
		GasLimit:             uint64(50),
		GasUsed:              uint64(100),
		Value:                boostTypes.U256Str{0x0a},
	}
	convertedBidTrace := BoostBidToBidTrace(&bidTrace)
	require.Equal(t, bidTrace.Slot, convertedBidTrace.Slot)
	require.Equal(t, phase0.Hash32(bidTrace.ParentHash), convertedBidTrace.ParentHash)
	require.Equal(t, phase0.BLSPubKey(bidTrace.BuilderPubkey), convertedBidTrace.BuilderPubkey)
	require.Equal(t, phase0.BLSPubKey(bidTrace.ProposerPubkey), convertedBidTrace.ProposerPubkey)
	require.Equal(t, bellatrix.ExecutionAddress(bidTrace.ProposerFeeRecipient), convertedBidTrace.ProposerFeeRecipient)
	require.Equal(t, bidTrace.GasLimit, convertedBidTrace.GasLimit)
	require.Equal(t, bidTrace.GasUsed, convertedBidTrace.GasUsed)
	require.Equal(t, bidTrace.Value.BigInt().String(), convertedBidTrace.Value.ToBig().String())
}

func TestDataVersion(t *testing.T) {
	require.Equal(t, ForkVersionStringBellatrix, consensusspec.DataVersionBellatrix.String())
	require.Equal(t, ForkVersionStringCapella, consensusspec.DataVersionCapella.String())
	require.Equal(t, ForkVersionStringDeneb, consensusspec.DataVersionDeneb.String())
}

func TestEncodeDecodeTxs(t *testing.T) {
	testAddr := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	tx1 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(1),
		Gas:      1,
		To:       &testAddr,
		Value:    big.NewInt(1),
		Data:     []byte("tx1"),
	})
	tx2 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(2),
		Gas:      2,
		To:       &testAddr,
		Value:    big.NewInt(2),
		Data:     []byte("tx2"),
	})

	txs := encodeTransactions([]*gethtypes.Transaction{tx1, tx2})

	decodedTxs, err := DecodeTransactions(txs)
	require.NoError(t, err)
	require.Equal(t, 2, len(decodedTxs))
	decodedTx1 := decodedTxs[0]
	decodedTx2 := decodedTxs[1]
	require.Equal(t, tx1.Nonce(), decodedTx1.Nonce())
	require.Equal(t, tx2.Nonce(), decodedTx2.Nonce())
	require.Equal(t, tx1.To(), decodedTx1.To())
	require.Equal(t, tx2.To(), decodedTx2.To())
	require.Equal(t, tx1.Value(), decodedTx1.Value())
	require.Equal(t, tx2.Value(), decodedTx2.Value())
	require.Equal(t, tx1.Data(), decodedTx1.Data())
	require.Equal(t, tx2.Data(), decodedTx2.Data())
	require.Equal(t, tx1.Gas(), decodedTx1.Gas())
	require.Equal(t, tx2.Gas(), decodedTx2.Gas())
	require.Equal(t, tx1.GasPrice(), decodedTx1.GasPrice())
	require.Equal(t, tx2.GasPrice(), decodedTx2.GasPrice())
	require.Equal(t, tx1.Hash(), decodedTx1.Hash())
	require.Equal(t, tx2.Hash(), decodedTx2.Hash())
}

func TestTobTxSubmitRequestJsonEncodingAndDecoding(t *testing.T) {
	testAddr := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")

	tx1 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(1),
		Gas:      1,
		To:       &testAddr,
		Value:    big.NewInt(1),
		Data:     []byte("tx1"),
	})
	tx2 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(2),
		Gas:      2,
		To:       &testAddr,
		Value:    big.NewInt(2),
		Data:     []byte("tx2"),
	})
	tx1byte, err := tx1.MarshalBinary()
	require.NoError(t, err)
	tx2byte, err := tx2.MarshalBinary()
	require.NoError(t, err)
	txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx1byte, tx2byte}}
	txRoot, err := txs.HashTreeRoot()
	require.NoError(t, err)

	tobTxRequest := TobTxsSubmitRequest{
		TobTxs:     txs,
		Slot:       10,
		TobSlotId:  0,
		ParentHash: "0x0000000",
	}

	jsonEncodedRequest, err := tobTxRequest.MarshalJSON()
	require.NoError(t, err)

	decodedTobTxRequest := new(TobTxsSubmitRequest)
	err = decodedTobTxRequest.UnmarshalJSON(jsonEncodedRequest)
	require.NoError(t, err)

	require.Equal(t, tobTxRequest.Slot, decodedTobTxRequest.Slot)
	require.Equal(t, tobTxRequest.ParentHash, decodedTobTxRequest.ParentHash)
	require.Equal(t, tobTxRequest.TobSlotId, decodedTobTxRequest.TobSlotId)
	decodedTxRoot, err := decodedTobTxRequest.TobTxs.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, txRoot, decodedTxRoot)
}

func TestBlockAssemblerRequestJsonEncodingAndDecoding(t *testing.T) {
	testAddr := common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e")
	requestPayloadJSONBytes := LoadGzippedBytes(t, "../testdata/submitBlockPayloadCapella_Goerli2.json.gz")

	blockSubmitRequest := new(BuilderSubmitBlockRequest)
	err := json.Unmarshal(requestPayloadJSONBytes, &blockSubmitRequest)
	require.NoError(t, err)

	tx1 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(1),
		Gas:      1,
		To:       &testAddr,
		Value:    big.NewInt(1),
		Data:     []byte("tx1"),
	})
	tx2 := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(2),
		Gas:      2,
		To:       &testAddr,
		Value:    big.NewInt(2),
		Data:     []byte("tx2"),
	})
	tx1byte, err := tx1.MarshalBinary()
	require.NoError(t, err)
	tx2byte, err := tx2.MarshalBinary()
	require.NoError(t, err)
	txs := bellatrixUtil.ExecutionPayloadTransactions{Transactions: []bellatrix.Transaction{tx1byte, tx2byte}}
	txRoot, err := txs.HashTreeRoot()
	require.NoError(t, err)

	gasLimit := uint64(10000)

	assemblyRequest := BlockAssemblerRequest{
		TobTxs:             txs,
		RobPayload:         *blockSubmitRequest,
		RegisteredGasLimit: gasLimit,
	}

	encodedAssemblyRequest, err := assemblyRequest.MarshalJSON()
	require.NoError(t, err)
	decodedAssemblyRequest := new(BlockAssemblerRequest)
	err = decodedAssemblyRequest.UnmarshalJSON(encodedAssemblyRequest)
	require.NoError(t, err)

	decodedTxsRoot, err := decodedAssemblyRequest.TobTxs.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, txRoot, decodedTxsRoot)
	require.Equal(t, assemblyRequest.RegisteredGasLimit, decodedAssemblyRequest.RegisteredGasLimit)
	require.Equal(t, assemblyRequest.RobPayload, decodedAssemblyRequest.RobPayload)
}
