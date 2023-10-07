package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-builder-client/spec"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilbellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	boostTypes "github.com/flashbots/go-boost-utils/types"
)

var (
	ErrUnknownNetwork = errors.New("unknown network")
	ErrEmptyPayload   = errors.New("empty payload")

	EthNetworkSepolia = "sepolia"
	EthNetworkGoerli  = "goerli"
	EthNetworkMainnet = "mainnet"
	EthNetworkCustom  = "custom"

	CapellaForkVersionSepolia = "0x90000072"
	CapellaForkVersionGoerli  = "0x03001020"
	CapellaForkVersionMainnet = "0x03000000"

	DenebForkVersionSepolia = "0x90000073"
	DenebForkVersionGoerli  = "0x04001020"
	DenebForkVersionMainnet = "0x04000000"

	ForkVersionStringBellatrix = "bellatrix"
	ForkVersionStringCapella   = "capella"
	ForkVersionStringDeneb     = "deneb"

	// this is for storing DeFi addresses for state interference checks
	DaiToken  = "dai"
	WethToken = "weth"
	UsdcToken = "usdc"
	// 2 addresses are specifically in custom devnet, we have 2 pairs of Dai/Weth for arbitrage tests
	DaiWethPair1    = "dai_weth_pair_1"
	DaiWethPair2    = "dai_weth_pair_2"
	UniswapFactory1 = "uniswap_factory_1"
	UniswapFactory2 = "uniswap_factory_2"
	UniV3SwapRouter = "uniswap_v3_swap_router"

	// allow a max of 3 ToB txs excluding the payout
	MaxTobTxs = 3
)

type EthNetworkDetails struct {
	Name                     string
	GenesisForkVersionHex    string
	GenesisValidatorsRootHex string
	BellatrixForkVersionHex  string
	CapellaForkVersionHex    string
	DenebForkVersionHex      string

	DomainBuilder                 boostTypes.Domain
	DomainBeaconProposerBellatrix boostTypes.Domain
	DomainBeaconProposerCapella   boostTypes.Domain
	DomainBeaconProposerDeneb     boostTypes.Domain
}

func NewEthNetworkDetails(networkName string) (ret *EthNetworkDetails, err error) {
	var genesisForkVersion string
	var genesisValidatorsRoot string
	var bellatrixForkVersion string
	var capellaForkVersion string
	var denebForkVersion string
	var domainBuilder boostTypes.Domain
	var domainBeaconProposerBellatrix boostTypes.Domain
	var domainBeaconProposerCapella boostTypes.Domain
	var domainBeaconProposerDeneb boostTypes.Domain

	switch networkName {
	case EthNetworkSepolia:
		genesisForkVersion = boostTypes.GenesisForkVersionSepolia
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootSepolia
		bellatrixForkVersion = boostTypes.BellatrixForkVersionSepolia
		capellaForkVersion = CapellaForkVersionSepolia
		denebForkVersion = DenebForkVersionSepolia
	case EthNetworkGoerli:
		genesisForkVersion = boostTypes.GenesisForkVersionGoerli
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootGoerli
		bellatrixForkVersion = boostTypes.BellatrixForkVersionGoerli
		capellaForkVersion = CapellaForkVersionGoerli
		denebForkVersion = DenebForkVersionGoerli
	case EthNetworkMainnet:
		genesisForkVersion = boostTypes.GenesisForkVersionMainnet
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootMainnet
		bellatrixForkVersion = boostTypes.BellatrixForkVersionMainnet
		capellaForkVersion = CapellaForkVersionMainnet
		denebForkVersion = DenebForkVersionMainnet
	case EthNetworkCustom:
		genesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")
		genesisValidatorsRoot = os.Getenv("GENESIS_VALIDATORS_ROOT")
		bellatrixForkVersion = os.Getenv("BELLATRIX_FORK_VERSION")
		capellaForkVersion = os.Getenv("CAPELLA_FORK_VERSION")
		denebForkVersion = os.Getenv("DENEB_FORK_VERSION")
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownNetwork, networkName)
	}

	domainBuilder, err = ComputeDomain(boostTypes.DomainTypeAppBuilder, genesisForkVersion, boostTypes.Root{}.String())
	if err != nil {
		return nil, err
	}

	domainBeaconProposerBellatrix, err = ComputeDomain(boostTypes.DomainTypeBeaconProposer, bellatrixForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	domainBeaconProposerCapella, err = ComputeDomain(boostTypes.DomainTypeBeaconProposer, capellaForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	domainBeaconProposerDeneb, err = ComputeDomain(boostTypes.DomainTypeBeaconProposer, denebForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	return &EthNetworkDetails{
		Name:                          networkName,
		GenesisForkVersionHex:         genesisForkVersion,
		GenesisValidatorsRootHex:      genesisValidatorsRoot,
		BellatrixForkVersionHex:       bellatrixForkVersion,
		CapellaForkVersionHex:         capellaForkVersion,
		DenebForkVersionHex:           denebForkVersion,
		DomainBuilder:                 domainBuilder,
		DomainBeaconProposerBellatrix: domainBeaconProposerBellatrix,
		DomainBeaconProposerCapella:   domainBeaconProposerCapella,
		DomainBeaconProposerDeneb:     domainBeaconProposerDeneb,
	}, nil
}

func (e *EthNetworkDetails) String() string {
	return fmt.Sprintf(
		`EthNetworkDetails{
	Name: %s, 
	GenesisForkVersionHex: %s, 
	GenesisValidatorsRootHex: %s,
	BellatrixForkVersionHex: %s, 
	CapellaForkVersionHex: %s, 
	DenebForkVersionHex: %s,
	DomainBuilder: %x, 
	DomainBeaconProposerBellatrix: %x, 
	DomainBeaconProposerCapella: %x, 
	DomainBeaconProposerDeneb: %x
}`,
		e.Name,
		e.GenesisForkVersionHex,
		e.GenesisValidatorsRootHex,
		e.BellatrixForkVersionHex,
		e.CapellaForkVersionHex,
		e.DenebForkVersionHex,
		e.DomainBuilder,
		e.DomainBeaconProposerBellatrix,
		e.DomainBeaconProposerCapella,
		e.DomainBeaconProposerDeneb)
}

type BuilderGetValidatorsResponseEntry struct {
	Slot           uint64                                  `json:"slot,string"`
	ValidatorIndex uint64                                  `json:"validator_index,string"`
	Entry          *boostTypes.SignedValidatorRegistration `json:"entry"`
}

type BidTraceV2 struct {
	apiv1.BidTrace
	BlockNumber uint64 `json:"block_number,string" db:"block_number"`
	NumTx       uint64 `json:"num_tx,string" db:"num_tx"`
}

type BidTraceV2JSON struct {
	Slot                 uint64 `json:"slot,string"`
	ParentHash           string `json:"parent_hash"`
	BlockHash            string `json:"block_hash"`
	BuilderPubkey        string `json:"builder_pubkey"`
	ProposerPubkey       string `json:"proposer_pubkey"`
	ProposerFeeRecipient string `json:"proposer_fee_recipient"`
	GasLimit             uint64 `json:"gas_limit,string"`
	GasUsed              uint64 `json:"gas_used,string"`
	Value                string `json:"value"`
	NumTx                uint64 `json:"num_tx,string"`
	BlockNumber          uint64 `json:"block_number,string"`
}

func (b BidTraceV2) MarshalJSON() ([]byte, error) {
	return json.Marshal(&BidTraceV2JSON{
		Slot:                 b.Slot,
		ParentHash:           b.ParentHash.String(),
		BlockHash:            b.BlockHash.String(),
		BuilderPubkey:        b.BuilderPubkey.String(),
		ProposerPubkey:       b.ProposerPubkey.String(),
		ProposerFeeRecipient: b.ProposerFeeRecipient.String(),
		GasLimit:             b.GasLimit,
		GasUsed:              b.GasUsed,
		Value:                b.Value.ToBig().String(),
		NumTx:                b.NumTx,
		BlockNumber:          b.BlockNumber,
	})
}

func (b *BidTraceV2) UnmarshalJSON(data []byte) error {
	params := &struct {
		NumTx       uint64 `json:"num_tx,string"`
		BlockNumber uint64 `json:"block_number,string"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	b.NumTx = params.NumTx
	b.BlockNumber = params.BlockNumber

	bidTrace := new(apiv1.BidTrace)
	err = json.Unmarshal(data, bidTrace)
	if err != nil {
		return err
	}
	b.BidTrace = *bidTrace
	return nil
}

func (b *BidTraceV2JSON) CSVHeader() []string {
	return []string{
		"slot",
		"parent_hash",
		"block_hash",
		"builder_pubkey",
		"proposer_pubkey",
		"proposer_fee_recipient",
		"gas_limit",
		"gas_used",
		"value",
		"num_tx",
		"block_number",
	}
}

func (b *BidTraceV2JSON) ToCSVRecord() []string {
	return []string{
		fmt.Sprint(b.Slot),
		b.ParentHash,
		b.BlockHash,
		b.BuilderPubkey,
		b.ProposerPubkey,
		b.ProposerFeeRecipient,
		fmt.Sprint(b.GasLimit),
		fmt.Sprint(b.GasUsed),
		b.Value,
		fmt.Sprint(b.NumTx),
		fmt.Sprint(b.BlockNumber),
	}
}

type BidTraceV2WithTimestampJSON struct {
	BidTraceV2JSON
	Timestamp            int64 `json:"timestamp,string,omitempty"`
	TimestampMs          int64 `json:"timestamp_ms,string,omitempty"`
	OptimisticSubmission bool  `json:"optimistic_submission"`
}

func (b *BidTraceV2WithTimestampJSON) CSVHeader() []string {
	return []string{
		"slot",
		"parent_hash",
		"block_hash",
		"builder_pubkey",
		"proposer_pubkey",
		"proposer_fee_recipient",
		"gas_limit",
		"gas_used",
		"value",
		"num_tx",
		"block_number",
		"timestamp",
		"timestamp_ms",
		"optimistic_submission",
	}
}

func (b *BidTraceV2WithTimestampJSON) ToCSVRecord() []string {
	return []string{
		fmt.Sprint(b.Slot),
		b.ParentHash,
		b.BlockHash,
		b.BuilderPubkey,
		b.ProposerPubkey,
		b.ProposerFeeRecipient,
		fmt.Sprint(b.GasLimit),
		fmt.Sprint(b.GasUsed),
		b.Value,
		fmt.Sprint(b.NumTx),
		fmt.Sprint(b.BlockNumber),
		fmt.Sprint(b.Timestamp),
		fmt.Sprint(b.TimestampMs),
		fmt.Sprint(b.OptimisticSubmission),
	}
}

type SignedBlindedBeaconBlock struct {
	Bellatrix *boostTypes.SignedBlindedBeaconBlock
	Capella   *apiv1capella.SignedBlindedBeaconBlock
}

func (s *SignedBlindedBeaconBlock) MarshalJSON() ([]byte, error) {
	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}
	if s.Bellatrix != nil {
		return json.Marshal(s.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (s *SignedBlindedBeaconBlock) Slot() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.Slot)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Slot
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) BlockHash() string {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockHash.String()
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockHash.String()
	}
	return ""
}

func (s *SignedBlindedBeaconBlock) BlockNumber() uint64 {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockNumber
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockNumber
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) ProposerIndex() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.ProposerIndex)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.ProposerIndex
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) Signature() []byte {
	if s.Capella != nil {
		return s.Capella.Signature[:]
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Signature[:]
	}
	return nil
}

//nolint:nolintlint,ireturn
func (s *SignedBlindedBeaconBlock) Message() boostTypes.HashTreeRoot {
	if s.Capella != nil {
		return s.Capella.Message
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message
	}
	return nil
}

type SignedBeaconBlock struct {
	Bellatrix *boostTypes.SignedBeaconBlock
	Capella   *consensuscapella.SignedBeaconBlock
}

func (s *SignedBeaconBlock) MarshalJSON() ([]byte, error) {
	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}
	if s.Bellatrix != nil {
		return json.Marshal(s.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (s *SignedBeaconBlock) Slot() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.Slot)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Slot
	}
	return 0
}

func (s *SignedBeaconBlock) BlockHash() string {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayload.BlockHash.String()
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayload.BlockHash.String()
	}
	return ""
}

type VersionedExecutionPayload struct {
	Bellatrix *boostTypes.GetPayloadResponse
	Capella   *api.VersionedExecutionPayload
}

func (e *VersionedExecutionPayload) MarshalJSON() ([]byte, error) {
	if e.Capella != nil {
		return json.Marshal(e.Capella)
	}
	if e.Bellatrix != nil {
		return json.Marshal(e.Bellatrix)
	}

	return nil, ErrEmptyPayload
}

func (e *VersionedExecutionPayload) UnmarshalJSON(data []byte) error {
	capella := new(api.VersionedExecutionPayload)
	err := json.Unmarshal(data, capella)
	if err == nil && capella.Capella != nil {
		e.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.GetPayloadResponse)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	e.Bellatrix = bellatrix
	return nil
}

func (e *VersionedExecutionPayload) NumTx() int {
	if e.Capella != nil {
		return len(e.Capella.Capella.Transactions)
	}
	if e.Bellatrix != nil {
		return len(e.Bellatrix.Data.Transactions)
	}
	return 0
}

type BuilderSubmitBlockRequest struct {
	Bellatrix *boostTypes.BuilderSubmitBlockRequest
	Capella   *capella.SubmitBlockRequest
}

func (b *BuilderSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	if b.Capella != nil {
		return json.Marshal(b.Capella)
	}
	if b.Bellatrix != nil {
		return json.Marshal(b.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (b *BuilderSubmitBlockRequest) UnmarshalJSON(data []byte) error {
	capella := new(capella.SubmitBlockRequest)
	err := json.Unmarshal(data, capella)
	if err == nil {
		b.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.BuilderSubmitBlockRequest)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	b.Bellatrix = bellatrix
	return nil
}

func (b *BuilderSubmitBlockRequest) HasExecutionPayload() bool {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload != nil
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload != nil
	}
	return false
}

func (b *BuilderSubmitBlockRequest) ExecutionPayloadResponse() (*GetPayloadResponse, error) {
	if b.Bellatrix != nil {
		return &GetPayloadResponse{
			Bellatrix: &boostTypes.GetPayloadResponse{
				Version: boostTypes.VersionString(consensusspec.DataVersionBellatrix.String()),
				Data:    b.Bellatrix.ExecutionPayload,
			},
			Capella: nil,
		}, nil
	}

	if b.Capella != nil {
		return &GetPayloadResponse{
			Capella: &api.VersionedExecutionPayload{
				Version:   consensusspec.DataVersionCapella,
				Capella:   b.Capella.ExecutionPayload,
				Bellatrix: nil,
			},
			Bellatrix: nil,
		}, nil
	}

	return nil, ErrEmptyPayload
}

func (b *BuilderSubmitBlockRequest) Slot() uint64 {
	if b.Capella != nil {
		return b.Capella.Message.Slot
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.Slot
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) BlockHash() string {
	if b.Capella != nil {
		return b.Capella.Message.BlockHash.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.BlockHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) ExecutionPayloadBlockHash() string {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.BlockHash.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.BlockHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) BuilderPubkey() phase0.BLSPubKey {
	if b.Capella != nil {
		return b.Capella.Message.BuilderPubkey
	}
	if b.Bellatrix != nil {
		return phase0.BLSPubKey(b.Bellatrix.Message.BuilderPubkey)
	}
	return phase0.BLSPubKey{}
}

func (b *BuilderSubmitBlockRequest) ProposerFeeRecipient() string {
	if b.Capella != nil {
		return b.Capella.Message.ProposerFeeRecipient.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.ProposerFeeRecipient.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) Timestamp() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.Timestamp
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.Timestamp
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) ProposerPubkey() string {
	if b.Capella != nil {
		return b.Capella.Message.ProposerPubkey.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.ProposerPubkey.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) ParentHash() string {
	if b.Capella != nil {
		return b.Capella.Message.ParentHash.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.ParentHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) ExecutionPayloadParentHash() string {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.ParentHash.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.ParentHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) Value() *big.Int {
	if b.Capella != nil {
		return b.Capella.Message.Value.ToBig()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.Value.BigInt()
	}
	return nil
}

func (b *BuilderSubmitBlockRequest) NumTx() int {
	if b.Capella != nil {
		return len(b.Capella.ExecutionPayload.Transactions)
	}
	if b.Bellatrix != nil {
		return len(b.Bellatrix.ExecutionPayload.Transactions)
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) BlockNumber() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.BlockNumber
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.BlockNumber
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) GasUsed() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.GasUsed
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.GasUsed
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) GasLimit() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.GasLimit
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.GasLimit
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) Signature() phase0.BLSSignature {
	if b.Capella != nil {
		return b.Capella.Signature
	}
	if b.Bellatrix != nil {
		return phase0.BLSSignature(b.Bellatrix.Signature)
	}
	return phase0.BLSSignature{}
}

func (b *BuilderSubmitBlockRequest) Random() string {
	if b.Capella != nil {
		return fmt.Sprintf("%#x", b.Capella.ExecutionPayload.PrevRandao)
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.Random.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) Message() *apiv1.BidTrace {
	if b.Capella != nil {
		return b.Capella.Message
	}
	if b.Bellatrix != nil {
		return BoostBidToBidTrace(b.Bellatrix.Message)
	}
	return nil
}

func BoostBidToBidTrace(bidTrace *boostTypes.BidTrace) *apiv1.BidTrace {
	if bidTrace == nil {
		return nil
	}
	return &apiv1.BidTrace{
		BuilderPubkey:        phase0.BLSPubKey(bidTrace.BuilderPubkey),
		Slot:                 bidTrace.Slot,
		ProposerPubkey:       phase0.BLSPubKey(bidTrace.ProposerPubkey),
		ProposerFeeRecipient: bellatrix.ExecutionAddress(bidTrace.ProposerFeeRecipient),
		BlockHash:            phase0.Hash32(bidTrace.BlockHash),
		Value:                U256StrToUint256(bidTrace.Value),
		ParentHash:           phase0.Hash32(bidTrace.ParentHash),
		GasLimit:             bidTrace.GasLimit,
		GasUsed:              bidTrace.GasUsed,
	}
}

type GetPayloadResponse struct {
	Bellatrix *boostTypes.GetPayloadResponse
	Capella   *api.VersionedExecutionPayload
}

func (p *GetPayloadResponse) UnmarshalJSON(data []byte) error {
	capella := new(api.VersionedExecutionPayload)
	err := json.Unmarshal(data, capella)
	if err == nil && capella.Capella != nil {
		p.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.GetPayloadResponse)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	p.Bellatrix = bellatrix
	return nil
}

func (p *GetPayloadResponse) MarshalJSON() ([]byte, error) {
	if p.Bellatrix != nil {
		return json.Marshal(p.Bellatrix)
	}
	if p.Capella != nil {
		return json.Marshal(p.Capella)
	}
	return nil, ErrEmptyPayload
}

type GetHeaderResponse struct {
	Bellatrix *boostTypes.GetHeaderResponse
	Capella   *spec.VersionedSignedBuilderBid
}

func (p *GetHeaderResponse) UnmarshalJSON(data []byte) error {
	capella := new(spec.VersionedSignedBuilderBid)
	err := json.Unmarshal(data, capella)
	if err == nil && capella.Capella != nil {
		p.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.GetHeaderResponse)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	p.Bellatrix = bellatrix
	return nil
}

func (p *GetHeaderResponse) MarshalJSON() ([]byte, error) {
	if p.Capella != nil {
		return json.Marshal(p.Capella)
	}
	if p.Bellatrix != nil {
		return json.Marshal(p.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (p *GetHeaderResponse) Value() *big.Int {
	if p.Capella != nil {
		return p.Capella.Capella.Message.Value.ToBig()
	}
	if p.Bellatrix != nil {
		return p.Bellatrix.Data.Message.Value.BigInt()
	}
	return nil
}

func (p *GetHeaderResponse) BlockHash() phase0.Hash32 {
	if p.Capella != nil {
		return p.Capella.Capella.Message.Header.BlockHash
	}
	if p.Bellatrix != nil {
		return phase0.Hash32(p.Bellatrix.Data.Message.Header.BlockHash)
	}
	return phase0.Hash32{}
}

func (p *GetHeaderResponse) Empty() bool {
	if p == nil {
		return true
	}
	if p.Capella != nil {
		return p.Capella.Capella == nil || p.Capella.Capella.Message == nil
	}
	if p.Bellatrix != nil {
		return p.Bellatrix.Data == nil || p.Bellatrix.Data.Message == nil
	}
	return true
}

func (b *BuilderSubmitBlockRequest) Withdrawals() []*consensuscapella.Withdrawal {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.Withdrawals
	}
	return nil
}

func encodeTransactions(txs []*types.Transaction) [][]byte {
	var enc = make([][]byte, len(txs))
	for i, tx := range txs {
		enc[i], _ = tx.MarshalBinary()
	}
	return enc
}

func DecodeTransactions(enc [][]byte) ([]*types.Transaction, error) {
	var txs = make([]*types.Transaction, len(enc))
	for i, encTx := range enc {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(encTx); err != nil {
			return nil, fmt.Errorf("invalid transaction %d: %v", i, err)
		}
		txs[i] = &tx
	}
	return txs, nil
}

type TobTxsSubmitRequest struct {
	TobTxs     utilbellatrix.ExecutionPayloadTransactions
	Slot       uint64
	ParentHash string
}

type IntermediateTobTxsSubmitRequest struct {
	TobTxs     []byte `json:"tobTxs"`
	Slot       uint64 `json:"slot"`
	ParentHash string `json:"parentHash"`
}

func (t *TobTxsSubmitRequest) MarshalJSON() ([]byte, error) {
	txBytes, err := t.TobTxs.MarshalSSZ()
	if err != nil {
		return nil, err
	}

	return json.Marshal(IntermediateTobTxsSubmitRequest{
		TobTxs:     txBytes,
		Slot:       t.Slot,
		ParentHash: t.ParentHash,
	})
}

func (t *TobTxsSubmitRequest) UnmarshalJSON(data []byte) error {
	var intermediateJson IntermediateTobTxsSubmitRequest
	err := json.Unmarshal(data, &intermediateJson)
	if err != nil {
		return err
	}

	err = t.TobTxs.UnmarshalSSZ(intermediateJson.TobTxs)
	if err != nil {
		return err
	}
	t.Slot = intermediateJson.Slot
	t.ParentHash = intermediateJson.ParentHash

	return nil
}

type BlockAssemblerRequest struct {
	TobTxs             utilbellatrix.ExecutionPayloadTransactions `json:"tob_txs"`
	RobPayload         BuilderSubmitBlockRequest                  `json:"rob_payload"`
	RegisteredGasLimit uint64                                     `json:"registered_gas_limit,string"`
}

type IntermediateBlockAssemblerRequest struct {
	TobTxs             []byte `json:"tob_txs"`
	RobPayload         []byte `json:"rob_payload"`
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (r *BlockAssemblerRequest) MarshalJSON() ([]byte, error) {
	sszedTobTxs, err := r.TobTxs.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	encodedRobPayload, err := r.RobPayload.MarshalJSON()
	if err != nil {
		return nil, err
	}
	intermediateStruct := IntermediateBlockAssemblerRequest{
		TobTxs:             sszedTobTxs,
		RobPayload:         encodedRobPayload,
		RegisteredGasLimit: r.RegisteredGasLimit,
	}

	return json.Marshal(intermediateStruct)
}

func (b *BlockAssemblerRequest) UnmarshalJSON(data []byte) error {
	var intermediateJson IntermediateBlockAssemblerRequest
	err := json.Unmarshal(data, &intermediateJson)
	if err != nil {
		return err
	}
	err = b.TobTxs.UnmarshalSSZ(intermediateJson.TobTxs)
	if err != nil {
		return err
	}
	b.RegisteredGasLimit = intermediateJson.RegisteredGasLimit
	blockRequest := new(BuilderSubmitBlockRequest)
	err = json.Unmarshal(intermediateJson.RobPayload, &blockRequest)
	if err != nil {
		return err
	}
	b.RobPayload = *blockRequest

	return nil
}

// callLog is the result of LOG opCode
type CallLog struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    hexutil.Bytes  `json:"data"`
}

type CallTrace struct {
	From         common.Address  `json:"from"`
	Gas          *hexutil.Uint64 `json:"gas"`
	GasUsed      *hexutil.Uint64 `json:"gasUsed"`
	To           *common.Address `json:"to,omitempty"`
	Input        hexutil.Bytes   `json:"input"`
	Output       hexutil.Bytes   `json:"output,omitempty"`
	Error        string          `json:"error,omitempty"`
	RevertReason string          `json:"revertReason,omitempty"`
	Calls        []CallTrace     `json:"calls,omitempty"`
	Logs         []CallLog       `json:"logs,omitempty"`
	Value        *hexutil.Big    `json:"value,omitempty"`
	// Gencodec adds overridden fields at the end
	Type string `json:"type"`
}

type CallTraceResponse struct {
	Result CallTrace `json:"result"`
}

type NetworkTobTxChecker func(CallTrace) (bool, error)

type TobValidationRequest struct {
	TobTxs               utilbellatrix.ExecutionPayloadTransactions
	ParentHash           string
	ProposerFeeRecipient string
}

type IntermediateTobValidationRequest struct {
	TobTxs               []byte `json:"tob_txs"`
	ParentHash           string `json:"parent_hash"`
	ProposerFeeRecipient string `json:"proposer_fee_recipient"`
}

func (t *TobValidationRequest) MarshalJson() ([]byte, error) {
	sszedTobTxs, err := t.TobTxs.MarshalSSZ()
	if err != nil {
		return nil, err
	}

	intermediateStruct := IntermediateTobValidationRequest{
		TobTxs:               sszedTobTxs,
		ParentHash:           t.ParentHash,
		ProposerFeeRecipient: t.ProposerFeeRecipient,
	}

	return json.Marshal(intermediateStruct)
}

func (t *TobValidationRequest) UnmarshalJson(data []byte) error {
	var intermediateJson IntermediateTobValidationRequest
	err := json.Unmarshal(data, &intermediateJson)
	if err != nil {
		return err
	}

	err = t.TobTxs.UnmarshalSSZ(intermediateJson.TobTxs)
	if err != nil {
		return err
	}
	t.ParentHash = intermediateJson.ParentHash

	return nil
}
