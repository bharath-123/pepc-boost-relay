package api

import (
	"math/big"
	"strconv"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/stretchr/testify/require"
)

func startTestBackend(t *testing.T) (*phase0.BLSPubKey, *bls.SecretKey, *testBackend) {
	t.Helper()
	// Setup test key pair.
	sk, _, err := bls.GenerateNewKeypair()
	require.NoError(t, err)
	blsPubkey, err := bls.PublicKeyFromSecretKey(sk)
	require.NoError(t, err)
	pkBytes := blsPubkey.Bytes()
	var pubkey phase0.BLSPubKey
	copy(pubkey[:], pkBytes[:])
	pkStr := pubkey.String()

	// Setup test backend.
	backend := newTestBackend(t, 1)
	backend.relay.genesisInfo = &beaconclient.GetGenesisResponse{}
	backend.relay.genesisInfo.Data.GenesisTime = 0
	backend.relay.proposerDutiesMap = map[uint64]*common.BuilderGetValidatorsResponseEntry{
		slot: {
			Entry: &boostTypes.SignedValidatorRegistration{
				Message: &boostTypes.RegisterValidatorRequestMessage{
					FeeRecipient: [20]byte(feeRecipient),
					GasLimit:     5000,
					Timestamp:    0xffffffff,
					Pubkey:       [48]byte(phase0.BLSPubKey{}),
				},
			},
		},
	}
	backend.relay.opts.BlockBuilderAPI = true
	backend.relay.beaconClient = beaconclient.NewMockMultiBeaconClient()
	backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{}
	backend.relay.blockBuildersCache = map[string]*blockBuilderCacheEntry{
		pkStr: {
			status: common.BuilderStatus{
				IsHighPrio:   true,
				IsOptimistic: true,
			},
			collateral: big.NewInt(int64(collateral)),
		},
	}

	// Setup test db, redis, and datastore.
	mockDB := &database.MockDB{
		Builders: map[string]*database.BlockBuilderEntry{
			pkStr: {
				BuilderPubkey: pkStr,
				IsHighPrio:    true,
				IsOptimistic:  true,
				BuilderID:     builderID,
				Collateral:    strconv.Itoa(collateral),
			},
		},
		Demotions: map[string]bool{},
		Refunds:   map[string]bool{},
	}
	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)
	mockRedis, err := datastore.NewRedisCache("", redisTestServer.Addr(), "")
	require.NoError(t, err)
	mockDS, err := datastore.NewDatastore(mockRedis, nil, mockDB)
	require.NoError(t, err)

	backend.relay.datastore = mockDS
	backend.relay.redis = mockRedis
	backend.relay.db = mockDB

	// Prepare redis
	// err = backend.relay.redis.SetKnownValidator(boostTypes.NewPubkeyHex(pubkey.String()), proposerInd)
	// require.NoError(t, err)

	// count, err := backend.relay.datastore.RefreshKnownValidators()
	// require.NoError(t, err)
	// require.Equal(t, count, 1)

	backend.relay.headSlot.Store(40)
	return &pubkey, sk, backend
}

// TODO - this test will keep evolving as we expand the state interference checks
func TestCcheckTxAndSenderValidity(t *testing.T) {
	cases := []struct {
		description   string
		txs           []*gethtypes.Transaction
		requiredError string
	}{
		{
			description:   "no txs sent",
			txs:           []*gethtypes.Transaction{},
			requiredError: "empty txs sent",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			_, _, backend := startTestBackend(t)
			backend.relay.checkTxAndSenderValidity(c.txs)

		})
	}
}
