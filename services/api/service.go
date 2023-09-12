// Package api contains the API webserver for the proposer and block-builder APIs
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NYTimes/gziphandler"
	builderCapella "github.com/attestantio/go-builder-client/api/capella"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/api/v1/capella"
	bellatrix2 "github.com/attestantio/go-eth2-client/spec/bellatrix"
	capella2 "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/go-eth2-client/util/bellatrix"
	"github.com/buger/jsonparser"
	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/go-redis/redis/v9"
	"github.com/gorilla/mux"
	"github.com/holiman/uint256"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
	"golang.org/x/exp/slices"
)

const (
	ErrBlockAlreadyKnown  = "simulation failed: block already known"
	ErrBlockRequiresReorg = "simulation failed: block requires a reorg"
	ErrMissingTrieNode    = "missing trie node"
)

var (
	ErrMissingLogOpt              = errors.New("log parameter is nil")
	ErrMissingBeaconClientOpt     = errors.New("beacon-client is nil")
	ErrMissingDatastoreOpt        = errors.New("proposer datastore is nil")
	ErrRelayPubkeyMismatch        = errors.New("relay pubkey does not match existing one")
	ErrServerAlreadyStarted       = errors.New("server was already started")
	ErrBuilderAPIWithoutSecretKey = errors.New("cannot start builder API without secret key")
	ErrMismatchedForkVersions     = errors.New("can not find matching fork versions as retrieved from beacon node")
	ErrMissingForkVersions        = errors.New("invalid fork version from beacon node")
)

var (
	// Proposer API (builder-specs)
	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload        = "/eth/v1/builder/blinded_blocks"

	// Block builder API
	pathBuilderGetValidators = "/relay/v1/builder/validators"
	pathSubmitNewBlock       = "/relay/v1/builder/blocks"
	pathSubmitNewTobTxs      = "/relay/v1/builder/tob_txs"

	// Data API
	pathDataProposerPayloadDelivered = "/relay/v1/data/bidtraces/proposer_payload_delivered"
	pathDataBuilderBidsReceived      = "/relay/v1/data/bidtraces/builder_blocks_received"
	pathDataValidatorRegistration    = "/relay/v1/data/validator_registration"
	pathDataGetCurrentTobTx          = "/relay/v1/data/current_tob_tx"
	// this is for the builders to know if they are interacting with a pepc relayer or not.
	// this solution is so that builder can enable pepc relayer specific features like validator payout changes etc
	pathDataIsPepcRelayer = "/relay/v1/data/is_pepc_relayer"

	// Internal API
	pathInternalBuilderStatus     = "/internal/v1/builder/{pubkey:0x[a-fA-F0-9]+}"
	pathInternalBuilderCollateral = "/internal/v1/builder/collateral/{pubkey:0x[a-fA-F0-9]+}"

	// number of goroutines to save active validator
	numValidatorRegProcessors = cli.GetEnvInt("NUM_VALIDATOR_REG_PROCESSORS", 10)

	// various timings
	timeoutGetPayloadRetryMs  = cli.GetEnvInt("GETPAYLOAD_RETRY_TIMEOUT_MS", 100)
	getHeaderRequestCutoffMs  = cli.GetEnvInt("GETHEADER_REQUEST_CUTOFF_MS", 3000)
	getPayloadRequestCutoffMs = cli.GetEnvInt("GETPAYLOAD_REQUEST_CUTOFF_MS", 4000)
	getPayloadResponseDelayMs = cli.GetEnvInt("GETPAYLOAD_RESPONSE_DELAY_MS", 1000)

	// api settings
	apiReadTimeoutMs       = cli.GetEnvInt("API_TIMEOUT_READ_MS", 1500)
	apiReadHeaderTimeoutMs = cli.GetEnvInt("API_TIMEOUT_READHEADER_MS", 600)
	apiIdleTimeoutMs       = cli.GetEnvInt("API_TIMEOUT_IDLE_MS", 3_000)
	apiWriteTimeoutMs      = cli.GetEnvInt("API_TIMEOUT_WRITE_MS", 10_000)
	apiMaxHeaderBytes      = cli.GetEnvInt("API_MAX_HEADER_BYTES", 60_000)

	// api shutdown: wait time (to allow removal from load balancer before stopping http server)
	apiShutdownWaitDuration = common.GetEnvDurationSec("API_SHUTDOWN_WAIT_SEC", 30)

	// api shutdown: whether to stop sending bids during shutdown phase (only useful if running a single-instance testnet setup)
	apiShutdownStopSendingBids = os.Getenv("API_SHUTDOWN_STOP_SENDING_BIDS") == "1"

	// maximum payload bytes for a block submission to be fast-tracked (large payloads slow down other fast-tracked requests!)
	fastTrackPayloadSizeLimit = cli.GetEnvInt("FAST_TRACK_PAYLOAD_SIZE_LIMIT", 230_000)

	// user-agents which shouldn't receive bids
	apiNoHeaderUserAgents = common.GetEnvStrSlice("NO_HEADER_USERAGENTS", []string{
		"mev-boost/v1.5.0 Go-http-client/1.1", // Prysm v4.0.1 (Shapella signing issue)
	})
)

// RelayAPIOpts contains the options for a relay
type RelayAPIOpts struct {
	Log *logrus.Entry

	ListenAddr  string
	BlockSimURL string

	BeaconClient beaconclient.IMultiBeaconClient
	Datastore    *datastore.Datastore
	Redis        *datastore.RedisCache
	Memcached    *datastore.Memcached
	DB           database.IDatabaseService

	SecretKey *bls.SecretKey // used to sign bids (getHeader responses)

	// Network specific variables
	EthNetDetails common.EthNetworkDetails

	// APIs to enable
	ProposerAPI     bool
	BlockBuilderAPI bool
	DataAPI         bool
	PprofAPI        bool
	InternalAPI     bool
}

type payloadAttributesHelper struct {
	slot              uint64
	parentHash        string
	withdrawalsRoot   phase0.Root
	payloadAttributes beaconclient.PayloadAttributes
}

// Data needed to issue a block validation request.
type blockSimOptions struct {
	isHighPrio bool
	fastTrack  bool
	log        *logrus.Entry
	builder    *blockBuilderCacheEntry
	req        *common.BuilderBlockValidationRequest
}

type blockAssemblyOptions struct {
	log *logrus.Entry
	req *common.BlockAssemblerRequest
}

type blockBuilderCacheEntry struct {
	status     common.BuilderStatus
	collateral *big.Int
}

type blockSimResult struct {
	wasSimulated         bool
	optimisticSubmission bool
	requestErr           error
	validationErr        error
}

type blockAssemblyResult struct {
	assembledPayload *capella2.ExecutionPayload
	requestErr       error
	validationErr    error
}

// RelayAPI represents a single Relay instance
type RelayAPI struct {
	opts RelayAPIOpts
	log  *logrus.Entry

	blsSk     *bls.SecretKey
	publicKey *boostTypes.PublicKey

	relayerPayoutAddress common2.Address

	srv         *http.Server
	srvStarted  uberatomic.Bool
	srvShutdown uberatomic.Bool

	beaconClient beaconclient.IMultiBeaconClient
	datastore    *datastore.Datastore
	redis        *datastore.RedisCache
	memcached    *datastore.Memcached
	db           database.IDatabaseService

	headSlot     uberatomic.Uint64
	genesisInfo  *beaconclient.GetGenesisResponse
	capellaEpoch uint64
	denebEpoch   uint64

	proposerDutiesLock       sync.RWMutex
	proposerDutiesResponse   *[]byte // raw http response
	proposerDutiesMap        map[uint64]*common.BuilderGetValidatorsResponseEntry
	proposerDutiesSlot       uint64
	isUpdatingProposerDuties uberatomic.Bool

	blockSimRateLimiter IBlockSimRateLimiter
	blockAssembler      IBlockAssembler

	validatorRegC chan boostTypes.SignedValidatorRegistration

	// used to wait on any active getPayload calls on shutdown
	getPayloadCallsInFlight sync.WaitGroup

	// Feature flags
	ffForceGetHeader204          bool
	ffDisableLowPrioBuilders     bool
	ffDisablePayloadDBStorage    bool // disable storing the execution payloads in the database
	ffLogInvalidSignaturePayload bool // log payload if getPayload signature validation fails
	ffEnableCancellations        bool // whether to enable block builder cancellations
	ffRegValContinueOnInvalidSig bool // whether to continue processing further validators if one fails
	ffIgnorableValidationErrors  bool // whether to enable ignorable validation errors

	payloadAttributes     map[string]payloadAttributesHelper // key:parentBlockHash
	payloadAttributesLock sync.RWMutex

	// The slot we are currently optimistically simulating.
	optimisticSlot uberatomic.Uint64
	// The number of optimistic blocks being processed (only used for logging).
	optimisticBlocksInFlight uberatomic.Uint64
	// Wait group used to monitor status of per-slot optimistic processing.
	optimisticBlocksWG sync.WaitGroup
	// Cache for builder statuses and collaterals.
	blockBuildersCache map[string]*blockBuilderCacheEntry
}

// NewRelayAPI creates a new service. if builders is nil, allow any builder
func NewRelayAPI(opts RelayAPIOpts) (api *RelayAPI, err error) {
	if opts.Log == nil {
		return nil, ErrMissingLogOpt
	}

	if opts.BeaconClient == nil {
		return nil, ErrMissingBeaconClientOpt
	}

	if opts.Datastore == nil {
		return nil, ErrMissingDatastoreOpt
	}

	// If block-builder API is enabled, then ensure secret key is all set
	var publicKey boostTypes.PublicKey
	if opts.BlockBuilderAPI {
		if opts.SecretKey == nil {
			return nil, ErrBuilderAPIWithoutSecretKey
		}

		// If using a secret key, ensure it's the correct one
		blsPubkey, err := bls.PublicKeyFromSecretKey(opts.SecretKey)
		if err != nil {
			return nil, err
		}
		publicKey, err = boostTypes.BlsPublicKeyToPublicKey(blsPubkey)
		if err != nil {
			return nil, err
		}
		opts.Log.Infof("Using BLS key: %s", publicKey.String())

		// ensure pubkey is same across all relay instances
		_pubkey, err := opts.Redis.GetRelayConfig(datastore.RedisConfigFieldPubkey)
		if err != nil {
			return nil, err
		} else if _pubkey == "" {
			err := opts.Redis.SetRelayConfig(datastore.RedisConfigFieldPubkey, publicKey.String())
			if err != nil {
				return nil, err
			}
		} else if _pubkey != publicKey.String() {
			return nil, fmt.Errorf("%w: new=%s old=%s", ErrRelayPubkeyMismatch, publicKey.String(), _pubkey)
		}
	}

	api = &RelayAPI{
		opts:      opts,
		log:       opts.Log,
		blsSk:     opts.SecretKey,
		publicKey: &publicKey,
		// TODO - make this a config option
		relayerPayoutAddress: common2.HexToAddress("0x4E9A3d9D1cd2A2b2371b8b3F489aE72259886f1A"),
		datastore:            opts.Datastore,
		beaconClient:         opts.BeaconClient,
		redis:                opts.Redis,
		memcached:            opts.Memcached,
		db:                   opts.DB,

		payloadAttributes: make(map[string]payloadAttributesHelper),

		proposerDutiesResponse: &[]byte{},
		blockSimRateLimiter:    NewBlockSimulationRateLimiter(opts.BlockSimURL),
		blockAssembler:         NewBlockAssembler(opts.BlockSimURL),

		validatorRegC: make(chan boostTypes.SignedValidatorRegistration, 450_000),
	}

	if os.Getenv("FORCE_GET_HEADER_204") == "1" {
		api.log.Warn("env: FORCE_GET_HEADER_204 - forcing getHeader to always return 204")
		api.ffForceGetHeader204 = true
	}

	if os.Getenv("DISABLE_LOWPRIO_BUILDERS") == "1" {
		api.log.Warn("env: DISABLE_LOWPRIO_BUILDERS - allowing only high-level builders")
		api.ffDisableLowPrioBuilders = true
	}

	if os.Getenv("DISABLE_PAYLOAD_DATABASE_STORAGE") == "1" {
		api.log.Warn("env: DISABLE_PAYLOAD_DATABASE_STORAGE - disabling storing payloads in the database")
		api.ffDisablePayloadDBStorage = true
	}

	if os.Getenv("LOG_INVALID_GETPAYLOAD_SIGNATURE") == "1" {
		api.log.Warn("env: LOG_INVALID_GETPAYLOAD_SIGNATURE - getPayload payloads with invalid proposer signature will be logged")
		api.ffLogInvalidSignaturePayload = true
	}

	if os.Getenv("ENABLE_BUILDER_CANCELLATIONS") == "1" {
		api.log.Warn("env: ENABLE_BUILDER_CANCELLATIONS - builders are allowed to cancel submissions when using ?cancellation=1")
		api.ffEnableCancellations = true
	}

	if os.Getenv("REGISTER_VALIDATOR_CONTINUE_ON_INVALID_SIG") == "1" {
		api.log.Warn("env: REGISTER_VALIDATOR_CONTINUE_ON_INVALID_SIG - validator registration will continue processing even if one validator has an invalid signature")
		api.ffRegValContinueOnInvalidSig = true
	}

	if os.Getenv("ENABLE_IGNORABLE_VALIDATION_ERRORS") == "1" {
		api.log.Warn("env: ENABLE_IGNORABLE_VALIDATION_ERRORS - some validation errors will be ignored")
		api.ffIgnorableValidationErrors = true
	}

	return api, nil
}

func (api *RelayAPI) getRouter() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/", api.handleRoot).Methods(http.MethodGet)
	r.HandleFunc("/livez", api.handleLivez).Methods(http.MethodGet)
	r.HandleFunc("/readyz", api.handleReadyz).Methods(http.MethodGet)

	// Proposer API
	if api.opts.ProposerAPI {
		api.log.Info("proposer API enabled")
		r.HandleFunc(pathStatus, api.handleStatus).Methods(http.MethodGet)
		r.HandleFunc(pathRegisterValidator, api.handleRegisterValidator).Methods(http.MethodPost)
		r.HandleFunc(pathGetHeader, api.handleGetHeader).Methods(http.MethodGet)
		r.HandleFunc(pathGetPayload, api.handleGetPayload).Methods(http.MethodPost)
	}

	// Builder API
	if api.opts.BlockBuilderAPI {
		api.log.Info("block builder API enabled")
		r.HandleFunc(pathBuilderGetValidators, api.handleBuilderGetValidators).Methods(http.MethodGet)
		r.HandleFunc(pathSubmitNewBlock, api.handleSubmitNewBlock).Methods(http.MethodPost)
		r.HandleFunc(pathSubmitNewTobTxs, api.handleSubmitNewTobTxs).Methods(http.MethodPost)
	}

	// Data API
	if api.opts.DataAPI {
		api.log.Info("data API enabled")
		r.HandleFunc(pathDataProposerPayloadDelivered, api.handleDataProposerPayloadDelivered).Methods(http.MethodGet)
		r.HandleFunc(pathDataBuilderBidsReceived, api.handleDataBuilderBidsReceived).Methods(http.MethodGet)
		r.HandleFunc(pathDataValidatorRegistration, api.handleDataValidatorRegistration).Methods(http.MethodGet)
		r.HandleFunc(pathDataGetCurrentTobTx, api.handleDataGetCurrentTobTx).Methods(http.MethodGet)
		r.HandleFunc(pathDataIsPepcRelayer, api.handleDataIsPepcRelayer).Methods(http.MethodGet)
	}

	// Pprof
	if api.opts.PprofAPI {
		api.log.Info("pprof API enabled")
		r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	}

	// /internal/...
	if api.opts.InternalAPI {
		api.log.Info("internal API enabled")
		r.HandleFunc(pathInternalBuilderStatus, api.handleInternalBuilderStatus).Methods(http.MethodGet, http.MethodPost, http.MethodPut)
		r.HandleFunc(pathInternalBuilderCollateral, api.handleInternalBuilderCollateral).Methods(http.MethodPost, http.MethodPut)
	}

	mresp := common.MustB64Gunzip("H4sICAtOkWQAA2EudHh0AKWVPW+DMBCGd36Fe9fIi5Mt8uqqs4dIlZiCEqosKKhVO2Txj699GBtDcEl4JwTnh/t4dS7YWom2FcVaiETSDEmIC+pWLGRVgKrD3UY0iwnSj6THofQJDomiR13BnPgjvJDqNWX+OtzH7inWEGvr76GOCGtg3Kp7Ak+lus3zxLNtmXaMUncjcj1cwbOH3xBZtJCYG6/w+hdpB6ErpnqzFPZxO4FdXB3SAEgpscoDqWeULKmJA4qyfYFg0QV+p7hD8GGDd6C8+mElGDKab1CWeUQMVVvVDTJVj6nngHmNOmSoe6yH1BM3KZIKpuRaHKrOFd/3ksQwzdK+ejdM4VTzSDfjJsY1STeVTWb0T9JWZbJs8DvsNvwaddKdUy4gzVIzWWaWk3IF8D35kyUDf3FfKipwk/DYUee2nYyWQD0xEKDHeprzeXYwVmZD/lXt1OOg8EYhFfitsmQVcwmbUutpdt3PoqWdMyd2DYHKbgcmPlEYMxPjR6HhxOfuNG52xZr7TtzpygJJKNtWS14Uf0T6XSmzBwAA")
	r.HandleFunc("/miladyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK); w.Write(mresp) }).Methods(http.MethodGet) //nolint:errcheck

	// r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(api.log, r)
	withGz := gziphandler.GzipHandler(loggedRouter)
	return withGz
}

// StartServer starts up this API instance and HTTP server
// - First it initializes the cache and updates local information
// - Once that is done, the HTTP server is started
func (api *RelayAPI) StartServer() (err error) {
	if api.srvStarted.Swap(true) {
		return ErrServerAlreadyStarted
	}

	log := api.log.WithField("method", "StartServer")

	// Get best beacon-node status by head slot, process current slot and start slot updates
	syncStatus, err := api.beaconClient.BestSyncStatus()
	if err != nil {
		return err
	}
	currentSlot := syncStatus.HeadSlot

	// Initialize block builder cache.
	api.blockBuildersCache = make(map[string]*blockBuilderCacheEntry)

	// Get genesis info
	api.genesisInfo, err = api.beaconClient.GetGenesis()
	if err != nil {
		return err
	}
	log.Infof("genesis info: %d", api.genesisInfo.Data.GenesisTime)

	// Get and prepare fork schedule
	forkSchedule, err := api.beaconClient.GetForkSchedule()
	if err != nil {
		return err
	}
	for _, fork := range forkSchedule.Data {
		log.Infof("forkSchedule: version=%s / epoch=%d", fork.CurrentVersion, fork.Epoch)
		switch fork.CurrentVersion {
		case api.opts.EthNetDetails.CapellaForkVersionHex:
			api.capellaEpoch = fork.Epoch
		case api.opts.EthNetDetails.DenebForkVersionHex:
			api.denebEpoch = fork.Epoch
		}
	}

	// Print fork version information
	if hasReachedFork(currentSlot, api.denebEpoch) {
		log.Infof("deneb fork detected (currentEpoch: %d / denebEpoch: %d)", common.SlotToEpoch(currentSlot), api.denebEpoch)
	} else if hasReachedFork(currentSlot, api.capellaEpoch) {
		log.Infof("capella fork detected (currentEpoch: %d / capellaEpoch: %d)", common.SlotToEpoch(currentSlot), api.capellaEpoch)
	} else {
		return ErrMismatchedForkVersions
	}

	// start proposer API specific things
	if api.opts.ProposerAPI {
		// Update known validators (which can take 10-30 sec). This is a requirement for service readiness, because without them,
		// getPayload() doesn't have the information it needs (known validators), which could lead to missed slots.
		go api.datastore.RefreshKnownValidators(api.log, api.beaconClient, currentSlot)

		// Start the validator registration db-save processor
		api.log.Infof("starting %d validator registration processors", numValidatorRegProcessors)
		for i := 0; i < numValidatorRegProcessors; i++ {
			go api.startValidatorRegistrationDBProcessor()
		}
	}

	// start block-builder API specific things
	if api.opts.BlockBuilderAPI {
		// Get current proposer duties blocking before starting, to have them ready
		api.updateProposerDuties(syncStatus.HeadSlot)

		// Subscribe to payload attributes events (only for builder-api)
		go func() {
			c := make(chan beaconclient.PayloadAttributesEvent)
			api.beaconClient.SubscribeToPayloadAttributesEvents(c)
			for {
				payloadAttributes := <-c
				api.processPayloadAttributes(payloadAttributes)
			}
		}()
	}

	// Process current slot
	api.processNewSlot(currentSlot)

	// Start regular slot updates
	go func() {
		c := make(chan beaconclient.HeadEventData)
		api.beaconClient.SubscribeToHeadEvents(c)
		for {
			headEvent := <-c
			api.processNewSlot(headEvent.Slot)
		}
	}()

	// create and start HTTP server
	api.srv = &http.Server{
		Addr:    api.opts.ListenAddr,
		Handler: api.getRouter(),

		ReadTimeout:       time.Duration(apiReadTimeoutMs) * time.Millisecond,
		ReadHeaderTimeout: time.Duration(apiReadHeaderTimeoutMs) * time.Millisecond,
		WriteTimeout:      time.Duration(apiWriteTimeoutMs) * time.Millisecond,
		IdleTimeout:       time.Duration(apiIdleTimeoutMs) * time.Millisecond,
		MaxHeaderBytes:    apiMaxHeaderBytes,
	}
	err = api.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (api *RelayAPI) IsReady() bool {
	// If server is shutting down, return false
	if api.srvShutdown.Load() {
		return false
	}

	// Proposer API readiness checks
	if api.opts.ProposerAPI {
		knownValidatorsUpdated := api.datastore.KnownValidatorsWasUpdated.Load()
		return knownValidatorsUpdated
	}

	// Block-builder API readiness checks
	return true
}

// StopServer gracefully shuts down the HTTP server:
// - Stop returning bids
// - Set ready /readyz to negative status
// - Wait a bit to allow removal of service from load balancer and draining of requests
func (api *RelayAPI) StopServer() (err error) {
	// avoid running this twice. setting srvShutdown to true makes /readyz switch to negative status
	if wasStopping := api.srvShutdown.Swap(true); wasStopping {
		return nil
	}

	// start server shutdown
	api.log.Info("Stopping server...")

	// stop returning bids on getHeader calls (should only be used when running a single instance)
	if api.opts.ProposerAPI && apiShutdownStopSendingBids {
		api.ffForceGetHeader204 = true
		api.log.Info("Disabled returning bids on getHeader")
	}

	// wait some time to get service removed from load balancer
	api.log.Infof("Waiting %.2f seconds before shutdown...", apiShutdownWaitDuration.Seconds())
	time.Sleep(apiShutdownWaitDuration)

	// wait for any active getPayload call to finish
	api.getPayloadCallsInFlight.Wait()

	// shutdown
	return api.srv.Shutdown(context.Background())
}

func (api *RelayAPI) startValidatorRegistrationDBProcessor() {
	for valReg := range api.validatorRegC {
		err := api.datastore.SaveValidatorRegistration(valReg)
		if err != nil {
			api.log.WithError(err).WithFields(logrus.Fields{
				"reg_pubkey":       valReg.Message.Pubkey,
				"reg_feeRecipient": valReg.Message.FeeRecipient,
				"reg_gasLimit":     valReg.Message.GasLimit,
				"reg_timestamp":    valReg.Message.Timestamp,
			}).Error("error saving validator registration")
		}
	}
}

// simulateBlock sends a request for a block simulation to blockSimRateLimiter.
func (api *RelayAPI) assembleBlock(ctx context.Context, opts blockAssemblyOptions) (*capella2.ExecutionPayload, error, error) {
	t := time.Now()
	res, requestErr, validationErr := api.blockAssembler.Send(ctx, opts.req)
	log := opts.log.WithFields(logrus.Fields{
		"durationMs": time.Since(t).Milliseconds(),
		"numWaiting": api.blockSimRateLimiter.CurrentCounter(),
	})
	if validationErr != nil {
		if api.ffIgnorableValidationErrors {
			// Operators chooses to ignore certain validation errors
			ignoreError := validationErr.Error() == ErrBlockAlreadyKnown || validationErr.Error() == ErrBlockRequiresReorg || strings.Contains(validationErr.Error(), ErrMissingTrieNode)
			if ignoreError {
				log.WithError(validationErr).Warn("block validation failed with ignorable error")
				return nil, nil, nil
			}
		}
		log.WithError(validationErr).Warn("block validation failed")
		return nil, validationErr, nil
	}
	if requestErr != nil {
		log.WithError(requestErr).Warn("block validation failed: request error")
		return nil, requestErr, nil
	}
	log.Info("block validation successful")
	return res, nil, nil
}

// simulateBlock sends a request for a block simulation to blockSimRateLimiter.
func (api *RelayAPI) simulateBlock(ctx context.Context, opts blockSimOptions) (requestErr, validationErr error) {
	t := time.Now()
	requestErr, validationErr = api.blockSimRateLimiter.Send(ctx, opts.req, opts.isHighPrio, opts.fastTrack)
	log := opts.log.WithFields(logrus.Fields{
		"durationMs": time.Since(t).Milliseconds(),
		"numWaiting": api.blockSimRateLimiter.CurrentCounter(),
	})
	if validationErr != nil {
		if api.ffIgnorableValidationErrors {
			// Operators chooses to ignore certain validation errors
			ignoreError := validationErr.Error() == ErrBlockAlreadyKnown || validationErr.Error() == ErrBlockRequiresReorg || strings.Contains(validationErr.Error(), ErrMissingTrieNode)
			if ignoreError {
				log.WithError(validationErr).Warn("block validation failed with ignorable error")
				return nil, nil
			}
		}
		log.WithError(validationErr).Warn("block validation failed")
		return nil, validationErr
	}
	if requestErr != nil {
		log.WithError(requestErr).Warn("block validation failed: request error")
		return requestErr, nil
	}
	log.Info("block validation successful")
	return nil, nil
}

func (api *RelayAPI) demoteBuilder(pubkey string, req *common.BuilderSubmitBlockRequest, simError error) {
	builderEntry, ok := api.blockBuildersCache[pubkey]
	if !ok {
		api.log.Warnf("builder %v not in the builder cache", pubkey)
		builderEntry = &blockBuilderCacheEntry{} //nolint:exhaustruct
	}
	newStatus := common.BuilderStatus{
		IsHighPrio:    builderEntry.status.IsHighPrio,
		IsBlacklisted: builderEntry.status.IsBlacklisted,
		IsOptimistic:  false,
	}
	api.log.Infof("demoted builder, new status: %v", newStatus)
	if err := api.db.SetBlockBuilderIDStatusIsOptimistic(pubkey, false); err != nil {
		api.log.Error(fmt.Errorf("error setting builder: %v status: %w", pubkey, err))
	}
	// Write to demotions table.
	api.log.WithFields(logrus.Fields{"builder_pubkey": pubkey}).Info("demoting builder")
	if err := api.db.InsertBuilderDemotion(req, simError); err != nil {
		api.log.WithError(err).WithFields(logrus.Fields{
			"errorWritingDemotionToDB": true,
			"bidTrace":                 req.Message,
			"simError":                 simError,
		}).Error("failed to save demotion to database")
	}
}

// processOptimisticBlock is called on a new goroutine when a optimistic block
// needs to be simulated.
func (api *RelayAPI) processOptimisticBlock(opts blockSimOptions, simResultC chan *blockSimResult) {
	api.optimisticBlocksInFlight.Add(1)
	defer func() { api.optimisticBlocksInFlight.Sub(1) }()
	api.optimisticBlocksWG.Add(1)
	defer api.optimisticBlocksWG.Done()

	ctx := context.Background()
	builderPubkey := opts.req.BuilderPubkey().String()
	opts.log.WithFields(logrus.Fields{
		"builderPubkey": builderPubkey,
		// NOTE: this value is just an estimate because many goroutines could be
		// updating api.optimisticBlocksInFlight concurrently. Since we just use
		// it for logging, it is not atomic to avoid the performance impact.
		"optBlocksInFlight": api.optimisticBlocksInFlight,
	}).Infof("simulating optimistic block with hash: %v", opts.req.BuilderSubmitBlockRequest.BlockHash())
	reqErr, simErr := api.simulateBlock(ctx, opts)
	simResultC <- &blockSimResult{reqErr == nil, true, reqErr, simErr}
	if reqErr != nil || simErr != nil {
		// Mark builder as non-optimistic.
		opts.builder.status.IsOptimistic = false
		api.log.WithError(simErr).Warn("block simulation failed in processOptimisticBlock, demoting builder")

		var demotionErr error
		if reqErr != nil {
			demotionErr = reqErr
		} else {
			demotionErr = simErr
		}

		// Demote the builder.
		api.demoteBuilder(builderPubkey, &opts.req.BuilderSubmitBlockRequest, demotionErr)
	}
}

func (api *RelayAPI) processPayloadAttributes(payloadAttributes beaconclient.PayloadAttributesEvent) {
	apiHeadSlot := api.headSlot.Load()
	payloadAttrSlot := payloadAttributes.Data.ProposalSlot

	// require proposal slot in the future
	if payloadAttrSlot <= apiHeadSlot {
		return
	}
	log := api.log.WithFields(logrus.Fields{
		"headSlot":          apiHeadSlot,
		"payloadAttrSlot":   payloadAttrSlot,
		"payloadAttrParent": payloadAttributes.Data.ParentBlockHash,
	})

	// discard payload attributes if already known
	api.payloadAttributesLock.RLock()
	_, ok := api.payloadAttributes[payloadAttributes.Data.ParentBlockHash]
	api.payloadAttributesLock.RUnlock()

	if ok {
		return
	}

	var withdrawalsRoot phase0.Root
	var err error
	if hasReachedFork(payloadAttrSlot, api.capellaEpoch) {
		withdrawalsRoot, err = ComputeWithdrawalsRoot(payloadAttributes.Data.PayloadAttributes.Withdrawals)
		log = log.WithField("withdrawalsRoot", withdrawalsRoot.String())
		if err != nil {
			log.WithError(err).Error("error computing withdrawals root")
			return
		}
	}

	api.payloadAttributesLock.Lock()
	defer api.payloadAttributesLock.Unlock()

	// Step 1: clean up old ones
	for parentBlockHash, attr := range api.payloadAttributes {
		if attr.slot < apiHeadSlot {
			delete(api.payloadAttributes, parentBlockHash)
		}
	}

	// Step 2: save new one
	api.payloadAttributes[payloadAttributes.Data.ParentBlockHash] = payloadAttributesHelper{
		slot:              payloadAttrSlot,
		parentHash:        payloadAttributes.Data.ParentBlockHash,
		withdrawalsRoot:   withdrawalsRoot,
		payloadAttributes: payloadAttributes.Data.PayloadAttributes,
	}

	log.WithFields(logrus.Fields{
		"randao":    payloadAttributes.Data.PayloadAttributes.PrevRandao,
		"timestamp": payloadAttributes.Data.PayloadAttributes.Timestamp,
	}).Info("updated payload attributes")
}

func (api *RelayAPI) processNewSlot(headSlot uint64) {
	prevHeadSlot := api.headSlot.Load()
	if headSlot <= prevHeadSlot {
		return
	}

	// If there's gaps between previous and new headslot, print the missed slots
	if prevHeadSlot > 0 {
		for s := prevHeadSlot + 1; s < headSlot; s++ {
			api.log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
		}
	}

	// store the head slot
	api.headSlot.Store(headSlot)

	// only for builder-api
	if api.opts.BlockBuilderAPI || api.opts.ProposerAPI {
		// update proposer duties in the background
		go api.updateProposerDuties(headSlot)

		// update the optimistic slot
		go api.prepareBuildersForSlot(headSlot)
	}

	if api.opts.ProposerAPI {
		go api.datastore.RefreshKnownValidators(api.log, api.beaconClient, headSlot)
	}

	// log
	epoch := headSlot / common.SlotsPerEpoch
	api.log.WithFields(logrus.Fields{
		"epoch":              epoch,
		"slotHead":           headSlot,
		"slotStartNextEpoch": (epoch + 1) * common.SlotsPerEpoch,
	}).Infof("updated headSlot to %d", headSlot)
}

func (api *RelayAPI) updateProposerDuties(headSlot uint64) {
	// Ensure only one updating is running at a time
	if api.isUpdatingProposerDuties.Swap(true) {
		return
	}
	defer api.isUpdatingProposerDuties.Store(false)

	// Update once every 8 slots (or more, if a slot was missed)
	if headSlot%8 != 0 && headSlot-api.proposerDutiesSlot < 8 {
		return
	}

	// Load upcoming proposer duties from Redis
	duties, err := api.redis.GetProposerDuties()
	if err != nil {
		api.log.WithError(err).Error("failed getting proposer duties from redis")
		return
	}

	// Prepare raw bytes for HTTP response
	respBytes, err := json.Marshal(duties)
	if err != nil {
		api.log.WithError(err).Error("error marshalling duties")
	}

	// Prepare the map for lookup by slot
	dutiesMap := make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	for index, duty := range duties {
		dutiesMap[duty.Slot] = &duties[index]
	}

	// Update
	api.proposerDutiesLock.Lock()
	if len(respBytes) > 0 {
		api.proposerDutiesResponse = &respBytes
	}
	api.proposerDutiesMap = dutiesMap
	api.proposerDutiesSlot = headSlot
	api.proposerDutiesLock.Unlock()

	// pretty-print
	_duties := make([]string, len(duties))
	for i, duty := range duties {
		_duties[i] = fmt.Sprint(duty.Slot)
	}
	sort.Strings(_duties)
	api.log.Infof("proposer duties updated: %s", strings.Join(_duties, ", "))
}

func (api *RelayAPI) prepareBuildersForSlot(headSlot uint64) {
	// Wait until there are no optimistic blocks being processed. Then we can
	// safely update the slot.
	api.optimisticBlocksWG.Wait()
	api.optimisticSlot.Store(headSlot + 1)

	builders, err := api.db.GetBlockBuilders()
	if err != nil {
		api.log.WithError(err).Error("unable to read block builders from db, not updating builder cache")
		return
	}
	api.log.Debugf("Updating builder cache with %d builders from database", len(builders))

	newCache := make(map[string]*blockBuilderCacheEntry)
	for _, v := range builders {
		entry := &blockBuilderCacheEntry{ //nolint:exhaustruct
			status: common.BuilderStatus{
				IsHighPrio:    v.IsHighPrio,
				IsBlacklisted: v.IsBlacklisted,
				IsOptimistic:  v.IsOptimistic,
			},
		}
		// Try to parse builder collateral string to big int.
		builderCollateral, ok := big.NewInt(0).SetString(v.Collateral, 10)
		if !ok {
			api.log.WithError(err).Errorf("could not parse builder collateral string %s", v.Collateral)
			entry.collateral = big.NewInt(0)
		} else {
			entry.collateral = builderCollateral
		}
		newCache[v.BuilderPubkey] = entry
	}
	api.blockBuildersCache = newCache
}

func (api *RelayAPI) RespondError(w http.ResponseWriter, code int, message string) {
	api.Respond(w, code, HTTPErrorResp{code, message})
}

func (api *RelayAPI) RespondOK(w http.ResponseWriter, response any) {
	api.Respond(w, http.StatusOK, response)
}

func (api *RelayAPI) RespondMsg(w http.ResponseWriter, code int, msg string) {
	api.Respond(w, code, HTTPMessageResp{msg})
}

func (api *RelayAPI) Respond(w http.ResponseWriter, code int, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if response == nil {
		return
	}

	// write the json response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		api.log.WithField("response", response).WithError(err).Error("Couldn't write response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *RelayAPI) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// ---------------
//  PROPOSER APIS
// ---------------

func (api *RelayAPI) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "MEV-Boost Relay API")
}

func (api *RelayAPI) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	ua := req.UserAgent()
	log := api.log.WithFields(logrus.Fields{
		"method":        "registerValidator",
		"ua":            ua,
		"mevBoostV":     common.GetMevBoostVersionFromUserAgent(ua),
		"headSlot":      api.headSlot.Load(),
		"contentLength": req.ContentLength,
	})
	log.Infof("DEBUGGG: handleRegisterValidator request received!!")

	start := time.Now().UTC()
	registrationTimestampUpperBound := start.Unix() + 10 // 10 seconds from now

	numRegTotal := 0
	numRegProcessed := 0
	numRegActive := 0
	numRegNew := 0
	processingStoppedByError := false

	// Setup error handling
	handleError := func(_log *logrus.Entry, code int, msg string) {
		processingStoppedByError = true
		_log.Warnf("error: %s", msg)
		api.RespondError(w, code, msg)
	}

	// Start processing
	if req.ContentLength == 0 {
		log.Info("empty request")
		api.RespondError(w, http.StatusBadRequest, "empty request")
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.WithError(err).WithField("contentLength", req.ContentLength).Warn("failed to read request body")
		api.RespondError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	req.Body.Close()

	parseRegistration := func(value []byte) (reg *boostTypes.SignedValidatorRegistration, err error) {
		// Pubkey
		_pubkey, err := jsonparser.GetUnsafeString(value, "message", "pubkey")
		if err != nil {
			return nil, fmt.Errorf("registration message error (pubkey): %w", err)
		}

		pubkey, err := boostTypes.HexToPubkey(_pubkey)
		if err != nil {
			return nil, fmt.Errorf("registration message error (pubkey): %w", err)
		}

		// Timestamp
		_timestamp, err := jsonparser.GetUnsafeString(value, "message", "timestamp")
		if err != nil {
			return nil, fmt.Errorf("registration message error (timestamp): %w", err)
		}

		timestamp, err := strconv.ParseUint(_timestamp, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp: %w", err)
		}

		// GasLimit
		_gasLimit, err := jsonparser.GetUnsafeString(value, "message", "gas_limit")
		if err != nil {
			return nil, fmt.Errorf("registration message error (gasLimit): %w", err)
		}

		gasLimit, err := strconv.ParseUint(_gasLimit, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid gasLimit: %w", err)
		}

		// FeeRecipient
		_feeRecipient, err := jsonparser.GetUnsafeString(value, "message", "fee_recipient")
		if err != nil {
			return nil, fmt.Errorf("registration message error (fee_recipient): %w", err)
		}

		feeRecipient, err := boostTypes.HexToAddress(_feeRecipient)
		if err != nil {
			return nil, fmt.Errorf("registration message error (fee_recipient): %w", err)
		}

		// Signature
		_signature, err := jsonparser.GetUnsafeString(value, "signature")
		if err != nil {
			return nil, fmt.Errorf("registration message error (signature): %w", err)
		}

		signature, err := boostTypes.HexToSignature(_signature)
		if err != nil {
			return nil, fmt.Errorf("registration message error (signature): %w", err)
		}

		// Construct and return full registration object
		reg = &boostTypes.SignedValidatorRegistration{
			Message: &boostTypes.RegisterValidatorRequestMessage{
				FeeRecipient: feeRecipient,
				GasLimit:     gasLimit,
				Timestamp:    timestamp,
				Pubkey:       pubkey,
			},
			Signature: signature,
		}

		return reg, nil
	}

	// Iterate over the registrations
	_, err = jsonparser.ArrayEach(body, func(value []byte, dataType jsonparser.ValueType, offset int, _err error) {
		numRegTotal += 1
		if processingStoppedByError {
			return
		}
		numRegProcessed += 1
		regLog := log.WithFields(logrus.Fields{
			"numRegistrationsSoFar":     numRegTotal,
			"numRegistrationsProcessed": numRegProcessed,
		})

		// Extract immediately necessary registration fields
		signedValidatorRegistration, err := parseRegistration(value)
		if err != nil {
			handleError(regLog, http.StatusBadRequest, err.Error())
			return
		}

		// Add validator pubkey to logs
		pkHex := signedValidatorRegistration.Message.Pubkey.PubkeyHex()
		regLog = regLog.WithFields(logrus.Fields{
			"pubkey":       pkHex,
			"signature":    signedValidatorRegistration.Signature.String(),
			"feeRecipient": signedValidatorRegistration.Message.FeeRecipient.String(),
			"gasLimit":     signedValidatorRegistration.Message.GasLimit,
			"timestamp":    signedValidatorRegistration.Message.Timestamp,
		})

		// Ensure a valid timestamp (not too early, and not too far in the future)
		registrationTimestamp := int64(signedValidatorRegistration.Message.Timestamp)
		if registrationTimestamp < int64(api.genesisInfo.Data.GenesisTime) {
			handleError(regLog, http.StatusBadRequest, "timestamp too early")
			return
		} else if registrationTimestamp > registrationTimestampUpperBound {
			handleError(regLog, http.StatusBadRequest, "timestamp too far in the future")
			return
		}

		// Check if a real validator
		isKnownValidator := api.datastore.IsKnownValidator(pkHex)
		if !isKnownValidator {
			handleError(regLog, http.StatusBadRequest, fmt.Sprintf("not a known validator: %s", pkHex.String()))
			return
		}

		// Check for a previous registration timestamp
		prevTimestamp, err := api.redis.GetValidatorRegistrationTimestamp(pkHex)
		if err != nil {
			regLog.WithError(err).Error("error getting last registration timestamp")
		} else if prevTimestamp >= signedValidatorRegistration.Message.Timestamp {
			// abort if the current registration timestamp is older or equal to the last known one
			return
		}

		// Verify the signature
		ok, err := boostTypes.VerifySignature(signedValidatorRegistration.Message, api.opts.EthNetDetails.DomainBuilder, signedValidatorRegistration.Message.Pubkey[:], signedValidatorRegistration.Signature[:])
		if err != nil {
			regLog.WithError(err).Error("error verifying registerValidator signature")
			return
		} else if !ok {
			regLog.Info("invalid validator signature")
			if api.ffRegValContinueOnInvalidSig {
				return
			} else {
				handleError(regLog, http.StatusBadRequest, fmt.Sprintf("failed to verify validator signature for %s", signedValidatorRegistration.Message.Pubkey.String()))
				return
			}
		}

		// Now we have a new registration to process
		numRegNew += 1

		// Save to database
		select {
		case api.validatorRegC <- *signedValidatorRegistration:
		default:
			regLog.Error("validator registration channel full")
		}
	})

	log = log.WithFields(logrus.Fields{
		"timeNeededSec":             time.Since(start).Seconds(),
		"timeNeededMs":              time.Since(start).Milliseconds(),
		"numRegistrations":          numRegTotal,
		"numRegistrationsActive":    numRegActive,
		"numRegistrationsProcessed": numRegProcessed,
		"numRegistrationsNew":       numRegNew,
		"processingStoppedByError":  processingStoppedByError,
	})

	if err != nil {
		handleError(log, http.StatusBadRequest, "error in traversing json")
		return
	}

	log.Info("validator registrations call processed")
	w.WriteHeader(http.StatusOK)
}

func (api *RelayAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slotStr := vars["slot"]
	parentHashHex := vars["parent_hash"]
	proposerPubkeyHex := vars["pubkey"]
	ua := req.UserAgent()
	headSlot := api.headSlot.Load()

	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSlot.Error())
		return
	}

	requestTime := time.Now().UTC()
	slotStartTimestamp := api.genesisInfo.Data.GenesisTime + (slot * common.SecondsPerSlot)
	msIntoSlot := requestTime.UnixMilli() - int64((slotStartTimestamp * 1000))

	log := api.log.WithFields(logrus.Fields{
		"method":           "getHeader",
		"headSlot":         headSlot,
		"slot":             slotStr,
		"parentHash":       parentHashHex,
		"pubkey":           proposerPubkeyHex,
		"ua":               ua,
		"mevBoostV":        common.GetMevBoostVersionFromUserAgent(ua),
		"requestTimestamp": requestTime.Unix(),
		"slotStartSec":     slotStartTimestamp,
		"msIntoSlot":       msIntoSlot,
	})

	if len(proposerPubkeyHex) != 98 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidPubkey.Error())
		return
	}

	if len(parentHashHex) != 66 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidHash.Error())
		return
	}

	if slot < headSlot {
		api.RespondError(w, http.StatusBadRequest, "slot is too old")
		return
	}

	log.Debug("getHeader request received")

	if slices.Contains(apiNoHeaderUserAgents, ua) {
		log.Info("rejecting getHeader by user agent")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if api.ffForceGetHeader204 {
		log.Info("forced getHeader 204 response")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Only allow requests for the current slot until a certain cutoff time
	if getHeaderRequestCutoffMs > 0 && msIntoSlot > 0 && msIntoSlot > int64(getHeaderRequestCutoffMs) {
		log.Info("getHeader sent too late")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	bid, err := api.redis.GetBestBid(slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		log.WithError(err).Error("could not get bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if bid.Empty() {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Error on bid without value
	if bid.Value().Cmp(big.NewInt(0)) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.WithFields(logrus.Fields{
		"value":     bid.Value().String(),
		"blockHash": bid.BlockHash().String(),
	}).Info("bid delivered")
	api.RespondOK(w, bid)
}

func (api *RelayAPI) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	api.getPayloadCallsInFlight.Add(1)
	defer api.getPayloadCallsInFlight.Done()

	ua := req.UserAgent()
	headSlot := api.headSlot.Load()
	receivedAt := time.Now().UTC()
	log := api.log.WithFields(logrus.Fields{
		"method":                "getPayload",
		"ua":                    ua,
		"mevBoostV":             common.GetMevBoostVersionFromUserAgent(ua),
		"contentLength":         req.ContentLength,
		"headSlot":              headSlot,
		"headSlotEpochPos":      (headSlot % common.SlotsPerEpoch) + 1,
		"idArg":                 req.URL.Query().Get("id"),
		"timestampRequestStart": receivedAt.UnixMilli(),
	})

	// Log at start and end of request
	log.Info("request initiated")
	defer func() {
		log.WithFields(logrus.Fields{
			"timestampRequestFin": time.Now().UTC().UnixMilli(),
			"requestDurationMs":   time.Since(receivedAt).Milliseconds(),
		}).Info("request finished")
	}()

	// Read the body first, so we can decode it later
	body, err := io.ReadAll(req.Body)
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			log.WithError(err).Error("getPayload request failed to decode (i/o timeout)")
			api.RespondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		log.WithError(err).Error("could not read body of request from the beacon node")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Decode payload
	payload := new(common.SignedBlindedBeaconBlock)
	// TODO: add deneb support.
	payload.Capella = new(capella.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(payload.Capella); err != nil {
		log.WithError(err).Warn("failed to decode capella getPayload request")
		api.RespondError(w, http.StatusBadRequest, "failed to decode capella payload")
		return
	}

	// Take time after the decoding, and add to logging
	decodeTime := time.Now().UTC()
	slotStartTimestamp := api.genesisInfo.Data.GenesisTime + (payload.Slot() * common.SecondsPerSlot)
	msIntoSlot := decodeTime.UnixMilli() - int64((slotStartTimestamp * 1000))
	log = log.WithFields(logrus.Fields{
		"slot":                 payload.Slot(),
		"slotEpochPos":         (payload.Slot() % common.SlotsPerEpoch) + 1,
		"blockHash":            payload.BlockHash(),
		"slotStartSec":         slotStartTimestamp,
		"msIntoSlot":           msIntoSlot,
		"timestampAfterDecode": decodeTime.UnixMilli(),
		"proposerIndex":        payload.ProposerIndex(),
	})

	// Ensure the proposer index is expected
	api.proposerDutiesLock.RLock()
	slotDuty := api.proposerDutiesMap[payload.Slot()]
	api.proposerDutiesLock.RUnlock()
	if slotDuty == nil {
		log.Warn("could not find slot duty")
	} else {
		log = log.WithField("feeRecipient", slotDuty.Entry.Message.FeeRecipient)
		if slotDuty.ValidatorIndex != payload.ProposerIndex() {
			log.WithField("expectedProposerIndex", slotDuty.ValidatorIndex).Warn("not the expected proposer index")
			api.RespondError(w, http.StatusBadRequest, "not the expected proposer index")
			return
		}
	}

	// Get the proposer pubkey based on the validator index from the payload
	proposerPubkey, found := api.datastore.GetKnownValidatorPubkeyByIndex(payload.ProposerIndex())
	if !found {
		log.Errorf("could not find proposer pubkey for index %d", payload.ProposerIndex())
		api.RespondError(w, http.StatusBadRequest, "could not match proposer index to pubkey")
		return
	}

	// Add proposer pubkey to logs
	log = log.WithField("proposerPubkey", proposerPubkey.String())

	// Create a BLS pubkey from the hex pubkey
	pk, err := boostTypes.HexToPubkey(proposerPubkey.String())
	if err != nil {
		log.WithError(err).Warn("could not convert pubkey to types.PublicKey")
		api.RespondError(w, http.StatusBadRequest, "could not convert pubkey to types.PublicKey")
		return
	}

	// Validate proposer signature (first attempt verifying the Capella signature)
	// TODO: add deneb support.
	ok, err := boostTypes.VerifySignature(payload.Message(), api.opts.EthNetDetails.DomainBeaconProposerCapella, pk[:], payload.Signature())
	if !ok || err != nil {
		if api.ffLogInvalidSignaturePayload {
			txt, _ := json.Marshal(payload) //nolint:errchkjson
			fmt.Println("payload_invalid_sig_capella: ", string(txt), "pubkey:", proposerPubkey.String())
		}
		log.WithError(err).Warn("could not verify capella payload signature")
		api.RespondError(w, http.StatusBadRequest, "could not verify payload signature")
		return
	}

	// Log about received payload (with a valid proposer signature)
	log = log.WithField("timestampAfterSignatureVerify", time.Now().UTC().UnixMilli())
	log.Info("getPayload request received")

	// TODO: store signed blinded block in database (always)

	// Get the response - from Redis, Memcache or DB
	// note that recent mev-boost versions only send getPayload to relays that provided the bid
	getPayloadResp, err := api.datastore.GetGetPayloadResponse(log, payload.Slot(), proposerPubkey.String(), payload.BlockHash())
	if err != nil || getPayloadResp == nil {
		log.WithError(err).Warn("failed getting execution payload (1/2)")
		time.Sleep(time.Duration(timeoutGetPayloadRetryMs) * time.Millisecond)

		// Try again
		getPayloadResp, err = api.datastore.GetGetPayloadResponse(log, payload.Slot(), proposerPubkey.String(), payload.BlockHash())
		if err != nil || getPayloadResp == nil {
			// Still not found! Error out now.
			if errors.Is(err, datastore.ErrExecutionPayloadNotFound) {
				// Couldn't find the execution payload, maybe it never was submitted to our relay! Check that now
				_, err := api.db.GetBlockSubmissionEntry(payload.Slot(), proposerPubkey.String(), payload.BlockHash())
				if errors.Is(err, sql.ErrNoRows) {
					log.Warn("failed getting execution payload (2/2) - payload not found, block was never submitted to this relay")
					api.RespondError(w, http.StatusBadRequest, "no execution payload for this request - block was never seen by this relay")
				} else if err != nil {
					log.WithError(err).Error("failed getting execution payload (2/2) - payload not found, and error on checking bids")
				} else {
					log.Error("failed getting execution payload (2/2) - payload not found, but found bid in database")
				}
			} else { // some other error
				log.WithError(err).Error("failed getting execution payload (2/2) - error")
			}
			api.RespondError(w, http.StatusBadRequest, "no execution payload for this request")
			return
		}
	}

	// Now we know this relay also has the payload
	log = log.WithField("timestampAfterLoadResponse", time.Now().UTC().UnixMilli())

	// Check whether getPayload has already been called -- TODO: do we need to allow multiple submissions of one blinded block?
	err = api.redis.CheckAndSetLastSlotAndHashDelivered(payload.Slot(), payload.BlockHash())
	log = log.WithField("timestampAfterAlreadyDeliveredCheck", time.Now().UTC().UnixMilli())
	if err != nil {
		if errors.Is(err, datastore.ErrAnotherPayloadAlreadyDeliveredForSlot) {
			// BAD VALIDATOR, 2x GETPAYLOAD FOR DIFFERENT PAYLOADS
			log.Warn("validator called getPayload twice for different payload hashes")
			api.RespondError(w, http.StatusBadRequest, "another payload for this slot was already delivered")
			return
		} else if errors.Is(err, datastore.ErrPastSlotAlreadyDelivered) {
			// BAD VALIDATOR, 2x GETPAYLOAD FOR PAST SLOT
			log.Warn("validator called getPayload for past slot")
			api.RespondError(w, http.StatusBadRequest, "payload for this slot was already delivered")
			return
		} else if errors.Is(err, redis.TxFailedErr) {
			// BAD VALIDATOR, 2x GETPAYLOAD + RACE
			log.Warn("validator called getPayload twice (race)")
			api.RespondError(w, http.StatusBadRequest, "payload for this slot was already delivered (race)")
			return
		}
		log.WithError(err).Error("redis.CheckAndSetLastSlotAndHashDelivered failed")
	}

	// Handle early/late requests
	if msIntoSlot < 0 {
		// Wait until slot start (t=0) if still in the future
		_msSinceSlotStart := time.Now().UTC().UnixMilli() - int64((slotStartTimestamp * 1000))
		if _msSinceSlotStart < 0 {
			delayMillis := _msSinceSlotStart * -1
			log = log.WithField("delayMillis", delayMillis)
			log.Info("waiting until slot start t=0")
			time.Sleep(time.Duration(delayMillis) * time.Millisecond)
		}
	} else if getPayloadRequestCutoffMs > 0 && msIntoSlot > int64(getPayloadRequestCutoffMs) {
		// Reject requests after cutoff time
		log.Warn("getPayload sent too late")
		api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("sent too late - %d ms into slot", msIntoSlot))

		go func() {
			err := api.db.InsertTooLateGetPayload(payload.Slot(), proposerPubkey.String(), payload.BlockHash(), slotStartTimestamp, uint64(receivedAt.UnixMilli()), uint64(decodeTime.UnixMilli()), uint64(msIntoSlot))
			if err != nil {
				log.WithError(err).Error("failed to insert payload too late into db")
			}
		}()
		return
	}

	// Check that ExecutionPayloadHeader fields (sent by the proposer) match our known ExecutionPayload
	err = EqExecutionPayloadToHeader(payload, getPayloadResp)
	if err != nil {
		log.WithError(err).Warn("ExecutionPayloadHeader not matching known ExecutionPayload")
		api.RespondError(w, http.StatusBadRequest, "invalid execution payload header")
		return
	}

	// Publish the signed beacon block via beacon-node
	timeBeforePublish := time.Now().UTC().UnixMilli()
	log = log.WithField("timestampBeforePublishing", timeBeforePublish)
	signedBeaconBlock := common.SignedBlindedBeaconBlockToBeaconBlock(payload, getPayloadResp)
	code, err := api.beaconClient.PublishBlock(signedBeaconBlock) // errors are logged inside
	if err != nil || code != http.StatusOK {
		log.WithError(err).WithField("code", code).Error("failed to publish block")
		api.RespondError(w, http.StatusBadRequest, "failed to publish block")
		return
	}
	timeAfterPublish := time.Now().UTC().UnixMilli()
	msNeededForPublishing := uint64(timeAfterPublish - timeBeforePublish)
	log = log.WithField("timestampAfterPublishing", timeAfterPublish)
	log.WithField("msNeededForPublishing", msNeededForPublishing).Info("block published through beacon node")

	// give the beacon network some time to propagate the block
	time.Sleep(time.Duration(getPayloadResponseDelayMs) * time.Millisecond)

	// respond to the HTTP request
	api.RespondOK(w, getPayloadResp)
	log = log.WithFields(logrus.Fields{
		"numTx":       getPayloadResp.NumTx(),
		"blockNumber": payload.BlockNumber(),
	})
	log.Info("execution payload delivered")

	// Save information about delivered payload
	go func() {
		bidTrace, err := api.redis.GetBidTrace(payload.Slot(), proposerPubkey.String(), payload.BlockHash())
		if err != nil {
			log.WithError(err).Error("failed to get bidTrace for delivered payload from redis")
			return
		}

		err = api.db.SaveDeliveredPayload(bidTrace, payload, decodeTime, msNeededForPublishing)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"bidTrace": bidTrace,
				"payload":  payload,
			}).Error("failed to save delivered payload")
		}

		// Increment builder stats
		err = api.db.IncBlockBuilderStatsAfterGetPayload(bidTrace.BuilderPubkey.String())
		if err != nil {
			log.WithError(err).Error("failed to increment builder-stats after getPayload")
		}

		// Wait until optimistic blocks are complete.
		api.optimisticBlocksWG.Wait()

		// Check if there is a demotion for the winning block.
		_, err = api.db.GetBuilderDemotion(bidTrace)
		// If demotion not found, we are done!
		if errors.Is(err, sql.ErrNoRows) {
			log.Info("no demotion in getPayload, successful block proposal")
			return
		}
		if err != nil {
			log.WithError(err).Error("failed to read demotion table in getPayload")
			return
		}
		// Demotion found, update the demotion table with refund data.
		builderPubkey := bidTrace.BuilderPubkey.String()
		log = log.WithFields(logrus.Fields{
			"builderPubkey": builderPubkey,
			"slot":          bidTrace.Slot,
			"blockHash":     bidTrace.BlockHash,
		})
		log.Warn("demotion found in getPayload, inserting refund justification")

		// Prepare refund data.
		signedBeaconBlock := common.SignedBlindedBeaconBlockToBeaconBlock(payload, getPayloadResp)

		// Get registration entry from the DB.
		registrationEntry, err := api.db.GetValidatorRegistration(proposerPubkey.String())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.WithError(err).Error("no registration found for validator " + proposerPubkey.String())
			} else {
				log.WithError(err).Error("error reading validator registration")
			}
		}
		var signedRegistration *boostTypes.SignedValidatorRegistration
		if registrationEntry != nil {
			signedRegistration, err = registrationEntry.ToSignedValidatorRegistration()
			if err != nil {
				log.WithError(err).Error("error converting registration to signed registration")
			}
		}

		err = api.db.UpdateBuilderDemotion(bidTrace, signedBeaconBlock, signedRegistration)
		if err != nil {
			log.WithFields(logrus.Fields{
				"errorWritingRefundToDB": true,
				"bidTrace":               bidTrace,
				"signedBeaconBlock":      signedBeaconBlock,
				"signedRegistration":     signedRegistration,
			}).WithError(err).Error("unable to update builder demotion with refund justification")
		}
	}()
}

// --------------------
//
//	BLOCK BUILDER APIS
//
// --------------------
func (api *RelayAPI) handleBuilderGetValidators(w http.ResponseWriter, req *http.Request) {
	api.proposerDutiesLock.RLock()
	resp := api.proposerDutiesResponse
	api.proposerDutiesLock.RUnlock()
	_, err := w.Write(*resp)
	if err != nil {
		api.log.WithError(err).Warn("failed to write response for builderGetValidators")
	}
}

func (api *RelayAPI) checkSubmissionFeeRecipient(w http.ResponseWriter, log *logrus.Entry, payload *common.BuilderSubmitBlockRequest) (uint64, bool) {
	api.proposerDutiesLock.RLock()
	slotDuty := api.proposerDutiesMap[payload.Slot()]
	api.proposerDutiesLock.RUnlock()
	if slotDuty == nil {
		log.Warn("could not find slot duty")
		api.RespondError(w, http.StatusBadRequest, "could not find slot duty")
		return 0, false
	} else if !strings.EqualFold(slotDuty.Entry.Message.FeeRecipient.String(), payload.ProposerFeeRecipient()) {
		log.WithFields(logrus.Fields{
			"expectedFeeRecipient": slotDuty.Entry.Message.FeeRecipient.String(),
			"actualFeeRecipient":   payload.ProposerFeeRecipient(),
		}).Info("fee recipient does not match")
		api.RespondError(w, http.StatusBadRequest, "fee recipient does not match")
		return 0, false
	}
	return slotDuty.Entry.Message.GasLimit, true
}

func (api *RelayAPI) checkSubmissionPayloadAttrs(w http.ResponseWriter, log *logrus.Entry, payload *common.BuilderSubmitBlockRequest) bool {
	api.payloadAttributesLock.RLock()
	attrs, ok := api.payloadAttributes[payload.ParentHash()]
	api.payloadAttributesLock.RUnlock()
	if !ok || payload.Slot() != attrs.slot {
		log.Warn("payload attributes not (yet) known")
		api.RespondError(w, http.StatusBadRequest, "payload attributes not (yet) known")
		return false
	}

	if payload.Random() != attrs.payloadAttributes.PrevRandao {
		msg := fmt.Sprintf("incorrect prev_randao - got: %s, expected: %s", payload.Random(), attrs.payloadAttributes.PrevRandao)
		log.Info(msg)
		api.RespondError(w, http.StatusBadRequest, msg)
		return false
	}

	if hasReachedFork(payload.Slot(), api.capellaEpoch) { // Capella requires correct withdrawals
		withdrawalsRoot, err := ComputeWithdrawalsRoot(payload.Withdrawals())
		if err != nil {
			log.WithError(err).Warn("could not compute withdrawals root from payload")
			api.RespondError(w, http.StatusBadRequest, "could not compute withdrawals root")
			return false
		}

		if withdrawalsRoot != attrs.withdrawalsRoot {
			msg := fmt.Sprintf("incorrect withdrawals root - got: %s, expected: %s", withdrawalsRoot.String(), attrs.withdrawalsRoot.String())
			log.Info(msg)
			api.RespondError(w, http.StatusBadRequest, msg)
			return false
		}
	}

	return true
}

func (api *RelayAPI) checkSubmissionSlotDetails(w http.ResponseWriter, log *logrus.Entry, headSlot uint64, payload *common.BuilderSubmitBlockRequest) bool {
	// TODO: add deneb support.
	if payload.Capella == nil {
		log.Info("rejecting submission - non-capella payload for capella fork")
		api.RespondError(w, http.StatusBadRequest, "non-capella payload")
		return false
	}

	if payload.Slot() <= headSlot {
		log.Info("submitNewBlock failed: submission for past slot")
		api.RespondError(w, http.StatusBadRequest, "submission for past slot")
		return false
	}

	// Timestamp check
	expectedTimestamp := api.genesisInfo.Data.GenesisTime + (payload.Slot() * common.SecondsPerSlot)
	if payload.Timestamp() != expectedTimestamp {
		log.Warnf("incorrect timestamp. got %d, expected %d", payload.Timestamp(), expectedTimestamp)
		api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("incorrect timestamp. got %d, expected %d", payload.Timestamp(), expectedTimestamp))
		return false
	}

	return true
}

func (api *RelayAPI) checkBuilderEntry(w http.ResponseWriter, log *logrus.Entry, builderPubkey phase0.BLSPubKey) (*blockBuilderCacheEntry, bool) {
	builderEntry, ok := api.blockBuildersCache[builderPubkey.String()]
	if !ok {
		log.Warnf("unable to read builder: %s from the builder cache, using low-prio and no collateral", builderPubkey.String())
		builderEntry = &blockBuilderCacheEntry{
			status: common.BuilderStatus{
				IsHighPrio:    false,
				IsOptimistic:  false,
				IsBlacklisted: false,
			},
			collateral: big.NewInt(0),
		}
	}

	if builderEntry.status.IsBlacklisted {
		log.Info("builder is blacklisted")
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		return builderEntry, false
	}

	// In case only high-prio requests are accepted, fail others
	if api.ffDisableLowPrioBuilders && !builderEntry.status.IsHighPrio {
		log.Info("rejecting low-prio builder (ff-disable-low-prio-builders)")
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		return builderEntry, false
	}

	return builderEntry, true
}

// Checks the quality of the TOB txs, if it is the txs expected in a TOB
func (api *RelayAPI) checkTobTxsStateInterference(txs []*types.Transaction) error {
	if len(txs) > 2 {
		return fmt.Errorf("we support only 1 tx on the TOB currently, got %d", len(txs))
	}

	// TODO - check if nonce is valid
	// TODO - check if tx has already been included in a block
	firstTx := txs[0]
	if firstTx.To() == nil {
		return fmt.Errorf("contract creation cannot be a TOB tx")
	}
	// This address is from the kurtosis local devnet. Need to expand state interference checks
	if *firstTx.To() != common2.HexToAddress("0xB9D7a3554F221B34f49d7d3C61375E603aFb699e") {
		return fmt.Errorf("TOB tx can only be sent to uniswap v2 router")
	}

	// TODO - add check for whether the tx is a eth/usdc swap
	return nil
}

// This method checks the following:
// 1. If the tx has already been included in a block
// 2. If the user sending the tx has enough balance to pay for the tx
// 3. If the sender nonce is valid
// 4. Checks if the final tx is a validator payout
func (api *RelayAPI) checkTxAndSenderValidity(txs []*types.Transaction, log *logrus.Entry) error {
	// TODO - ALL PAYOUT RELATED THINGS!
	// TODO - Finish the payout tx validation like check the sender account balance. We don't have to validate the builder payout txs. The onus of
	// it falls on the builder
	// TODO - we need to add a new tx to the TOB txs which sends the payout from the relayer to the validator and the builder. Pick this up once other things are done
	// TODO - check all the txs to see if the nonce is valid, value is valid, check if the tx has already been included. These can be confirmed from the
	// execution layer. We should ideally
	// TODO - Add state interference checks as in checkTobTxsStateInterference

	// Start: Payout checks
	lastTx := txs[len(txs)-1]
	log.Info("DEBUG: last tx is ", lastTx)

	log.Info("DEBUG: Checking the TO address of the last tx")
	if lastTx.To() != nil && *lastTx.To() != api.relayerPayoutAddress {
		return fmt.Errorf("We require a payment tx to the relayer along with the TOB txs!")
	}
	log.Info("DEBUG: Checking the value of the last tx")
	if lastTx.Value().Cmp(big.NewInt(0)) == 0 {
		return fmt.Errorf("The relayer payment tx is non-zero!")
	}
	log.Info("DEBUG: Checking the data of the last tx")
	if len(lastTx.Data()) != 0 {
		return fmt.Errorf("The relayer payment tx has malformed data!")
	}
	// TODO - extend payout checks
	// End: Payout checks

	// State interference checks
	return api.checkTobTxsStateInterference(txs)
}

func (api *RelayAPI) handleSubmitNewTobTxs(w http.ResponseWriter, req *http.Request) {
	//var pf common.Profile
	//var prevTime, nextTime time.Time
	headSlot := api.headSlot.Load()
	receivedAt := time.Now().UTC()
	//prevTime = receivedAt

	log := api.log.WithFields(logrus.Fields{
		"method":                "submitTobTxs",
		"contentLength":         req.ContentLength,
		"headSlot":              headSlot,
		"timestampRequestStart": receivedAt.UnixMilli(),
	})

	log.Info("DEBUG: submit TOB Txs request initiated")
	defer func() {
		log.WithFields(logrus.Fields{
			"timestampRequestFin": time.Now().UTC().UnixMilli(),
			"requestDurationMs":   time.Since(receivedAt).Milliseconds(),
		}).Info("request finished")
	}()

	tobTxRequest := new(common.TobTxsSubmitRequest)

	var r io.Reader = req.Body
	limitReader := io.LimitReader(r, 10*1024*1024) // 10 MB
	requestBytes, err := io.ReadAll(limitReader)
	if err != nil {
		log.WithError(err).Warn("could not read payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check for JSON encoding
	contentType := req.Header.Get("Content-Type")
	if contentType == "application/json" {
		log = log.WithField("reqContentType", "json")
		if err := json.Unmarshal(requestBytes, tobTxRequest); err != nil {
			log.WithError(err).Warn("could not decode payload - JSON")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		log.Error("We do not support non-JSON requests yet!", contentType)
		api.Respond(w, http.StatusBadRequest, "invalid content-type")
		return
	}

	log.Info("DEBUG: submit TOB Txs request decoded", "tobTxRequest", tobTxRequest)
	slot := tobTxRequest.Slot
	parentHash := tobTxRequest.ParentHash
	if len(tobTxRequest.TobTxs.Transactions) == 0 {
		log.Error("Empty TOB tx request sent!")
		api.Respond(w, http.StatusBadRequest, "Empty TOB tx request sent!")
		return
	}
	//
	if slot < headSlot {
		log.Error("TOB tx request for past slot!")
		api.Respond(w, http.StatusBadRequest, "Submitted TOB tx request for past slot!")
		return
	}

	// We only allow bidding for TOB 1 slot prior
	if slot-headSlot > 1 {
		log.Error("Slot's TOB bid not yet started!!")
		api.Respond(w, http.StatusBadRequest, "Slot's TOB bid not yet started!!")
	}

	// decode the txs
	transactionBytes := make([][]byte, len(tobTxRequest.TobTxs.Transactions))
	for i, txHexBytes := range tobTxRequest.TobTxs.Transactions {
		transactionBytes[i] = txHexBytes[:]
	}
	txs, err := common.DecodeTransactions(transactionBytes)
	if err != nil {
		log.WithError(err).Warn("could not decode transactions")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(txs) == 1 {
		log.Error("We require a payment tx along with the TOB txs!")
		api.Respond(w, http.StatusBadRequest, "We require a payment tx along with the TOB txs!")
		return
	}
	log.Info("DEBUG: decoded txs are ", txs)

	// TODO - check the validity of txs

	err = api.checkTxAndSenderValidity(txs, log)
	if err != nil {
		log.WithError(err).Warn("error validating the txs")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	lastTx := txs[len(txs)-1]

	// TODO - simulate the tx to check for tx validity
	err = api.checkTobTxsStateInterference(txs)
	if err != nil {
		log.WithError(err).Warn("could not validate tob txs")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
	}

	tx := api.redis.NewTxPipeline()

	tobTxValue := lastTx.Value()
	log.Info("DEBUG: tobTxValue is ", tobTxValue)
	log.Info("DEBUG: Writing TobTxValue to redis cache with key", slot, parentHash)
	// store it in a redis cache. The ROB block will pick it up and assemble it along with its own txs
	currentTobTxValue, err := api.redis.GetTobTxValue(context.Background(), tx, slot, parentHash)
	if err != nil {
		log.WithError(err).Warn("could not get current Tob Tx value")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Info("DEBUG: currentTobTxValue is ", currentTobTxValue)
	log.Info("DEBUG: tobTxValue is ", tobTxValue)
	log.Info("DEBUG: tobTxValue.Cmp(currentTobTxValue) is ", tobTxValue.Cmp(currentTobTxValue))
	log.Info("DEBUG: Wrote TobTxValue to redis cache with key", slot, parentHash)

	if currentTobTxValue.Cmp(tobTxValue) > 0 {
		log.Error("TOB tx value is less than the current value!")
		api.Respond(w, http.StatusBadRequest, "TOB tx value is less than the current value!")
		return
	}

	// TODO - bchain - simulate the txs on the parent block. If it fails, reject the txs.
	// This is already solved and should be straightforward to implement. its basically simulation
	// with some additional checks

	// add the tob tx to the redis cache
	err = api.redis.SetTobTx(context.Background(), tx, slot, parentHash, transactionBytes)
	if err != nil {
		log.WithError(err).Warn("could not set Tob Tx")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// set the tob tx value in the redis cache
	err = api.redis.SetTobTxValue(context.Background(), tx, tobTxValue, slot, parentHash)
	if err != nil {
		log.WithError(err).Warn("could not set Tob Tx Value")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	api.Respond(w, http.StatusOK, "Tob Tx submitted successfully!")
	return
}

func (api *RelayAPI) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	var pf common.Profile
	var prevTime, nextTime time.Time

	headSlot := api.headSlot.Load()
	receivedAt := time.Now().UTC()
	prevTime = receivedAt

	args := req.URL.Query()
	isCancellationEnabled := args.Get("cancellations") == "1"

	log := api.log.WithFields(logrus.Fields{
		"method":                "submitNewBlock",
		"contentLength":         req.ContentLength,
		"headSlot":              headSlot,
		"cancellationEnabled":   isCancellationEnabled,
		"timestampRequestStart": receivedAt.UnixMilli(),
	})

	// Log at start and end of request
	log.Info("request initiated")
	defer func() {
		log.WithFields(logrus.Fields{
			"timestampRequestFin": time.Now().UTC().UnixMilli(),
			"requestDurationMs":   time.Since(receivedAt).Milliseconds(),
		}).Info("request finished")
	}()

	var err error
	var r io.Reader = req.Body
	isGzip := req.Header.Get("Content-Encoding") == "gzip"
	log = log.WithField("reqIsGzip", isGzip)
	if isGzip {
		r, err = gzip.NewReader(req.Body)
		if err != nil {
			log.WithError(err).Warn("could not create gzip reader")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	limitReader := io.LimitReader(r, 10*1024*1024) // 10 MB
	requestPayloadBytes, err := io.ReadAll(limitReader)
	if err != nil {
		log.WithError(err).Warn("could not read payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	payload := new(common.BuilderSubmitBlockRequest)

	// Check for SSZ encoding
	contentType := req.Header.Get("Content-Type")
	if contentType == "application/octet-stream" {
		log = log.WithField("reqContentType", "ssz")
		payload.Capella = new(builderCapella.SubmitBlockRequest)
		if err = payload.Capella.UnmarshalSSZ(requestPayloadBytes); err != nil {
			log.WithError(err).Warn("could not decode payload - SSZ")

			// SSZ decoding failed. try JSON as fallback (some builders used octet-stream for json before)
			if err2 := json.Unmarshal(requestPayloadBytes, payload); err2 != nil {
				log.WithError(fmt.Errorf("%w / %w", err, err2)).Warn("could not decode payload - SSZ or JSON")
				api.RespondError(w, http.StatusBadRequest, err.Error())
				return
			}
			log = log.WithField("reqContentType", "json")
		} else {
			log.Debug("received ssz-encoded payload")
		}
	} else {
		log = log.WithField("reqContentType", "json")
		if err := json.Unmarshal(requestPayloadBytes, payload); err != nil {
			log.WithError(err).Warn("could not decode payload - JSON")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	nextTime = time.Now().UTC()
	pf.Decode = uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	isLargeRequest := len(requestPayloadBytes) > fastTrackPayloadSizeLimit
	log = log.WithFields(logrus.Fields{
		"timestampAfterDecoding": time.Now().UTC().UnixMilli(),
		"slot":                   payload.Slot(),
		"builderPubkey":          payload.BuilderPubkey().String(),
		"blockHash":              payload.BlockHash(),
		"proposerPubkey":         payload.ProposerPubkey(),
		"parentHash":             payload.ParentHash(),
		"value":                  payload.Value().String(),
		"numTx":                  payload.NumTx(),
		"payloadBytes":           len(requestPayloadBytes),
		"isLargeRequest":         isLargeRequest,
	})

	if payload.Message() == nil || !payload.HasExecutionPayload() {
		api.RespondError(w, http.StatusBadRequest, "missing parts of the payload")
		return
	}

	ok := api.checkSubmissionSlotDetails(w, log, headSlot, payload)
	if !ok {
		return
	}

	builderPubkey := payload.BuilderPubkey()
	builderEntry, ok := api.checkBuilderEntry(w, log, builderPubkey)
	if !ok {
		return
	}

	log = log.WithFields(logrus.Fields{
		"builderIsHighPrio":     builderEntry.status.IsHighPrio,
		"timestampAfterChecks1": time.Now().UTC().UnixMilli(),
	})

	gasLimit, ok := api.checkSubmissionFeeRecipient(w, log, payload)
	if !ok {
		return
	}

	// Don't accept blocks with 0 value
	if payload.Value().Cmp(ZeroU256.BigInt()) == 0 || payload.NumTx() == 0 {
		log.Info("submitNewBlock failed: block with 0 value or no txs")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Sanity check the submission
	err = SanityCheckBuilderBlockSubmission(payload)
	if err != nil {
		log.WithError(err).Info("block submission sanity checks failed")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	log = log.WithField("timestampBeforeAttributesCheck", time.Now().UTC().UnixMilli())

	ok = api.checkSubmissionPayloadAttrs(w, log, payload)
	if !ok {
		return
	}

	// Verify the signature
	log = log.WithField("timestampBeforeSignatureCheck", time.Now().UTC().UnixMilli())
	signature := payload.Signature()
	ok, err = boostTypes.VerifySignature(payload.Message(), api.opts.EthNetDetails.DomainBuilder, builderPubkey[:], signature[:])
	log = log.WithField("timestampAfterSignatureCheck", time.Now().UTC().UnixMilli())
	if err != nil {
		log.WithError(err).Warn("failed verifying builder signature")
		api.RespondError(w, http.StatusBadRequest, "failed verifying builder signature")
		return
	} else if !ok {
		log.Warn("invalid builder signature")
		api.RespondError(w, http.StatusBadRequest, "invalid signature")
		return
	}

	// Create the redis pipeline tx
	tx := api.redis.NewTxPipeline()

	//Reject new submissions once the payload for this slot was delivered - TODO: store in memory as well
	slotLastPayloadDelivered, err := api.redis.GetLastSlotDelivered(context.Background(), tx)
	if err != nil && !errors.Is(err, redis.Nil) {
		log.WithError(err).Error("failed to get delivered payload slot from redis")
	} else if payload.Slot() <= slotLastPayloadDelivered {
		log.Info("rejecting submission because payload for this slot was already delivered")
		api.RespondError(w, http.StatusBadRequest, "payload for this slot was already delivered")
		return
	}

	// ---------------------------------
	// THE BID WILL BE ASSEMBLED SHORTLY
	// ---------------------------------

	// Get the best TOB tx value set from Redis
	// If so proceed with assembly.
	// check if there is a TOB tx
	log.Info("DEBUG: checking for tob txs")
	tobTxs, err := api.redis.GetTobTx(context.Background(), tx, payload.Slot(), payload.ParentHash())
	if err != nil {
		log.WithError(err).Error("failed to get tob txs from redis")
		api.RespondError(w, http.StatusInternalServerError, "failed to get tob txs from redis")
	}
	// if there are no TOB txs then the ROB block is the final block
	totalBidValue := payload.Value()

	if len(tobTxs) > 0 {
		log.Info("DEBUG: tob txs found")
		tobTxValue, err := api.redis.GetTobTxValue(context.Background(), tx, payload.Slot(), payload.ParentHash())
		if err != nil {
			log.WithError(err).Error("failed to get tob tx value from redis")
			api.RespondError(w, http.StatusInternalServerError, "failed to get tob tx value from redis")
		}

		totalBidValue = new(big.Int).Add(payload.Value(), tobTxValue)
	} else {
		log.Info("DEBUG: no tob txs found")
	}

	// Get the latest top bid value from Redis
	bidIsTopBid := false
	topBidValue, err := api.redis.GetTopBidValue(context.Background(), tx, payload.Slot(), payload.ParentHash(), payload.ProposerPubkey())
	if err != nil {
		log.WithError(err).Error("failed to get top bid value from redis")
	} else {
		bidIsTopBid = totalBidValue.Cmp(topBidValue) == 1
		log = log.WithFields(logrus.Fields{
			"topBidValue":    topBidValue.String(),
			"newBidIsTopBid": bidIsTopBid,
		})
	}

	// we have a TOB tx, now assemble the block. Block assembly has the same properties as simulation but returns the final
	// execution payload. If there are no TOB txs, we send an empty list to the assembler
	assemblyResultC := make(chan *blockAssemblyResult, 1)
	var eligibleAt time.Time // will be set once the bid is ready

	// Deferred saving of the builder submission to database (whenever this function ends)
	defer func() {
		savePayloadToDatabase := !api.ffDisablePayloadDBStorage
		var res *blockAssemblyResult
		select {
		case res = <-assemblyResultC:
		case <-time.After(10 * time.Second):
			log.Warn("timed out waiting for assembly result")
			res = &blockAssemblyResult{
				assembledPayload: nil,
				requestErr:       nil,
				validationErr:    nil,
			}
		}

		log.Info("DEBUG: Building out the final aggregated payload")
		// building the final aggregated payload
		originalPayloadMessage := payload.Message()
		finalBuilderSubmission := &common.BuilderSubmitBlockRequest{
			Bellatrix: payload.Bellatrix,
			Capella: &builderCapella.SubmitBlockRequest{
				Message: &v1.BidTrace{
					Slot:                 originalPayloadMessage.Slot,
					ParentHash:           originalPayloadMessage.ParentHash,
					BlockHash:            originalPayloadMessage.BlockHash,
					BuilderPubkey:        originalPayloadMessage.BuilderPubkey,
					ProposerPubkey:       originalPayloadMessage.ProposerPubkey,
					ProposerFeeRecipient: originalPayloadMessage.ProposerFeeRecipient,
					GasLimit:             originalPayloadMessage.GasLimit,
					GasUsed:              originalPayloadMessage.GasUsed,
					Value:                uint256.NewInt(totalBidValue.Uint64()),
				},
				ExecutionPayload: res.assembledPayload,
				Signature:        payload.Signature(),
			},
		}
		log.Info("DEBUG: Done building out the final aggregated payload")

		log.Info("DEBUG: Saving the builder block submission to the database")
		submissionEntry, err := api.db.SaveBuilderBlockSubmission(finalBuilderSubmission, res.requestErr, res.validationErr, receivedAt, eligibleAt, true, savePayloadToDatabase, pf, false)
		if err != nil {
			log.WithError(err).WithField("payload", payload).Error("saving builder block submission to database failed")
			return
		}
		log.Info("DEBUG: Done saving the builder block submission to the database")

		log.Info("DEBUG: Saving the block builder entry to the database")
		err = api.db.UpsertBlockBuilderEntryAfterSubmission(submissionEntry, false)
		if err != nil {
			log.WithError(err).Error("failed to upsert block-builder-entry")
		}
		log.Info("DEBUG: Done saving the block builder entry to the database")
	}()

	tobTxsToSendToAssembler := bellatrix.ExecutionPayloadTransactions{
		Transactions: []bellatrix2.Transaction{},
	}

	for _, tobTxByte := range tobTxs {
		tobTxsToSendToAssembler.Transactions = append(tobTxsToSendToAssembler.Transactions, tobTxByte)
	}

	opts := blockAssemblyOptions{
		log: log,
		req: &common.BlockAssemblerRequest{
			TobTxs:             tobTxsToSendToAssembler,
			RobPayload:         payload,
			RegisteredGasLimit: gasLimit,
		},
	}

	log.Info("DEBUG: Opts for block assembly is set\n", opts)

	timeBeforeAssembly := time.Now().UTC()

	log = log.WithFields(logrus.Fields{
		"timestampBeforeAssembly": timeBeforeAssembly.UTC().UnixMilli(),
	})

	log.Info("DEBUG: Assembling the block")
	assembledPayload, requestErr, validationErr := api.assembleBlock(context.Background(), opts) // success/error logging happens inside
	log.Info("DEBUG: Done assembling the block")
	assemblyResultC <- &blockAssemblyResult{
		assembledPayload: assembledPayload,
		requestErr:       requestErr,
		validationErr:    validationErr,
	}
	log.Info("DEBUG: Done sending the block assembly result to the channel with res\n", assembledPayload)
	assemblyDurationMs := time.Since(timeBeforeAssembly).Milliseconds()
	log = log.WithFields(logrus.Fields{
		"timestampAfterAssembly": time.Now().UTC().UnixMilli(),
		"assemblyDurationMs":     assemblyDurationMs,
	})
	if requestErr != nil { // Request error
		if os.IsTimeout(requestErr) {
			api.RespondError(w, http.StatusGatewayTimeout, "assembly request timeout")
		} else {
			api.RespondError(w, http.StatusBadRequest, requestErr.Error())
		}
		return
	} else {
		if validationErr != nil {
			api.RespondError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
	}

	log.Info("DEBUG: Preparing the get header response")
	// Prepare the response data
	getHeaderResponse, err := common.BuildGetHeaderResponse(payload, api.blsSk, api.publicKey, api.opts.EthNetDetails.DomainBuilder)
	if err != nil {
		log.WithError(err).Error("could not sign builder bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	log.Info("DEBUG: Preparing the get payload response")
	getPayloadResponse, err := common.BuildGetPayloadResponse(payload)
	if err != nil {
		log.WithError(err).Error("could not build getPayload response")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// This will be the assembled payload
	bidTrace := common.BidTraceV2{
		BidTrace:    *payload.Message(),
		BlockNumber: payload.BlockNumber(),
		NumTx:       uint64(payload.NumTx()),
	}

	//
	// Save to Redis
	//
	log.Info("DEBUG: Saving the bid and updating the top bids")
	updateBidResult, err := api.redis.SaveBidAndUpdateTopBid(context.Background(), tx, &bidTrace, payload, getPayloadResponse, getHeaderResponse, receivedAt, isCancellationEnabled, big.NewInt(0))
	if err != nil {
		log.WithError(err).Error("could not save bid and update top bids")
		api.RespondError(w, http.StatusInternalServerError, "failed saving and updating bid")
		return
	}

	// Add fields to logs
	log = log.WithFields(logrus.Fields{
		"timestampAfterBidUpdate":    time.Now().UTC().UnixMilli(),
		"wasBidSavedInRedis":         updateBidResult.WasBidSaved,
		"wasTopBidUpdated":           updateBidResult.WasTopBidUpdated,
		"topBidValue":                updateBidResult.TopBidValue,
		"prevTopBidValue":            updateBidResult.PrevTopBidValue,
		"profileRedisSavePayloadUs":  updateBidResult.TimeSavePayload.Microseconds(),
		"profileRedisUpdateTopBidUs": updateBidResult.TimeUpdateTopBid.Microseconds(),
		"profileRedisUpdateFloorUs":  updateBidResult.TimeUpdateFloor.Microseconds(),
	})

	if updateBidResult.WasBidSaved {
		// Bid is eligible to win the auction
		eligibleAt = time.Now().UTC()
		log = log.WithField("timestampEligibleAt", eligibleAt.UnixMilli())

		// Save to memcache in the background
		if api.memcached != nil {
			go func() {
				err = api.memcached.SaveExecutionPayload(payload.Slot(), payload.ProposerPubkey(), payload.BlockHash(), getPayloadResponse)
				if err != nil {
					log.WithError(err).Error("failed saving execution payload in memcached")
				}
			}()
		}
	}

	nextTime = time.Now().UTC()
	pf.RedisUpdate = uint64(nextTime.Sub(prevTime).Microseconds())
	pf.Total = uint64(nextTime.Sub(receivedAt).Microseconds())

	// All done, log with profiling information
	log.WithFields(logrus.Fields{
		"profileDecodeUs":    pf.Decode,
		"profilePrechecksUs": pf.Prechecks,
		"profileSimUs":       pf.Simulation,
		"profileRedisUs":     pf.RedisUpdate,
		"profileTotalUs":     pf.Total,
	}).Info("received block from builder")
	w.WriteHeader(http.StatusOK)

}

// ---------------
//
//	INTERNAL APIS
//
// ---------------
func (api *RelayAPI) handleInternalBuilderStatus(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	builderPubkey := vars["pubkey"]
	builderEntry, err := api.db.GetBlockBuilderByPubkey(builderPubkey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			api.RespondError(w, http.StatusBadRequest, "builder not found")
			return
		}

		api.log.WithError(err).Error("could not get block builder")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Method == http.MethodGet {
		api.RespondOK(w, builderEntry)
		return
	} else if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
		st := common.BuilderStatus{
			IsHighPrio:    builderEntry.IsHighPrio,
			IsBlacklisted: builderEntry.IsBlacklisted,
			IsOptimistic:  builderEntry.IsOptimistic,
		}
		trueStr := "true"
		args := req.URL.Query()
		if args.Get("high_prio") != "" {
			st.IsHighPrio = args.Get("high_prio") == trueStr
		}
		if args.Get("blacklisted") != "" {
			st.IsBlacklisted = args.Get("blacklisted") == trueStr
		}
		if args.Get("optimistic") != "" {
			st.IsOptimistic = args.Get("optimistic") == trueStr
		}
		api.log.WithFields(logrus.Fields{
			"builderPubkey": builderPubkey,
			"isHighPrio":    st.IsHighPrio,
			"isBlacklisted": st.IsBlacklisted,
			"isOptimistic":  st.IsOptimistic,
		}).Info("updating builder status")
		err := api.db.SetBlockBuilderStatus(builderPubkey, st)
		if err != nil {
			err := fmt.Errorf("error setting builder: %v status: %w", builderPubkey, err)
			api.log.Error(err)
			api.RespondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		api.RespondOK(w, st)
	}
}

func (api *RelayAPI) handleInternalBuilderCollateral(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	builderPubkey := vars["pubkey"]
	if req.Method == http.MethodPost || req.Method == http.MethodPut {
		args := req.URL.Query()
		collateral := args.Get("collateral")
		value := args.Get("value")
		log := api.log.WithFields(logrus.Fields{
			"pubkey":     builderPubkey,
			"collateral": collateral,
			"value":      value,
		})
		log.Infof("updating builder collateral")
		if err := api.db.SetBlockBuilderCollateral(builderPubkey, collateral, value); err != nil {
			fullErr := fmt.Errorf("unable to set collateral in db for pubkey: %v: %w", builderPubkey, err)
			log.Error(fullErr.Error())
			api.RespondError(w, http.StatusInternalServerError, fullErr.Error())
			return
		}
		api.RespondOK(w, NilResponse)
	}
}

// -----------
//  DATA APIS
// -----------

func (api *RelayAPI) handleDataProposerPayloadDelivered(w http.ResponseWriter, req *http.Request) {
	var err error
	args := req.URL.Query()

	filters := database.GetPayloadsFilters{
		Limit: 200,
	}

	if args.Get("slot") != "" && args.Get("cursor") != "" {
		api.RespondError(w, http.StatusBadRequest, "cannot specify both slot and cursor")
		return
	} else if args.Get("slot") != "" {
		filters.Slot, err = strconv.ParseUint(args.Get("slot"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid slot argument")
			return
		}
	} else if args.Get("cursor") != "" {
		filters.Cursor, err = strconv.ParseUint(args.Get("cursor"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid cursor argument")
			return
		}
	}

	if args.Get("block_hash") != "" {
		var hash boostTypes.Hash
		err = hash.UnmarshalText([]byte(args.Get("block_hash")))
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid block_hash argument")
			return
		}
		filters.BlockHash = args.Get("block_hash")
	}

	if args.Get("block_number") != "" {
		filters.BlockNumber, err = strconv.ParseUint(args.Get("block_number"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid block_number argument")
			return
		}
	}

	if args.Get("proposer_pubkey") != "" {
		if err = checkBLSPublicKeyHex(args.Get("proposer_pubkey")); err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid proposer_pubkey argument")
			return
		}
		filters.ProposerPubkey = args.Get("proposer_pubkey")
	}

	if args.Get("builder_pubkey") != "" {
		if err = checkBLSPublicKeyHex(args.Get("builder_pubkey")); err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid builder_pubkey argument")
			return
		}
		filters.BuilderPubkey = args.Get("builder_pubkey")
	}

	if args.Get("limit") != "" {
		_limit, err := strconv.ParseUint(args.Get("limit"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid limit argument")
			return
		}
		if _limit > filters.Limit {
			api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("maximum limit is %d", filters.Limit))
			return
		}
		filters.Limit = _limit
	}

	if args.Get("order_by") == "value" {
		filters.OrderByValue = 1
	} else if args.Get("order_by") == "-value" {
		filters.OrderByValue = -1
	}

	deliveredPayloads, err := api.db.GetRecentDeliveredPayloads(filters)
	if err != nil {
		api.log.WithError(err).Error("error getting recent payloads")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := make([]common.BidTraceV2JSON, len(deliveredPayloads))
	for i, payload := range deliveredPayloads {
		response[i] = database.DeliveredPayloadEntryToBidTraceV2JSON(payload)
	}

	api.RespondOK(w, response)
}

func (api *RelayAPI) handleDataBuilderBidsReceived(w http.ResponseWriter, req *http.Request) {
	var err error
	args := req.URL.Query()

	filters := database.GetBuilderSubmissionsFilters{
		Limit:         500,
		Slot:          0,
		BlockHash:     "",
		BlockNumber:   0,
		BuilderPubkey: "",
	}

	if args.Get("cursor") != "" {
		api.RespondError(w, http.StatusBadRequest, "cursor argument not supported")
		return
	}

	if args.Get("slot") != "" {
		filters.Slot, err = strconv.ParseUint(args.Get("slot"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid slot argument")
			return
		}
	}

	if args.Get("block_hash") != "" {
		var hash boostTypes.Hash
		err = hash.UnmarshalText([]byte(args.Get("block_hash")))
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid block_hash argument")
			return
		}
		filters.BlockHash = args.Get("block_hash")
	}

	if args.Get("block_number") != "" {
		filters.BlockNumber, err = strconv.ParseUint(args.Get("block_number"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid block_number argument")
			return
		}
	}

	if args.Get("builder_pubkey") != "" {
		if err = checkBLSPublicKeyHex(args.Get("builder_pubkey")); err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid builder_pubkey argument")
			return
		}
		filters.BuilderPubkey = args.Get("builder_pubkey")
	}

	// at least one query arguments is required
	if filters.Slot == 0 && filters.BlockHash == "" && filters.BlockNumber == 0 && filters.BuilderPubkey == "" {
		api.RespondError(w, http.StatusBadRequest, "need to query for specific slot or block_hash or block_number or builder_pubkey")
		return
	}

	if args.Get("limit") != "" {
		_limit, err := strconv.ParseUint(args.Get("limit"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid limit argument")
			return
		}
		if _limit > filters.Limit {
			api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("maximum limit is %d", filters.Limit))
			return
		}
		filters.Limit = _limit
	}

	blockSubmissions, err := api.db.GetBuilderSubmissions(filters)
	if err != nil {
		api.log.WithError(err).Error("error getting recent payloads")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := make([]common.BidTraceV2WithTimestampJSON, len(blockSubmissions))
	for i, payload := range blockSubmissions {
		response[i] = database.BuilderSubmissionEntryToBidTraceV2WithTimestampJSON(payload)
	}

	api.RespondOK(w, response)
}

func (api *RelayAPI) handleDataGetCurrentTobTx(w http.ResponseWriter, req *http.Request) {
	slot := req.URL.Query().Get("slot")
	if slot == "" {
		api.RespondError(w, http.StatusBadRequest, "missing slot argument")
		return
	}
	parentHash := req.URL.Query().Get("parent_hash")
	if parentHash == "" {
		api.RespondError(w, http.StatusBadRequest, "missing parent_hash argument")
		return
	}

	// TODO - bchain - finish impl of this, should be pretty straightforward

}

func (api *RelayAPI) handleDataIsPepcRelayer(w http.ResponseWriter, req *http.Request) {
	// TODO - Add a flag to enable and disable PEPC activities. For now, we always return true.
	api.RespondMsg(w, http.StatusOK, "true")
}

func (api *RelayAPI) handleDataValidatorRegistration(w http.ResponseWriter, req *http.Request) {
	pkStr := req.URL.Query().Get("pubkey")
	if pkStr == "" {
		api.RespondError(w, http.StatusBadRequest, "missing pubkey argument")
		return
	}

	var pk boostTypes.PublicKey
	err := pk.UnmarshalText([]byte(pkStr))
	if err != nil {
		api.RespondError(w, http.StatusBadRequest, "invalid pubkey")
		return
	}

	registrationEntry, err := api.db.GetValidatorRegistration(pkStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			api.RespondError(w, http.StatusBadRequest, "no registration found for validator "+pkStr)
			return
		}
		api.log.WithError(err).Error("error getting validator registration")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	signedRegistration, err := registrationEntry.ToSignedValidatorRegistration()
	if err != nil {
		api.log.WithError(err).Error("error converting registration entry to signed validator registration")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	api.RespondOK(w, signedRegistration)
}

func (api *RelayAPI) handleLivez(w http.ResponseWriter, req *http.Request) {
	api.RespondMsg(w, http.StatusOK, "live")
}

func (api *RelayAPI) handleReadyz(w http.ResponseWriter, req *http.Request) {
	if api.IsReady() {
		api.RespondMsg(w, http.StatusOK, "ready")
	} else {
		api.RespondMsg(w, http.StatusServiceUnavailable, "not ready")
	}
}
