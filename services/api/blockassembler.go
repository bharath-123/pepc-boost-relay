package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/go-utils/jsonrpc"
	"github.com/flashbots/mev-boost-relay/common"
)

var assemblyRequestTimeout = time.Duration(cli.GetEnvInt("BLOCKASSEMBLY_TIMEOUT_MS", 60000)) * time.Millisecond

type IBlockAssembler interface {
	Send(context context.Context, request *common.BlockAssemblerRequest) (*capella.ExecutionPayload, error, error)
}

type BlockAssembler struct {
	cv               *sync.Cond
	counter          int64
	blockAssemblyURL string
	client           http.Client
}

func NewBlockAssembler(blockAssemblyURL string) *BlockAssembler {
	return &BlockAssembler{
		cv:               sync.NewCond(&sync.Mutex{}),
		blockAssemblyURL: blockAssemblyURL,
		client: http.Client{ //nolint:exhaustruct
			Timeout: assemblyRequestTimeout,
		},
	}
}

func (b *BlockAssembler) Send(context context.Context, request *common.BlockAssemblerRequest) (payload *capella.ExecutionPayload, requestErr, validationErr error) {
	b.cv.L.Lock()
	cnt := atomic.AddInt64(&b.counter, 1)
	if maxConcurrentBlocks > 0 && cnt > maxConcurrentBlocks {
		b.cv.Wait()
	}
	b.cv.L.Unlock()

	defer func() {
		b.cv.L.Lock()
		atomic.AddInt64(&b.counter, -1)
		b.cv.Signal()
		b.cv.L.Unlock()
	}()

	if err := context.Err(); err != nil {
		return nil, fmt.Errorf("%w, %w", ErrRequestClosed, err), nil
	}

	var assembleReq *jsonrpc.JSONRPCRequest
	if request.RobPayload.Capella == nil {
		return nil, ErrNoCapellaPayload, nil
	}

	// Prepare headers
	headers := http.Header{}
	headers.Add("X-Request-ID", fmt.Sprintf("%d/%s", request.RobPayload.Slot(), request.RobPayload.BlockHash()))

	// Create and fire off JSON-RPC request
	assembleReq = jsonrpc.NewJSONRPCRequest("1", "flashbots_blockAssembler", request)
	resp, requestErr, validationErr := SendJSONRPCRequest(&b.client, *assembleReq, b.blockAssemblyURL, headers)

	// decode the response to engine.ExecutionPayloadEnvelope
	if resp != nil {
		payload = &capella.ExecutionPayload{}
		err := json.Unmarshal(resp.Result, payload)
		if err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err), nil
		}
	}

	return payload, requestErr, validationErr
}
