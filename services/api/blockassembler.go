package api

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/go-utils/jsonrpc"
	"github.com/flashbots/mev-boost-relay/common"
)

type IBlockAssembler interface {
	Send(context context.Context, tobPayload *capella.ExecutionPayload, robPayload *capella.ExecutionPayload, tobValue *big.Int, robValue *big.Int) (error, error)
}

type BlockAssembler struct {
	cv          *sync.Cond
	counter     int64
	blockSimURL string
	client      http.Client
}

func NewBlockAssembler(blockSimURL string) *BlockAssembler {
	return &BlockAssembler{
		cv:          sync.NewCond(&sync.Mutex{}),
		blockSimURL: blockSimURL,
		client: http.Client{ //nolint:exhaustruct
			Timeout: simRequestTimeout,
		},
	}
}

func (b *BlockAssembler) Send(context context.Context, payload *common.BuilderBlockValidationRequest, isHighPrio, fastTrack bool) (requestErr, validationErr error) {
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
		return fmt.Errorf("%w, %w", ErrRequestClosed, err), nil
	}

	var simReq *jsonrpc.JSONRPCRequest
	if payload.Capella == nil {
		return ErrNoCapellaPayload, nil
	}
	// TODO: add deneb support.

	// Prepare headers
	headers := http.Header{}
	headers.Add("X-Request-ID", fmt.Sprintf("%d/%s", payload.Slot(), payload.BlockHash()))
	if isHighPrio {
		headers.Add("X-High-Priority", "true")
	}
	if fastTrack {
		headers.Add("X-Fast-Track", "true")
	}

	// Create and fire off JSON-RPC request
	simReq = jsonrpc.NewJSONRPCRequest("1", "flashbots_blockAssembler", payload)
	_, requestErr, validationErr = SendJSONRPCRequest(&b.client, *simReq, b.blockSimURL, headers)
	return requestErr, validationErr
}
