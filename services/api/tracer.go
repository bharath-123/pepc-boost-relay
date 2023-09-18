package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/mev-boost-relay/common"
)

type ITracer interface {
	TraceTx(context context.Context, tx *types.Transaction) (*common.CallTraceResponse, error)
}

type Tracer struct {
	tracerUrl string
	client    http.Client
}

func NewTracer(tracerUrl string) *Tracer {
	return &Tracer{
		tracerUrl: tracerUrl,
		client: http.Client{ //nolint:exhaustruct
			Timeout: assemblyRequestTimeout,
		},
	}
}

func (t *Tracer) TraceTx(context context.Context, tx *types.Transaction) (*common.CallTraceResponse, error) {
	hexEncodedData := fmt.Sprintf("0x%s", hex.EncodeToString(tx.Data()))
	hexGas := fmt.Sprintf("0x%x", tx.Gas())
	hexValue := fmt.Sprintf("0x%x", tx.Value())

	// Create the JSON-RPC request
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "debug_traceCall",
		"params": []interface{}{map[string]interface{}{
			"to":    tx.To(),
			"gas":   hexGas,
			"data":  hexEncodedData,
			"value": hexValue,
		}, "latest", map[string]interface{}{"tracer": "callTracer", "disableStorage": false, "disableMemory": false}},
		"id": 1,
	}

	// Serialize the request to JSON
	requestBody, err := json.Marshal(request)
	if err != nil {
		fmt.Printf("Failed to serialize JSON request: %v\n", err)
		return nil, err
	}

	// Send the HTTP POST request to the Ethereum client
	resp, err := http.Post(t.tracerUrl, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Printf("Failed to send HTTP request: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Parse the JSON response
	var jsonResponse common.CallTraceResponse
	err = json.NewDecoder(resp.Body).Decode(&jsonResponse)
	if err != nil {
		fmt.Printf("Failed to parse JSON response: %v\n", err)
		return nil, err
	}

	// Print the response
	return &jsonResponse, nil

}
