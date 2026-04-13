package pow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/unicitynetwork/finality-gadget/pow/types"
)

// IPCClient implements the Client interface by communicating over a Unix Domain Socket.
// It assumes the PoW node exposes a JSON-RPC interface via HTTP over the socket.
// (If the node uses raw TCP-like newline-delimited JSON over the socket instead of HTTP,
// this client can be easily adapted to write/read directly to the net.Conn).
type IPCClient struct {
	socketPath string
	httpClient *http.Client
	nextID     atomic.Int64
}

// NewIPCClient creates a new client that connects to the PoW node via a Unix socket.
func NewIPCClient(socketPath string) *IPCClient {
	return &IPCClient{
		socketPath: socketPath,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			// Configure the HTTP client to dial a unix socket instead of tcp
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

// jsonRpcRequest represents a standard JSON-RPC 2.0 request.
type jsonRpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// jsonRpcResponse represents a standard JSON-RPC 2.0 response.
type jsonRpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  interface{}     `json:"error"`
	ID     int             `json:"id"`
}

// call sends a JSON-RPC request to the PoW node.
func (c *IPCClient) call(ctx context.Context, method string, params []interface{}, result interface{}) error {
	reqID := int(c.nextID.Add(1))
	reqBody := &jsonRpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      reqID,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// The URL doesn't strictly matter since the dialer forces the unix socket
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("rpc call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status: %s", resp.Status)
	}

	if resp.Body == nil {
		return nil
	}

	// wrap resp.Body with MaxBytesReader to limit response size
	resp.Body = http.MaxBytesReader(nil, resp.Body, 5*1024*1024)

	// read all bytes to be able to log the response if error occurs
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var rpcResp jsonRpcResponse
	if err := json.Unmarshal(bodyBytes, &rpcResp); err != nil {
		return fmt.Errorf("failed to decode response: %w. Response body: %s", err, string(bodyBytes))
	}

	// TODO PoW node always returns ID=0
	//if rpcResp.ID != reqID {
	//	return fmt.Errorf("rpc response ID mismatch: expected %d, got %d", reqID, rpcResp.ID)
	//}

	if rpcResp.Error != nil {
		return fmt.Errorf("rpc error: %v", rpcResp.Error)
	}

	if result != nil {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return fmt.Errorf("failed to unmarshal result: %w", err)
		}
	}

	return nil
}

// GetTip returns the current tip of the active PoW chain.
func (c *IPCClient) GetTip(ctx context.Context) (*types.BlockHeader, error) {
	// 1. Call getbestblockhash to get the hash of the current tip
	var hash string
	if err := c.call(ctx, "getbestblockhash", []interface{}{}, &hash); err != nil {
		return nil, fmt.Errorf("failed to get best block hash: %w", err)
	}

	// 2. Call getblockheader <tip_hash> to retrieve the block's details
	block, err := c.GetBlockHeaderByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get tip block header: %w", err)
	}

	return block, nil
}

// GetBlockHeaderByHash returns a block by its hash.
func (c *IPCClient) GetBlockHeaderByHash(ctx context.Context, hash string) (*types.BlockHeader, error) {
	var block types.BlockHeader
	if err := c.call(ctx, "getblockheader", []interface{}{hash}, &block); err != nil {
		return nil, fmt.Errorf("failed to invoke getblockheader: %w", err)
	}
	return &block, nil
}

// GetChainTips returns information about all known branch tips in the block tree.
func (c *IPCClient) GetChainTips(ctx context.Context) ([]types.ChainTip, error) {
	var tips []types.ChainTip
	if err := c.call(ctx, "getchaintips", []interface{}{}, &tips); err != nil {
		return nil, err
	}
	return tips, nil
}

// GetBlockHeaderByHeight returns the block at a specific height in the active chain.
func (c *IPCClient) GetBlockHeaderByHeight(ctx context.Context, height uint64) (*types.BlockHeader, error) {
	// 1. Get the hash of the block at this height
	var hash string
	if err := c.call(ctx, "getblockhash", []interface{}{height}, &hash); err != nil {
		return nil, fmt.Errorf("failed to get block hash for height %d: %w", height, err)
	}

	// 2. Fetch the block info using the hash
	block, err := c.GetBlockHeaderByHash(ctx, hash)
	if err != nil {
		return nil, err
	}

	return block, nil
}
