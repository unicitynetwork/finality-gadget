package txsystem

// Integration probes for F11 (Confirmations → IsActive consensus gate) and
// F20 (JSON-RPC error-field masking), exercised through the REAL pow.IPCClient
// against a mock unicityd HTTP server on a Unix socket.
//
// Unlike the interface-level mockPowClient used elsewhere in this package,
// these tests drive the actual IPC code path:
//
//     mock unicityd (crafted JSON-RPC) → pow.IPCClient → FGPTxSystem.FollowerVerify
//
// so attacker-controlled response bytes flow through the same parsing the
// production node uses. This is the closest deterministic analogue of the
// live bft-fgp-2sh e2e for these two findings.
//
// See aggregator-subscription/INVESTIGATIONS.md §F11 (Confirmations sub-finding)
// and §F20, and E2E_FOLLOWUP_PROBES.md.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
	"github.com/unicitynetwork/finality-gadget/pow"
	powtypes "github.com/unicitynetwork/finality-gadget/pow/types"
)

var ipcSockCounter atomic.Uint64

func shortIPCSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "fgp-ipc-int-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, fmt.Sprintf("s%d.sock", ipcSockCounter.Add(1)))
}

// mockUnicityd dispatches JSON-RPC by method:
//   - getbestblockhash → returns tipHash (JSON string)
//   - getblockheader [hash] → returns blocks[hash], or rawError if set
type mockUnicityd struct {
	tipHash  string
	blocks   map[string]powtypes.BlockHeader
	rawError string // if non-empty, getblockheader returns this raw "error" JSON value
}

func startMockUnicityd(t *testing.T, m *mockUnicityd) string {
	t.Helper()
	sock := shortIPCSock(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
			ID     int               `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		writeResult := func(resultJSON string) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":` + resultJSON + `,"error":null,"id":0}`))
		}

		switch req.Method {
		case "getbestblockhash":
			b, _ := json.Marshal(m.tipHash)
			writeResult(string(b))
		case "getblockheader":
			if m.rawError != "" {
				// F20: emit a non-null, non-object error value.
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":null,"error":` + m.rawError + `,"id":0}`))
				return
			}
			var hash string
			if len(req.Params) > 0 {
				_ = json.Unmarshal(req.Params[0], &hash)
			}
			blk, ok := m.blocks[hash]
			if !ok {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":null,"error":"block not found","id":0}`))
				return
			}
			b, _ := json.Marshal(blk)
			writeResult(string(b))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":null,"error":"unknown method","id":0}`))
		}
	})

	server := &http.Server{Handler: handler}
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	go func() { _ = server.Serve(ln) }()
	time.Sleep(40 * time.Millisecond)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return sock
}

// F11 — Confirmations field gates IsActive() in FollowerVerify, via the real
// IPC client. Demonstrates that a crafted Confirmations value flips the
// consensus gate.
func TestFGP11_Integration_ConfirmationsGatesIsActive(t *testing.T) {
	const proposedHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const tipHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	cases := []struct {
		name          string
		confirmations int
		expectAccept  bool
		note          string
	}{
		{
			name: "Confirmations=6 (honest active) → ACCEPT", confirmations: 6, expectAccept: true,
			note: "normal active block at sufficient depth",
		},
		{
			name: "Confirmations=1 (orphan claims active) → ACCEPT", confirmations: 1, expectAccept: true,
			note: "GAP: a malicious unicityd sets Confirmations=1 on an orphan; IsActive() passes; " +
				"depth check uses tip/height (also unicityd-controlled) so the block is accepted",
		},
		{
			name: "Confirmations=0 → REJECT at IsActive", confirmations: 0, expectAccept: false,
			note: "IsActive() = Confirmations>0 is false",
		},
		{
			name: "Confirmations=-1 (negative) → REJECT at IsActive", confirmations: -1, expectAccept: false,
			note: "negative confirmations also fails IsActive()",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &mockUnicityd{
				tipHash: tipHash,
				blocks: map[string]powtypes.BlockHeader{
					// proposed block: height 100, depth = 106-100 = 6 = dFG → passes depth check
					proposedHash: {Hash: proposedHash, Height: 100, Confirmations: c.confirmations},
					// tip: height 106, active
					tipHash: {Hash: tipHash, Height: 106, Confirmations: 1},
				},
			}
			sock := startMockUnicityd(t, m)
			client := pow.NewIPCClient(sock)

			s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
				PartitionParams: map[string]string{"dFG": "6"},
			}, client, logger.New(t))
			require.NoError(t, err)

			hashBytes, _ := hex.DecodeString(proposedHash)
			summary, err := s.FollowerVerify(context.Background(), 1, hashBytes)

			if c.expectAccept {
				require.NoError(t, err, "[%s] %s", c.name, c.note)
				require.NotNil(t, summary)
				t.Logf("ACCEPTED (confirmations=%d): %s", c.confirmations, c.note)
			} else {
				require.Error(t, err, "[%s] %s", c.name, c.note)
				require.Contains(t, err.Error(), "not in the active chain")
				t.Logf("REJECTED (confirmations=%d) at IsActive gate: %v", c.confirmations, err)
			}
		})
	}
}

// F20 — a non-null, non-object JSON-RPC error field (false / 0 / "") masks the
// result; through FollowerVerify this surfaces as a confusing "rpc error: ..."
// wrapped in "failed to get block by hash".
func TestFGP20_Integration_ErrorFieldMasksResult(t *testing.T) {
	const proposedHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	for _, rawErr := range []string{"false", "0", `""`} {
		t.Run("error="+rawErr, func(t *testing.T) {
			m := &mockUnicityd{
				tipHash:  proposedHash,
				rawError: rawErr, // getblockheader always returns this error value
			}
			sock := startMockUnicityd(t, m)
			client := pow.NewIPCClient(sock)

			s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
				PartitionParams: map[string]string{"dFG": "6"},
			}, client, logger.New(t))
			require.NoError(t, err)

			hashBytes, _ := hex.DecodeString(proposedHash)
			summary, err := s.FollowerVerify(context.Background(), 1, hashBytes)

			require.Error(t, err, "non-null error field should surface as an error")
			require.Nil(t, summary)
			require.Contains(t, err.Error(), "rpc error",
				"GAP: a non-spec error value (%s) is treated as an RPC error and "+
					"masks the (absent) result; surfaces here as: %v", rawErr, err)
			t.Logf("F20 confirmed through FollowerVerify: error=%s → %v", rawErr, err)
		})
	}
}
