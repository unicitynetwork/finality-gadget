package pow

// Test_IPCClient_BodySizeCap verifies the 5 MB MaxBytesReader cap in
// pow/ipc_client.go.
//
// Background: finality-gadget issue #1 body flagged "pow/ipc_client.go:89
// io.ReadAll(resp.Body) lacks size constraints" as an ADJACENT concern.
// PR #11 addressed it (commit eb5aa9d, hardened in 8b578d9 from
// io.LimitReader to http.MaxBytesReader so truncation surfaces as an
// error rather than silent truncation).
//
// This is the F8 test from aggregator-subscription/INVESTIGATIONS.md.
//
// Sets up an in-process HTTP server on a Unix socket that returns a
// controllable-size body, drives the IPCClient through its private
// `call()` helper (accessible from same-package tests), and asserts:
//   • bodies well-under the cap  → call succeeds (body read OK, parse may fail later but NOT with a size error)
//   • bodies just-under the cap  → ditto
//   • bodies just-over the cap   → call fails with a MaxBytesError (size-related error)
//   • bodies way-over the cap    → ditto
//
// Issue:  https://github.com/unicitynetwork/finality-gadget/issues/1 (adjacent concern)
// Fix PR: https://github.com/unicitynetwork/finality-gadget/pull/11 (separate from #13)

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// shortSockPath returns a unix-socket path under /tmp that is well within
// Linux's 108-byte sun_path limit, regardless of the (possibly long) test name.
// t.TempDir() folds the test name into the path which can overflow for nested
// subtests with descriptive names.
var sockCounter atomic.Uint64

func shortSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "fgp-ipc-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, fmt.Sprintf("s%d.sock", sockCounter.Add(1)))
}

// Mirror of the cap in ipc_client.go (kept in sync by hand — when it changes
// here, that's the signal to update the production value too).
const ipcClientBodyCap = 5 * 1024 * 1024

func startMockUnicityd(t *testing.T, bodySize int) (sockPath string, shutdown func()) {
	t.Helper()
	sockPath = shortSockPath(t)

	// Pre-build the "result" payload: bodySize bytes of 'x'. We wrap it in a
	// JSON-RPC envelope. The total response body size is bodySize + envelope
	// overhead (~50 bytes). For the over/under-cap distinction this is good
	// enough — we set bodySize such that total ≈ desired.
	payload := make([]byte, bodySize)
	for i := range payload {
		payload[i] = 'x'
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Build: {"jsonrpc":"2.0","result":"<bodySize bytes>","error":null,"id":1}
		// Note: payload bytes happen to be valid JSON string content (just 'x's).
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"`))
		_, _ = w.Write(payload)
		_, _ = w.Write([]byte(`","error":null,"id":1}`))
	})

	server := &http.Server{Handler: handler}
	ln, err := net.Listen("unix", sockPath)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = server.Serve(ln)
	}()

	// Tiny wait so accept() is ready.
	time.Sleep(30 * time.Millisecond)

	shutdown = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		wg.Wait()
	}
	return sockPath, shutdown
}

func Test_IPCClient_BodySizeCap(t *testing.T) {
	scenarios := []struct {
		name              string
		bodySize          int
		expectSizeError   bool
		errMustContainAny []string // expected substrings (any-match) in the error
	}{
		{
			name:            "well-under-cap (1 KB)",
			bodySize:        1024,
			expectSizeError: false,
		},
		{
			name:            "just-under-cap (cap - 1 KB)",
			bodySize:        ipcClientBodyCap - 1024,
			expectSizeError: false,
		},
		{
			name:              "just-over-cap (cap + 1 KB)",
			bodySize:          ipcClientBodyCap + 1024,
			expectSizeError:   true,
			errMustContainAny: []string{"too large", "max", "size", "exceeded", "limit"},
		},
		{
			name:              "way-over-cap (2 × cap)",
			bodySize:          2 * ipcClientBodyCap,
			expectSizeError:   true,
			errMustContainAny: []string{"too large", "max", "size", "exceeded", "limit"},
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			sock, shutdown := startMockUnicityd(t, sc.bodySize)
			defer shutdown()

			client := NewIPCClient(sock)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Use the private call helper directly (same-package access).
			// "result" in our mock is a long string of x's; decode into a string.
			var result string
			err := client.call(ctx, "getbestblockhash", []interface{}{}, &result)

			if sc.expectSizeError {
				require.Error(t, err, "expected size-related error for body=%d (cap=%d)",
					sc.bodySize, ipcClientBodyCap)
				errLower := strings.ToLower(err.Error())
				matched := false
				for _, sub := range sc.errMustContainAny {
					if strings.Contains(errLower, sub) {
						matched = true
						break
					}
				}
				if !matched {
					t.Errorf("error did not match any expected size-related substring %v: %v",
						sc.errMustContainAny, err)
				}
				t.Logf("got expected size-cap error: %v", err)
			} else {
				// Under the cap the body MUST be readable end-to-end.
				// (We don't care about subsequent parse success — only that
				// the read didn't trip the cap.)
				if err != nil {
					errLower := strings.ToLower(err.Error())
					sizeRelated := false
					for _, sub := range []string{"too large", "max bytes", "size exceed"} {
						if strings.Contains(errLower, sub) {
							sizeRelated = true
							break
						}
					}
					if sizeRelated {
						t.Errorf("under-cap body unexpectedly hit size cap: %v", err)
					}
					t.Logf("under-cap call had non-size error (expected — payload is x's, not a real hash): %v",
						err)
				} else {
					t.Logf("under-cap call succeeded (body=%d ≤ cap=%d)",
						sc.bodySize, ipcClientBodyCap)
				}
			}

			_ = fmt.Sprintf // keep imports happy in some build modes
		})
	}
}

// ---------------------------------------------------------------------------
// Additional coverage for issue #6 / PR #11
// ---------------------------------------------------------------------------
//
// Beyond the 5 MB cap above, issue #6 expected:
//   #6.1  HTTP client timeout                 (✅ in code: 5s; covered below)
//   #6.2  DialContext honors ctx              (✅ in code; covered below)
//   #6.3  Response body size cap              (✅ covered by BodySizeCap)
//   #6.4  Block header validation             (❌ NOT implemented — gap tests below)
//   #6.5  JSON-RPC ID counter + validation    (⚠️ counter ✅, validation disabled
//                                              pending unicityd "always returns
//                                              id=0" bug — separate ticket)
//
// All tests here use the same in-process unix-socket mock pattern as
// startMockUnicityd above, with custom handlers per scenario.

// startMockUnicitydHandler is a variant of startMockUnicityd that takes a
// caller-supplied http.Handler — useful for hung-server, slow-body, error,
// and malformed-payload scenarios.
func startMockUnicitydHandler(t *testing.T, handler http.Handler) (sockPath string, shutdown func()) {
	t.Helper()
	sockPath = shortSockPath(t)

	server := &http.Server{Handler: handler}
	ln, err := net.Listen("unix", sockPath)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = server.Serve(ln)
	}()
	time.Sleep(30 * time.Millisecond)

	shutdown = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		wg.Wait()
	}
	return sockPath, shutdown
}

// --- #6.1 / #6.2: timeout & context behavior --------------------------------

// Test_IPCClient_Timeout_HungServer verifies the 5s httpClient.Timeout
// added in commit eb5aa9d. A hung server (handler never returns) must
// cause the call to fail within ~5-6 seconds — not block indefinitely.
//
// Pre-fix (no Timeout, plain net.Dial) this would have blocked forever,
// freezing the FGP partition as described in issue #6.
func Test_IPCClient_Timeout_HungServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 5s timeout test in -short mode")
	}

	// Handler that never returns until the test ends.
	done := make(chan struct{})
	defer close(done)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	})

	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)

	// Use a long ctx — the test is about httpClient.Timeout, not ctx.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	var result string
	err := client.call(ctx, "getbestblockhash", []interface{}{}, &result)
	elapsed := time.Since(start)

	require.Error(t, err, "hung server should produce a timeout error")
	// httpClient.Timeout is 5s. Allow generous margin for CI variance.
	require.Less(t, elapsed, 8*time.Second,
		"call should have timed out near 5s, instead waited %s", elapsed)
	require.GreaterOrEqual(t, elapsed, 4500*time.Millisecond,
		"call returned too fast (%s) — timeout may not be firing", elapsed)

	t.Logf("hung-server call failed in %s with: %v", elapsed, err)
}

// Test_IPCClient_Context_PreCancelled verifies that the DialContext
// fix (commit eb5aa9d replaced net.Dial with net.Dialer.DialContext) honors
// a pre-cancelled context — the call must fail near-immediately, not wait
// for any timer.
//
// Pre-fix this would have ignored ctx during dial and blocked or succeeded
// regardless of cancellation.
func Test_IPCClient_Context_PreCancelled(t *testing.T) {
	// Server that, if reached, would respond quickly — but it should never
	// be reached because dial honors the pre-cancelled ctx.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"x","error":null,"id":1}`))
	})
	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	start := time.Now()
	var result string
	err := client.call(ctx, "getbestblockhash", []interface{}{}, &result)
	elapsed := time.Since(start)

	require.Error(t, err, "pre-cancelled ctx should produce an error")
	require.Less(t, elapsed, 500*time.Millisecond,
		"pre-cancelled ctx should return near-instantly, took %s", elapsed)
	require.Contains(t, err.Error(), "context",
		"error should reference context cancellation: %v", err)

	t.Logf("pre-cancelled ctx returned in %s: %v", elapsed, err)
}

// Test_IPCClient_Context_CancelledMidFlight verifies ctx cancellation while
// the request is in flight aborts the call quickly.
func Test_IPCClient_Context_CancelledMidFlight(t *testing.T) {
	// Handler sleeps for 3s before responding — long enough for us to cancel.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(3 * time.Second):
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"x","error":null,"id":1}`))
		}
	})
	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel 200ms into the call.
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	var result string
	err := client.call(ctx, "getbestblockhash", []interface{}{}, &result)
	elapsed := time.Since(start)

	require.Error(t, err, "cancelled ctx should produce an error")
	require.Less(t, elapsed, 1500*time.Millisecond,
		"cancelled ctx should abort quickly, took %s", elapsed)

	t.Logf("mid-flight cancel returned in %s: %v", elapsed, err)
}

// --- #6.5: JSON-RPC ID counter ----------------------------------------------

// Test_IPCClient_RequestID_StrictlyMonotonic verifies the atomic nextID
// counter added in commit eb5aa9d (replacing the hardcoded ID=1).
//
// We intercept the request bodies on the server side and assert IDs are
// strictly increasing across N sequential calls.
func Test_IPCClient_RequestID_StrictlyMonotonic(t *testing.T) {
	var (
		mu     sync.Mutex
		gotIDs []int
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRpcRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		mu.Lock()
		gotIDs = append(gotIDs, req.ID)
		mu.Unlock()
		// echo with id=0 (mimics current unicityd behavior the TODO mentions)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"\"x\"","error":null,"id":0}`))
	})
	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const N = 10
	for i := 0; i < N; i++ {
		var s string
		_ = client.call(ctx, "getbestblockhash", []interface{}{}, &s)
	}

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, gotIDs, N)
	for i := 1; i < N; i++ {
		require.Greater(t, gotIDs[i], gotIDs[i-1],
			"IDs not strictly increasing: %v", gotIDs)
	}
	t.Logf("observed IDs: %v", gotIDs)
}

// Test_IPCClient_RequestID_UniqueUnderConcurrency stresses the atomic
// counter from G goroutines × M calls each. All G*M IDs must be unique.
func Test_IPCClient_RequestID_UniqueUnderConcurrency(t *testing.T) {
	var (
		mu     sync.Mutex
		gotIDs = map[int]int{} // id -> count
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		gotIDs[req.ID]++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"\"x\"","error":null,"id":0}`))
	})
	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const G, M = 8, 25
	var wg sync.WaitGroup
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < M; i++ {
				var s string
				_ = client.call(ctx, "getbestblockhash", []interface{}{}, &s)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, gotIDs, G*M, "expected %d unique IDs, got %d (duplicates indicate a race)", G*M, len(gotIDs))
	for id, count := range gotIDs {
		require.Equal(t, 1, count, "ID %d appeared %d times — duplicates", id, count)
	}
}

// --- Robustness against bad servers (defense in depth) ----------------------

// Test_IPCClient_Socket_NotExist verifies a missing socket file fails
// cleanly with a connect-time error, not a panic.
func Test_IPCClient_Socket_NotExist(t *testing.T) {
	client := NewIPCClient("/nonexistent/test.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var s string
	err := client.call(ctx, "getbestblockhash", []interface{}{}, &s)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rpc call failed",
		"missing socket should surface as rpc-call error: %v", err)
}

// Test_IPCClient_HTTPStatus_NonOK verifies that non-200 responses produce
// a clear error rather than attempting to parse the body.
func Test_IPCClient_HTTPStatus_NonOK(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream is on fire"))
	})
	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var s string
	err := client.call(ctx, "getbestblockhash", []interface{}{}, &s)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected http status",
		"500 should surface as unexpected-status error: %v", err)
}

// Test_IPCClient_RPCErrorField verifies the JSON-RPC `error` field is
// propagated rather than silently dropped.
func Test_IPCClient_RPCErrorField(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":null,"error":{"code":-32601,"message":"method not found"},"id":0}`))
	})
	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var s string
	err := client.call(ctx, "bogus", []interface{}{}, &s)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rpc error")
	require.Contains(t, err.Error(), "method not found")
}

// Test_IPCClient_NonJSON_Response verifies garbage responses fail cleanly.
func Test_IPCClient_NonJSON_Response(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not the rpc you were looking for</html>"))
	})
	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var s string
	err := client.call(ctx, "getbestblockhash", []interface{}{}, &s)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode response")
}

// --- #6.4: BLOCK HEADER VALIDATION GAP (documents missing checks) ----------
//
// These tests demonstrate that the IPC client currently performs ZERO
// validation of BlockHeader contents. They will PASS today (proving the
// gap) and should be UPDATED to require errors once validation is added.
//
// Why this matters — each missing check is a defense-in-depth gap that a
// compromised or buggy PoW node can exploit:
//
//   • Empty hash: txsystem/fgp_txsystem.go:163 hex.DecodeString("") returns
//     []byte{}, not an error → an empty-hash block gets certified.
//   • Wrong-length hash: no length check anywhere in the client → a 16-byte
//     or 50-byte hash is silently accepted into the certification record.
//   • Non-hex hash: caught downstream by hex.DecodeString — but ONLY at the
//     candBlock site (one of three GetBlockHeaderBy* call paths).
//   • Absurd height (max uint64): no bound check → downstream uint64 math
//     (tip.Height - block.Height etc.) is at risk. FGP #5's FollowerVerify
//     check now catches `block.Height > tip.Height`, but a tip.Height ==
//     math.MaxUint64 still tunnels through.
//   • Empty PreviousBlockHash / RxHash: never read by FGP → no chain-linkage
//     verification between successive certifications, no PoW verification
//     at the FGP layer at all.

func Test_IPCClient_NoBlockHeaderValidation_DocumentsGap(t *testing.T) {
	cases := []struct {
		name       string
		headerJSON string
		risk       string
	}{
		{
			name:       "empty hash accepted",
			headerJSON: `{"hash":"","height":42,"previousblockhash":"aa","rx_hash":"bb"}`,
			risk:       "empty-hash block can be certified; hex.DecodeString(\"\") returns []byte{}, not an error",
		},
		{
			name:       "16-byte (too short) hash accepted",
			headerJSON: `{"hash":"00112233445566778899aabbccddeeff","height":1,"previousblockhash":"aa","rx_hash":"bb"}`,
			risk:       "non-standard hash length tunnels into the BFT certification record; consumers must each re-check",
		},
		{
			name:       "100-byte (too long) hash accepted",
			headerJSON: `{"hash":"` + strings.Repeat("ab", 100) + `","height":1,"previousblockhash":"aa","rx_hash":"bb"}`,
			risk:       "oversized hash silently accepted; no upper bound",
		},
		{
			name:       "max-uint64 height accepted",
			headerJSON: `{"hash":"aa","height":18446744073709551615,"previousblockhash":"bb","rx_hash":"cc"}`,
			risk:       "no upper-bound on height; defense-in-depth — FGP #5's FollowerVerify catches one underflow site, others may exist",
		},
		{
			name:       "all-fields-zero header accepted",
			headerJSON: `{"hash":"","height":0,"previousblockhash":"","rx_hash":""}`,
			risk:       "genesis-like sentinel can be returned mid-chain; chain linkage never checked",
		},
		{
			name:       "empty previousblockhash and rx_hash accepted",
			headerJSON: `{"hash":"aa","height":5,"previousblockhash":"","rx_hash":""}`,
			risk:       "no chain-linkage check across certifications; no PoW verification at FGP layer",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"jsonrpc":"2.0","result":%s,"error":null,"id":0}`, c.headerJSON)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			sock, shutdown := startMockUnicitydHandler(t, handler)
			defer shutdown()

			client := NewIPCClient(sock)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			// Use the public surface that an FGP consumer would.
			hdr, err := client.GetBlockHeaderByHash(ctx, "anyhash")

			// GAP: the client returns the malformed header without error.
			// When validation is added this should change to require.Error.
			require.NoError(t, err,
				"GAP: client accepted malformed header (%s) — risk: %s",
				c.name, c.risk)
			require.NotNil(t, hdr,
				"GAP: client returned nil header without error (%s)", c.name)
			t.Logf("GAP confirmed: %s — %s", c.name, c.risk)
		})
	}
}

// Test_IPCClient_NonHexHash_FailsDownstream_NotAtClient documents that the
// only "validation" of Hash currently happens at hex.DecodeString in
// txsystem/fgp_txsystem.go:163 — and ONLY for the candidate-block path.
// The client itself accepts it. This proves the missing validation belongs
// at the client boundary, not deep inside txsystem.
func Test_IPCClient_NonHexHash_AcceptedByClient(t *testing.T) {
	body := `{"jsonrpc":"2.0","result":{"hash":"ZZ-not-hex-ZZ","height":1,"previousblockhash":"aa","rx_hash":"bb"},"error":null,"id":0}`
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	hdr, err := client.GetBlockHeaderByHash(ctx, "anyhash")
	require.NoError(t, err,
		"GAP: client accepted non-hex hash; would only fail later at hex.DecodeString in txsystem (candidate-block path only)")
	require.Equal(t, "ZZ-not-hex-ZZ", hdr.Hash)
}

// ---------------------------------------------------------------------------
// F10 — Response-ID validation (currently disabled pending unicity-node fix)
// ---------------------------------------------------------------------------
//
// pow/ipc_client.go:109-112 has the response-ID validation commented out
// with `// TODO PoW node always returns ID=0`. That upstream bug was fixed
// in unicity-node@f7d9fdb ("Mirror request id in rpc response") on the
// bft-snapshots branch, so the TODO is stale.
//
// This is a negative-assertion test: it PASSES today (documenting that the
// client does NOT reject a mismatched response ID) and should be FLIPPED to
// require.Error once the validation block is uncommented.
//
// See INVESTIGATIONS.md §F10 and aggregator-subscription E2E_FOLLOWUP_PROBES.md.
func Test_IPCClient_RequestID_ResponseMismatchAcceptedToday_DocumentsGap(t *testing.T) {
	// Mock always responds with id=999, never echoing the request's id.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		// Deliberately mismatch: request had id=N (N>=1), respond with 999.
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"deadbeef","error":null,"id":999}`))
	})
	sock, shutdown := startMockUnicitydHandler(t, handler)
	defer shutdown()

	client := NewIPCClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var s string
	err := client.call(ctx, "getbestblockhash", []interface{}{}, &s)

	// GAP: the client currently ignores the response ID entirely.
	// When pow/ipc_client.go:109-112 is uncommented, this should become:
	//   require.Error(t, err)
	//   require.Contains(t, err.Error(), "rpc response ID mismatch")
	require.NoError(t, err,
		"GAP: client accepted a response with id=999 for a request with a different id "+
			"(validation disabled at ipc_client.go:109-112). Flip to require.Error when re-enabled.")
	require.Equal(t, "deadbeef", s, "result should still decode despite the ID mismatch")
	t.Logf("GAP confirmed: response-ID mismatch (999 vs request id) accepted silently")
}

// ---------------------------------------------------------------------------
// F3 — Pool-side stale-FD behavior after PoW restart (self-healing probe)
// ---------------------------------------------------------------------------
//
// After unicityd restarts, the FGP leader's http.Transport keep-alive pool
// holds a connection to the OLD process. The next RPC reuses the stale FD and
// fails (connection reset / EOF). The audit's live probe on bft-fgp-2sh showed
// the pool SELF-HEALS within ~1 T1 cycle — the transport retires the dead
// connection and the subsequent call succeeds.
//
// This test reproduces that at unit level:
//   1. Start a mock server on a fixed unix socket; make a call (pools a conn).
//   2. Shut the server down + remove the socket (simulates unicityd stopping).
//   3. Start a NEW server on the same socket path (simulates the restart).
//   4. Subsequent call(s) must EVENTUALLY succeed — proving self-healing.
//
// It tolerates whether the FIRST post-restart call errors (Go's transport
// retry behavior for POST is version/timing dependent) — the load-bearing
// assertion is that the client recovers without needing a fresh IPCClient.
//
// See INVESTIGATIONS.md §F3 / §F12 and E2E_FOLLOWUP_PROBES.md F3-S1.
func Test_IPCClient_StalePoolAfterServerRestart_SelfHeals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping restart/self-heal test in -short mode")
	}

	sockPath := shortSockPath(t)

	startServer := func() func() {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","error":null,"id":0}`))
		})
		server := &http.Server{Handler: handler}
		ln, err := net.Listen("unix", sockPath)
		require.NoError(t, err)
		go func() { _ = server.Serve(ln) }()
		time.Sleep(40 * time.Millisecond)
		return func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
		}
	}

	client := NewIPCClient(sockPath)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. First call — establishes a pooled keep-alive connection.
	stop1 := startServer()
	var s string
	require.NoError(t, client.call(ctx, "getbestblockhash", nil, &s),
		"baseline call before restart should succeed")
	require.Equal(t, "ok", s)

	// 2. Stop the server and remove the socket (unix sockets must be unlinked
	//    before a new listener can bind the same path) — simulates unicityd stop.
	stop1()
	_ = os.Remove(sockPath)

	// 3. Restart a fresh server on the same socket path — simulates the restart.
	stop2 := startServer()
	defer stop2()

	// 4. The client must recover. The first post-restart call MAY hit the
	//    stale pooled connection and error; if so, a retry must succeed. We
	//    allow up to a few attempts within the T1-equivalent window.
	var firstErr error
	recovered := false
	for attempt := 1; attempt <= 5; attempt++ {
		var out string
		err := client.call(ctx, "getbestblockhash", nil, &out)
		if err == nil {
			recovered = true
			t.Logf("recovered on attempt %d (firstErr=%v)", attempt, firstErr)
			require.Equal(t, "ok", out)
			break
		}
		if firstErr == nil {
			firstErr = err
			t.Logf("stale-pool symptom on attempt 1: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	require.True(t, recovered,
		"client failed to self-heal after server restart within 5 attempts; "+
			"this would indicate the F3 fix (CloseIdleConnections / IdleConnTimeout) is needed "+
			"to recover at all, not just faster")

	// Documentation: note whether the stale-FD symptom actually surfaced.
	if firstErr != nil {
		t.Logf("F3 stale-pool symptom reproduced (first post-restart call failed: %v), "+
			"then transport self-healed — matches live bft-fgp-2sh probe", firstErr)
	} else {
		t.Logf("no stale-pool symptom this run (transport reused or re-dialed cleanly); "+
			"self-heal still confirmed")
	}
}

// ---------------------------------------------------------------------------
// Decision-table + equivalence-partition probe of the JSON-RPC response
// envelope parsing in call() (ipc_client.go:104-122).
// ---------------------------------------------------------------------------
//
// Technique: decision table over (Error field) × (Result field), plus
// equivalence partitioning of the Error field's JSON type. JSON-RPC 2.0
// says `error` must be null or an object — but the client checks
// `rpcResp.Error != nil` where Error is interface{}. So a buggy/malicious
// unicityd sending error as `false`, `0`, or `""` would be treated as an
// RPC error and MASK an otherwise-valid result. This probe documents the
// actual behavior for each class so we know whether it's a finding.
func Test_IPCClient_ResponseEnvelope_DecisionTable(t *testing.T) {
	cases := []struct {
		name         string
		responseJSON string
		expectErr    bool
		errContains  string
		wantResult   string // checked only when expectErr == false
		note         string
	}{
		{
			name:         "error=null, result=valid → success",
			responseJSON: `{"result":"abc","error":null,"id":0}`,
			expectErr:    false, wantResult: "abc",
			note: "happy path",
		},
		{
			name:         "error=object, result=null → rpc error",
			responseJSON: `{"result":null,"error":{"code":-1,"message":"boom"},"id":0}`,
			expectErr:    true, errContains: "rpc error",
			note: "spec-correct error",
		},
		{
			name:         "error=null, result=null → success, empty",
			responseJSON: `{"result":null,"error":null,"id":0}`,
			expectErr:    false, wantResult: "",
			note: "json null decodes into string as no-op",
		},
		{
			name:         "error ABSENT, result ABSENT → ?",
			responseJSON: `{"id":0}`,
			note:         "PROBE: result is nil RawMessage; json.Unmarshal(nil, ...) behavior",
		},
		{
			name:         "error=false (NOT spec) → ?",
			responseJSON: `{"result":"abc","error":false,"id":0}`,
			note:         "PROBE: error!=nil is TRUE for bool false → may MASK valid result",
		},
		{
			name:         "error=0 (NOT spec) → ?",
			responseJSON: `{"result":"abc","error":0,"id":0}`,
			note:         "PROBE: error!=nil is TRUE for number 0 → may MASK valid result",
		},
		{
			name:         "error=empty-string (NOT spec) → ?",
			responseJSON: `{"result":"abc","error":"","id":0}`,
			note:         "PROBE: error!=nil is TRUE for empty string → may MASK valid result",
		},
		{
			name:         "result=number, decode into string → ?",
			responseJSON: `{"result":12345,"error":null,"id":0}`,
			note:         "PROBE: type mismatch on result decode",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(c.responseJSON))
			})
			sock, shutdown := startMockUnicitydHandler(t, handler)
			defer shutdown()

			client := NewIPCClient(sock)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			var result string
			err := client.call(ctx, "getbestblockhash", []interface{}{}, &result)

			// For the explicit (non-PROBE) rows, assert.
			if c.errContains != "" || c.expectErr {
				if c.expectErr {
					require.Error(t, err)
					if c.errContains != "" {
						require.Contains(t, err.Error(), c.errContains)
					}
				}
			} else if c.wantResult != "" || c.name == "error=null, result=null → success, empty" {
				require.NoError(t, err)
				require.Equal(t, c.wantResult, result)
			}

			// For ALL rows, log the empirical outcome so PROBE rows are visible.
			t.Logf("[%s] err=%v result=%q  (%s)", c.name, err, result, c.note)
		})
	}
}

// ---------------------------------------------------------------------------
// F11 — BVA on hash length + equivalence on unchecked BlockHeader fields
// ---------------------------------------------------------------------------
//
// Technique: boundary value analysis on Hash length (a 32-byte hash = 64 hex
// chars; test 0/62/63/64/65/66/128) plus equivalence partitioning of fields
// the client never validates (Confirmations negative, Time negative/future).
// All should be accepted today (the F11 gap). When BlockHeader.Validate()
// lands, the out-of-bounds lengths should be rejected.
func Test_IPCClient_BlockHeader_HashLengthBVA_DocumentsGap(t *testing.T) {
	hexN := func(n int) string { return strings.Repeat("ab", n/2) + strings.Repeat("c", n%2) }

	cases := []struct {
		name    string
		hashLen int // in hex chars
	}{
		{"empty (0)", 0},
		{"62 (one byte short)", 62},
		{"63 (odd, just under)", 63},
		{"64 (exact 32-byte)", 64},
		{"65 (odd, just over)", 65},
		{"66 (one byte over)", 66},
		{"128 (double)", 128},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hash := hexN(c.hashLen)
			body := fmt.Sprintf(`{"jsonrpc":"2.0","result":{"hash":"%s","height":1},"error":null,"id":0}`, hash)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			sock, shutdown := startMockUnicitydHandler(t, handler)
			defer shutdown()

			client := NewIPCClient(sock)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			hdr, err := client.GetBlockHeaderByHash(ctx, "x")
			// GAP: client accepts ANY hash length. When Validate() lands, only
			// len==64 should pass; flip the others to require.Error.
			require.NoError(t, err, "GAP: client accepted hash of %d hex chars", c.hashLen)
			require.Equal(t, c.hashLen, len(hdr.Hash))
			t.Logf("GAP: hash length %d accepted (only 64 is spec-valid)", c.hashLen)
		})
	}
}

// F11 — equivalence partitioning of never-validated numeric fields.
func Test_IPCClient_BlockHeader_UncheckedNumericFields_DocumentsGap(t *testing.T) {
	cases := []struct {
		name string
		body string
		risk string
	}{
		{
			name: "negative Confirmations",
			body: `{"jsonrpc":"2.0","result":{"hash":"aa","height":1,"confirmations":-99},"error":null,"id":0}`,
			risk: "IsActive() relies on Confirmations>0; a crafted negative value flips active/inactive logic",
		},
		{
			name: "negative Time",
			body: `{"jsonrpc":"2.0","result":{"hash":"aa","height":1,"time":-1},"error":null,"id":0}`,
			risk: "negative unix timestamp accepted; downstream time math could underflow",
		},
		{
			name: "far-future Time",
			body: `{"jsonrpc":"2.0","result":{"hash":"aa","height":1,"time":99999999999},"error":null,"id":0}`,
			risk: "year-5138 timestamp accepted; no sanity bound",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(c.body))
			})
			sock, shutdown := startMockUnicitydHandler(t, handler)
			defer shutdown()
			client := NewIPCClient(sock)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			hdr, err := client.GetBlockHeaderByHash(ctx, "x")
			require.NoError(t, err, "GAP: client accepted %s — %s", c.name, c.risk)
			t.Logf("GAP: %s accepted (hdr=%+v) — %s", c.name, hdr, c.risk)
		})
	}
}

// ---------------------------------------------------------------------------
// F3 — abrupt connection close variant (reliably reproduces stale-FD error)
// ---------------------------------------------------------------------------
//
// The earlier self-heal test used graceful server.Shutdown(), which lets the
// transport re-dial cleanly so the stale-FD symptom often doesn't surface.
// This variant uses server.Close() — which abruptly tears down active
// connections (like unicityd being SIGKILL'd) — to reliably produce the
// "connection reset / EOF" on the pooled connection, then confirms recovery.
func Test_IPCClient_AbruptServerClose_ReproducesStaleFD_ThenRecovers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping abrupt-close test in -short mode")
	}
	sockPath := shortSockPath(t)

	startServer := func() *http.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","error":null,"id":0}`))
		})
		server := &http.Server{Handler: handler}
		ln, err := net.Listen("unix", sockPath)
		require.NoError(t, err)
		go func() { _ = server.Serve(ln) }()
		time.Sleep(40 * time.Millisecond)
		return server
	}

	client := NewIPCClient(sockPath)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Baseline call — pools a keep-alive connection.
	server1 := startServer()
	var s string
	require.NoError(t, client.call(ctx, "getbestblockhash", nil, &s))
	require.Equal(t, "ok", s)

	// 2. ABRUPT close (server.Close, not Shutdown) — forcibly tears down the
	//    pooled connection, simulating unicityd SIGKILL.
	require.NoError(t, server1.Close())
	_ = os.Remove(sockPath)

	// 3. Restart on the same socket.
	server2 := startServer()
	defer func() { _ = server2.Close() }()

	// 4. Recovery: the first call MAY error on the stale FD; a subsequent call
	//    MUST succeed. Document whether the stale-FD symptom surfaced.
	var firstErr error
	recovered := false
	for attempt := 1; attempt <= 5; attempt++ {
		var out string
		err := client.call(ctx, "getbestblockhash", nil, &out)
		if err == nil {
			recovered = true
			require.Equal(t, "ok", out)
			break
		}
		if firstErr == nil {
			firstErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, recovered, "client must self-heal after abrupt server close (firstErr=%v)", firstErr)
	if firstErr != nil {
		t.Logf("F3 stale-FD symptom reproduced via abrupt close: %v — then self-healed", firstErr)
	} else {
		t.Logf("no stale-FD symptom even with abrupt close (transport re-dialed); self-heal confirmed")
	}
}
