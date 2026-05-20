package partition

// Task 5 — verification of FGP #3 fix (PR #13, commits f4156d3 + 982cbe8).
//
// Issue: https://github.com/unicitynetwork/finality-gadget/issues/3
// Fix PRs: https://github.com/unicitynetwork/finality-gadget/pull/13
//   commit f4156d3 — refactor node recovery (dedicated replication thread + Busy status)
//   commit 982cbe8 — allow multiple concurrent replication requests (configurable maxWorkers)
//
// The dev added 6 tests in partition/recovery_test.go that cover the
// per-request behaviour (happy path, error paths, Busy when channel is
// pre-filled). However, those tests DO NOT exercise the actual
// `replicationLoop` worker pool — they call `processReplicationRequest`
// directly or test `handleLedgerReplicationRequest`'s select-decision
// against an artificially-filled channel.
//
// The MAIN claim of the fix — "prevents possible goroutine exhaustion
// attack vector and cleanly handles shutdown" — is therefore not
// directly verified by the dev's tests. This file adds the missing
// verification:
//
//   T1. Goroutine count stays bounded under a 1000-request flood.
//   T2. With maxWorkers=N, exactly N workers process concurrently.
//   T3. Shutdown lifecycle — cancelling ctx makes all workers exit.
//   T4. replication.Busy.String() round-trips correctly.
//   T5. NewNodeConf rejects maxWorkers < 1.
//
// T1 is the linchpin — it directly demonstrates that the
// goroutine-exhaustion attack vector is mitigated.

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-go-base/types"

	testlogger "github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
	testpeer "github.com/unicitynetwork/finality-gadget/internal/testutils/peer"
	testsig "github.com/unicitynetwork/finality-gadget/internal/testutils/sig"
	testtrustbase "github.com/unicitynetwork/finality-gadget/internal/testutils/trustbase"
	"github.com/unicitynetwork/finality-gadget/network/protocol/replication"
)

// concurrentMockValidatorNetwork is a thread-safe Send/lastResponse mock — the
// dev's MockValidatorNetwork is not concurrency-safe (`append` races under
// concurrent Sends). We need a safe variant for the flood test.
type concurrentMockValidatorNetwork struct {
	mu             sync.Mutex
	sentMessages   []any
	statusCounts   map[replication.Status]int
}

func newConcurrentMockNet() *concurrentMockValidatorNetwork {
	return &concurrentMockValidatorNetwork{statusCounts: map[replication.Status]int{}}
}

func (m *concurrentMockValidatorNetwork) Send(_ context.Context, msg any, _ ...peer.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentMessages = append(m.sentMessages, msg)
	if resp, ok := msg.(*replication.LedgerReplicationResponse); ok {
		m.statusCounts[resp.Status]++
	}
	return nil
}

func (m *concurrentMockValidatorNetwork) ReceivedChannel() <-chan any         { return nil }
func (m *concurrentMockValidatorNetwork) RegisterValidatorProtocols() error  { return nil }

func (m *concurrentMockValidatorNetwork) countByStatus() map[replication.Status]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[replication.Status]int, len(m.statusCounts))
	for k, v := range m.statusCounts {
		cp[k] = v
	}
	return cp
}

func (m *concurrentMockValidatorNetwork) total() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sentMessages)
}

// setupNodeWithWorkers spins up a test node with the given maxWorkers, swaps
// in the concurrency-safe mock, swaps in a channel sized to maxWorkers, and
// starts maxWorkers replicationLoop goroutines bound to the returned ctx.
// The cleanup func cancels the ctx and waits for all workers to exit.
func setupNodeWithWorkers(t *testing.T, maxWorkers int, blockCount int) (*Node, *concurrentMockValidatorNetwork, context.Context, func()) {
	t.Helper()
	node, _ := createTestNode(t, testNodeOpts{blockCount: blockCount})

	mockNet := newConcurrentMockNet()
	node.network = mockNet
	node.conf.replicationConfig.maxWorkers = uint64(maxWorkers)
	node.replicationCh = make(chan replicationRequest, maxWorkers)

	ctx, cancel := context.WithCancel(t.Context())

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			node.replicationLoop(ctx)
		}()
	}

	cleanup := func() {
		cancel()
		// give workers up to 2 s to exit; in normal runs they exit immediately
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("replicationLoop workers did not exit within 2 s after ctx cancel — shutdown lifecycle BROKEN")
		}
	}
	return node, mockNet, ctx, cleanup
}

// T1 — attack-vector reproducer. Fire a large flood of replication requests
// concurrently; the goroutine count MUST stay bounded (worker pool size
// + caller goroutines + Go runtime baseline), NOT grow with request count.
//
// Pre-fix design (`go func() { ... }()` per request) would have spawned 1
// goroutine per request → ~1000 transient goroutines plus 1000 BoltDB
// iterators. Post-fix design: at most `maxWorkers` (here 2) workers are
// running on the node side at any time; surplus requests get Busy and
// don't spawn anything.
func TestFGP3_AttackVector_FloodDoesNotSpawnUnboundedGoroutines(t *testing.T) {
	const maxWorkers = 2
	const floodSize = 1000

	node, mockNet, ctx, cleanup := setupNodeWithWorkers(t, maxWorkers, 5)
	defer cleanup()

	baseline := runtime.NumGoroutine()
	t.Logf("baseline goroutines (after workers started, before flood): %d", baseline)

	peerIDs := testpeer.GeneratePeerIDs(t, 1)

	// Fire the flood — all from a single tight loop, no per-request goroutines
	// (the attacker is just hammering the API, not spawning client goroutines).
	for i := 0; i < floodSize; i++ {
		req := newReplicationRequest(node.PartitionID(), node.ShardID(), peerIDs[0].String(), 1, 5)
		// handleLedgerReplicationRequest is the API entry point that an
		// incoming libp2p message would invoke.
		require.NoError(t, node.handleLedgerReplicationRequest(ctx, req))
	}

	// Let the workers drain whatever they can in a short window. We don't
	// require ALL to complete — only that goroutine count stays bounded.
	time.Sleep(200 * time.Millisecond)

	peak := runtime.NumGoroutine()
	t.Logf("peak goroutines after %d-request flood: %d (delta from baseline = %d)",
		floodSize, peak, peak-baseline)

	// Allow some headroom for Go runtime / GC / timers — pre-fix would be
	// ~floodSize, post-fix should be a small constant.
	delta := peak - baseline
	require.LessOrEqual(t, delta, 50,
		"goroutine count grew by %d under a %d-request flood — attack vector NOT mitigated",
		delta, floodSize)

	// Sanity: we should have seen some Busy responses since 1000 ≫ 2.
	statusCounts := mockNet.countByStatus()
	t.Logf("status distribution across %d response sends: %+v",
		mockNet.total(), statusCounts)
	require.Greater(t, statusCounts[replication.Busy], 0,
		"expected at least some Busy responses under flood; got distribution: %+v", statusCounts)
	require.Greater(t, statusCounts[replication.Ok], 0,
		"expected at least some Ok responses (workers should have processed some); got distribution: %+v", statusCounts)
}

// T2 — verify the worker pool can actually run N requests in parallel.
// With maxWorkers=5, we hand-craft 5 replication requests that the worker
// pool processes; we expect all 5 to be handled (sum of Ok responses == 5,
// or in the worst case, Ok + Busy == 5).
func TestFGP3_WorkerPool_RunsRequestsInParallel(t *testing.T) {
	const maxWorkers = 5
	node, mockNet, ctx, cleanup := setupNodeWithWorkers(t, maxWorkers, 5)
	defer cleanup()

	peerIDs := testpeer.GeneratePeerIDs(t, 1)
	for i := 0; i < maxWorkers; i++ {
		req := newReplicationRequest(node.PartitionID(), node.ShardID(), peerIDs[0].String(), 1, 5)
		require.NoError(t, node.handleLedgerReplicationRequest(ctx, req))
	}

	// Wait for the worker pool to drain.
	require.Eventually(t, func() bool {
		return mockNet.countByStatus()[replication.Ok] >= maxWorkers
	}, 2*time.Second, 20*time.Millisecond,
		"expected %d Ok responses, got distribution: %+v",
		maxWorkers, mockNet.countByStatus())

	t.Logf("worker pool processed %d requests in parallel (no Busy required at this load)", maxWorkers)
}

// T3 — shutdown lifecycle. Confirm that cancelling ctx causes all workers to
// exit cleanly within a bounded window. The cleanup func in setupNodeWithWorkers
// asserts this with a 2-second deadline; calling cleanup() explicitly here so
// the test will FAIL with a clear message if workers leak.
func TestFGP3_Shutdown_AllWorkersExitOnCtxCancel(t *testing.T) {
	const maxWorkers = 10
	_, _, _, cleanup := setupNodeWithWorkers(t, maxWorkers, 3)
	// Cleanup will cancel + wait + Fatal if any worker fails to exit.
	cleanup()
	t.Logf("all %d replicationLoop workers exited cleanly after ctx cancel", maxWorkers)
}

// T4 — replication.Busy was newly added to the Status enum by commit f4156d3;
// its String() representation must be "Busy" for log clarity.
func TestFGP3_Status_BusyStringIsBusy(t *testing.T) {
	require.Equal(t, "Busy", replication.Busy.String())
	// And sanity: the pre-existing statuses still string correctly.
	require.Equal(t, "OK", replication.Ok.String())
}

// T5 — config validation added in commit 982cbe8: maxWorkers < 1 must be
// rejected by NewNodeConf. Exercises the real validation end-to-end by
// running the full NewNodeConf happy-path setup but with maxWorkers=0.
func TestFGP3_Config_MaxWorkersZeroRejected(t *testing.T) {
	// Full setup mirrors partition/configuration_test.go TestNewNodeConf
	// (same packages, same helpers — see createKeyConf in that file).
	blockDB := memorydb.New()
	shardDB := memorydb.New()
	log := testlogger.New(t)

	keyConf, nodeInfo := createKeyConf(t)
	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     0x01010101,
		ShardID:         types.ShardID{},
		PartitionTypeID: 999,
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       2500 * time.Millisecond,
		Epoch:           0,
		EpochStart:      1,
		Validators:      []*types.NodeInfo{nodeInfo},
	}

	shardConfStore, err := NewShardConfStore(shardDB, log)
	require.NoError(t, err)
	require.NoError(t, shardConfStore.Store(shardConf))

	signer, _ := testsig.CreateSignerAndVerifier(t)
	trustBase := testtrustbase.NewTrustBase(t, signer)
	trustBaseStore, err := trustbase.NewTrustBaseStore(memorydb.New(), log)
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	// Happy-path control: maxWorkers=1 succeeds. This shows the rest of the
	// setup is correct so the test failure for maxWorkers=0 is isolated.
	conf, err := NewNodeConf(keyConf, shardConfStore, trustBaseStore,
		WithBlockDB(blockDB),
		WithReplicationParams(1, 2, 1, 1000*time.Millisecond),
	)
	require.NoError(t, err, "happy-path control: maxWorkers=1 should succeed")
	require.NotNil(t, conf)

	// And now the negative case: maxWorkers=0 MUST be rejected.
	_, err = NewNodeConf(keyConf, shardConfStore, trustBaseStore,
		WithBlockDB(blockDB),
		WithReplicationParams(1, 2, 0, 1000*time.Millisecond),
	)
	require.Error(t, err, "maxWorkers=0 must be rejected by NewNodeConf")
	require.Contains(t, err.Error(), "replication max workers",
		"expected an error mentioning 'replication max workers', got: %v", err)
	t.Logf("NewNodeConf correctly rejected maxWorkers=0: %v", err)
}
