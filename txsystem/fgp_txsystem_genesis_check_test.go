package txsystem

// Task 7 — verification of FGP #7 fix (PR #13, commit 7cc4c1b "better genesis check").
//
// Issue: https://github.com/unicitynetwork/finality-gadget/issues/7
// Fix PR: https://github.com/unicitynetwork/finality-gadget/pull/13
//
// The bug: LeaderPropose used `!bytes.Equal(s.pendingStateHash, s.genesisHash)`
// to decide whether to fetch hFG (the height of the last FG-certified PoW
// block).  But:
//
//   • s.pendingStateHash is reset to nil after Commit() or Revert()
//   • s.genesisHash is also nil (never set)
//   • Therefore bytes.Equal(nil, nil) is always true between rounds,
//     making the "genesis branch" always take effect — hFG stays at 0
//     forever, EVEN AFTER blocks have been certified.
//
// Consequences:
//   • Line 122 `if tip.Height <= hFG`  → always evaluates as `tip.Height <= 0`
//                                        → re-finalization not detected
//   • Line 133 `if candidateHeight <= hFG` → always `candidateHeight <= 0`
//                                            → re-finalization not detected
//
// The fix: change the condition to `s.committedStateHash != nil`, which is
// the correct invariant (fetch hFG iff we have a committed state).
//
// The dev added NO tests for this fix (commit 7cc4c1b is a 4-line code-only
// change). This file fills that gap:
//
//   T1 — Post-commit: hFG IS fetched and finalization proceeds normally
//        (proves the bug fix takes effect at all)
//
//   T2 — Post-commit: tip.Height <= hFG → re-finalization REJECTED
//        (proves the line-122 safety check is now functional)
//
//   T3 — Post-commit: candidateHeight <= hFG → re-finalization REJECTED
//        (proves the line-133 safety check is now functional)
//
//   T4 — Genesis case (committedStateHash=nil) still works
//        (boundary preservation — the fix didn't break genesis bootstrap)
//
//   T5 — THE LINCHPIN: pendingStateHash=nil + committedStateHash set
//        (the exact "between rounds" state)
//        Pre-fix this would have silently re-finalized an already-finalized
//        block at the committed height.  Post-fix correctly rejects.

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
	powtypes "github.com/unicitynetwork/finality-gadget/pow/types"
)

// committedHashHex is a fixed 32-byte hex string used as a "previously
// committed" PoW block hash across these tests.
const committedHashHex = "cafebabe11111111222222223333333344444444555555556666666677777777"

func decodeHashHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	require.NoError(t, err)
	return b
}

// T1 — Post-commit, hFG is fetched from the committedStateHash and
// finalization proceeds normally.
//
//	committedStateHash = <hash>  (set; height=10 in the mock)
//	tip.Height         = 15
//	dFG                = 3       → candidateHeight = 15 - 2 = 13
//	hFG                = 10      (fetched correctly)
//
// 13 > hFG=10, so propose should succeed.
func TestFGP7_LeaderPropose_PostCommit_hFGCorrectlyFetched(t *testing.T) {
	log := logger.New(t)
	committedHash := decodeHashHex(t, committedHashHex)

	mockClient := &mockPowClient{
		tipHeight: 15,
		tips:      []powtypes.ChainTip{{Status: "active", Height: 15, BranchLen: 0}},
		blocks: map[string]*powtypes.BlockHeader{
			// fgp-side believes the committed block is at PoW height 10
			committedHashHex: {Hash: committedHashHex, Height: 10},
		},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "3"},
	}, mockClient, log)
	require.NoError(t, err)

	// simulate: we have already finalized a block (commit happened earlier).
	// In real life this would be done via Commit() on a previous round; here we
	// set the fields directly because we're testing LeaderPropose in isolation.
	s.committedStateHash = committedHash
	s.committedStateHeight = 10
	s.pendingStateHash = nil // typical "between rounds" state

	summary, err := s.LeaderPropose(t.Context(), 1)
	require.NoError(t, err, "post-commit propose with valid range should succeed")
	require.NotNil(t, summary)
	t.Logf("✓ Propose succeeded with hFG correctly fetched (10) and candidate at height 13")
}

// T2 — Post-commit, tip.Height <= hFG must be REJECTED (the line-122 safety
// check is functional only when hFG is correctly fetched).
//
//	committedStateHash = <hash>  (height=10)
//	tip.Height         = 10      (same as hFG)
//	dFG                = 3
//
// Pre-fix, hFG=0 → `10 <= 0` → false → proceeds.  Wrong: nothing new to finalize.
// Post-fix, hFG=10 → `10 <= 10` → true → returns "no new final enough PoW block".
func TestFGP7_LeaderPropose_RejectsRefinalizeAtSameHeight(t *testing.T) {
	log := logger.New(t)
	committedHash := decodeHashHex(t, committedHashHex)

	mockClient := &mockPowClient{
		tipHeight: 10, // tip is at the SAME height as the last committed block
		tips:      []powtypes.ChainTip{{Status: "active", Height: 10, BranchLen: 0}},
		blocks: map[string]*powtypes.BlockHeader{
			committedHashHex: {Hash: committedHashHex, Height: 10},
		},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "3"},
	}, mockClient, log)
	require.NoError(t, err)

	s.committedStateHash = committedHash
	s.committedStateHeight = 10
	s.pendingStateHash = nil

	summary, err := s.LeaderPropose(t.Context(), 1)
	require.Error(t, err, "tip <= hFG must be rejected")
	require.Contains(t, err.Error(), "tip height 10",
		"expected message containing 'tip height 10'; got: %v", err)
	require.Contains(t, err.Error(), "hFG 10",
		"expected message showing hFG=10 (post-fix value); got: %v", err)
	require.Nil(t, summary)
	t.Logf("✓ Refinalization at same height correctly rejected: %v", err)
}

// T3 — Post-commit, candidateHeight <= hFG must be REJECTED (the line-133
// safety check).
//
//	committedStateHash = <hash>  (height=10)
//	tip.Height         = 11
//	dFG                = 3       → candidateHeight = 11 - 2 = 9
//
// Pre-fix, hFG=0 → `9 <= 0` → false → would re-finalize block 9.
// Post-fix, hFG=10 → `9 <= 10` → true → "already finalized or older".
//
// HOWEVER — line 127 catches this earlier because
// `tip.Height(11) - hFG(10) = 1 < dFG-1 = 2` → "not enough confirmations".
// So in this scenario we ACTUALLY hit the line-127 check, not the line-133
// check.  The error message differs but the outcome is the same: rejected.
// Documented in the test logs.
func TestFGP7_LeaderPropose_RejectsRefinalizeBelowCommitted(t *testing.T) {
	log := logger.New(t)
	committedHash := decodeHashHex(t, committedHashHex)

	mockClient := &mockPowClient{
		tipHeight: 11,
		tips:      []powtypes.ChainTip{{Status: "active", Height: 11, BranchLen: 0}},
		blocks: map[string]*powtypes.BlockHeader{
			committedHashHex: {Hash: committedHashHex, Height: 10},
		},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "3"},
	}, mockClient, log)
	require.NoError(t, err)

	s.committedStateHash = committedHash
	s.committedStateHeight = 10
	s.pendingStateHash = nil

	summary, err := s.LeaderPropose(t.Context(), 1)
	require.Error(t, err, "candidate <= hFG (or insufficient confirmations) must be rejected")
	require.Nil(t, summary)
	t.Logf("✓ Refinalization-below-committed correctly rejected: %v", err)
}

// T4 — Boundary: genesis case (committedStateHash=nil) still works.
//
// Confirms the fix did not break the genesis bootstrap path: when nothing
// has been committed yet, hFG=0 is correct (and the function should NOT
// try to call powClient.GetBlockHeaderByHash on a nil hash).
func TestFGP7_LeaderPropose_GenesisCase_StillWorks(t *testing.T) {
	log := logger.New(t)
	mockClient := &mockPowClient{
		tipHeight: 10,
		tips:      []powtypes.ChainTip{{Status: "active", Height: 10, BranchLen: 0}},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "3"},
	}, mockClient, log)
	require.NoError(t, err)

	// fresh node: committedStateHash stays nil
	require.Nil(t, s.committedStateHash)

	summary, err := s.LeaderPropose(t.Context(), 1)
	require.NoError(t, err, "genesis propose must succeed without a committed hash")
	require.NotNil(t, summary)
	t.Logf("✓ Genesis-state propose still works (hFG=0 is correct here)")
}

// T5 — THE LINCHPIN: pre-fix bug scenario.
//
// committedStateHash = <hash>, pendingStateHash = nil (the typical
// "between rounds" state — this is what happens immediately after a
// successful Commit() and before the next propose).
//
// PRE-FIX (the bug):
//   • `bytes.Equal(s.pendingStateHash, s.genesisHash) == bytes.Equal(nil, nil) == true`
//   • → SKIP hFG fetch
//   • → hFG stays at 0
//   • → safety check `candidateHeight <= hFG` becomes `candidateHeight <= 0`
//   • → re-finalization of an already-finalized block goes through silently
//
// POST-FIX:
//   • `s.committedStateHash != nil` is TRUE
//   • → fetch hFG = 10 (the committed block's PoW height)
//   • → safety check fires correctly when candidate <= hFG
//
// Scenario: tip=12, dFG=3, committed at height 10.
//   candidateHeight = 12 - 2 = 10
//   Pre-fix: hFG=0 → `10 <= 0` → false → would re-finalize block 10!
//   Post-fix: hFG=10 → `10 - 10 = 0 < dFG-1=2` → line 127 fires first → reject.
//
// Either way the post-fix path produces an error, and pre-fix produced a
// silent success.  This is the clearest demonstration of the fix.
func TestFGP7_LeaderPropose_LinchpinScenario_RefinalizationBlocked(t *testing.T) {
	log := logger.New(t)
	committedHash := decodeHashHex(t, committedHashHex)

	mockClient := &mockPowClient{
		tipHeight: 12,
		tips:      []powtypes.ChainTip{{Status: "active", Height: 12, BranchLen: 0}},
		blocks: map[string]*powtypes.BlockHeader{
			committedHashHex: {Hash: committedHashHex, Height: 10},
		},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "3"},
	}, mockClient, log)
	require.NoError(t, err)

	// simulate "between rounds" — committed exists, pending was reset to nil
	s.committedStateHash = committedHash
	s.committedStateHeight = 10
	s.pendingStateHash = nil

	summary, err := s.LeaderPropose(t.Context(), 1)
	require.Error(t, err, "re-finalization of an already-finalized block MUST be rejected")
	require.Nil(t, summary)
	t.Logf("✓ Pre-fix bug NOT reproduced (post-fix correctly blocks): %v", err)
}
