package txsystem

// Task 6 — verification of FGP #5 fix (PR #13, commit 0bc2ed4 "prohibit dFG=0").
//
// Issue: https://github.com/unicitynetwork/finality-gadget/issues/5
// Fix PR: https://github.com/unicitynetwork/finality-gadget/pull/13
//
// The dev's commit 0bc2ed4 added 4 logical pieces and 2 tests:
//
//   Part 1 — NewFGPTxSystem rejects dFG=0           (covered: TestNewFGPTxSystem_dFGZero)
//   Part 2 — UpdateConfig rejects dFG=0             (covered: TestUpdateConfig_dFGZero)
//   Part 3 — LeaderPropose rejects branchLen > height  (NO dev test)
//   Part 4 — FollowerVerify rejects block.Height > tip.Height  (NO dev test)
//
// This file fills the gaps with 5 tests:
//
//   T1 — FollowerVerify rejects block-ahead-of-tip (Part 4)
//        Pre-fix this would underflow on `tip.Height - block.Height` and the
//        condition `huge_uint64 < s.dFG-1` would be FALSE — i.e. the malicious
//        "block from the future" would be ACCEPTED. The most security-relevant
//        of the four parts.
//
//   T2 — LeaderPropose rejects branchLen > height (Part 3)
//        Pre-fix this would underflow on `forkHeight = t.Height - t.BranchLen`.
//        Less severe (depends on candidateHeight comparison after), but
//        clearly an "impossible state from PoW node" that should be rejected.
//
//   T3 — dFG=1 boundary: depth-0 block ACCEPTED in FollowerVerify
//        With dFG=1, `s.dFG-1 = 0`. A block at the tip height (depth 0) satisfies
//        `tip.Height-block.Height (0) < s.dFG-1 (0)` → false → ACCEPT. This is
//        the minimum-valid-dFG path that the dFG=0 guard makes the actual lower
//        boundary.
//
//   T4 — dFG=1 boundary: block ABOVE the tip caught by Part 4 sanity check
//        Combines the new minimum dFG with the new "future block" check.
//
//   T5 — dFG=1 boundary: LeaderPropose works at minimum (no underflow on
//        candidateHeight = tip.Height - (s.dFG-1) when dFG=1).

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
	powtypes "github.com/unicitynetwork/finality-gadget/pow/types"
)

// T1 — FollowerVerify: a block whose height is BEYOND tip.Height must be
// rejected by the new sanity check (line 205 of fgp_txsystem.go).
//
// Pre-fix (no sanity check) the subtraction tip.Height - block.Height would
// wrap around to a huge uint64. The next comparison `huge < s.dFG-1` would
// be FALSE, so the function would have returned the block as "ACCEPT" —
// i.e. a block from the future would have been wrongly finalized.
func TestFGP5_FollowerVerify_BlockAheadOfTip_Rejected(t *testing.T) {
	log := logger.New(t)
	const proposedHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	mockClient := &mockPowClient{
		tipHeight: 5, // tip is at height 5
		blocks: map[string]*powtypes.BlockHeader{
			proposedHash: {
				Hash:          proposedHash,
				Height:        20, // proposed block claims to be at height 20 (ahead of tip!)
				Confirmations: 1,  // and active, somehow
			},
		},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "6"},
	}, mockClient, log)
	require.NoError(t, err)

	hashBytes, _ := hex.DecodeString(proposedHash)
	summary, err := s.FollowerVerify(context.Background(), 1, hashBytes)

	require.Error(t, err, "must reject a block whose height exceeds tip.Height")
	require.Contains(t, err.Error(), "ahead of tip",
		"expected 'ahead of tip' in the error; got: %v", err)
	require.Nil(t, summary)
	t.Logf("✓ FollowerVerify correctly rejected block-ahead-of-tip: %v", err)
}

// T2 — LeaderPropose: a chain tip with branchLen > height must be rejected by
// the new sanity check (line 154 of fgp_txsystem.go).
//
// Pre-fix, the subtraction forkHeight = t.Height - t.BranchLen would wrap
// around to a huge uint64; the subsequent `forkHeight < candidateHeight`
// check would be FALSE (huge > small), so the impossible chain tip would
// have been silently accepted as "no conflict".
func TestFGP5_LeaderPropose_BranchLenExceedsHeight_Rejected(t *testing.T) {
	log := logger.New(t)
	mockClient := &mockPowClient{
		tipHeight: 10,
		tips: []powtypes.ChainTip{
			{Status: "active", Height: 10, BranchLen: 0},
			// IMPOSSIBLE in a valid PoW chain — branchLen exceeds height
			{Status: "valid-fork", Height: 5, BranchLen: 8},
		},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "6"},
	}, mockClient, log)
	require.NoError(t, err)

	summary, err := s.LeaderPropose(t.Context(), 1)

	require.Error(t, err, "must reject a chain tip whose branchLen exceeds its height")
	require.Contains(t, err.Error(), "invalid chain tip: branch length 8 exceeds height 5",
		"expected the precise sanity-check error; got: %v", err)
	require.Nil(t, summary)
	t.Logf("✓ LeaderPropose correctly rejected branchLen > height: %v", err)
}

// T3 — dFG=1 (minimum valid) — depth-0 block ACCEPTED in FollowerVerify.
//
// dFG=1 means "1 confirmation needed" → a block at exactly the tip height
// (depth = 0) qualifies. The new guard dFG>=1 makes this the lower boundary.
// Verifies no underflow in `s.dFG-1` (0) and no underflow in
// `tip.Height-block.Height` (0); the comparison `0 < 0` is correctly false.
func TestFGP5_FollowerVerify_dFG1_DepthZeroAccepted(t *testing.T) {
	log := logger.New(t)
	const proposedHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	mockClient := &mockPowClient{
		tipHeight: 5,
		blocks: map[string]*powtypes.BlockHeader{
			proposedHash: {
				Hash:          proposedHash,
				Height:        5, // depth = 5 - 5 = 0
				Confirmations: 1, // active chain, 1 confirmation
			},
		},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "1"},
	}, mockClient, log)
	require.NoError(t, err)

	hashBytes, _ := hex.DecodeString(proposedHash)
	summary, err := s.FollowerVerify(context.Background(), 1, hashBytes)

	require.NoError(t, err, "dFG=1 with depth-0 block should ACCEPT (no underflow at the boundary)")
	require.NotNil(t, summary)
	require.Equal(t, hashBytes, summary.Root())
	t.Logf("✓ dFG=1 minimum boundary works: depth-0 block accepted")
}

// T4 — dFG=1 boundary combined with the Part 4 sanity check: even at the
// minimum valid dFG, a block ABOVE the tip is still rejected (the sanity
// check at line 205 runs BEFORE the dFG-depth comparison at line 208).
func TestFGP5_FollowerVerify_dFG1_BlockAboveTip_StillRejected(t *testing.T) {
	log := logger.New(t)
	const proposedHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	mockClient := &mockPowClient{
		tipHeight: 4,
		blocks: map[string]*powtypes.BlockHeader{
			proposedHash: {
				Hash:          proposedHash,
				Height:        5, // above the tip
				Confirmations: 1,
			},
		},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "1"},
	}, mockClient, log)
	require.NoError(t, err)

	hashBytes, _ := hex.DecodeString(proposedHash)
	summary, err := s.FollowerVerify(context.Background(), 1, hashBytes)

	require.Error(t, err, "block above tip must still be rejected even at dFG=1")
	require.Contains(t, err.Error(), "ahead of tip",
		"sanity check must fire before the dFG-depth comparison; got: %v", err)
	require.Nil(t, summary)
	t.Logf("✓ dFG=1 + block-above-tip: sanity check still catches it: %v", err)
}

// T5 — dFG=1 minimum — LeaderPropose at the lowest reachable state.
//
// Verifies the LeaderPropose path doesn't underflow when dFG=1 and the chain
// has only the genesis-area blocks. With dFG=1, candidateHeight = tip.Height
// - (1-1) = tip.Height (no underflow even at low tip heights).
func TestFGP5_LeaderPropose_dFG1_Works(t *testing.T) {
	log := logger.New(t)
	mockClient := &mockPowClient{
		tipHeight: 1, // genesis-area; tip at height 1
		tips: []powtypes.ChainTip{
			{Status: "active", Height: 1, BranchLen: 0},
		},
	}
	s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{
		PartitionParams: map[string]string{"dFG": "1"},
	}, mockClient, log)
	require.NoError(t, err)

	summary, err := s.LeaderPropose(t.Context(), 1)
	require.NoError(t, err,
		"dFG=1 with tip at minimum height must succeed without underflow")
	require.NotNil(t, summary)
	// State summary's Root() is the candidate block's hash; the mockPowClient's
	// GetBlockHeaderByHeight returns a fixed hash of 32 0x01 bytes.
	require.Equal(t, bytes.Repeat([]byte{1}, 32), summary.Root(),
		"candidate block hash should be the mock's deterministic 32×0x01 value")
	t.Logf("✓ LeaderPropose at dFG=1, tip=1 succeeds; candidate hash: %x", summary.Root())
}
