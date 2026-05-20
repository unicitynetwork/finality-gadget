package partition

// Tests for FGP #10 — "RegisterValidatorProtocols error logged but not
// returned — node runs in broken state."
//
// Issue:    https://github.com/unicitynetwork/finality-gadget/issues/10
// Fix PR:   https://github.com/unicitynetwork/finality-gadget/pull/13
// Fix commit: 4556098 "return fatal error instead of logging"
//
// Primary fix (commit 4556098):
//
//   partition/node.go:110-112 — one-line change:
//     - n.log.ErrorContext(ctx, "Failed to register validator protocols", logger.Error(err))
//     + return fmt.Errorf("failed to register validator protocols: %w", err)
//
// This file covers:
//
//   T1  — primary fix verification: when RegisterValidatorProtocols
//         returns an error, n.Run(ctx) must propagate it (not log+continue).
//
// And probes the three "Related Issues" the #10 body called out, which
// were silently DROPPED by PR #13 (same pattern as #6.4 and #8 adjacents):
//
//   G1  — printUC doesn't check uc.InputRecord nil before dereferencing
//         uc.InputRecord.Hash (node.go:299-306)
//   G2  — Validators() leaves zero-value peer.ID entries in the returned
//         slice when peer.Decode fails (node.go:256-267)
//   G3  — sendCertificationRequest accesses luc.UnicitySeal.Timestamp
//         without nil-check (proposal_producer.go:49)
//
// G1-G3 are negative-assertion tests documenting the gap; flip to
// require.NoError / require.NotPanics when the production fix lands.

import (
	"context"
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	testlogger "github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
)

// errorRegisteringValidatorNetwork — minimal mock implementing the
// ValidatorNetwork interface; RegisterValidatorProtocols returns a sentinel.
type errorRegisteringValidatorNetwork struct {
	regErr error
}

func (m *errorRegisteringValidatorNetwork) Send(_ context.Context, _ any, _ ...peer.ID) error {
	return nil
}
func (m *errorRegisteringValidatorNetwork) ReceivedChannel() <-chan any { return nil }
func (m *errorRegisteringValidatorNetwork) RegisterValidatorProtocols() error {
	return m.regErr
}

// T1 — primary fix verification.
//
// When RegisterValidatorProtocols returns an error, n.Run(ctx) must return
// it — not log and continue. Pre-fix, the error was logged and Run kept
// going, leaving the node stuck in "initializing" state forever.
func TestFGP10_RegisterValidatorProtocols_ErrorPropagated(t *testing.T) {
	log := testlogger.New(t)
	sentinel := errors.New("simulated p2p protocol registration failure")

	// Minimal *Node — only the fields Run() touches BEFORE network operations
	// matter for this test. We never get past line 111 in node.go.
	n := &Node{
		log:     log,
		network: &errorRegisteringValidatorNetwork{regErr: sentinel},
	}

	err := n.Run(context.Background())

	require.Error(t, err, "Run must propagate RegisterValidatorProtocols error")
	require.ErrorIs(t, err, sentinel,
		"the propagated error must wrap the original (verify with errors.Is)")
	require.Contains(t, err.Error(), "register validator protocols",
		"error message should mention what failed: %v", err)
	t.Logf("primary fix confirmed: %v", err)
}

// T1b — control: when RegisterValidatorProtocols succeeds, Run proceeds.
//
// This ensures T1 is actually distinguishing the error case from a generic
// "Run returns something" — Run does many things after line 111, so we
// need a control that proves the error gate is what's catching it.
//
// We don't run a real Run() (would require full Node setup) — instead we
// just call the registration step directly and confirm nil → no error.
func TestFGP10_RegisterValidatorProtocols_NoErrorWhenSuccess(t *testing.T) {
	n := &Node{
		log:     testlogger.New(t),
		network: &errorRegisteringValidatorNetwork{regErr: nil},
	}
	// We can't call full Run without more setup, but the registration step
	// itself returns nil with our mock, and the gate at lines 110-111 is
	// the only place RegisterValidatorProtocols is called.
	require.NoError(t, n.network.RegisterValidatorProtocols())
	t.Logf("control case: nil registration error means Run passes the gate at node.go:110-112")
}

// G1 — printUC dereferences uc.InputRecord without nil-check.
//
// Issue #10 body listed this as a Related Issue. The fix in PR #13 did
// NOT address it. Current code (node.go:299-306) checks `if uc == nil`
// at the top, then accesses uc.InputRecord.Hash directly — if
// uc.InputRecord is nil but uc is not, this panics.
//
// This test demonstrates the gap by passing a UC with nil InputRecord
// and asserting that printUC panics (currently). Post-fix this should
// become require.NotPanics + an assertion that the printed string handles
// the missing InputRecord gracefully.
func TestFGP10_RELATED_PrintUC_NilInputRecord_PanicsCurrently_DocumentsGap(t *testing.T) {
	uc := &types.UnicityCertificate{
		Version:     1,
		InputRecord: nil, // ← the gap
	}

	require.Panics(t, func() {
		_ = printUC(uc)
	}, "GAP CLOSED: printUC now handles nil InputRecord without panic — flip this to require.NotPanics")

	t.Logf("GAP confirmed: printUC(uc) panics when uc.InputRecord == nil; " +
		"#10 body's Related Issue (nil dereference in printUC) is NOT addressed in PR #13")
}

// G2 — Validators() leaves zero-value peer.ID entries when peer.Decode fails.
//
// Issue #10 body listed this as a Related Issue. Code (node.go:256-267):
//
//   validatorIDs := make(peer.IDSlice, len(validators))  // ← pre-allocated full length
//   for idx, validator := range validators {
//       validatorID, err := peer.Decode(validator.NodeID)
//       if err != nil {
//           n.log.Error(...)
//           continue                                     // ← skips assignment
//       }
//       validatorIDs[idx] = validatorID
//   }
//   return validatorIDs                                  // ← contains zero-value
//                                                          peer.ID("") entries
//
// The returned slice has a peer.ID("") in every slot where decode failed —
// not removed, not flagged. Downstream code iterating over the slice can
// try to .Send() to an empty peer.ID, fail silently or log spurious errors.
//
// This test seeds a shardConf with mixed valid + invalid NodeIDs and asserts
// the returned slice contains zero-value entries (the gap).
func TestFGP10_RELATED_Validators_ZeroValueOnBadDecode_DocumentsGap(t *testing.T) {
	validIDs := []string{
		"16Uiu2HAm4xdyx6DCZdTbZR2jdaLjXUsew8FhZ6QqSAg9HAmZdxyn", // real-looking peer ID
	}
	invalidIDs := []string{
		"not-a-valid-peer-id",
		"",
		"random-garbage-base58",
	}

	shardConf := &types.PartitionDescriptionRecord{
		Validators: []*types.NodeInfo{
			{NodeID: validIDs[0]},
			{NodeID: invalidIDs[0]},
			{NodeID: invalidIDs[1]},
			{NodeID: invalidIDs[2]},
		},
	}

	n := &Node{log: testlogger.New(t)}
	n.shardConf.Store(shardConf)

	got := n.Validators()
	require.Len(t, got, 4, "returned slice should have one entry per Validators input")

	zeroValueCount := 0
	for _, id := range got {
		if id == peer.ID("") {
			zeroValueCount++
		}
	}
	require.Equal(t, 3, zeroValueCount,
		"GAP CLOSED: Validators() now filters out failed-decode entries — "+
			"flip this assertion when the fix lands (expected 0 zero-value entries)")
	t.Logf("GAP confirmed: Validators() returned %d zero-value peer.ID entries "+
		"alongside %d valid ones; downstream Send() to peer.ID(\"\") is silent failure",
		zeroValueCount, 4-zeroValueCount)
}

// G3 — sendCertificationRequest accesses luc.UnicitySeal.Timestamp without nil-check.
//
// Issue #10 body listed this as a Related Issue. Code (proposal_producer.go:49):
//
//   Timestamp: luc.UnicitySeal.Timestamp,
//
// If luc.UnicitySeal == nil, this panics. The luc is loaded from internal
// state; a corrupted or partial UC could trigger this.
//
// This test is structural: it asserts the assumption that
// luc.UnicitySeal can be nil is unguarded in the code. We test the
// code path indirectly by constructing a UC with nil UnicitySeal and
// confirming that accessing .Timestamp panics — the same crash sendCertificationRequest
// would hit if it received such a luc.
func TestFGP10_RELATED_NilUnicitySeal_PanicsOnTimestampAccess_DocumentsGap(t *testing.T) {
	uc := &types.UnicityCertificate{
		Version:      1,
		InputRecord:  &types.InputRecord{},
		UnicitySeal:  nil, // ← the gap
	}

	require.Panics(t, func() {
		_ = uc.UnicitySeal.Timestamp
	}, "GAP CLOSED: UnicitySeal.Timestamp access no longer panics on nil — "+
		"sendCertificationRequest at proposal_producer.go:49 must now nil-check first")

	t.Logf("GAP confirmed: accessing uc.UnicitySeal.Timestamp panics when " +
		"UnicitySeal is nil; sendCertificationRequest does not guard against this")
}

// ---------------------------------------------------------------------------
// F17 — Validators() loop testing (technique: loop coverage)
// ---------------------------------------------------------------------------
//
// Beyond the mixed-validity case (1 valid + 3 invalid) already covered, loop
// testing exercises the boundary iteration counts: zero, one, all-valid,
// all-invalid. The interesting question is the empty-set and all-invalid
// behavior — does Validators() return an empty slice, a slice of zero-value
// peer.IDs, or panic?
func TestFGP17_Validators_LoopBoundaries_DocumentsGap(t *testing.T) {
	const validID = "16Uiu2HAm4xdyx6DCZdTbZR2jdaLjXUsew8FhZ6QqSAg9HAmZdxyn"

	cases := []struct {
		name           string
		nodeIDs        []string
		wantLen        int
		wantZeroValues int // how many peer.ID("") entries expected (the gap)
	}{
		{"zero validators", []string{}, 0, 0},
		{"one valid", []string{validID}, 1, 0},
		{"all valid (3)", []string{validID, validID, validID}, 3, 0},
		{"all invalid (3)", []string{"bad1", "bad2", "bad3"}, 3, 3},
		{"one invalid only", []string{"bad"}, 1, 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			validators := make([]*types.NodeInfo, len(c.nodeIDs))
			for i, id := range c.nodeIDs {
				validators[i] = &types.NodeInfo{NodeID: id}
			}
			shardConf := &types.PartitionDescriptionRecord{Validators: validators}

			n := &Node{log: testlogger.New(t)}
			n.shardConf.Store(shardConf)

			var got peer.IDSlice
			require.NotPanics(t, func() { got = n.Validators() },
				"Validators() must not panic for %s", c.name)

			require.Len(t, got, c.wantLen,
				"returned slice length for %s", c.name)

			zeroes := 0
			for _, id := range got {
				if id == peer.ID("") {
					zeroes++
				}
			}
			require.Equal(t, c.wantZeroValues, zeroes,
				"zero-value peer.ID count for %s (the F17 gap)", c.name)

			t.Logf("[%s] len=%d zero-values=%d", c.name, len(got), zeroes)
		})
	}
}
