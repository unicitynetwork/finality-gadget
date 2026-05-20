package network

// Test_deserializeMsg_streaming_oversize_rejected — streaming wire-level test
// for finality-gadget #1. NOT a full cluster e2e (no libp2p, no running
// FGP daemon); see notes below for what a true cluster e2e would entail.
//
// The unit test Test_deserializeMsg/length_exceeds_maximum_message_size
// calls deserializeMsg directly with synthetic bytes pre-buffered in a
// bytes.Reader. THIS test exercises the same code through a real
// io.Pipe — bytes leave one goroutine via the writer end of a real
// connection-like reader/writer pair, and arrive in the deserializeMsg
// call on the reader end. That proves the cap fires while bytes are
// being streamed across a reader, not only when they're pre-buffered.
//
// Crucially, the test sends ONLY the 9-byte varint length prefix and
// then closes the writer — the body is never sent. The cap MUST fire on
// the length prefix alone, before the decoder is invoked and before any
// allocation occurs. That's the DoS-amplification proof.
//
// What this test is NOT:
//   • Not a libp2p stream test (no noise/yamux/peerID handshake).
//   • Not a test against a running FGP daemon (no docker, no network).
//   • Not coverage of LibP2PNetwork.handleStream registration.
// A true cluster e2e would set up two libp2p hosts in-process or attack
// a live fgp-node-* container; both add a lot of setup for marginal
// additional confidence because deserializeMsg is reader-shape-agnostic.
//
// Issue:  https://github.com/unicitynetwork/finality-gadget/issues/1
// Fix PR: https://github.com/unicitynetwork/finality-gadget/pull/13

import (
	"encoding/binary"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_deserializeMsg_streaming_oversize_rejected(t *testing.T) {
	const oversize = uint64(maxMsgSize + 1) // 16 MB + 1 byte

	scenarios := []struct {
		name             string
		declaredLength   uint64
		bytesActuallySent int // we don't actually need to send oversize bytes; the cap should fire on the LENGTH prefix
		expectRejected   bool
		expectErrContain string
	}{
		{
			name:             "declared length exceeds 16 MB cap (length-prefix-only attack)",
			declaredLength:   oversize,
			bytesActuallySent: 0, // we don't write the body — cap MUST fire on the length prefix alone
			expectRejected:   true,
			expectErrContain: "exceeds maximum",
		},
		{
			name:             "declared length way over (32 GB) — the original 8 GiB+ attack from the issue body",
			declaredLength:   uint64(32) * 1024 * 1024 * 1024,
			bytesActuallySent: 0,
			expectRejected:   true,
			expectErrContain: "exceeds maximum",
		},
		{
			name:             "declared length at exactly the cap +1",
			declaredLength:   uint64(maxMsgSize) + 1,
			bytesActuallySent: 0,
			expectRejected:   true,
			expectErrContain: "exceeds maximum",
		},
		{
			name:             "declared length zero — different rejection path, but ensures we didn't break it",
			declaredLength:   0,
			bytesActuallySent: 0,
			expectRejected:   true,
			expectErrContain: "data length zero",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			// Real connection-like pair: writes on one end appear as reads on the other.
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()

			// Reader side: call deserializeMsg, capture result.
			var (
				wg     sync.WaitGroup
				rerr   error
				dest   interface{}
			)
			wg.Add(1)
			go func() {
				defer wg.Done()
				rerr = deserializeMsg(reader, &dest)
			}()

			// Writer side: write the malicious length prefix and (optionally) some bytes.
			// We do NOT need to write the full oversize body — the cap should fire on the
			// length prefix alone. Sending nothing afterwards proves the cap is enforced
			// before the decoder is even invoked / before any allocation occurs.
			lenBuf := make([]byte, binary.MaxVarintLen64)
			n := binary.PutUvarint(lenBuf, sc.declaredLength)
			_, werr := writer.Write(lenBuf[:n])
			require.NoError(t, werr)

			// If for some reason the test expected normal flow, we'd write the body here.
			// For our oversize cases, we close the writer to signal EOF — but only AFTER
			// the cap should have fired.
			//
			// Give the reader goroutine a brief moment to read the length prefix and react.
			time.Sleep(20 * time.Millisecond)
			_ = writer.Close()

			// Wait for the reader to return.
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("deserializeMsg didn't return within 2 s — cap may not be firing on the length prefix alone")
			}

			if sc.expectRejected {
				require.Error(t, rerr, "expected deserializeMsg to reject scenario %q", sc.name)
				require.Contains(t, strings.ToLower(rerr.Error()),
					strings.ToLower(sc.expectErrContain),
					"reject reason for scenario %q didn't contain %q (got: %v)",
					sc.name, sc.expectErrContain, rerr)
				t.Logf("✓ rejected as expected: %v", rerr)
			} else {
				require.NoError(t, rerr, "expected no error for scenario %q", sc.name)
			}
		})
	}
}
