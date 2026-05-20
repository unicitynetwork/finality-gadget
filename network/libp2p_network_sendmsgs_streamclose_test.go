package network

// Test_LibP2PNetwork_SendMsgs_closes_stream — verification of the fix
// applied in commit 924a01a ("close stream in SendMsgs") merged via
// PR #13.
//
// Issue:  https://github.com/unicitynetwork/finality-gadget/issues/2
// Fix PR: https://github.com/unicitynetwork/finality-gadget/pull/13
//
// Pre-fix behaviour: LibP2PNetwork.SendMsgs created a libp2p stream on
// first message and never closed it before returning — every call leaked
// one stream on every return path (success or error). Over time the
// libp2p per-peer stream limit was reached and outbound communication
// stalled.
//
// Fix: a single `defer stream.Close()` was added at the top of SendMsgs
// (network/libp2p_network.go:108-112).
//
// This test makes the leak directly observable at the libp2p stream
// level: after SendMsgs returns, the sender's open-stream count on the
// connection to the receiver MUST return to its baseline. The check is
// applied across the full set of return paths:
//
//   1. happy path (1 msg)                — stream created, write OK, return nil
//   2. happy path (5 msgs)               — same, batched
//   3. 100 sequential calls              — no accumulation across calls
//   4. unknown msg type (early return)   — stream never created (control)
//   5. CreateStream fails (no addr)      — stream stays nil (control)
//   6. empty queue (Len()==0)            — loop body never executes (control)
//   7. stream write error after success  — stream IS created, then Write fails → fix MUST still close it
//
// Cases 1+2+3+7 are the actual fix-verification cases. 4+5+6 are
// controls proving the new `defer` is null-safe (doesn't NPE when
// `stream == nil`).
//
// IMPORTANT cross-repo finding (verified manually 2026-05-14):
// bft-core has an IDENTICAL SendMsgs implementation at
// bft-core/network/network.go:119 that is STILL MISSING this fix on the
// `main` branch (HEAD ceceacd1). Filing as a follow-up against bft-core
// is recommended — every BFT/shard/aggregator node consuming
// bft-core/network leaks one libp2p stream per SendMsgs call.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	testlogger "github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
)

// minimal CBOR-serializable message type for these tests
type sendmsgsTestMsg struct {
	_    struct{} `cbor:",toarray"`
	Body string
}

// msgQueueFIFO is a tiny MsgQueue implementation for the tests.
type msgQueueFIFO struct {
	items []any
}

func (q *msgQueueFIFO) Len() int { return len(q.items) }
func (q *msgQueueFIFO) PopFront() any {
	if len(q.items) == 0 {
		return nil
	}
	v := q.items[0]
	q.items = q.items[1:]
	return v
}
func (q *msgQueueFIFO) PushBack(v any) { q.items = append(q.items, v) }

// countOpenStreamsToOnProtocol returns the count of open libp2p streams from
// `from` to `to` that are on the given protocol ID. Filtering by protocol ID
// is important — libp2p has background streams (IDENTIFY etc.) that would
// otherwise pollute the count.
//
// Streams may take a brief moment to be torn down after stream.Close() (the
// remote side has to read EOF and close its end), so callers should use
// waitForStreamCountOnProtocol with a settle window.
func countOpenStreamsToOnProtocol(from, to *Peer, protocolID string) int {
	conns := from.host.Network().ConnsToPeer(to.ID())
	total := 0
	for _, c := range conns {
		for _, s := range c.GetStreams() {
			if string(s.Protocol()) == protocolID {
				total++
			}
		}
	}
	return total
}

// waitForStreamCountOnProtocol blocks until the protocol-filtered stream
// count from→to equals `want`, or times out (test fails with the actual count).
func waitForStreamCountOnProtocol(t *testing.T, from, to *Peer, protocolID string, want int, msg string) {
	t.Helper()
	deadline := time.Now().Add(WaitDuration)
	last := -1
	for time.Now().Before(deadline) {
		last = countOpenStreamsToOnProtocol(from, to, protocolID)
		if last == want {
			return
		}
		time.Sleep(WaitShortTick)
	}
	t.Fatalf("%s: expected %d open streams on protocol %q, got %d after %s",
		msg, want, protocolID, last, WaitDuration)
}

const sendmsgsTestProtocolID = "test/sendmsgs-streamclose/0.0.1"

// setupTwoPeerNetwork creates two connected peers with a single registered
// protocol on each. Sender (nw1) has the send protocol; receiver (nw2)
// has the receive protocol with the given queue capacity (default 100).
func setupTwoPeerNetwork(t *testing.T, recvCapacity uint) (*Peer, *LibP2PNetwork, *Peer, *LibP2PNetwork) {
	t.Helper()
	if recvCapacity == 0 {
		recvCapacity = 100
	}

	peer1 := createPeer(t)
	nw1, err := NewLibP2PNetwork(peer1, 100, testlogger.New(t))
	require.NoError(t, err)

	peer2 := createPeer(t)
	nw2, err := NewLibP2PNetwork(peer2, recvCapacity, testlogger.New(t))
	require.NoError(t, err)

	// init peerstore so peer1 can dial peer2
	peer1.Network().Peerstore().AddAddrs(peer2.ID(), peer2.MultiAddresses(), peerstore.PermanentAddrTTL)

	require.NoError(t, nw1.registerSendProtocol(SendProtocolDescription{
		ProtocolID: sendmsgsTestProtocolID,
		MsgType:    sendmsgsTestMsg{},
		Timeout:    1 * time.Second,
	}))
	require.NoError(t, nw2.registerReceiveProtocol(ReceiveProtocolDescription{
		ProtocolID: sendmsgsTestProtocolID,
		TypeFn:     func() any { return &sendmsgsTestMsg{} },
	}))
	return peer1, nw1, peer2, nw2
}

func Test_LibP2PNetwork_SendMsgs_closes_stream(t *testing.T) {
	t.Run("1_happy_path_single_message_closes_stream", func(t *testing.T) {
		peer1, nw1, peer2, nw2 := setupTwoPeerNetwork(t, 100)
		q := &msgQueueFIFO{}
		q.PushBack(&sendmsgsTestMsg{Body: "hello"})

		require.NoError(t, nw1.SendMsgs(context.Background(), q, peer2.ID()))

		// receiver got it
		require.Eventually(t, func() bool { return len(nw2.receivedMsgs) == 1 },
			WaitDuration, WaitTick, "receiver should get exactly 1 message")

		// AND no stream on our protocol remains open on the sender side
		waitForStreamCountOnProtocol(t, peer1, peer2, sendmsgsTestProtocolID, 0,
			"after successful single-msg SendMsgs the stream MUST be closed")
	})

	t.Run("2_happy_path_five_messages_closes_stream", func(t *testing.T) {
		peer1, nw1, peer2, nw2 := setupTwoPeerNetwork(t, 100)
		q := &msgQueueFIFO{}
		for i := 0; i < 5; i++ {
			q.PushBack(&sendmsgsTestMsg{Body: fmt.Sprintf("msg-%d", i)})
		}

		require.NoError(t, nw1.SendMsgs(context.Background(), q, peer2.ID()))

		require.Eventually(t, func() bool { return len(nw2.receivedMsgs) == 5 },
			WaitDuration, WaitTick, "receiver should get all 5 messages")
		waitForStreamCountOnProtocol(t, peer1, peer2, sendmsgsTestProtocolID, 0,
			"after batched SendMsgs the stream MUST be closed")
	})

	t.Run("3_no_accumulation_across_100_sequential_calls", func(t *testing.T) {
		peer1, nw1, peer2, _ := setupTwoPeerNetwork(t, 1000)
		const N = 100
		for i := 0; i < N; i++ {
			q := &msgQueueFIFO{}
			q.PushBack(&sendmsgsTestMsg{Body: fmt.Sprintf("call-%d", i)})
			require.NoError(t, nw1.SendMsgs(context.Background(), q, peer2.ID()))
		}
		// Pre-fix this would have left ~N open streams on the sender (until libp2p
		// stream-cap kicked in and SendMsgs started failing). Post-fix: 0.
		waitForStreamCountOnProtocol(t, peer1, peer2, sendmsgsTestProtocolID, 0,
			fmt.Sprintf("after %d sequential SendMsgs calls there must be NO leftover streams", N))
	})

	t.Run("4_unknown_msg_type_no_stream_ever_created", func(t *testing.T) {
		// Register protocol for one type, send messages of a different type → early
		// return ("no protocol registered for messages of type ...") BEFORE stream
		// is created. The defer must be null-safe.
		peer1, nw1, peer2, _ := setupTwoPeerNetwork(t, 100)
		type unregisteredMsg struct {
			_ struct{} `cbor:",toarray"`
		}
		q := &msgQueueFIFO{}
		q.PushBack(&unregisteredMsg{})

		err := nw1.SendMsgs(context.Background(), q, peer2.ID())
		require.Error(t, err, "expected SendMsgs to reject unknown msg type")
		require.Contains(t, err.Error(), "no protocol registered for messages of type")

		// Stream was never created → must remain 0. No NPE from the defer.
		waitForStreamCountOnProtocol(t, peer1, peer2, sendmsgsTestProtocolID, 0,
			"no protocol registered: stream must never have been created")
	})

	t.Run("5_create_stream_fails_no_stream_left_open", func(t *testing.T) {
		// Sender has no address for the receiver in its peerstore → CreateStream
		// returns an error, `stream` stays nil. defer must be null-safe.
		peer1 := createPeer(t)
		nw1, err := NewLibP2PNetwork(peer1, 100, testlogger.New(t))
		require.NoError(t, err)
		peer2 := createPeer(t)

		require.NoError(t, nw1.registerSendProtocol(SendProtocolDescription{
			ProtocolID: sendmsgsTestProtocolID,
			MsgType:    sendmsgsTestMsg{},
			Timeout:    100 * time.Millisecond,
		}))
		// NOTE: peer1's peerstore does NOT contain peer2's addrs → dial will fail.

		q := &msgQueueFIFO{}
		q.PushBack(&sendmsgsTestMsg{Body: "won't be delivered"})

		err = nw1.SendMsgs(context.Background(), q, peer2.ID())
		require.Error(t, err)
		require.Contains(t, err.Error(), "opening p2p stream",
			"expected error from CreateStream, got: %v", err)

		// No stream on our protocol was created. peer1 may not even have a
		// connection to peer2.
		require.Equal(t, 0,
			countOpenStreamsToOnProtocol(peer1, peer2, sendmsgsTestProtocolID),
			"CreateStream failed: no streams on our protocol should exist")
	})

	t.Run("6_empty_queue_no_stream_created", func(t *testing.T) {
		// SendMsgs is called with an empty queue → the loop body never executes,
		// stream stays nil, return nil. defer must be null-safe.
		peer1, nw1, peer2, _ := setupTwoPeerNetwork(t, 100)
		q := &msgQueueFIFO{} // Len()==0 from the start

		require.NoError(t, nw1.SendMsgs(context.Background(), q, peer2.ID()))
		require.Equal(t, 0,
			countOpenStreamsToOnProtocol(peer1, peer2, sendmsgsTestProtocolID),
			"empty queue: no stream should ever have been created")
	})

	t.Run("7_stream_write_error_still_closes_stream", func(t *testing.T) {
		// The critical fix-verification case. Force a stream write error after
		// the stream has been created. Pre-fix this leaked. Post-fix the defer
		// closes the stream even on the error-return path.
		//
		// Strategy (mirrors bft-core's "stream reset by receiver while still
		// sending" test): receiver capacity=1, push 10000 messages. The receiver
		// reads 1, then drops subsequent ones and eventually resets the stream
		// → stream.Write returns "stream reset" → SendMsgs returns with error.
		peer1, nw1, peer2, _ := setupTwoPeerNetwork(t, 1)
		q := &msgQueueFIFO{}
		for i := 1; i <= 10000; i++ {
			q.PushBack(&sendmsgsTestMsg{Body: fmt.Sprintf(
				"make a test message that is a bit longer to simulate real messages: test message %d", i)})
		}

		err := nw1.SendMsgs(context.Background(), q, peer2.ID())
		require.Error(t, err, "expected a stream-write error from the receiver dropping")
		// The exact error string may vary with libp2p versions, but
		// "stream write error" is the wrapper added by SendMsgs itself.
		msg := err.Error()
		require.True(t,
			strings.Contains(msg, "stream write error") || strings.Contains(msg, "stream reset"),
			"expected a stream-related write error, got: %v", err)

		// THE KEY ASSERTION: post-fix, the stream is closed via the defer.
		// Pre-fix, this would have been >= 1.
		waitForStreamCountOnProtocol(t, peer1, peer2, sendmsgsTestProtocolID, 0,
			"after stream-write error the stream MUST still be closed (defer fix verification)")
	})
}

