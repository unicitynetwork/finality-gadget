package network

// Test_deserializeMsg_amplification_observability is the F7 reproducer
// (aggregator-subscription/INVESTIGATIONS.md F7).
//
// Background: finality-gadget issue #1 body flagged "CBOR decoder default
// limits allow memory amplification" as an ADJACENT concern. PR #13 added
// an OUTER-length cap of 16 MB (the headline fix) but did NOT add any
// decoder-internal limits (max nested depth, max array elements during
// decode, etc.). So in theory a malicious peer could craft a payload
// whose outer length is well-under 16 MB but whose decoded representation
// expands by some factor.
//
// THIS TEST IS OBSERVATIONAL — it documents the current behaviour by
// feeding the deserializer payloads with high decode-amplification ratios
// and printing the heap-alloc ratio. It does NOT fail the build; it
// records observations via t.Logf. If the ratio turns out to be huge,
// promote F7 to a confirmed bug and configure CBOR decoder limits.
//
// Three crafted payloads:
//   • nested arrays depth 1000   — 1 KB outer, 1000 nested empty arrays
//   • nested arrays depth 10000  — 10 KB outer, 10000 nested empty arrays
//   • flat array, 1 M empty els  — ~1 MB outer, 1 million [] inside
//
// All three are well under the 16 MB outer cap, so they pass the headline
// fix. The question is whether the CBOR library expands them safely.
//
// Issue:  https://github.com/unicitynetwork/finality-gadget/issues/1 (adjacent)
// Fix PR: https://github.com/unicitynetwork/finality-gadget/pull/13 (outer cap only)
// Tracking: aggregator-subscription/INVESTIGATIONS.md F7

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

func Test_deserializeMsg_amplification_observability(t *testing.T) {
	type scenario struct {
		name     string
		buildBuf func() []byte
	}
	scenarios := []scenario{
		{
			name: "nested-arrays-depth-1000",
			buildBuf: func() []byte {
				// CBOR: 1000 levels of [ [ [ ... [] ... ] ] ]
				// Each opening uses 1 byte (0x81 = array(1 element)).
				// Innermost: empty array (0x80).
				inner := []byte{0x80}
				for i := 0; i < 1000; i++ {
					inner = append([]byte{0x81}, inner...)
				}
				return inner
			},
		},
		{
			name: "nested-arrays-depth-10000",
			buildBuf: func() []byte {
				inner := []byte{0x80}
				for i := 0; i < 10000; i++ {
					inner = append([]byte{0x81}, inner...)
				}
				return inner
			},
		},
		{
			name: "flat-array-1M-empty-elements",
			buildBuf: func() []byte {
				// CBOR: array with 1_000_000 elements, each an empty array.
				// 0x9a = array, 4-byte BE length prefix follows.
				var buf bytes.Buffer
				buf.WriteByte(0x9a)
				_ = binary.Write(&buf, binary.BigEndian, uint32(1_000_000))
				for i := 0; i < 1_000_000; i++ {
					buf.WriteByte(0x80) // empty array
				}
				return buf.Bytes()
			},
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			payload := sc.buildBuf()
			t.Logf("CBOR payload size: %d bytes (well under the 16 MB outer cap)",
				len(payload))

			// Wrap in a libp2p frame: uvarint length prefix + payload.
			var frame bytes.Buffer
			lenBuf := make([]byte, binary.MaxVarintLen64)
			n := binary.PutUvarint(lenBuf, uint64(len(payload)))
			frame.Write(lenBuf[:n])
			frame.Write(payload)

			t.Logf("framed size (length-prefix + payload): %d bytes", frame.Len())

			// Stable baseline before decode.
			var m0, m1 runtime.MemStats
			runtime.GC()
			runtime.GC()
			runtime.ReadMemStats(&m0)

			// Decode into an `any` destination.
			var dest interface{}
			err := deserializeMsg(bytes.NewReader(frame.Bytes()), &dest)

			runtime.ReadMemStats(&m1)

			// HeapAlloc is the only field directly comparable here.
			delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
			ratio := float64(delta) / float64(len(payload))

			if err != nil {
				t.Logf("decoder REJECTED payload: %v", err)
				t.Logf("  outer=%d alloc delta during attempt=%d (ratio=%.2fx)",
					len(payload), delta, ratio)
				t.Logf("  → CBOR library has a protective limit (good!). F7 not exploitable for this shape.")
			} else {
				t.Logf("decoder ACCEPTED payload")
				t.Logf("  outer=%d alloc delta during decode=%d (ratio=%.2fx)",
					len(payload), delta, ratio)
				if ratio > 50.0 {
					t.Logf("⚠ amplification ratio > 50x — F7 likely exploitable; configure decoder limits.")
				} else if ratio > 10.0 {
					t.Logf("ratio 10-50x — moderate amplification; consider decoder limits as defense in depth.")
				} else {
					t.Logf("ratio ≤ 10x — bounded; outer cap provides sufficient protection.")
				}
			}
		})
	}
}
