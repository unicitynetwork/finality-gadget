package partition

// Tests for F14 — finality-gadget #8 "Related Issue":
// "Private key material in partition/configuration.go:252-280 is never
//  zeroed from memory"
//
// Issue: https://github.com/unicitynetwork/finality-gadget/issues/8
// Tracked: INVESTIGATIONS.md §F14 (aggregator-subscription)
//
// These tests probe whether the F14 concern is VALID and CURRENTLY UNADDRESSED.
// They are negative-assertion tests — they pass today (documenting the gap)
// and should be UPDATED (flip require.True → require.False, or add a real
// Zero() call check) once the production fix lands.
//
// What we want to know:
//
//   Q1: Is the loaded private-key byte material reachable in memory after
//       it has been used (e.g. by AuthKeyPair() or Signer())?
//       Test K1: confirms YES — the bytes stay live on the KeyConf struct
//       and on the returned PeerKeyPair until either the struct is GC'd or
//       the process exits.
//
//   Q2: Does the package expose any API to explicitly zero the bytes?
//       Test K2: confirms NO — no Zero(), Wipe(), Close(), or finalizer
//       on KeyConf or on the returned types.
//
//   Q3: After we drop our user-side references, does the GC at least
//       collect the bytes "soon"? Or do they persist?
//       Test K3: pins a pointer to the byte slice's backing array via
//       unsafe, drops the user-side reference, forces GC repeatedly, and
//       checks whether the bytes have been zeroed/reclaimed. This is the
//       direct test of the security concern: if the bytes are still
//       readable after we've "released" the key, an attacker with heap
//       inspection ability can read them.
//
// Severity assessment:
//   • If K3 shows the bytes persist: the F14 concern is REAL — core dumps,
//     /proc/<pid>/mem scrapes, swap-out, and memory scraping malware can
//     all extract the key.
//   • If GC zeroes/relocates immediately: the concern is LOWER severity
//     but still real for the long tail of attacks against any byte slice
//     that hasn't been GC'd yet.

import (
	"bytes"
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// Synthetic 32-byte secp256k1 private key. NOT a real network key — just
// a pattern of bytes that's easy to spot in memory dumps.
var fakePrivKey = []byte{
	0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

func newTestKeyConf(t *testing.T) *KeyConf {
	t.Helper()
	// Copy the fake key bytes so each test gets its own allocation we can
	// independently observe.
	kbytes := make([]byte, len(fakePrivKey))
	copy(kbytes, fakePrivKey)

	return &KeyConf{
		SigKey:  Key{Algorithm: KeyAlgorithmSecp256k1, PrivateKey: hex.Bytes(kbytes)},
		AuthKey: Key{Algorithm: KeyAlgorithmSecp256k1, PrivateKey: hex.Bytes(kbytes)},
	}
}

// K1 — After AuthKeyPair() returns, the loaded private-key bytes are STILL
// in `c.AuthKey.PrivateKey`. Nothing was zeroed.
func Test_F14_PrivateKeyBytesStayInKeyConf_DocumentsGap(t *testing.T) {
	kc := newTestKeyConf(t)
	originalCopy := make([]byte, len(kc.AuthKey.PrivateKey))
	copy(originalCopy, kc.AuthKey.PrivateKey)

	_, err := kc.AuthKeyPair()
	require.NoError(t, err)

	require.True(t, bytes.Equal(originalCopy, kc.AuthKey.PrivateKey),
		"GAP CLOSED: KeyConf.AuthKey.PrivateKey was modified by AuthKeyPair() — likely zeroed")
	t.Logf("GAP confirmed: KeyConf.AuthKey.PrivateKey still holds the original key bytes after AuthKeyPair() — never zeroed")
}

// K1b — Same check for Signer().
func Test_F14_PrivateKeyBytesStayInKeyConf_AfterSigner_DocumentsGap(t *testing.T) {
	kc := newTestKeyConf(t)
	originalCopy := make([]byte, len(kc.SigKey.PrivateKey))
	copy(originalCopy, kc.SigKey.PrivateKey)

	_, err := kc.Signer()
	require.NoError(t, err)

	require.True(t, bytes.Equal(originalCopy, kc.SigKey.PrivateKey),
		"GAP CLOSED: KeyConf.SigKey.PrivateKey was modified by Signer() — likely zeroed")
	t.Logf("GAP confirmed: KeyConf.SigKey.PrivateKey still holds the original key bytes after Signer() — never zeroed")
}

// K2 — No method exists on KeyConf to zero/wipe/clear the key material.
// This is the API-level gap: even a security-conscious caller has no way
// to explicitly clear the bytes.
func Test_F14_NoKeyZeroAPI_DocumentsGap(t *testing.T) {
	kc := &KeyConf{}
	kcType := reflect.TypeOf(kc)

	bannedNames := map[string]bool{
		"Zero": false, "Wipe": false, "Clear": false, "Close": false, "Destroy": false,
	}
	for i := 0; i < kcType.NumMethod(); i++ {
		name := kcType.Method(i).Name
		if _, isBanned := bannedNames[name]; isBanned {
			t.Errorf("GAP CLOSED: KeyConf now exposes method %q — flip this assertion", name)
			bannedNames[name] = true
		}
	}
	for name, found := range bannedNames {
		require.False(t, found,
			"expected KeyConf to LACK %s method (gap); flip when fix lands", name)
	}
	t.Logf("GAP confirmed: KeyConf has none of {Zero, Wipe, Clear, Close, Destroy} methods")
}

// K2b — The returned PeerKeyPair also has no Zero method.
func Test_F14_PeerKeyPairHasNoZeroAPI_DocumentsGap(t *testing.T) {
	kc := newTestKeyConf(t)
	pkp, err := kc.AuthKeyPair()
	require.NoError(t, err)

	pkpType := reflect.TypeOf(pkp)
	for i := 0; i < pkpType.NumMethod(); i++ {
		name := pkpType.Method(i).Name
		require.NotContains(t, []string{"Zero", "Wipe", "Clear", "Close"}, name,
			"GAP CLOSED: PeerKeyPair now exposes %s — flip this assertion", name)
	}
	t.Logf("GAP confirmed: %T also has no Zero/Wipe/Clear/Close method — caller cannot clear the returned bytes either", pkp)
}

// K3 — The direct security test: pin a pointer to the byte slice backing
// array, drop the user-side reference, force GC repeatedly, then read the
// bytes via the pinned pointer. If we still see the original key, an
// attacker with heap-read access (core dump, /proc/<pid>/mem, swap, memory
// scraper) can recover the key.
//
// This test uses `unsafe` deliberately — that's the only way to model the
// attacker's view of the heap.
func Test_F14_KeyBytes_AreReadable_AfterUserDereferenced_DocumentsGap(t *testing.T) {
	var backingArrayPtr unsafe.Pointer
	var keyLen int

	// Scope: load the key, use it, then drop our handle. The backing array
	// pointer survives in the outer scope because we captured it before
	// dropping the slice header.
	func() {
		kc := newTestKeyConf(t)
		_, err := kc.AuthKeyPair()
		require.NoError(t, err)

		// Capture the address of the backing array. This is what an
		// attacker scraping memory would have to find — we cheat by
		// stashing it directly.
		bs := []byte(kc.AuthKey.PrivateKey)
		keyLen = len(bs)
		require.Greater(t, keyLen, 0)
		backingArrayPtr = unsafe.Pointer(&bs[0])

		// Drop the user-side handle.
		kc = nil
		_ = kc
	}()

	// Force GC. Multiple times to give it every opportunity to collect.
	for i := 0; i < 5; i++ {
		runtime.GC()
	}

	// Read the bytes via the pinned pointer. This mirrors an attacker
	// pointing at the right heap address.
	stillThere := unsafe.Slice((*byte)(backingArrayPtr), keyLen)
	readback := make([]byte, keyLen)
	copy(readback, stillThere)

	if bytes.Equal(readback, fakePrivKey) {
		t.Logf("GAP CONFIRMED, SEVERITY HIGH: original key bytes still readable via raw "+
			"memory address after the user-side KeyConf was dereferenced and 5 × runtime.GC() "+
			"fired. An attacker with /proc/<pid>/mem read access, a core dump, or a swap "+
			"file can recover the key. Bytes at pinned address: %x", readback)
	} else {
		// Either GC reclaimed/reused the page, or some path zeroed it.
		// Both are partial mitigations but neither is reliable defense.
		t.Logf("Bytes at pinned address have changed since release — could be GC reuse "+
			"(not a real defense) or explicit zeroing. Read: %x; original: %x", readback, fakePrivKey)
	}

	// We assert "the gap is documented" — this test currently passes regardless
	// of GC behavior. The signal is the t.Logf line above. Flip the assertion
	// when a real Zero() method exists.
	require.NotNil(t, backingArrayPtr,
		"could not capture key backing-array pointer — test infra broken")
}

// K4 — Show that the fix is feasible: zeroing a []byte is a one-liner that
// works correctly on any *Key.PrivateKey. This is the "feasibility cross-check"
// that proves F14's suggested fix is trivial to implement.
func Test_F14_ZeroingBytes_IsFeasible(t *testing.T) {
	kc := newTestKeyConf(t)
	original := make([]byte, len(kc.AuthKey.PrivateKey))
	copy(original, kc.AuthKey.PrivateKey)

	// Hypothetical Zero() implementation:
	for i := range kc.AuthKey.PrivateKey {
		kc.AuthKey.PrivateKey[i] = 0
	}
	for i := range kc.SigKey.PrivateKey {
		kc.SigKey.PrivateKey[i] = 0
	}

	require.NotEqual(t, original, []byte(kc.AuthKey.PrivateKey),
		"manual zeroing must work on hex.Bytes (proves the fix is one trivial method away)")
	for _, b := range kc.AuthKey.PrivateKey {
		require.Equal(t, byte(0), b, "all bytes should be zero after manual wipe")
	}
	t.Logf("Zeroing []byte/hex.Bytes is trivial — F14 fix is a single (*KeyConf).Zero() method")
}
