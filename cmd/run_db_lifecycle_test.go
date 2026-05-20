package main

// Tests for FGP #8 — "BoltDB handles never closed in runNode — leaked
// locks prevent clean restart".
//
// Issue:    https://github.com/unicitynetwork/finality-gadget/issues/8
// Fix PR:   https://github.com/unicitynetwork/finality-gadget/pull/13
// Fix commit: 1718933 "close databases"
//
// The fix added three `defer db.Close()` calls to cmd/run.go at lines
// 139, 179, 197 for shardConfDB, trustBaseDB, blockDB respectively. It
// also changed initDB's return type from keyvaluedb.KeyValueDB (interface,
// no Close()) to *boltdb.BoltDB (concrete, has Close()).
//
// What these tests prove:
//
//   T1  — `Test_BoltDB_ExclusiveLock_HeldByOpener`:
//         BoltDB takes an exclusive lock while open. A second open of the
//         SAME path while the first handle is still open MUST fail.
//         This establishes that the bug premise is real — without defer
//         Close, a process trying to re-open its own DB will deadlock or
//         fail.
//
//   T2  — `Test_BoltDB_LockReleased_AfterClose`:
//         After Close(), the same path can be re-opened. This is the
//         mechanism the fix relies on — defer Close() fires, lock is
//         released, next opener succeeds.
//
//   T3  — `Test_RunNode_ReleasesAllThreeDBLocksOnReturn`:
//         Integration-level: replicate runNode's exact DB-opening
//         sequence (3 BoltDBs) including the deferred Close() calls,
//         then in phase 2 attempt to re-open all three files. All three
//         re-opens MUST succeed. If any `defer Close()` were missing,
//         the corresponding re-open would fail. This is the symptom-
//         level test of the #8 fix.
//
// NOT covered (out of scope of this fix):
//   - The two "Related Issues" from the #8 body: logger Sync() on
//     shutdown and private-key zeroing. The fix silently dropped both;
//     see INVESTIGATIONS.md §F8-related entries for the gap.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
)

// T1 — BoltDB's exclusive lock is real
func Test_BoltDB_ExclusiveLock_HeldByOpener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db1, err := boltdb.New(path)
	require.NoError(t, err, "first open should succeed")
	t.Cleanup(func() { _ = db1.Close() })

	// Second open of the same path while db1 is still held.
	// Run in a goroutine with a short timeout in case the underlying
	// implementation blocks on flock() instead of returning an error.
	done := make(chan error, 1)
	go func() {
		db2, err := boltdb.New(path)
		if db2 != nil {
			_ = db2.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err,
			"second open of locked DB should fail (got nil error — lock not enforced?)")
		t.Logf("second open correctly rejected: %v", err)
	case <-time.After(3 * time.Second):
		t.Logf("second open blocked (>3s) — flock() is being held; this also proves the lock is exclusive")
		// Blocking is also acceptable behavior — it proves the lock is held.
		// The fix's `defer Close()` would release the lock so a real restart succeeds.
	}
}

// T2 — closing releases the lock
func Test_BoltDB_LockReleased_AfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db1, err := boltdb.New(path)
	require.NoError(t, err)
	require.NoError(t, db1.Close(), "close must succeed")

	db2, err := boltdb.New(path)
	require.NoError(t, err, "re-open after close must succeed")
	require.NoError(t, db2.Close())
}

// T3 — runNode's exact 3-DB sequence releases all locks on return
//
// This test replicates the structure of cmd/run.go lines ~135-198:
//
//   shardConfDB, _ := flags.initDB(...)
//   defer shardConfDB.Close()    // line 139, added by 1718933
//   trustBaseDB, _ := flags.initDB(...)
//   defer trustBaseDB.Close()    // line 179, added by 1718933
//   blockDB, _ := flags.initDB(...)
//   defer blockDB.Close()        // line 197, added by 1718933
//
// We do not invoke the real runNode (would require keys.json, shard-conf.json,
// trust-base.json fixtures and a configured logger). Instead we directly
// exercise flags.initDB() in the same order with the same defers, then in
// phase 2 attempt to re-open every file.
//
// Pre-fix behavior (no defers): phase 2 re-opens would either fail with a
// lock error or block indefinitely. Post-fix: all three re-opens succeed.
func Test_RunNode_ReleasesAllThreeDBLocksOnReturn(t *testing.T) {
	home := t.TempDir()
	flags := &cliFlags{HomeDir: home}

	// Phase 1: emulate runNode's DB-opening block.
	func() {
		shardDB, err := flags.initDB("", shardConfDBFileName)
		require.NoError(t, err)
		defer shardDB.Close()

		tbDB, err := flags.initDB("", "trustbase.db")
		require.NoError(t, err)
		defer tbDB.Close()

		blockDB, err := flags.initDB("", blockDBFileName)
		require.NoError(t, err)
		defer blockDB.Close()

		// Inside the func, all three DBs are open with deferred closes.
		// Verify locks are actually held right now (negative control).
		for _, name := range []string{shardConfDBFileName, "trustbase.db", blockDBFileName} {
			path := filepath.Join(home, name)
			done := make(chan error, 1)
			go func(p string) {
				db, err := boltdb.New(p)
				if db != nil {
					_ = db.Close()
				}
				done <- err
			}(path)
			select {
			case err := <-done:
				require.Error(t, err,
					"while runNode-style block is live, %s should be locked (got nil error)", name)
			case <-time.After(500 * time.Millisecond):
				// blocking is also acceptable proof of lock
			}
		}
	}() // <- all three defers fire here, simulating runNode returning

	// Phase 2: every file must be re-openable now that defers have fired.
	for _, name := range []string{shardConfDBFileName, "trustbase.db", blockDBFileName} {
		path := filepath.Join(home, name)
		require.FileExists(t, path)

		db, err := boltdb.New(path)
		require.NoError(t, err,
			"expected re-open of %s to succeed after defers fired (this is the #8 fix)", name)
		require.NoError(t, db.Close())
	}
}

// T4 — double-call of runNode-style pattern (graceful restart symptom)
//
// Drives the same 3-DB open/close pattern TWICE against the same FGP_HOME,
// asserting both invocations succeed. This is the direct analogue of:
//
//   $ fgp run    # ctrl-C → returns
//   $ fgp run    # must work
//
// Pre-fix this would have either (a) leaked the BoltDB handle within the
// same process, blocking the second call, or (b) corrupted state from
// in-flight writes that weren't synced before return.
func Test_RunNode_TwoSequentialInvocationsBothSucceed(t *testing.T) {
	home := t.TempDir()
	flags := &cliFlags{HomeDir: home}

	runOnce := func(t *testing.T) {
		t.Helper()
		shardDB, err := flags.initDB("", shardConfDBFileName)
		require.NoError(t, err)
		defer shardDB.Close()
		tbDB, err := flags.initDB("", "trustbase.db")
		require.NoError(t, err)
		defer tbDB.Close()
		blockDB, err := flags.initDB("", blockDBFileName)
		require.NoError(t, err)
		defer blockDB.Close()
	}

	runOnce(t) // first invocation
	runOnce(t) // second invocation — must succeed
}
