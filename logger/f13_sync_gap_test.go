package logger

// Tests for F13 — finality-gadget #8 "Related Issue":
// "Log file handle in logger/slog.go:192-197 lacks Sync() on shutdown,
//  risking data loss"
//
// Issue: https://github.com/unicitynetwork/finality-gadget/issues/8
// Tracked: INVESTIGATIONS.md §F13 (aggregator-subscription)
//
// These tests probe whether the F13 concern is VALID and CURRENTLY UNADDRESSED.
// They are negative-assertion tests — they pass today (documenting the gap)
// and should be UPDATED (require.NoError → require.True for "exposed API")
// once the production fix lands.
//
// What we want to know:
//
//   Q1: Is there a public API on the logger package that an operator can
//       call to flush log buffers before shutdown?
//       Test G1: confirms NO such API exists today.
//
//   Q2: Is the log file's underlying *os.File accessible by callers (so they
//       could call Sync() on it themselves)?
//       Test G2: confirms NO — `filenameToWriter` returns io.Writer, and the
//       returned *slog.Logger does not expose the *os.File.
//
//   Q3: Without an explicit Sync(), does graceful shutdown (process exit
//       after `cmd/main.go:quitSignalContext()` cancels ctx) actually lose
//       log lines?
//       Test G3: writes N lines, drops the logger reference, then re-reads
//       the file from disk to count lines. With Go's *os.File.Write being
//       unbuffered (one write() syscall per line), this measures whether
//       data is lost in practice.
//       → Outcome predicts whether the issue body's "risking data loss"
//         framing is real for the process-exit case, or whether (like #8's
//         lock framing) it's only true for system-level crashes.

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// G1 — no Close()/Sync() method on the package's public API surface.
//
// `logger.New()` returns `*slog.Logger`. There is no `*Logger` wrapper type
// in this package that exposes Close/Sync, and `*slog.Logger` itself has no
// Close/Sync method. Therefore the operator has no way to flush log buffers
// at shutdown without reaching past the package abstraction.
func Test_F13_LoggerHasNoCloseOrSyncAPI_DocumentsGap(t *testing.T) {
	cfg := &LogConfiguration{
		Format:     "json",
		OutputPath: filepath.Join(t.TempDir(), "g1.log"),
	}
	log, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, log)

	logType := reflect.TypeOf(log)
	for i := 0; i < logType.NumMethod(); i++ {
		name := logType.Method(i).Name
		require.NotEqual(t, "Close", name, "GAP CLOSED: *slog.Logger now exposes Close()")
		require.NotEqual(t, "Sync", name, "GAP CLOSED: *slog.Logger now exposes Sync()")
		require.NotEqual(t, "Flush", name, "GAP CLOSED: *slog.Logger now exposes Flush()")
	}
	t.Logf("GAP confirmed: %T has no Close/Sync/Flush method", log)
}

// G2 — `filenameToWriter` returns the bare `io.Writer`. The caller of
// `New(cfg)` gets a `*slog.Logger`, with no way to recover the underlying
// `*os.File` to call Sync() on it themselves.
func Test_F13_FileWriterNotRetrievableFromLogger_DocumentsGap(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "g2.log")
	cfg := &LogConfiguration{
		Format:     "json",
		OutputPath: logPath,
	}
	log, err := New(cfg)
	require.NoError(t, err)

	// Walk all exported fields/methods looking for *os.File access.
	v := reflect.ValueOf(log).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		require.NotEqual(t, "*os.File", f.Type().String(),
			"GAP CLOSED: logger now exposes a *os.File field that callers could Sync()")
	}
	t.Logf("GAP confirmed: no exported *os.File on %T — caller cannot Sync() the log file", log)
}

// G3 — How much data is actually at risk?
//
// Write N JSON log lines. Do not call any Close/Sync. Re-read the file
// directly from disk (separate fd) and count lines. With Go's *os.File.Write
// being unbuffered (one write() syscall per Write), the kernel page cache
// should already contain every line, and the read should see all N — even
// without an explicit flush.
//
// What this DOES prove if it passes (we expect it to):
//   • No data loss on graceful process exit *as long as the kernel survives*.
//     Process exit → kernel flushes its page cache eventually.
//   • The "data loss" framing in #8's body is overstated for the process-
//     crash case — only system crashes (kernel panic, power loss) would lose
//     un-Sync()'d data.
//
// What this does NOT cover:
//   • Buffered handlers (some slog implementations buffer internally; the
//     stdlib JSON handler does not — verified empirically).
//   • System-level crashes — those still risk data loss without Sync().
//
// If THIS test ever starts failing (lines missing), it would mean slog or
// the chosen handler started buffering internally; that's a separate fact
// the F13 concern would then be REAL for graceful exit too.
func Test_F13_LinesPersistedWithoutSync_AssessesConcernSeverity(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "g3.log")
	cfg := &LogConfiguration{
		Format:     "json",
		OutputPath: logPath,
		Level:      slog.LevelInfo.String(),
	}
	log, err := New(cfg)
	require.NoError(t, err)

	const N = 500
	for i := 0; i < N; i++ {
		log.LogAttrs(context.Background(), slog.LevelInfo, "test-line",
			slog.Int("seq", i),
			slog.String("payload", strings.Repeat("x", 64)),
		)
	}

	// No Sync, no Close. Just drop the reference and read the file.
	log = nil
	_ = log

	f, err := os.Open(logPath)
	require.NoError(t, err)
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		count++
	}
	require.NoError(t, scanner.Err())

	if count == N {
		t.Logf("GAP SEVERITY = LOW for graceful exit: all %d lines on disk without Sync. "+
			"#8's 'risking data loss' claim only applies to SYSTEM crashes (kernel panic, "+
			"power loss), not process exit. Fix is still worth adding for system-level "+
			"durability + symmetry with BoltDB close, but the framing in the issue body is "+
			"overstated for the process-crash case.", N)
	} else {
		t.Logf("GAP SEVERITY = HIGH: only %d of %d lines on disk without Sync — buffering "+
			"is in play. F13 concern is REAL for graceful exit too.", count, N)
	}

	// Either outcome documents the current behavior — both are informative.
	// The test is intentionally not a require.Equal — we're observing, not gating.
	require.Greater(t, count, 0, "logger produced zero lines — config or path broken")

	// Sanity: at least one line should have made it to disk.
	if count < N {
		// Print the gap explicitly so a reader of CI logs can see it.
		t.Logf("buffered lines NOT on disk: %d (of %d)", N-count, N)
	}
}

// G4 — Cross-check: if someone DID reach into the package internals and grab
// the *os.File, would Sync() actually work on it?
//
// This isn't testing the gap; it's testing that the fix is feasible. If
// Sync() returned an error or no-op on the file type the package uses,
// the fix would be harder than just "expose a Close method." We expect
// Sync to work cleanly.
func Test_F13_OsFile_SyncWorks_FixIsFeasible(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "g4.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	require.NoError(t, err)
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("test line at %s\n", t.Name()))
	require.NoError(t, err)
	require.NoError(t, f.Sync(), "Sync() must work on the underlying *os.File")
	t.Logf("Sync() works on the *os.File used by filenameToWriter — the F13 fix is feasible")
}
