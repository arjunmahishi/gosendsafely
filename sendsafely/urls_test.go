package sendsafely

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dt/gosendsafely/util"
)

// bigMockFile builds a file spanning more than one URL batch, so tests can tell
// per-batch behavior from per-segment behavior.
func bigMockFile(parts, chunkSize int) mockFile {
	chunks := make([][]byte, parts)
	for i := range chunks {
		chunks[i] = bytes.Repeat([]byte{byte('a' + i%26)}, chunkSize)
	}
	return mockFile{
		fileID:   "file-big",
		fileName: "big.bin",
		fileSize: parts * chunkSize,
		parts:    parts,
		chunks:   chunks,
	}
}

func openTestPackage(t *testing.T, server *mockSendSafelyServer, pkg *mockPackage) *Package {
	t.Helper()
	server.addPackage(pkg)

	t.Setenv("SS_API_KEY", server.validAPIKey)
	t.Setenv("SS_API_SECRET", server.validAPISecret)

	url := fmt.Sprintf("%s/receive/?packageCode=%s#keyCode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)
	p, err := OpenPackage(url, util.Limiter(4), CredentialOptions{NoKeyring: true})
	if err != nil {
		t.Fatalf("OpenPackage failed: %v", err)
	}
	return p
}

// TestDownload_RefreshesExpiredURLs covers the failure this package used to hit
// on multi-GB downloads: every presigned URL is minted up front, the download
// outlives the signing window, and the tail chunks come back 403 "Request has
// expired". The URLs are now re-minted instead.
func TestDownload_RefreshesExpiredURLs(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	const (
		parts     = urlBatchSize + 6 // spans two batches
		chunkSize = 64
	)
	file := bigMockFile(parts, chunkSize)
	p := openTestPackage(t, server, &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files:        []mockFile{file},
	})

	if _, err := p.Open(file.fileName); err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Every URL handed out during Open is now past its deadline, as it would be
	// on a download long enough to outlive the signature.
	mintsAfterOpen := len(server.mintCalls())
	server.expireURLs()

	dest := filepath.Join(t.TempDir(), "big.bin")
	if err := p.DownloadFile(file.fileName, dest, nil); err != nil {
		t.Fatalf("DownloadFile failed: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Join(file.chunks, nil)
	if !bytes.Equal(got, want) {
		t.Errorf("downloaded %d bytes, want %d (content mismatch: %v)", len(got), len(want), !bytes.Equal(got, want))
	}

	// DownloadFile re-Opens the file, so the second Open mints afresh; what
	// matters is that the expired batches were re-minted once each and not once
	// per segment. Two batches, and 12 fetch workers hitting them at once.
	mints := server.mintCalls()
	perBatch := map[[2]int]int{}
	for _, m := range mints[mintsAfterOpen:] {
		perBatch[m]++
	}
	for rng, n := range perBatch {
		if n > 2 { // one lazy mint + at most one refresh
			t.Errorf("segments %d-%d minted %d times; concurrent refreshes should collapse", rng[0], rng[1], n)
		}
	}
	if len(mints) > mintsAfterOpen+6 {
		t.Errorf("minted %d times after expiry, expected a handful of per-batch calls", len(mints)-mintsAfterOpen)
	}
}

// TestDownload_MintsLazily checks that opening a file doesn't mint URLs for
// segments nobody has asked for yet. Minting up front is what let signatures go
// stale before their chunks were read.
func TestDownload_MintsLazily(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	const parts = urlBatchSize * 4
	file := bigMockFile(parts, 32)
	p := openTestPackage(t, server, &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files:        []mockFile{file},
	})

	if _, err := p.Open(file.fileName); err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Open prefetches chunks 0, 1 and the last one: the first and last batch,
	// nothing in between.
	mints := server.mintCalls()
	if len(mints) != 2 {
		t.Fatalf("Open minted %d batches (%v), want 2 (first and last)", len(mints), mints)
	}
	if want := ([2]int{1, urlBatchSize}); mints[0] != want {
		t.Errorf("first mint was for segments %v, want %v", mints[0], want)
	}
	if want := ([2]int{parts - urlBatchSize + 1, parts}); mints[1] != want {
		t.Errorf("last mint was for segments %v, want %v", mints[1], want)
	}
}

// TestDownload_FatalErrorFailsFast checks that a 404 isn't retried: no fresh URL
// will conjure up a chunk that isn't there.
func TestDownload_FatalErrorFailsFast(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	// parts claims three chunks; the server only has one, so chunk 1 is a 404.
	file := mockFile{
		fileID:   "file-short",
		fileName: "short.bin",
		fileSize: 3072,
		parts:    3,
		chunks:   [][]byte{bytes.Repeat([]byte("A"), 1024)},
	}
	p := openTestPackage(t, server, &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files:        []mockFile{file},
	})

	_, err := p.Open(file.fileName)
	if err == nil {
		t.Fatal("expected Open to fail on a missing chunk")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected a 404 in the error, got: %v", err)
	}

	if n := server.downloadCount("TESTCODE", file.fileID, 1); n != 1 {
		t.Errorf("missing chunk was requested %d times, want 1 (no retries on a fatal error)", n)
	}
	if n := len(server.mintCalls()); n != 1 {
		t.Errorf("minted %d times, want 1 (a fatal error must not trigger a refresh)", n)
	}
}

// TestURLTable_RefreshCollapses checks the generation handshake directly: two
// holders of the same expired URL cause one re-mint, not two.
func TestURLTable_RefreshCollapses(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	file := bigMockFile(4, 16)
	p := openTestPackage(t, server, &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files:        []mockFile{file},
	})

	tbl := newURLTable(p, file.fileID, "checksum", file.parts)

	u0, gen0, err := tbl.url(0)
	if err != nil {
		t.Fatalf("url(0): %v", err)
	}
	u1, gen1, err := tbl.url(1)
	if err != nil {
		t.Fatalf("url(1): %v", err)
	}
	if gen0 != gen1 {
		t.Errorf("segments in the same batch have generations %d and %d, want equal", gen0, gen1)
	}
	if n := len(server.mintCalls()); n != 1 {
		t.Errorf("two segments of one batch caused %d mints, want 1", n)
	}

	// Both holders find their URL expired and refresh.
	server.expireURLs()
	r0, rgen0, err := tbl.refresh(0, gen0)
	if err != nil {
		t.Fatalf("refresh(0): %v", err)
	}
	r1, rgen1, err := tbl.refresh(1, gen1)
	if err != nil {
		t.Fatalf("refresh(1): %v", err)
	}
	if rgen0 <= gen0 {
		t.Errorf("refresh returned generation %d, want newer than %d", rgen0, gen0)
	}
	if rgen1 != rgen0 {
		t.Errorf("second refresh minted again (gen %d vs %d) instead of reusing the first", rgen1, rgen0)
	}
	if n := len(server.mintCalls()); n != 2 {
		t.Errorf("%d mints after two refreshes of one batch, want 2", n)
	}
	if r0 == u0 && r1 == u1 {
		t.Error("refresh returned the same URLs; nothing was re-minted")
	}
}
