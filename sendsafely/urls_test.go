package sendsafely

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// fakeURLTable builds a table whose minting is driven by the test rather than
// by an API, so the ordering between concurrent callers is controllable.
func fakeURLTable(parts int, mint func(start, end int) ([]ID, error)) *urlTable {
	return &urlTable{
		mintBatch: mint,
		parts:     parts,
		urls:      make([]ID, parts),
		batches:   make(map[int]*urlBatch),
	}
}

// TestURLTable_FailedRefreshSparesValidURL covers a cross-segment failure: one
// segment's URL expires and its re-mint fails for a passing reason, while a
// second segment in the same batch is merely asking for a URL it could already
// have. The second must not inherit the first's error — every fetch failure
// cancels the whole download, so one segment's blip would sink all of it.
func TestURLTable_FailedRefreshSparesValidURL(t *testing.T) {
	var (
		entered = make(chan struct{}, 4)
		release = make(chan error)
		calls   atomic.Int32
	)
	tbl := fakeURLTable(4, func(start, end int) ([]ID, error) {
		n := calls.Add(1)
		entered <- struct{}{}
		if err := <-release; err != nil {
			return nil, err
		}
		urls := make([]ID, end-start)
		for i := range urls {
			urls[i] = ID(fmt.Sprintf("url-%d-mint%d", start+i, n))
		}
		return urls, nil
	})

	// First mint succeeds, so every segment in the batch has a usable URL.
	go func() { release <- nil }()
	_, gen, err := tbl.url(0)
	if err != nil {
		t.Fatalf("initial mint: %v", err)
	}
	<-entered

	// Segment 0's URL expired; its refresh is in flight and about to fail.
	refreshed := make(chan error, 1)
	go func() {
		_, _, err := tbl.refresh(0, gen)
		refreshed <- err
	}()
	<-entered

	// Segment 1 now wants a URL. The one in the table is new enough, but the
	// failing mint is in flight, so it lands in the waiting path.
	type result struct {
		url ID
		err error
	}
	got := make(chan result, 1)
	go func() {
		u, _, err := tbl.url(1)
		got <- result{u, err}
	}()
	time.Sleep(50 * time.Millisecond) // let segment 1 reach the wait

	release <- errors.New("mint unavailable")

	if err := <-refreshed; err == nil {
		t.Error("refresh of the expired URL should have failed")
	}
	r := <-got
	if r.err != nil {
		t.Errorf("segment 1 failed with another segment's refresh error: %v", r.err)
	}
	if r.url != "url-1-mint1" {
		t.Errorf("segment 1 got URL %q, want the still-valid url-1-mint1", r.url)
	}
}

// TestFetchSegment_RetriesFailedMint checks the other half of that failure: the
// segment whose refresh genuinely failed retries the mint instead of taking the
// download down with it.
func TestFetchSegment_RetriesFailedMint(t *testing.T) {
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

	// The first mint fails; a retry succeeds.
	var calls atomic.Int32
	real := newURLTable(p, file.fileID, checksumFor(t, p), file.parts)
	tbl := fakeURLTable(file.parts, func(start, end int) ([]ID, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("mint unavailable")
		}
		return real.mintBatch(start, end)
	})

	data, err := p.fetchSegment(tbl, 0)
	if err != nil {
		t.Fatalf("fetchSegment gave up on a retryable mint failure: %v", err)
	}
	if !bytes.Equal(data, file.chunks[0]) {
		t.Errorf("segment 0 content mismatch")
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("mint called %d times, want 2 (one failure, one retry)", n)
	}
}

// checksumFor derives the per-package checksum the download-urls API expects.
func checksumFor(t *testing.T, p *Package) string {
	t.Helper()
	dk, err := pbkdf2.Key(sha256.New, p.keyCode, []byte(p.info.PackageCode), 1024, 32)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(dk)
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
