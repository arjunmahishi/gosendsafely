package sendsafely

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// urlBatchSize is the number of segments minted per download-urls/ call.
//
// Presigned S3 URLs carry a signing deadline, so minting them long before they
// are consumed is what causes "Request has expired". Minting a batch just
// before its segments are needed keeps the URLs young; refreshing (see
// urlTable.refresh) is the safety net for the cases where even a batch outlives
// its window.
const urlBatchSize = 64

// urlTable owns the segment index -> presigned URL mapping for one file. URLs
// are minted lazily, one batch at a time, and can be re-minted when their
// signature expires.
//
// Segment indices are zero-based here; the API numbers them from one.
type urlTable struct {
	// mintBatch mints presigned URLs for segments [start, end).
	mintBatch func(start, end int) ([]ID, error)
	parts     int

	mu      sync.Mutex
	urls    []ID
	batches map[int]*urlBatch
}

// urlBatch tracks the minting state of one batch of segments.
type urlBatch struct {
	// gen counts successful mints. A caller holding a URL from generation g
	// asks for generation g+1 to re-mint, so concurrent holders of the same
	// expired URL collapse onto a single API call.
	gen int
	// ready is non-nil while a mint is in flight; it is closed when that mint
	// finishes, successfully or not.
	ready chan struct{}
	err   error
}

func newURLTable(p *Package, fileID, checksum string, parts int) *urlTable {
	return &urlTable{
		mintBatch: func(start, end int) ([]ID, error) {
			return p.fetchURLs(fileID, checksum, start, end)
		},
		parts:   parts,
		urls:    make([]ID, parts),
		batches: make(map[int]*urlBatch),
	}
}

// url returns the presigned URL for segment i, minting its batch if it hasn't
// been minted yet. The returned generation identifies the minting that produced
// the URL; pass it back to refresh to re-mint only if nobody else already has.
func (t *urlTable) url(i int) (ID, int, error) {
	return t.mint(i, 1)
}

// refresh returns a URL for segment i minted more recently than generation
// staleGen. If another goroutine already re-minted the batch, its URL is
// returned without a further API call.
func (t *urlTable) refresh(i, staleGen int) (ID, int, error) {
	return t.mint(i, staleGen+1)
}

// mint ensures the batch holding segment i has been minted at generation
// minGen or later, and returns that segment's URL.
func (t *urlTable) mint(i, minGen int) (ID, int, error) {
	start := i / urlBatchSize * urlBatchSize

	for {
		t.mu.Lock()
		b := t.batches[start]
		if b == nil {
			b = &urlBatch{}
			t.batches[start] = b
		}

		// Someone else is minting this batch: wait for them rather than
		// stampeding the API with a redundant call.
		if b.ready != nil {
			ready := b.ready
			t.mu.Unlock()
			<-ready

			t.mu.Lock()
			err, gen, u := b.err, b.gen, t.urls[i]
			t.mu.Unlock()

			// Check the URL before the error. A mint we waited on belongs to
			// whoever started it: if it was refreshing a URL that expired for
			// them and it failed, that is no reason to fail us when the URL
			// already in the table is new enough for what we asked for.
			if gen >= minGen {
				return u, gen, nil
			}
			if err != nil {
				return "", 0, err
			}
			// Their mint predates what we need; go around and mint ourselves.
			continue
		}

		if b.gen >= minGen {
			u, gen := t.urls[i], b.gen
			t.mu.Unlock()
			return u, gen, nil
		}

		// We own the mint.
		ready := make(chan struct{})
		b.ready = ready
		t.mu.Unlock()

		end := min(start+urlBatchSize, t.parts)
		urls, err := t.mintBatch(start, end)

		t.mu.Lock()
		if err == nil {
			copy(t.urls[start:end], urls)
			b.gen++
		}
		b.err, b.ready = err, nil
		gen, u := b.gen, t.urls[i]
		t.mu.Unlock()
		close(ready)

		if err != nil {
			return "", 0, err
		}
		return u, gen, nil
	}
}

// fetchURLs mints presigned download URLs for segments [start, end) of a file.
// Indices are zero-based; the API's segment numbers are one-based.
func (p *Package) fetchURLs(fileID, checksum string, start, end int) ([]ID, error) {
	urlPath := fmt.Sprintf("/api/v2.0/package/%s/file/%s/download-urls/", p.info.PackageID, fileID)

	bodyBytes, err := json.Marshal(map[string]any{
		"checksum":     checksum,
		"startSegment": start + 1,
		"endSegment":   end,
	})
	if err != nil {
		return nil, err
	}

	resp, err := p.client.doRequest("POST", urlPath, bodyBytes)
	if err != nil {
		return nil, err
	}

	var dlResp struct {
		Response     string `json:"response"`
		DownloadUrls []struct {
			Part int    `json:"part"`
			URL  string `json:"url"`
		} `json:"downloadUrls"`
	}
	if err := json.Unmarshal(resp, &dlResp); err != nil {
		return nil, fmt.Errorf("failed to parse download URLs: %w", err)
	}
	if dlResp.Response != "SUCCESS" {
		return nil, fmt.Errorf("API returned: %s", dlResp.Response)
	}
	if got := len(dlResp.DownloadUrls); got < end-start {
		return nil, fmt.Errorf("requested download URLs for segments %d-%d, got %d", start+1, end, got)
	}

	urls := make([]ID, end-start)
	for i := range urls {
		urls[i] = ID(dlResp.DownloadUrls[i].URL)
	}
	return urls, nil
}

// httpError is a non-2xx reply to a chunk download. It keeps the status code so
// callers can tell an expired signature (recoverable by re-minting the URL)
// from a permanent failure.
type httpError struct {
	StatusCode int
	Body       string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("failed to download chunk, server reply %d: %s", e.StatusCode, e.Body)
}

// refreshable reports whether a freshly minted URL might make this error go
// away. S3 answers an expired signature with 403 AccessDenied / "Request has
// expired"; a 403 for any other reason costs us a bounded number of re-mints.
func (e *httpError) refreshable() bool {
	return e.StatusCode == http.StatusForbidden
}

// fatal reports whether retrying is pointless: the object or package is gone,
// or the request itself is malformed.
func (e *httpError) fatal() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500 && !e.refreshable()
}
