package sendsafely

import (
	"archive/zip"
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/dt/gosendsafely/util"
	"github.com/dt/gosendsafely/ziputil"
)

// TestZipExtract_EndToEnd runs the flow the consumer uses for .zip artifacts —
// open the package file, read the ZIP index off its trailer, then stream the
// whole archive back out through the chunk fetcher — over a file large enough
// to span several URL batches. Nothing expires here; this is the happy path,
// checking that lazily minted URLs and index-keyed chunks deliver the same
// bytes the old up-front minting did.
func TestZipExtract_EndToEnd(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	// Incompressible content, so the archive stays big enough to chunk.
	rng := rand.New(rand.NewSource(1))
	want := map[string][]byte{}
	for _, name := range []string{"a.bin", "nested/b.bin", "nested/deep/c.bin"} {
		buf := make([]byte, 40*1024)
		rng.Read(buf)
		want[name] = buf
	}

	zipBytes := makeZip(t, want)
	const chunkSize = 1024
	chunks := splitChunks(zipBytes, chunkSize)
	if len(chunks) <= urlBatchSize {
		t.Fatalf("test archive is %d chunks; needs more than one batch of %d", len(chunks), urlBatchSize)
	}

	file := mockFile{
		fileID:   "file-zip",
		fileName: "archive.zip",
		fileSize: len(zipBytes),
		parts:    len(chunks),
		chunks:   chunks,
	}
	p := openTestPackage(t, server, &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files:        []mockFile{file},
	})

	// 1. List entries.
	f, err := p.Open(file.fileName)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if f.Size() != len(zipBytes) {
		t.Errorf("file size %d, want %d", f.Size(), len(zipBytes))
	}
	index, err := ziputil.DecodeIndex(f)
	if err != nil {
		t.Fatalf("DecodeIndex failed: %v", err)
	}
	if len(index) != len(want) {
		t.Fatalf("index has %d entries, want %d", len(index), len(want))
	}

	// 2. Extract, from a second Open as the consumer does.
	f2, err := p.Open(file.fileName)
	if err != nil {
		t.Fatalf("second Open failed: %v", err)
	}
	index2, err := ziputil.DecodeIndex(f2)
	if err != nil {
		t.Fatalf("second DecodeIndex failed: %v", err)
	}

	dest := t.TempDir()
	if _, _, err := ziputil.Extract(f2, index2, dest, util.Limiter(8), nil); err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	for name, content := range want {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("%s: extracted %d bytes, want %d (content differs)", name, len(got), len(content))
		}
	}
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func splitChunks(data []byte, size int) [][]byte {
	var chunks [][]byte
	for off := 0; off < len(data); off += size {
		chunks = append(chunks, data[off:min(off+size, len(data))])
	}
	return chunks
}
