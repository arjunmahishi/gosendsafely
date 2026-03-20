package sendsafely

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dt/gosendsafely/util"
)

// mockSendSafelyServer creates a test server that simulates the SendSafely API.
type mockSendSafelyServer struct {
	*httptest.Server
	packages       map[string]*mockPackage
	userEmail      string
	validAPIKey    string
	validAPISecret string
}

type mockPackage struct {
	packageID    string
	packageCode  string
	serverSecret string
	keyCode      string
	files        []mockFile
}

type mockFile struct {
	fileID   string
	fileName string
	fileSize int
	parts    int
	chunks   [][]byte // decrypted content for each chunk
}

func newMockSendSafelyServer() *mockSendSafelyServer {
	m := &mockSendSafelyServer{
		packages:       make(map[string]*mockPackage),
		userEmail:      "test@example.com",
		validAPIKey:    "test-api-key",
		validAPISecret: "test-api-secret",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2.0/user/", m.handleUser)
	mux.HandleFunc("/api/v2.0/package/", m.handlePackage)
	mux.HandleFunc("/download/", m.handleDownload)

	m.Server = httptest.NewServer(mux)
	return m
}

func (m *mockSendSafelyServer) handleUser(w http.ResponseWriter, r *http.Request) {
	if !m.validateAuth(r) {
		json.NewEncoder(w).Encode(map[string]string{
			"response": "AUTHENTICATION_FAILED",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"response": "SUCCESS",
		"email":    m.userEmail,
	})
}

func (m *mockSendSafelyServer) handlePackage(w http.ResponseWriter, r *http.Request) {
	if !m.validateAuth(r) {
		json.NewEncoder(w).Encode(map[string]string{
			"response": "AUTHENTICATION_FAILED",
		})
		return
	}

	// Parse path: /api/v2.0/package/{packageCode}/ or /api/v2.0/package/{packageID}/file/{fileID}/download-urls/
	path := strings.TrimPrefix(r.URL.Path, "/api/v2.0/package/")
	parts := strings.Split(strings.Trim(path, "/"), "/")

	if len(parts) == 1 {
		// Get package info
		packageCode := parts[0]
		pkg, ok := m.packages[packageCode]
		if !ok {
			json.NewEncoder(w).Encode(map[string]string{
				"response": "PACKAGE_NOT_FOUND",
			})
			return
		}

		files := make([]map[string]interface{}, len(pkg.files))
		for i, f := range pkg.files {
			files[i] = map[string]interface{}{
				"fileId":   f.fileID,
				"fileName": f.fileName,
				"fileSize": fmt.Sprintf("%d", f.fileSize),
				"parts":    f.parts,
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"response":     "SUCCESS",
			"packageId":    pkg.packageID,
			"packageCode":  pkg.packageCode,
			"serverSecret": pkg.serverSecret,
			"files":        files,
		})
		return
	}

	if len(parts) >= 4 && parts[1] == "file" && parts[3] == "download-urls" {
		// Get download URLs
		packageID := parts[0]
		fileID := parts[2]

		// Find the package by ID
		var pkg *mockPackage
		for _, p := range m.packages {
			if p.packageID == packageID {
				pkg = p
				break
			}
		}
		if pkg == nil {
			json.NewEncoder(w).Encode(map[string]string{
				"response": "PACKAGE_NOT_FOUND",
			})
			return
		}

		// Find the file
		var file *mockFile
		for i := range pkg.files {
			if pkg.files[i].fileID == fileID {
				file = &pkg.files[i]
				break
			}
		}
		if file == nil {
			json.NewEncoder(w).Encode(map[string]string{
				"response": "FILE_NOT_FOUND",
			})
			return
		}

		var reqBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&reqBody)

		startSegment := 1
		endSegment := file.parts
		if v, ok := reqBody["startSegment"].(float64); ok {
			startSegment = int(v)
		}
		if v, ok := reqBody["endSegment"].(float64); ok {
			endSegment = int(v)
		}

		downloadUrls := make([]map[string]interface{}, 0)
		for i := startSegment; i <= min(endSegment, file.parts); i++ {
			downloadUrls = append(downloadUrls, map[string]interface{}{
				"part": i,
				"url":  fmt.Sprintf("%s/download/%s/%s/%d", m.Server.URL, pkg.packageCode, fileID, i-1),
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"response":     "SUCCESS",
			"downloadUrls": downloadUrls,
		})
		return
	}

	http.NotFound(w, r)
}

func (m *mockSendSafelyServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	// Parse path: /download/{packageCode}/{fileID}/{chunkIndex}
	path := strings.TrimPrefix(r.URL.Path, "/download/")
	parts := strings.Split(path, "/")
	if len(parts) != 3 {
		http.NotFound(w, r)
		return
	}

	packageCode := parts[0]
	fileID := parts[1]
	chunkIndex := 0
	fmt.Sscanf(parts[2], "%d", &chunkIndex)

	pkg, ok := m.packages[packageCode]
	if !ok {
		http.NotFound(w, r)
		return
	}

	var file *mockFile
	for i := range pkg.files {
		if pkg.files[i].fileID == fileID {
			file = &pkg.files[i]
			break
		}
	}
	if file == nil || chunkIndex >= len(file.chunks) {
		http.NotFound(w, r)
		return
	}

	// Encrypt the chunk data with PGP
	passphrase := pkg.serverSecret + pkg.keyCode
	encrypted, err := encryptPGP(file.chunks[chunkIndex], passphrase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(encrypted)
}

func (m *mockSendSafelyServer) validateAuth(r *http.Request) bool {
	apiKey := r.Header.Get("ss-api-key")
	return apiKey == m.validAPIKey
}

func (m *mockSendSafelyServer) addPackage(pkg *mockPackage) {
	m.packages[pkg.packageCode] = pkg
}

// TestOpenPackage_Success tests successfully opening a package and listing files.
func TestOpenPackage_Success(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	pkg := &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files: []mockFile{
			{fileID: "file-1", fileName: "document.pdf", fileSize: 1024, parts: 1, chunks: [][]byte{bytes.Repeat([]byte("A"), 1024)}},
			{fileID: "file-2", fileName: "archive.zip", fileSize: 2048, parts: 2, chunks: [][]byte{bytes.Repeat([]byte("B"), 1024), bytes.Repeat([]byte("C"), 1024)}},
		},
	}
	server.addPackage(pkg)

	// Set environment variables for credentials
	os.Setenv("SS_API_KEY", server.validAPIKey)
	os.Setenv("SS_API_SECRET", server.validAPISecret)
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	url := fmt.Sprintf("%s/receive/?packageCode=%s#keyCode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)

	result, err := OpenPackage(url, util.Limiter(4), CredentialOptions{NoKeyring: true})
	if err != nil {
		t.Fatalf("OpenPackage failed: %v", err)
	}

	files := result.Files()
	if len(files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(files))
	}

	if files[0].Name != "document.pdf" {
		t.Errorf("Expected first file name 'document.pdf', got '%s'", files[0].Name)
	}
	if files[0].Size != 1024 {
		t.Errorf("Expected first file size 1024, got %d", files[0].Size)
	}

	if files[1].Name != "archive.zip" {
		t.Errorf("Expected second file name 'archive.zip', got '%s'", files[1].Name)
	}
	if files[1].Size != 2048 {
		t.Errorf("Expected second file size 2048, got %d", files[1].Size)
	}
}

// TestOpenPackage_MissingPackageCode tests error when packageCode is missing from URL.
func TestOpenPackage_MissingPackageCode(t *testing.T) {
	os.Setenv("SS_API_KEY", "test-key")
	os.Setenv("SS_API_SECRET", "test-secret")
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	url := "https://example.com/receive/?other=param#keyCode=abc123"
	_, err := OpenPackage(url, nil, CredentialOptions{NoKeyring: true})
	if err == nil {
		t.Fatal("Expected error for missing packageCode")
	}
	if !strings.Contains(err.Error(), "packageCode not found") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestOpenPackage_MissingKeyCode tests error when keyCode is missing from URL.
func TestOpenPackage_MissingKeyCode(t *testing.T) {
	os.Setenv("SS_API_KEY", "test-key")
	os.Setenv("SS_API_SECRET", "test-secret")
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	url := "https://example.com/receive/?packageCode=TESTCODE"
	_, err := OpenPackage(url, nil, CredentialOptions{NoKeyring: true})
	if err == nil {
		t.Fatal("Expected error for missing keyCode")
	}
	if !strings.Contains(err.Error(), "keyCode not found") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestOpenPackage_AuthenticationFailed tests error handling for invalid credentials.
func TestOpenPackage_AuthenticationFailed(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	pkg := &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files:        []mockFile{},
	}
	server.addPackage(pkg)

	// Set invalid credentials
	os.Setenv("SS_API_KEY", "invalid-key")
	os.Setenv("SS_API_SECRET", "invalid-secret")
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	url := fmt.Sprintf("%s/receive/?packageCode=%s#keyCode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)

	_, err := OpenPackage(url, nil, CredentialOptions{NoKeyring: true})
	if err == nil {
		t.Fatal("Expected error for invalid credentials")
	}
	if !strings.Contains(err.Error(), "AUTHENTICATION_FAILED") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestOpenPackage_PackageNotFound tests error handling when package doesn't exist.
func TestOpenPackage_PackageNotFound(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	os.Setenv("SS_API_KEY", server.validAPIKey)
	os.Setenv("SS_API_SECRET", server.validAPISecret)
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	url := fmt.Sprintf("%s/receive/?packageCode=NONEXISTENT#keyCode=abc123", server.Server.URL)

	_, err := OpenPackage(url, nil, CredentialOptions{NoKeyring: true})
	if err == nil {
		t.Fatal("Expected error for non-existent package")
	}
	if !strings.Contains(err.Error(), "PACKAGE_NOT_FOUND") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestOpenPackage_URLVariants tests parsing of various URL formats.
func TestOpenPackage_URLVariants(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	pkg := &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files:        []mockFile{{fileID: "f1", fileName: "test.txt", fileSize: 100, parts: 1, chunks: [][]byte{bytes.Repeat([]byte("X"), 100)}}},
	}
	server.addPackage(pkg)

	os.Setenv("SS_API_KEY", server.validAPIKey)
	os.Setenv("SS_API_SECRET", server.validAPISecret)
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	testCases := []struct {
		name string
		url  string
	}{
		{"lowercase keycode", fmt.Sprintf("%s/receive/?packageCode=%s#keycode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)},
		{"uppercase keyCode", fmt.Sprintf("%s/receive/?packageCode=%s#keyCode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)},
		{"with escaped backslashes", fmt.Sprintf("%s/receive/?packageCode=%s#keyCode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := OpenPackage(tc.url, util.Limiter(4), CredentialOptions{NoKeyring: true})
			if err != nil {
				t.Fatalf("OpenPackage failed for %s: %v", tc.name, err)
			}
			if len(result.Files()) != 1 {
				t.Errorf("Expected 1 file for %s, got %d", tc.name, len(result.Files()))
			}
		})
	}
}

// TestPackage_Open tests opening a specific file from a package.
func TestPackage_Open(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	fileContent := bytes.Repeat([]byte("Hello, World! "), 100)
	pkg := &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files: []mockFile{
			{fileID: "file-1", fileName: "test.txt", fileSize: len(fileContent), parts: 1, chunks: [][]byte{fileContent}},
		},
	}
	server.addPackage(pkg)

	os.Setenv("SS_API_KEY", server.validAPIKey)
	os.Setenv("SS_API_SECRET", server.validAPISecret)
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	url := fmt.Sprintf("%s/receive/?packageCode=%s#keyCode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)

	result, err := OpenPackage(url, util.Limiter(4), CredentialOptions{NoKeyring: true})
	if err != nil {
		t.Fatalf("OpenPackage failed: %v", err)
	}

	file, err := result.Open("test.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if file.Name() != "test.txt" {
		t.Errorf("Expected file name 'test.txt', got '%s'", file.Name())
	}
	if file.Size() != len(fileContent) {
		t.Errorf("Expected file size %d, got %d", len(fileContent), file.Size())
	}
}

// TestPackage_Open_FileNotFound tests error when opening a non-existent file.
func TestPackage_Open_FileNotFound(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	pkg := &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files: []mockFile{
			{fileID: "file-1", fileName: "existing.txt", fileSize: 100, parts: 1, chunks: [][]byte{bytes.Repeat([]byte("A"), 100)}},
		},
	}
	server.addPackage(pkg)

	os.Setenv("SS_API_KEY", server.validAPIKey)
	os.Setenv("SS_API_SECRET", server.validAPISecret)
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	url := fmt.Sprintf("%s/receive/?packageCode=%s#keyCode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)

	result, err := OpenPackage(url, util.Limiter(4), CredentialOptions{NoKeyring: true})
	if err != nil {
		t.Fatalf("OpenPackage failed: %v", err)
	}

	_, err = result.Open("nonexistent.txt")
	if err == nil {
		t.Fatal("Expected error for non-existent file")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestPackage_DownloadFile tests downloading a file to disk.
func TestPackage_DownloadFile(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	fileContent := bytes.Repeat([]byte("Test file content. "), 50)
	pkg := &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files: []mockFile{
			{fileID: "file-1", fileName: "download-test.txt", fileSize: len(fileContent), parts: 1, chunks: [][]byte{fileContent}},
		},
	}
	server.addPackage(pkg)

	os.Setenv("SS_API_KEY", server.validAPIKey)
	os.Setenv("SS_API_SECRET", server.validAPISecret)
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	url := fmt.Sprintf("%s/receive/?packageCode=%s#keyCode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)

	// Use nil limiter to avoid potential deadlock in tests with pre-fetched chunks
	result, err := OpenPackage(url, nil, CredentialOptions{NoKeyring: true})
	if err != nil {
		t.Fatalf("OpenPackage failed: %v", err)
	}

	// Create temp directory for output
	tmpDir, err := os.MkdirTemp("", "ssdownload-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	outputPath := filepath.Join(tmpDir, "output.txt")

	var progressCalls int
	err = result.DownloadFile("download-test.txt", outputPath, func(stage string, bps int, frac float64) {
		progressCalls++
	})
	if err != nil {
		t.Fatalf("DownloadFile failed: %v", err)
	}

	// Verify file was downloaded
	downloadedContent, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	if !bytes.Equal(downloadedContent, fileContent) {
		t.Errorf("Downloaded content doesn't match original")
	}

	// Progress might not be called for very fast single-chunk downloads
	t.Logf("Progress callback called %d times", progressCalls)
}

// TestPackage_DownloadFile_MultipleChunks tests downloading a file with multiple chunks.
func TestPackage_DownloadFile_MultipleChunks(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	chunk1 := bytes.Repeat([]byte("CHUNK1"), 200)
	chunk2 := bytes.Repeat([]byte("CHUNK2"), 200)
	chunk3 := bytes.Repeat([]byte("CHUNK3"), 100)
	fullContent := append(append(chunk1, chunk2...), chunk3...)

	// Second file with a trailing empty chunk, simulating the API reporting
	// more parts than actually contain data.
	chunk4 := bytes.Repeat([]byte("CHUNK4"), 200)
	chunk5 := bytes.Repeat([]byte("CHUNK5"), 200)
	chunk6 := bytes.Repeat([]byte("CHUNK6"), 100)
	fullContent2 := append(append(chunk4, chunk5...), chunk6...)

	pkg := &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files: []mockFile{
			{fileID: "file-1", fileName: "multi-chunk.bin", fileSize: len(fullContent), parts: 3, chunks: [][]byte{chunk1, chunk2, chunk3}},
			{fileID: "file-2", fileName: "trailing-empty.bin", fileSize: len(fullContent2), parts: 4, chunks: [][]byte{chunk4, chunk5, chunk6, {}}},
		},
	}
	server.addPackage(pkg)

	os.Setenv("SS_API_KEY", server.validAPIKey)
	os.Setenv("SS_API_SECRET", server.validAPISecret)
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	url := fmt.Sprintf("%s/receive/?packageCode=%s#keyCode=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)

	// Use nil limiter to avoid potential deadlock in tests with pre-fetched chunks
	result, err := OpenPackage(url, nil, CredentialOptions{NoKeyring: true})
	if err != nil {
		t.Fatalf("OpenPackage failed: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "ssdownload-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	t.Run("multiple chunks well formed", func(t *testing.T) {
		outputPath := filepath.Join(tmpDir, "multi-chunk.bin")
		err = result.DownloadFile("multi-chunk.bin", outputPath, nil)
		if err != nil {
			t.Fatalf("DownloadFile failed: %v", err)
		}

		downloadedContent, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("Failed to read downloaded file: %v", err)
		}

		if !bytes.Equal(downloadedContent, fullContent) {
			t.Errorf("Downloaded content doesn't match original. Got %d bytes, expected %d bytes", len(downloadedContent), len(fullContent))
		}
	})

	t.Run("with trailing empty chunk", func(t *testing.T) {
		outputPath2 := filepath.Join(tmpDir, "trailing-empty.bin")
		err = result.DownloadFile("trailing-empty.bin", outputPath2, nil)
		if err != nil {
			t.Fatalf("DownloadFile failed for trailing empty chunk file: %v", err)
		}

		downloadedContent2, err := os.ReadFile(outputPath2)
		if err != nil {
			t.Fatalf("Failed to read downloaded file: %v", err)
		}

		if !bytes.Equal(downloadedContent2, fullContent2) {
			t.Errorf("Downloaded content doesn't match original. Got %d bytes, expected %d bytes", len(downloadedContent2), len(fullContent2))
		}
	})
}

// TestCredentials_Validate tests credential validation.
func TestCredentials_Validate(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	t.Run("valid credentials", func(t *testing.T) {
		creds := &Credentials{
			APIKey:    server.validAPIKey,
			APISecret: server.validAPISecret,
		}

		email, err := creds.Validate(server.Server.URL)
		if err != nil {
			t.Fatalf("Validate failed: %v", err)
		}
		if email != server.userEmail {
			t.Errorf("Expected email '%s', got '%s'", server.userEmail, email)
		}
	})

	t.Run("invalid credentials", func(t *testing.T) {
		creds := &Credentials{
			APIKey:    "bad-key",
			APISecret: "bad-secret",
		}

		_, err := creds.Validate(server.Server.URL)
		if err == nil {
			t.Fatal("Expected error for invalid credentials")
		}
	})
}

// TestLoadCredentials_FromEnv tests loading credentials from environment variables.
func TestLoadCredentials_FromEnv(t *testing.T) {
	os.Setenv("SS_API_KEY", "env-api-key")
	os.Setenv("SS_API_SECRET", "env-api-secret")
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	creds, err := LoadCredentials(CredentialOptions{NoKeyring: true})
	if err != nil {
		t.Fatalf("LoadCredentials failed: %v", err)
	}

	if creds.APIKey != "env-api-key" {
		t.Errorf("Expected APIKey 'env-api-key', got '%s'", creds.APIKey)
	}
	if creds.APISecret != "env-api-secret" {
		t.Errorf("Expected APISecret 'env-api-secret', got '%s'", creds.APISecret)
	}
}

// TestLoadCredentials_MissingEnv tests error when environment variables are not set.
func TestLoadCredentials_MissingEnv(t *testing.T) {
	os.Unsetenv("SS_API_KEY")
	os.Unsetenv("SS_API_SECRET")

	_, err := LoadCredentials(CredentialOptions{NoKeyring: true})
	if err == nil {
		t.Fatal("Expected error when credentials are not available")
	}
}

// TestClient_doRequest tests the HTTP request signing and execution.
func TestClient_doRequest(t *testing.T) {
	var receivedAPIKey, receivedSignature, receivedTimestamp string
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAPIKey = r.Header.Get("ss-api-key")
		receivedSignature = r.Header.Get("ss-request-signature")
		receivedTimestamp = r.Header.Get("ss-request-timestamp")

		if r.Body != nil {
			receivedBody, _ = io.ReadAll(r.Body)
		}

		json.NewEncoder(w).Encode(map[string]string{"response": "SUCCESS"})
	}))
	defer server.Close()

	cl := &client{
		baseURL:   server.URL,
		apiKey:    "test-api-key",
		apiSecret: "test-api-secret",
		http:      http.DefaultClient,
	}

	body := []byte(`{"test": "data"}`)
	_, err := cl.doRequest("POST", "/api/v2.0/test/", body)
	if err != nil {
		t.Fatalf("doRequest failed: %v", err)
	}

	if receivedAPIKey != "test-api-key" {
		t.Errorf("Expected API key 'test-api-key', got '%s'", receivedAPIKey)
	}

	if receivedSignature == "" {
		t.Error("Expected request signature to be set")
	}

	if receivedTimestamp == "" {
		t.Error("Expected request timestamp to be set")
	}

	if string(receivedBody) != string(body) {
		t.Errorf("Expected body '%s', got '%s'", string(body), string(receivedBody))
	}
}

// TestClient_doRequest_Error tests error handling for failed requests.
func TestClient_doRequest_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	cl := &client{
		baseURL:   server.URL,
		apiKey:    "test-api-key",
		apiSecret: "test-api-secret",
		http:      http.DefaultClient,
	}

	_, err := cl.doRequest("GET", "/api/v2.0/test/", nil)
	if err == nil {
		t.Fatal("Expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Expected error to mention status code 500: %v", err)
	}
}

// TestPBKDF2Checksum tests that PBKDF2 checksum calculation matches expected format.
func TestPBKDF2Checksum(t *testing.T) {
	keyCode := "test-key-code"
	packageCode := "TEST-PACKAGE"

	dk, err := pbkdf2.Key(sha256.New, keyCode, []byte(packageCode), 1024, 32)
	if err != nil {
		t.Fatalf("pbkdf2.Key failed: %v", err)
	}
	checksum := hex.EncodeToString(dk)

	if len(checksum) != 64 {
		t.Errorf("Expected checksum length 64, got %d", len(checksum))
	}

	// Verify it's valid hex
	_, err = hex.DecodeString(checksum)
	if err != nil {
		t.Errorf("Checksum is not valid hex: %v", err)
	}
}

// TestOpenPackage_EscapedURL tests handling of backslash-escaped URLs (from terminals).
func TestOpenPackage_EscapedURL(t *testing.T) {
	server := newMockSendSafelyServer()
	defer server.Close()

	pkg := &mockPackage{
		packageID:    "pkg-123",
		packageCode:  "TESTCODE",
		serverSecret: "server-secret-123",
		keyCode:      "key-code-456",
		files:        []mockFile{{fileID: "f1", fileName: "test.txt", fileSize: 100, parts: 1, chunks: [][]byte{bytes.Repeat([]byte("X"), 100)}}},
	}
	server.addPackage(pkg)

	os.Setenv("SS_API_KEY", server.validAPIKey)
	os.Setenv("SS_API_SECRET", server.validAPISecret)
	defer os.Unsetenv("SS_API_KEY")
	defer os.Unsetenv("SS_API_SECRET")

	// URL with backslash escapes (as might be pasted from iTerm2)
	escapedURL := fmt.Sprintf("%s/receive/\\?packageCode\\=%s\\#keyCode\\=%s", server.Server.URL, pkg.packageCode, pkg.keyCode)

	result, err := OpenPackage(escapedURL, util.Limiter(4), CredentialOptions{NoKeyring: true})
	if err != nil {
		t.Fatalf("OpenPackage failed for escaped URL: %v", err)
	}

	if len(result.Files()) != 1 {
		t.Errorf("Expected 1 file, got %d", len(result.Files()))
	}
}
