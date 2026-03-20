package sendsafely

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/dt/gosendsafely/stream"
	"github.com/dt/gosendsafely/util"
	"golang.org/x/sync/errgroup"
)

// OpenPackage parses a SendSafely URL, loads credentials, and fetches the list
// of files in the package. The returned package can be used to list or open the
// individual files.
func OpenPackage(rawURL string, lim util.Sem, credOpts CredentialOptions) (*Package, error) {
	// Strip backslash escapes (iTerm2 and other terminals escape special chars when pasting)
	rawURL = strings.ReplaceAll(rawURL, `\`, "")

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Extract packageCode from query params
	packageCode := u.Query().Get("packageCode")
	if packageCode == "" {
		// Try path-based format: /receive/?packageCode=XXX
		return nil, fmt.Errorf("packageCode not found in URL")
	}

	// Extract keyCode from fragment
	fragment := u.Fragment
	keyCode := ""
	if strings.HasPrefix(fragment, "keycode=") || strings.HasPrefix(fragment, "keyCode=") {
		keyCode = fragment[8:]
	} else if strings.Contains(fragment, "keycode=") {
		re := regexp.MustCompile(`keycode=([^&]+)`)
		matches := re.FindStringSubmatch(fragment)
		if len(matches) > 1 {
			keyCode = matches[1]
		}
	} else if strings.Contains(fragment, "keyCode=") {
		re := regexp.MustCompile(`keyCode=([^&]+)`)
		matches := re.FindStringSubmatch(fragment)
		if len(matches) > 1 {
			keyCode = matches[1]
		}
	}

	if keyCode == "" {
		return nil, fmt.Errorf("keyCode not found in URL fragment")
	}

	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	// Set BaseURL for credential validation
	credOpts.BaseURL = baseURL
	creds, source, err := loadCredentialsWithSource(credOpts)
	if err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 16

	cl := &client{
		baseURL:   baseURL,
		apiKey:    creds.APIKey,
		apiSecret: creds.APISecret,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}

	getPackage := func(c *client, packageCode, keyCode string) (*Package, error) {
		urlPath := fmt.Sprintf("/api/v2.0/package/%s/", packageCode)
		resp, err := c.doRequest("GET", urlPath, nil)
		if err != nil {
			return nil, err
		}
		res := Package{client: c, keyCode: keyCode}
		if err := json.Unmarshal(resp, &res.info); err != nil {
			return nil, fmt.Errorf("failed to parse package info: %w", err)
		}
		if res.info.Response != "SUCCESS" {
			return nil, fmt.Errorf("API returned: %s", res.info.Response)
		}
		return &res, nil
	}

	pkg, err := getPackage(cl, packageCode, keyCode)
	if err != nil {
		// If auth failed and credentials came from keyring, prompt for new ones
		if strings.Contains(err.Error(), "AUTHENTICATION_FAILED") && source == sourceKeyring {
			fmt.Fprintln(os.Stderr, "")
			creds, err = promptAndSaveCredentials(credOpts, "Saved credentials are invalid or expired.")
			if err != nil {
				return nil, err
			}
			cl.apiKey = creds.APIKey
			cl.apiSecret = creds.APISecret
			pkg, err = getPackage(cl, packageCode, keyCode)
		}
		if err != nil {
			return nil, err
		}
	}
	pkg.lim = lim
	return pkg, nil
}

type Package struct {
	client *client
	info   struct {
		PackageID    string `json:"packageId"`
		PackageCode  string `json:"packageCode"`
		ServerSecret string `json:"serverSecret"`
		Files        []struct {
			FileID   string `json:"fileId"`
			FileName string `json:"fileName"`
			FileSize string `json:"fileSize"`
			Parts    int    `json:"parts"`
		} `json:"files"`
		Response string `json:"response"`
	}
	keyCode string
	lim     util.Sem
}

// Files returns the list of files in the package.
func (p *Package) Files() []FileInfo {
	files := make([]FileInfo, len(p.info.Files))
	for i, f := range p.info.Files {
		size, _ := strconv.Atoi(f.FileSize)
		files[i] = FileInfo{Name: f.FileName, Size: util.BytesSize(size)}
	}
	return files
}

// Open opens a file from the package for reading. The returned File supports
// chunked streaming downloads with automatic decryption.
func (p *Package) Open(fileName string) (*File, error) {
	var fileID string
	var parts int
	var fileSize int

	for _, f := range p.info.Files {
		if f.FileName == fileName {
			fileID = f.FileID
			parts = f.Parts
			var err error
			fileSize, err = strconv.Atoi(f.FileSize)
			if err != nil {
				return nil, fmt.Errorf("invalid fileSize value for file %s: %w", fileName, err)
			}
			break
		}
	}

	if fileID == "" {
		return nil, fmt.Errorf("file %s not found in package", fileName)
	}

	// Collect chunk IDs (download URLs)
	chunkIDs := make([]ID, parts)

	dk, err := pbkdf2.Key(sha256.New, p.keyCode, []byte(p.info.PackageCode), 1024, 32)
	if err != nil {
		return nil, err
	}
	checksum := hex.EncodeToString(dk)

	const batchSize = 1000
	for i := 0; i < parts; i += batchSize {
		urlPath := fmt.Sprintf("/api/v2.0/package/%s/file/%s/download-urls/", p.info.PackageID, fileID)

		body := map[string]interface{}{
			"checksum":     checksum,
			"startSegment": i + 1,
			"endSegment":   min(i+batchSize, parts),
		}
		bodyBytes, _ := json.Marshal(body)

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

		for j := range dlResp.DownloadUrls {
			chunkIDs[i+j] = ID(dlResp.DownloadUrls[j].URL)
		}
	}

	// Pre-fetch first chunk(s) and last chunk to determine actual sizes
	prefetched := make(map[int][]byte)
	c0, err := p.fetchAndDecrypt(chunkIDs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to download chunk 0: %w", err)
	}
	prefetched[0] = c0

	// Determine nominal chunk size from chunk 1 (or chunk 0 if only one chunk)
	nominalSize := len(c0)
	if parts > 1 {
		c1, err := p.fetchAndDecrypt(chunkIDs[1])
		if err != nil {
			return nil, fmt.Errorf("failed to download chunk 1: %w", err)
		}
		prefetched[1] = c1
		nominalSize = len(c1)
	}

	// Pre-fetch last chunk to verify file size. The API may report trailing
	// empty chunks; strip them so the last chunk reflects actual data.
	if parts > 2 {
		cLast, err := p.fetchAndDecrypt(chunkIDs[parts-1])
		if err != nil {
			return nil, fmt.Errorf("failed to download last chunk: %w", err)
		}
		for len(cLast) == 0 && parts > 2 {
			delete(prefetched, parts-1)
			parts--
			chunkIDs = chunkIDs[:parts]
			cLast, err = p.fetchAndDecrypt(chunkIDs[parts-1])
			if err != nil {
				return nil, fmt.Errorf("failed to download last chunk: %w", err)
			}
		}
		prefetched[parts-1] = cLast

		// Adjust total file size based on actual chunk sizes
		// API fileSize may not match exact sum of decrypted chunks
		expectedLastSize := fileSize - len(c0) - nominalSize*(parts-2)
		if delta := len(cLast) - expectedLastSize; delta != 0 {
			fileSize += delta
		}
	}

	// Create file using stream package - it calculates offsets automatically
	file := stream.NewChunkedFile(
		fileName,
		fileSize,
		chunkIDs,
		nominalSize,
		func(id ID) ([]byte, error) {
			return p.fetchAndDecrypt(id)
		},
		prefetched,
	)

	return file, nil
}

func (c *client) fetchAttempt(url ID) ([]byte, error) {
	resp, err := c.http.Get(string(url))
	if err != nil {
		return nil, fmt.Errorf("failed to download chunk: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunk data: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("failed to download chunk, server reply %d: %s", resp.StatusCode, string(data[:min(200, len(data))]))
	}
	return data, nil
}

func (p *Package) fetchAndDecrypt(url ID) ([]byte, error) {
	var data []byte
	var err error
	for i := 0; i < 5; i++ {
		data, err = p.client.fetchAttempt(url)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(bytes.NewReader(data), nil, func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return []byte(p.info.ServerSecret + p.keyCode), nil
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read PGP message: %w", err)
	}

	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return plaintext, nil
}

// DownloadFile downloads a file from the package to the specified output path.
// It supports resumption: if a partial download exists (.ssget-tmp file), it will
// resume from where it left off (with a 4MB safety margin for torn blocks).
func (p *Package) DownloadFile(
	fileName, outputPath string, progress func(string, int, float64),
) error {
	if progress != nil {
		progress("fetching metadata", 0, 0)
	}

	file, err := p.Open(fileName)
	if err != nil {
		return err
	}
	// Create output directory if needed
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}

	// Write to temp file, then rename
	tmpPath := outputPath + ".ssget-tmp"

	// Check for existing partial download and calculate resume offset
	const safetyMargin = 4 << 20 // 4MB safety margin for torn blocks
	resumeOffset := 0

	if info, err := os.Stat(tmpPath); err == nil {
		existingSize := int(info.Size())
		if existingSize > safetyMargin {
			resumeOffset = existingSize - safetyMargin
		}
		// If existingSize <= safetyMargin, resumeOffset stays 0 (start over)
	}

	var f *os.File
	if resumeOffset > 0 {
		// Truncate and open for append at the resume offset
		f, err = os.OpenFile(tmpPath, os.O_RDWR, 0644)
		if err != nil {
			return err
		}
		if err := f.Truncate(int64(resumeOffset)); err != nil {
			f.Close()
			return err
		}
		if _, err := f.Seek(int64(resumeOffset), io.SeekStart); err != nil {
			f.Close()
			return err
		}
	} else {
		// Create new file (or truncate existing to 0)
		f, err = os.Create(tmpPath)
		if err != nil {
			return err
		}
	}
	defer f.Close()

	// Create reader starting at the resume offset
	reader := file.Reader(resumeOffset, file.Size()-resumeOffset)

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		return file.FetchChunks(ctx, p.lim)
	})

	g.Go(func() error {
		if progress != nil {
			// Show initial progress accounting for resumed bytes
			frac := float64(resumeOffset) / float64(file.Size())
			progress("downloading", 0, frac)
		}
		defer reader.Close()
		n := 0
		remaining := file.Size() - resumeOffset
		const chunkSize = 64 << 20
		lastProg := time.Now()
		var lastN int

		for n < remaining {
			m, err := io.CopyN(f, reader, int64(min(remaining-n, chunkSize)))
			if err != nil && err != io.EOF {
				return err
			}
			n += int(m)
			if progress != nil && time.Since(lastProg) > time.Second {
				elapsed := time.Since(lastProg).Seconds()
				bps := float64(n-lastN) / elapsed
				frac := float64(resumeOffset+n) / float64(file.Size())
				progress("downloading", int(bps), frac)
				lastProg = time.Now()
				lastN = n
			}
			if err == io.EOF {
				break
			}
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, outputPath)
}
