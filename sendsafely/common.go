package sendsafely

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/dt/gosendsafely/stream"
	"github.com/dt/gosendsafely/util"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

// ID is a presigned chunk download URL.
type ID string

// File is a package file streamed in chunks. Chunks are keyed by zero-based
// segment index rather than by URL, so an expired presigned URL can be
// re-minted for the same segment.
type File = stream.ChunkedFile[int]

type FileInfo struct {
	Name string
	Size util.BytesSize
}

type client struct {
	baseURL   string
	apiKey    string
	apiSecret string
	http      *http.Client
}

type Credentials struct {
	APIKey    string
	APISecret string
}

const keyringService = "sendsafely"

// CredentialOptions configures credential loading behavior.
type CredentialOptions struct {
	NoKeyring bool   // Skip keyring lookup and don't offer to save
	BaseURL   string // Base URL for API validation (required for validation)
}

type credentialSource int

const (
	sourceEnv credentialSource = iota
	sourceKeyring
	sourcePrompt
)

// LoadCredentials loads SendSafely API credentials from (in order):
// 1. Environment variables (SS_API_KEY, SS_API_SECRET)
// 2. System keyring (unless NoKeyring is set)
// 3. Interactive prompt (if terminal), with option to save to keyring
func LoadCredentials(opts CredentialOptions) (*Credentials, error) {
	creds, _, err := loadCredentialsWithSource(opts)
	return creds, err
}

func loadCredentialsWithSource(opts CredentialOptions) (*Credentials, credentialSource, error) {
	// 1. Environment variables
	if key, secret := os.Getenv("SS_API_KEY"), os.Getenv("SS_API_SECRET"); key != "" && secret != "" {
		return &Credentials{APIKey: key, APISecret: secret}, sourceEnv, nil
	}

	// 2. System keyring
	if !opts.NoKeyring {
		if creds, err := loadCredentialsFromKeyring(); err == nil {
			return creds, sourceKeyring, nil
		}
	}

	// 3. Interactive prompt
	creds, err := promptAndSaveCredentials(opts, "No SendSafely credentials found in SS_API_KEY/SS_API_SECRET or system keychain.")
	if err != nil {
		return nil, sourcePrompt, err
	}
	return creds, sourcePrompt, nil
}

func promptAndSaveCredentials(opts CredentialOptions, message string) (*Credentials, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("credentials not found: set SS_API_KEY and SS_API_SECRET environment variables")
	}

	fmt.Fprintln(os.Stderr, message)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "To get API credentials:")
	fmt.Fprintln(os.Stderr, "  1. Log in to SendSafely and go to Edit Profile")
	fmt.Fprintln(os.Stderr, "  2. Under API Keys, click 'Generate New Key'")
	fmt.Fprintln(os.Stderr, "  3. Copy the API Key and API Secret")
	fmt.Fprintln(os.Stderr, "")

	for {
		creds, err := promptForCredentials()
		if err != nil {
			return nil, err
		}

		// Validate before offering to save
		if opts.BaseURL != "" {
			fmt.Fprint(os.Stderr, "Validating credentials... ")
			email, err := creds.Validate(opts.BaseURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed: %v\n", err)
				fmt.Fprintln(os.Stderr, "Please try again.")
				fmt.Fprintln(os.Stderr, "")
				continue
			}
			fmt.Fprintf(os.Stderr, "ok (%s)\n", email)
		}

		if !opts.NoKeyring && promptYesNo("Save credentials to secure keychain?") {
			if err := saveCredentialsToKeyring(creds); err != nil {
				fmt.Fprintf(os.Stderr, "warning: couldn't save to keyring: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "Credentials saved to keychain.")
			}
		}

		return creds, nil
	}
}

// ForgetCredentials removes saved credentials from the system keyring.
func ForgetCredentials() error {
	var errs []error
	if err := keyring.Delete(keyringService, "api_key"); err != nil && err != keyring.ErrNotFound {
		errs = append(errs, err)
	}
	if err := keyring.Delete(keyringService, "api_secret"); err != nil && err != keyring.ErrNotFound {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to delete credentials: %v", errs)
	}
	return nil
}

// Validate checks if the credentials are valid by making a test API call.
// Returns the user's email on success for confirmation.
func (c *Credentials) Validate(baseURL string) (string, error) {
	cl := &client{
		baseURL:   baseURL,
		apiKey:    c.APIKey,
		apiSecret: c.APISecret,
		http:      &http.Client{Timeout: 10 * time.Second},
	}
	resp, err := cl.doRequest("GET", "/api/v2.0/user/", nil)
	if err != nil {
		return "", err
	}
	var userInfo struct {
		Email    string `json:"email"`
		Response string `json:"response"`
	}
	if err := json.Unmarshal(resp, &userInfo); err != nil {
		return "", err
	}
	if userInfo.Response != "SUCCESS" {
		return "", fmt.Errorf("API returned: %s", userInfo.Response)
	}
	return userInfo.Email, nil
}

func loadCredentialsFromKeyring() (*Credentials, error) {
	key, err := keyring.Get(keyringService, "api_key")
	if err != nil {
		return nil, err
	}
	secret, err := keyring.Get(keyringService, "api_secret")
	if err != nil {
		return nil, err
	}
	return &Credentials{APIKey: key, APISecret: secret}, nil
}

func saveCredentialsToKeyring(c *Credentials) error {
	if err := keyring.Set(keyringService, "api_key", c.APIKey); err != nil {
		return err
	}
	return keyring.Set(keyringService, "api_secret", c.APISecret)
}

func promptForCredentials() (*Credentials, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Fprint(os.Stderr, "SendSafely API Key: ")
	key, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read API key: %w", err)
	}

	fmt.Fprint(os.Stderr, "SendSafely API Secret: ")
	secretBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return nil, fmt.Errorf("failed to read API secret: %w", err)
	}

	return &Credentials{
		APIKey:    strings.TrimSpace(key),
		APISecret: strings.TrimSpace(string(secretBytes)),
	}, nil
}

func promptYesNo(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", prompt)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

func (c *client) doRequest(method, urlPath string, body []byte) ([]byte, error) {
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05+0000")

	bodyStr := ""
	if body != nil {
		bodyStr = string(body)
	}

	data := c.apiKey + urlPath + timestamp + bodyStr
	h := hmac.New(sha256.New, []byte(c.apiSecret))
	h.Write([]byte(data))
	signature := hex.EncodeToString(h.Sum(nil))

	fullURL := c.baseURL + urlPath
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("ss-api-key", c.apiKey)
	req.Header.Set("ss-request-signature", signature)
	req.Header.Set("ss-request-timestamp", timestamp)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// encryptPGP encrypts data using symmetric PGP with AES-256.
// The passphrase should be serverSecret + keyCode.
func encryptPGP(data []byte, passphrase string) ([]byte, error) {
	var buf bytes.Buffer
	config := &packet.Config{DefaultCipher: packet.CipherAES256}

	w, err := openpgp.SymmetricallyEncrypt(&buf, []byte(passphrase), nil, config)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
