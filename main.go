package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jamesruan/sodium"
	"gopkg.in/yaml.v3"
)

const (
	apiBase    = "https://api.github.com"
	userAgent  = "bulk-env-update/1.0"
	httpTO     = 30 * time.Second
)

// ---------- YAML config ----------
//
// Example (config.yaml):
//
// org: my-org
// repos:
//   - name: sample-repo
//     environments:
//       dev:
//         API_KEY: "@secrets/dev/api_key.txt"      # file-based (prefix with @)
//         CONN_STRING:
//           file: "secrets/dev/conn.txt"           # file-based (object form)
//         SIMPLE_VALUE: "hello"                     # literal string
//       prod:
//         API_KEY: "@secrets/prod/api_key.txt"
//
// ---------------------------------

type Config struct {
	Org   string    `yaml:"org"`
	Repos []RepoCfg `yaml:"repos"`
}

type RepoCfg struct {
	Name         string                                     `yaml:"name"`
	Environments map[string]map[string]any                  `yaml:"environments"` // envName -> (secretName -> value | {file:..}|{value:..})
}

// Resolve secret value from the flexible YAML forms.
// - "literal string" -> returns as-is
// - "@path/to/file"  -> returns file contents
// - {file: "..."}    -> returns file contents
// - {value: "..."}   -> returns the value
func resolveSecretValue(v any) (string, error) {
	switch t := v.(type) {
	case string:
		// '@' prefix => file path
		if strings.HasPrefix(t, "@") {
			path := strings.TrimPrefix(t, "@")
			b, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("read file %q: %w", path, err)
			}
			return string(b), nil
		}
		return t, nil
	case map[string]any:
		if fileV, ok := t["file"]; ok {
			path, ok := fileV.(string)
			if !ok {
				return "", fmt.Errorf("file value must be string, got %T", fileV)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("read file %q: %w", path, err)
			}
			return string(b), nil
		}
		if valV, ok := t["value"]; ok {
			s, ok := valV.(string)
			if !ok {
				return "", fmt.Errorf("value must be string, got %T", valV)
			}
			return s, nil
		}
		return "", fmt.Errorf("unsupported object for secret: keys=%v", mapsKeys(t))
	default:
		return "", fmt.Errorf("unsupported secret type: %T", v)
	}
}

func mapsKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------- GitHub API models ----------

type repoResp struct {
	ID int64 `json:"id"`
}

type envKeyResp struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"` // base64 public key (32 bytes when decoded)
}

// ---------- HTTP helpers ----------

type ghClient struct {
	http  *http.Client
	token string
}

func newGH(token string) *ghClient {
	return &ghClient{
		http: &http.Client{Timeout: httpTO},
		token: token,
	}
}

func (c *ghClient) doJSON(ctx context.Context, method, url string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s -> %d: %s", method, url, resp.StatusCode, strings.TrimSpace(string(b)))
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *ghClient) doNoBody(ctx context.Context, method, url string) error {
	return c.doJSON(ctx, method, url, nil, nil)
}

// ---------- GitHub operations ----------

func (c *ghClient) getRepoID(ctx context.Context, owner, repo string) (int64, error) {
	var out repoResp
	err := c.doJSON(ctx, "GET", fmt.Sprintf("%s/repos/%s/%s", apiBase, owner, repo), nil, &out)
	if err != nil {
		return 0, err
	}
	return out.ID, nil
}

// Create or update an environment (idempotent)
func (c *ghClient) ensureEnvironment(ctx context.Context, owner, repo, envName string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/environments/%s", apiBase, owner, repo, envName)
	// PUT with empty body is ok; you can pass optional properties if you need.
	payload := map[string]any{}
	return c.doJSON(ctx, "PUT", url, payload, nil)
}

func (c *ghClient) getEnvironmentPublicKey(ctx context.Context, repoID int64, envName string) (envKeyResp, error) {
	var out envKeyResp
	url := fmt.Sprintf("%s/repositories/%d/environments/%s/secrets/public-key", apiBase, repoID, envName)
	err := c.doJSON(ctx, "GET", url, nil, &out)
	return out, err
}

func (c *ghClient) putEnvironmentSecret(ctx context.Context, repoID int64, envName, secretName, encryptedB64, keyID string) error {
	url := fmt.Sprintf("%s/repositories/%d/environments/%s/secrets/%s", apiBase, repoID, envName, secretName)
	payload := map[string]any{
		"encrypted_value": encryptedB64,
		"key_id":          keyID,
	}
	return c.doJSON(ctx, "PUT", url, payload, nil)
}

// ---------- Encryption (libsodium sealed box) ----------

func encryptSecret(plaintext string, githubB64PublicKey string) (string, error) {
	// Decode GitHub’s base64-encoded 32-byte public key
	pubRaw, err := base64.StdEncoding.DecodeString(githubB64PublicKey)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	if len(pubRaw) != 32 {
		return "", fmt.Errorf("unexpected public key length: %d (want 32)", len(pubRaw))
	}

	// Build sodium.BoxPublicKey (struct wrapping sodium.Bytes)
	pk := sodium.BoxPublicKey{
		Bytes: sodium.Bytes(pubRaw),
	}

	// Encrypt using sealed box
	cipher := sodium.Bytes(plaintext).SealedBox(pk)

	// Return base64 ciphertext for the API
	return base64.StdEncoding.EncodeToString(cipher), nil
}

// ---------- Main ----------

func main() {
	cfgPath := flag.String("config", "config.yaml", "Path to YAML config")
	flag.Parse()

	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		log.Fatal("GITHUB_TOKEN env var is required (PAT or fine-grained token with repo/admin privileges)")
	}

	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("parse yaml: %v", err)
	}
	if cfg.Org == "" {
		log.Fatalln("config: 'org' is required")
	}
	if len(cfg.Repos) == 0 {
		log.Fatalln("config: 'repos' is empty")
	}

	ctx := context.Background()
	gh := newGH(token)

	for _, r := range cfg.Repos {
		repoName := strings.TrimSpace(r.Name)
		if repoName == "" {
			log.Println("skip repo with empty name")
			continue
		}

		log.Printf("==> Repo: %s/%s", cfg.Org, repoName)

		// Resolve repo ID once
		repoID, err := gh.getRepoID(ctx, cfg.Org, repoName)
		if err != nil {
			log.Fatalf("get repo id %s/%s: %v", cfg.Org, repoName, err)
		}

		// Iterate environments
		for envName, secrets := range r.Environments {
			envName = strings.TrimSpace(envName)
			if envName == "" {
				log.Println("  - skip environment with empty name")
				continue
			}
			log.Printf("  -> Ensure environment: %s", envName)

			// Ensure environment exists
			if err := gh.ensureEnvironment(ctx, cfg.Org, repoName, envName); err != nil {
				log.Fatalf("ensure environment %s: %v", envName, err)
			}

			// Get environment public key
			key, err := gh.getEnvironmentPublicKey(ctx, repoID, envName)
			if err != nil {
				log.Fatalf("get env public key (%s): %v", envName, err)
			}

			// Upload each secret
			for secretName, raw := range secrets {
				secretName = strings.TrimSpace(secretName)
				if secretName == "" {
					log.Println("    - skip secret with empty name")
					continue
				}

				plaintext, err := resolveSecretValue(raw)
				if err != nil {
					log.Fatalf("resolve secret %s/%s/%s: %v", repoName, envName, secretName, err)
				}

				// Normalize line endings & trim trailing newline from files
				plaintext = strings.TrimRight(plaintext, "\r\n")

				encB64, err := encryptSecret(plaintext, key.Key)
				if err != nil {
					log.Fatalf("encrypt secret %s/%s/%s: %v", repoName, envName, secretName, err)
				}

				if err := gh.putEnvironmentSecret(ctx, repoID, envName, secretName, encB64, key.KeyID); err != nil {
					log.Fatalf("put secret %s/%s/%s: %v", repoName, envName, secretName, err)
				}
				log.Printf("    ✓ %s", secretName)
			}
		}
	}

	log.Println("All done.")
}

// ---------- Small utilities (nice errors) ----------

func fatalIfErr(where string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", where, err)
	}
}

func mustAbs(p string) string {
	if p == "" {
		return p
	}
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func check(err error) {
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Fatal(err)
		}
	}
}

