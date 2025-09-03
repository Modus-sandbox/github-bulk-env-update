package main

import (
	"context"
	"crypto/rand"
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

	"golang.org/x/crypto/nacl/box"
	"gopkg.in/yaml.v3"
)

const (
	apiBase   = "https://api.github.com"
	userAgent = "bulk-env-update/1.6"
	httpTO    = 30 * time.Second
)

/*
Example config.yaml:

org: my-org
repos:
  - name: sample-repo
    teams:
      - slug: dev-team
        permission: Write     # maps to "push"
      - slug: qa-team
        permission: Read      # maps to "pull"
    ruleset:
      name: "Master"
      enforcement: active
      target_branches: ["~DEFAULT_BRANCH"]
      require_deployments: ["prd"]
      require_pull_request: true
      block_force_pushes: true
      restrict_deletions: true
      require_status_checks: ["build", "test"]
    environments:
      dev:
        API_KEY: "@secrets/dev/api_key.txt"
        SIMPLE_SECRET: "plain-string-secret"
      prod:
        DB_PASSWORD:
          file: "secrets/prod/db_password.txt"
        API_URL:
          value: "https://api.example.com"
*/

type Config struct {
	Org   string    `yaml:"org"`
	Repos []RepoCfg `yaml:"repos"`
}

type RepoCfg struct {
	Name         string                    `yaml:"name"`
	Environments map[string]map[string]any `yaml:"environments"`
	Ruleset      *RulesetCfg               `yaml:"ruleset,omitempty"`
	Teams        []TeamPerm                `yaml:"teams,omitempty"`
}

type RulesetCfg struct {
	Name                string   `yaml:"name"`
	Enforcement         string   `yaml:"enforcement"` // active|disabled (default active)
	TargetBranches      []string `yaml:"target_branches"`
	RequireDeployments  []string `yaml:"require_deployments,omitempty"`
	RequirePullRequest  bool     `yaml:"require_pull_request,omitempty"`
	BlockForcePushes    bool     `yaml:"block_force_pushes,omitempty"`
	RestrictDeletions   bool     `yaml:"restrict_deletions,omitempty"`
	RequireStatusChecks []string `yaml:"require_status_checks,omitempty"`
}

type TeamPerm struct {
	Slug       string `yaml:"slug"`
	Permission string `yaml:"permission"`
}

// ---------- Secret helpers ----------

func resolveSecretValue(v any) (string, error) {
	switch t := v.(type) {
	case string:
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
	Key   string `json:"key"`
}

type rulesetListItem struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	SourceType string `json:"source_type"` // "Repository" or "Organization"
}

// ---------- HTTP client ----------

type ghClient struct {
	http  *http.Client
	token string
}

func newGH(token string) *ghClient {
	return &ghClient{
		http:  &http.Client{Timeout: httpTO},
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
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
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

// ---------- GitHub operations (repos/envs) ----------

func (c *ghClient) getRepoID(ctx context.Context, owner, repo string) (int64, error) {
	var out repoResp
	err := c.doJSON(ctx, "GET", fmt.Sprintf("%s/repos/%s/%s", apiBase, owner, repo), nil, &out)
	if err != nil {
		return 0, err
	}
	return out.ID, nil
}

func (c *ghClient) ensureEnvironment(ctx context.Context, owner, repo, envName string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/environments/%s", apiBase, owner, repo, envName)
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

// ---------- GitHub operations (rulesets) ----------

func (c *ghClient) listRepoRulesets(ctx context.Context, owner, repo string) ([]rulesetListItem, error) {
	var out []rulesetListItem
	// Exclude org/parent rulesets; restrict to branch target
	url := fmt.Sprintf("%s/repos/%s/%s/rulesets?includes_parents=false&targets=branch", apiBase, owner, repo)
	if err := c.doJSON(ctx, "GET", url, nil, &out); err != nil {
		return nil, err
	}
	// Extra safety: keep only repo-scoped items
	filtered := out[:0]
	for _, r := range out {
		if strings.EqualFold(r.SourceType, "Repository") {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

func (c *ghClient) createRepoRuleset(ctx context.Context, owner, repo string, payload map[string]any) (int64, error) {
	var out rulesetListItem
	url := fmt.Sprintf("%s/repos/%s/%s/rulesets", apiBase, owner, repo)
	if err := c.doJSON(ctx, "POST", url, payload, &out); err != nil {
		return 0, err
	}
	return out.ID, nil
}

func (c *ghClient) deleteRepoRuleset(ctx context.Context, owner, repo string, id int64) error {
	url := fmt.Sprintf("%s/repos/%s/%s/rulesets/%d", apiBase, owner, repo, id)
	return c.doJSON(ctx, "DELETE", url, nil, nil)
}

// ---------- GitHub operations (teams) ----------

// PUT /orgs/{org}/teams/{team_slug}/repos/{org}/{repo}
func (c *ghClient) setTeamPermission(ctx context.Context, org, repo, team, perm string) error {
	url := fmt.Sprintf("%s/orgs/%s/teams/%s/repos/%s/%s", apiBase, org, team, org, repo)
	payload := map[string]any{
		"permission": perm, // pull | triage | push | maintain | admin
	}
	return c.doJSON(ctx, "PUT", url, payload, nil)
}

// Normalize UI-style permissions to API values
func normalizePermission(p string) (string, error) {
	switch strings.ToLower(p) {
	case "read", "pull":
		return "pull", nil
	case "triage":
		return "triage", nil
	case "write", "push":
		return "push", nil
	case "maintain":
		return "maintain", nil
	case "admin":
		return "admin", nil
	default:
		return "", fmt.Errorf("invalid permission %q (valid: Read, Write, Admin, Triage, Maintain)", p)
	}
}

// ---------- Ruleset payload ----------

func rulesetPayloadFromCfg(cfg *RulesetCfg) map[string]any {
	if cfg == nil {
		return nil
	}
	enforcement := cfg.Enforcement
	if enforcement == "" {
		enforcement = "active"
	}

	var rules []map[string]any

	// UI: Restrict deletions
	if cfg.RestrictDeletions {
		rules = append(rules, map[string]any{"type": "deletion"})
	}
	// UI: Block force pushes
	if cfg.BlockForcePushes {
		rules = append(rules, map[string]any{"type": "non_fast_forward"})
	}
	// UI: Require a pull request before merging
	if cfg.RequirePullRequest {
		rules = append(rules, map[string]any{"type": "pull_request"})
	}
	// UI: Require deployments to succeed
	if len(cfg.RequireDeployments) > 0 {
		rules = append(rules, map[string]any{
			"type": "required_deployments",
			"parameters": map[string]any{
				"required_deployment_environments": cfg.RequireDeployments,
			},
		})
	}
	// UI: Require status checks (simple translation from list of contexts)
	if len(cfg.RequireStatusChecks) > 0 {
		rules = append(rules, map[string]any{
			"type": "required_status_checks",
			"parameters": map[string]any{
				"required_checks":                     mapStatusChecks(cfg.RequireStatusChecks),
				"strict_required_status_checks_policy": false,
				"do_not_enforce_on_create":             false,
			},
		})
	}

	cond := map[string]any{}
	if len(cfg.TargetBranches) > 0 {
		cond["ref_name"] = map[string]any{
			"include": cfg.TargetBranches,
			"exclude": []string{},
		}
	}

	return map[string]any{
		"name":          cfg.Name,
		"target":        "branch",
		"enforcement":   enforcement,
		"conditions":    cond,
		"rules":         rules,
		"bypass_actors": []any{}, // add if you want bypasses
	}
}

func mapStatusChecks(ctxs []string) []map[string]any {
	out := make([]map[string]any, 0, len(ctxs))
	for _, c := range ctxs {
		out = append(out, map[string]any{
			"context":        c,
			"integration_id": nil, // set if tied to a GitHub App
		})
	}
	return out
}

// Upsert via delete+create (PATCH not supported for repo rulesets)
func (c *ghClient) upsertRepoRuleset(ctx context.Context, owner, repo string, cfg *RulesetCfg) error {
	if cfg == nil || strings.TrimSpace(cfg.Name) == "" {
		return nil
	}
	payload := rulesetPayloadFromCfg(cfg)

	existing, err := c.listRepoRulesets(ctx, owner, repo)
	if err != nil {
		return fmt.Errorf("list rulesets: %w", err)
	}

	var matchID int64
	for _, r := range existing {
		if strings.EqualFold(r.Name, cfg.Name) {
			matchID = r.ID
			break
		}
	}

	if matchID != 0 {
		if err := c.deleteRepoRuleset(ctx, owner, repo, matchID); err != nil {
			return fmt.Errorf("delete ruleset %q: %w", cfg.Name, err)
		}
		log.Printf("  -> Deleted old ruleset %q (id=%d)", cfg.Name, matchID)
	}

	if _, err := c.createRepoRuleset(ctx, owner, repo, payload); err != nil {
		return fmt.Errorf("create ruleset %q: %w", cfg.Name, err)
	}
	log.Printf("  -> Created ruleset %q", cfg.Name)
	return nil
}

// ---------- Encryption ----------

func encryptSecret(plaintext string, githubB64PublicKey string) (string, error) {
	pkRaw, err := base64.StdEncoding.DecodeString(githubB64PublicKey)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	if len(pkRaw) != 32 {
		return "", fmt.Errorf("unexpected public key length: %d (want 32)")
	}
	var pk [32]byte
	copy(pk[:], pkRaw)
	sealed, err := box.SealAnonymous(nil, []byte(plaintext), &pk, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("seal anonymous: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// ---------- Main ----------

func main() {
	cfgPath := flag.String("config", "config.yaml", "Path to YAML config")
	flag.Parse()

	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		log.Fatal("GITHUB_TOKEN env var is required")
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

		repoID, err := gh.getRepoID(ctx, cfg.Org, repoName)
		if err != nil {
			log.Fatalf("get repo id %s/%s: %v", cfg.Org, repoName, err)
		}

		// Step 1: environments + secrets
		createdEnvs := map[string]bool{}
		for envName, secrets := range r.Environments {
			envName = strings.TrimSpace(envName)
			if envName == "" {
				log.Println("  - skip environment with empty name")
				continue
			}
			log.Printf("  -> Ensure environment: %s", envName)
			if err := gh.ensureEnvironment(ctx, cfg.Org, repoName, envName); err != nil {
				log.Fatalf("ensure environment %s: %v", envName, err)
			}
			createdEnvs[envName] = true

			key, err := gh.getEnvironmentPublicKey(ctx, repoID, envName)
			if err != nil {
				log.Fatalf("get env public key (%s): %v", envName, err)
			}

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

		// Step 2: ruleset (after envs exist)
		if r.Ruleset != nil {
			if len(r.Ruleset.TargetBranches) == 0 {
				r.Ruleset.TargetBranches = []string{"~DEFAULT_BRANCH"}
			}
			// sanity-check required deployments
			missing := []string{}
			for _, e := range r.Ruleset.RequireDeployments {
				if !createdEnvs[e] {
					missing = append(missing, e)
				}
			}
			if len(missing) > 0 {
				log.Fatalf("ruleset requires env(s) %v not created. Add under 'environments' for %s/%s", missing, cfg.Org, repoName)
			}
			if err := gh.upsertRepoRuleset(ctx, cfg.Org, repoName, r.Ruleset); err != nil {
				log.Fatalf("ruleset upsert for %s: %v", repoName, err)
			}
		}

		// Step 3: team permissions
		for _, tp := range r.Teams {
			slug := strings.TrimSpace(tp.Slug)
			rawPerm := strings.TrimSpace(tp.Permission)
			if slug == "" || rawPerm == "" {
				log.Printf("  - skip team with empty slug/permission")
				continue
			}
			perm, err := normalizePermission(rawPerm)
			if err != nil {
				log.Fatalf("invalid team permission for team %q: %v", slug, err)
			}
			log.Printf("  -> Set team %q permission=%q", slug, perm)
			if err := gh.setTeamPermission(ctx, cfg.Org, repoName, slug, perm); err != nil {
				log.Fatalf("set team %s/%s perm %s: %v", cfg.Org, slug, perm, err)
			}
		}
	}

	log.Println("All done.")
}

// ---------- misc ----------

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
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

