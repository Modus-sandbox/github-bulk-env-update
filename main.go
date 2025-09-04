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
	userAgent = "bulk-env-update/2.0.3"
	httpTO    = 30 * time.Second
)

/*
Example config.yaml:

org: my-org
repos:
  - name: sample-repo
    teams:
      - slug: dev-team
        permission: Write
      - slug: qa-team
        permission: Read
    ruleset:
      name: "Master"
      enforcement: active
      target_branches: ["~DEFAULT_BRANCH"]
      require_deployments: ["prod"]
      require_pull_request: true
      pull_request_options:
        required_approving_review_count: 1
        dismiss_stale_reviews: true
        require_code_owner_review: true
        require_last_push_approval: true
        require_conversation_resolution: true
        #allowed_merge_methods: ["merge","squash","rebase"]
      block_force_pushes: true
      restrict_deletions: true
      # require_status_checks: ["build","test"]
    environments:
      dev:
        API_KEY: "@secrets/dev/api_key.txt"
        SIMPLE_SECRET: "plain-string-secret"
      prod:
        protection:
          reviewers:
            teams: ["ops-team"]
            users: ["alice"]
          prevent_self_review: true
          wait_timer: 0
          allow_admins_bypass: true
          # Allow all branches:
          # deployment_branch_policy: null
          # Or enable "Selected branches and tags":
          deployment_branch_policy:
            protected_branches: false
            custom_branch_policies: true
            branches: ["main", "release-*"]
            tags: ["v*"]
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
	Enforcement         string   `yaml:"enforcement"`
	TargetBranches      []string `yaml:"target_branches"`
	RequireDeployments  []string `yaml:"require_deployments,omitempty"`
	RequirePullRequest  bool     `yaml:"require_pull_request,omitempty"`
	BlockForcePushes    bool     `yaml:"block_force_pushes,omitempty"`
	RestrictDeletions   bool     `yaml:"restrict_deletions,omitempty"`
	RequireStatusChecks []string `yaml:"require_status_checks,omitempty"`

	// NEW: optional parameters for the "pull_request" rule
	PullRequestOptions *PullRequestOptions `yaml:"pull_request_options,omitempty"`
}

// NEW: shape for pull_request_options
type PullRequestOptions struct {
	RequiredApprovingReviewCount  int      `yaml:"required_approving_review_count,omitempty"`
	DismissStaleReviews           bool     `yaml:"dismiss_stale_reviews,omitempty"`
	RequireCodeOwnerReview        bool     `yaml:"require_code_owner_review,omitempty"`
	RequireLastPushApproval       bool     `yaml:"require_last_push_approval,omitempty"`
	RequireConversationResolution bool     `yaml:"require_conversation_resolution,omitempty"`
	AllowedMergeMethods           []string `yaml:"allowed_merge_methods,omitempty"` // ["merge","squash","rebase"]
}

type TeamPerm struct {
	Slug       string `yaml:"slug"`
	Permission string `yaml:"permission"`
}

// ---- Optional environment protection (parsed from env map under key "protection")

type EnvProtection struct {
	Reviewers struct {
		Teams []string `yaml:"teams"` // team slugs
		Users []string `yaml:"users"` // usernames
	} `yaml:"reviewers"`
	PreventSelfReview *bool `yaml:"prevent_self_review,omitempty"`
	WaitTimer         *int  `yaml:"wait_timer,omitempty"`          // seconds
	AllowAdminsBypass *bool `yaml:"allow_admins_bypass,omitempty"` // maps to can_admins_bypass

	DeploymentBranchPolicy *struct {
		ProtectedBranches    *bool    `yaml:"protected_branches,omitempty"`
		CustomBranchPolicies *bool    `yaml:"custom_branch_policies,omitempty"`
		Branches             []string `yaml:"branches,omitempty"` // desired branch patterns
		Tags                 []string `yaml:"tags,omitempty"`     // desired tag patterns
	} `yaml:"deployment_branch_policy,omitempty"`
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
	SourceType string `json:"source_type"`
}

type teamResp struct {
	ID int64 `json:"id"`
}
type userResp struct {
	ID int64 `json:"id"`
}

// For env branch/tag policies
type envPolicy struct {
	ID      int64  `json:"id"`
	Type    string `json:"type"`    // "branch" or "tag"
	Pattern string `json:"pattern"` // some responses use "name" instead
	Name    string `json:"name"`
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

// --- Environment protection (reviewers, wait timer, prevent self-review, admins bypass, deployment_branch_policy)

func (c *ghClient) getTeamID(ctx context.Context, org, slug string) (int64, error) {
	var out teamResp
	url := fmt.Sprintf("%s/orgs/%s/teams/%s", apiBase, org, slug)
	if err := c.doJSON(ctx, "GET", url, nil, &out); err != nil {
		return 0, err
	}
	return out.ID, nil
}

func (c *ghClient) getUserID(ctx context.Context, username string) (int64, error) {
	var out userResp
	url := fmt.Sprintf("%s/users/%s", apiBase, username)
	if err := c.doJSON(ctx, "GET", url, nil, &out); err != nil {
		return 0, err
	}
	return out.ID, nil
}

// Robust list: accept either a bare array OR a wrapper object {branch_policies:[...]} (optionally {policies:[...]})
func (c *ghClient) listEnvPolicies(ctx context.Context, owner, repo, env string) ([]envPolicy, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/environments/%s/deployment-branch-policies", apiBase, owner, repo, env)

	// Try array first
	var arr []envPolicy
	if err := c.doJSON(ctx, "GET", url, nil, &arr); err == nil {
		// normalize Pattern if missing
		for i := range arr {
			if arr[i].Pattern == "" {
				arr[i].Pattern = arr[i].Name
			}
		}
		return arr, nil
	}

	// Fallback: wrapper object
	var obj struct {
		TotalCount     int         `json:"total_count"`
		BranchPolicies []envPolicy `json:"branch_policies"`
		Policies       []envPolicy `json:"policies"`
	}
	if err := c.doJSON(ctx, "GET", url, nil, &obj); err != nil {
		return nil, err
	}
	var list []envPolicy
	if len(obj.BranchPolicies) > 0 {
		list = obj.BranchPolicies
	} else {
		list = obj.Policies
	}
	for i := range list {
		if list[i].Pattern == "" {
			list[i].Pattern = list[i].Name
		}
	}
	return list, nil
}

func (c *ghClient) createEnvPolicy(ctx context.Context, owner, repo, env, ptype, name string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/environments/%s/deployment-branch-policies", apiBase, owner, repo, env)
	// per API: only "type" and "name" are accepted
	payload := map[string]any{"type": ptype, "name": name}
	return c.doJSON(ctx, "POST", url, payload, nil)
}

func (c *ghClient) deleteEnvPolicy(ctx context.Context, owner, repo, env string, id int64) error {
	url := fmt.Sprintf("%s/repos/%s/%s/environments/%s/deployment-branch-policies/%d", apiBase, owner, repo, env, id)
	return c.doJSON(ctx, "DELETE", url, nil, nil)
}

// The main updater: PUT base protection, then reconcile custom branch/tag lists
func (c *ghClient) updateEnvironmentProtection(ctx context.Context, owner, repo, env string, prot EnvProtection, dbpExplicitNull bool) error {
	// reviewers -> [{type:"Team"|"User", id:int}]
	var reviewers []map[string]any
	for _, tslug := range prot.Reviewers.Teams {
		id, err := c.getTeamID(ctx, owner, tslug)
		if err != nil {
			return fmt.Errorf("resolve team %q: %w", tslug, err)
		}
		reviewers = append(reviewers, map[string]any{"type": "Team", "id": id})
	}
	for _, uname := range prot.Reviewers.Users {
		id, err := c.getUserID(ctx, uname)
		if err != nil {
			return fmt.Errorf("resolve user %q: %w", uname, err)
		}
		reviewers = append(reviewers, map[string]any{"type": "User", "id": id})
	}

	payload := map[string]any{"reviewers": reviewers}

	if prot.PreventSelfReview != nil {
		payload["prevent_self_review"] = *prot.PreventSelfReview
	}
	if prot.WaitTimer != nil {
		payload["wait_timer"] = *prot.WaitTimer
	}
	if prot.AllowAdminsBypass != nil {
		payload["can_admins_bypass"] = *prot.AllowAdminsBypass
	}

	if dbpExplicitNull {
		payload["deployment_branch_policy"] = nil
	} else if prot.DeploymentBranchPolicy != nil {
		dbp := map[string]any{}
		if prot.DeploymentBranchPolicy.ProtectedBranches != nil {
			dbp["protected_branches"] = *prot.DeploymentBranchPolicy.ProtectedBranches
		}
		if prot.DeploymentBranchPolicy.CustomBranchPolicies != nil {
			dbp["custom_branch_policies"] = *prot.DeploymentBranchPolicy.CustomBranchPolicies
		}
		if len(dbp) > 0 {
			payload["deployment_branch_policy"] = dbp
		}
	}

	// Show exactly what we send (useful and tidy)
	if jb, err := json.Marshal(payload); err == nil {
		log.Printf("    • PUT env payload: %s", string(jb))
	}

	url := fmt.Sprintf("%s/repos/%s/%s/environments/%s", apiBase, owner, repo, env)
	if err := c.doJSON(ctx, "PUT", url, payload, nil); err != nil {
		return err
	}

	// If custom_branch_policies is enabled, reconcile the explicit lists
	if prot.DeploymentBranchPolicy != nil &&
		prot.DeploymentBranchPolicy.CustomBranchPolicies != nil &&
		*prot.DeploymentBranchPolicy.CustomBranchPolicies {

		wantBranches := map[string]struct{}{}
		for _, b := range prot.DeploymentBranchPolicy.Branches {
			b = strings.TrimSpace(b)
			if b != "" {
				wantBranches[b] = struct{}{}
			}
		}
		wantTags := map[string]struct{}{}
		for _, t := range prot.DeploymentBranchPolicy.Tags {
			t = strings.TrimSpace(t)
			if t != "" {
				wantTags[t] = struct{}{}
			}
		}

		if len(wantBranches) > 0 || len(wantTags) > 0 {
			existing, err := c.listEnvPolicies(ctx, owner, repo, env)
			if err != nil {
				return fmt.Errorf("list env policies: %w", err)
			}
			type key struct{ T, P string }
			have := map[key]int64{}
			for _, p := range existing {
				pat := p.Pattern
				if pat == "" && p.Name != "" {
					pat = p.Name
				}
				have[key{strings.ToLower(p.Type), pat}] = p.ID
			}

			// Create missing branches
			for b := range wantBranches {
				k := key{"branch", b}
				if _, ok := have[k]; !ok {
					if err := c.createEnvPolicy(ctx, owner, repo, env, "branch", b); err != nil {
						return fmt.Errorf("create env branch policy %q: %w", b, err)
					}
					log.Printf("    • added branch policy: %s", b)
				}
			}
			// Create missing tags
			for t := range wantTags {
				k := key{"tag", t}
				if _, ok := have[k]; !ok {
					if err := c.createEnvPolicy(ctx, owner, repo, env, "tag", t); err != nil {
						return fmt.Errorf("create env tag policy %q: %w", t, err)
					}
					log.Printf("    • added tag policy: %s", t)
				}
			}

			// Delete extraneous policies (only if a list was supplied for that type)
			for k, id := range have {
				if k.T == "branch" && len(wantBranches) > 0 {
					if _, keep := wantBranches[k.P]; !keep {
						if err := c.deleteEnvPolicy(ctx, owner, repo, env, id); err != nil {
							return fmt.Errorf("delete env branch policy %q: %w", k.P, err)
						}
						log.Printf("    • removed branch policy: %s", k.P)
					}
				}
				if k.T == "tag" && len(wantTags) > 0 {
					if _, keep := wantTags[k.P]; !keep {
						if err := c.deleteEnvPolicy(ctx, owner, repo, env, id); err != nil {
							return fmt.Errorf("delete env tag policy %q: %w", k.P, err)
						}
						log.Printf("    • removed tag policy: %s", k.P)
					}
				}
			}
		}
	}

	// Clean output: no post-GET debug spam
	return nil
}

// ---------- GitHub operations (rulesets) ----------

func (c *ghClient) listRepoRulesets(ctx context.Context, owner, repo string) ([]rulesetListItem, error) {
	var out []rulesetListItem
	url := fmt.Sprintf("%s/repos/%s/%s/rulesets?includes_parents=false&targets=branch", apiBase, owner, repo)
	if err := c.doJSON(ctx, "GET", url, nil, &out); err != nil {
		return nil, err
	}
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

func (c *ghClient) setTeamPermission(ctx context.Context, org, repo, team, perm string) error {
	url := fmt.Sprintf("%s/orgs/%s/teams/%s/repos/%s/%s", apiBase, org, team, org, repo)
	payload := map[string]any{"permission": perm} // pull | triage | push | maintain | admin
	return c.doJSON(ctx, "PUT", url, payload, nil)
}

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
	if cfg.RestrictDeletions {
		rules = append(rules, map[string]any{"type": "deletion"})
	}
	if cfg.BlockForcePushes {
		rules = append(rules, map[string]any{"type": "non_fast_forward"})
	}
	if cfg.RequirePullRequest {
		// include parameters from pull_request_options when provided
		pr := map[string]any{"type": "pull_request"}
		if cfg.PullRequestOptions != nil {
			params := map[string]any{}
			o := cfg.PullRequestOptions
			if o.RequiredApprovingReviewCount > 0 {
				params["required_approving_review_count"] = o.RequiredApprovingReviewCount
			}
			// API expects dismiss_stale_reviews_on_push
			if o.DismissStaleReviews {
				params["dismiss_stale_reviews_on_push"] = true
			}
			if o.RequireCodeOwnerReview {
				params["require_code_owner_review"] = true
			}
			if o.RequireLastPushApproval {
				params["require_last_push_approval"] = true
			}
			// API expects required_review_thread_resolution
			if o.RequireConversationResolution {
				params["required_review_thread_resolution"] = true
			}

			// DO NOT send allowed_merge_methods here: not a ruleset parameter
			if len(params) > 0 {
				pr["parameters"] = params
			}
		}
		rules = append(rules, pr)
	}
	if len(cfg.RequireDeployments) > 0 {
		rules = append(rules, map[string]any{
			"type": "required_deployments",
			"parameters": map[string]any{
				"required_deployment_environments": cfg.RequireDeployments,
			},
		})
	}
	if len(cfg.RequireStatusChecks) > 0 {
		rules = append(rules, map[string]any{
			"type": "required_status_checks",
			"parameters": map[string]any{
				"required_checks":                      mapStatusChecks(cfg.RequireStatusChecks),
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
		"bypass_actors": []any{},
	}
}

func mapStatusChecks(ctxs []string) []map[string]any {
	out := make([]map[string]any, 0, len(ctxs))
	for _, c := range ctxs {
		out = append(out, map[string]any{"context": c, "integration_id": nil})
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

		// Step 1: environments + protection + secrets
		createdEnvs := map[string]bool{}
		for envName, entries := range r.Environments {
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

			// Detect explicit null for deployment_branch_policy
			dbpExplicitNull := false
			if protRaw, ok := entries["protection"]; ok {
				if mp, ok2 := protRaw.(map[string]any); ok2 {
					if _, exists := mp["deployment_branch_policy"]; exists && mp["deployment_branch_policy"] == nil {
						dbpExplicitNull = true
					}
				}

				// Convert map[any]any -> EnvProtection via YAML round-trip (keeps bools)
				var prot EnvProtection
				yb, err := yaml.Marshal(protRaw)
				if err != nil {
					log.Fatalf("marshal env protection yaml for %s/%s: %v", repoName, envName, err)
				}
				if err := yaml.Unmarshal(yb, &prot); err != nil {
					log.Fatalf("parse environment protection for %s/%s: %v", repoName, envName, err)
				}

				if err := gh.updateEnvironmentProtection(ctx, cfg.Org, repoName, envName, prot, dbpExplicitNull); err != nil {
					log.Fatalf("update env protection for %s/%s: %v", repoName, envName, err)
				}
				log.Printf("    ✓ protection updated")
			}

			// Secrets (all non-protection keys)
			key, err := gh.getEnvironmentPublicKey(ctx, repoID, envName)
			if err != nil {
				log.Fatalf("get env public key (%s): %v", envName, err)
			}
			for k, raw := range entries {
				if k == "protection" {
					continue
				}
				secretName := strings.TrimSpace(k)
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
