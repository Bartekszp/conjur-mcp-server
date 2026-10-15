package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"gopkg.in/yaml.v3"

	"conjur-mcp-server/internal/conjur"
)

// --- Input Validation & Redaction (Security Guardrails) ---

var (
	validIdentifierRegex  = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/]+$`)
	validQualifiedIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/:]+$`)
	apiKeyRedactionRegex  = regexp.MustCompile(`(?i)"api_key"\s*:\s*"[^"]+"`)
	yamlAnchorAliasRegex  = regexp.MustCompile(`(^|[\s,\[\{])([&*][a-zA-Z0-9_\-]+)`)
	adminAbuseRegex       = regexp.MustCompile(`(?i)(!user\s+["']?admin["']?|id\s*:\s*["']?admin["']?|role\s*:\s*(!user\s+)?["']?admin["']?)`)
	destructiveRegex      = regexp.MustCompile(`(?i)(update|replace|delete)`)
)

func validateIdentifier(val, fieldName string) error {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return fmt.Errorf("field '%s' cannot be empty", fieldName)
	}
	if len(trimmed) > 256 {
		return fmt.Errorf("field '%s' exceeds maximum length of 256 characters", fieldName)
	}
	if strings.Contains(trimmed, "..") {
		return fmt.Errorf("field '%s' cannot contain path traversal sequences ('..')", fieldName)
	}
	if !validIdentifierRegex.MatchString(trimmed) {
		return fmt.Errorf("field '%s' contains invalid characters: only alphanumeric characters and _, -, ., / are allowed", fieldName)
	}
	return nil
}

func validateQualifiedIdentifier(val, fieldName string) error {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return fmt.Errorf("field '%s' cannot be empty", fieldName)
	}
	if len(trimmed) > 256 {
		return fmt.Errorf("field '%s' exceeds maximum length of 256 characters", fieldName)
	}
	if strings.Contains(trimmed, "..") {
		return fmt.Errorf("field '%s' cannot contain path traversal sequences ('..')", fieldName)
	}
	if !validQualifiedIDRegex.MatchString(trimmed) {
		return fmt.Errorf("field '%s' contains invalid characters: only alphanumeric characters and _, -, ., /, : are allowed", fieldName)
	}
	return nil
}

func marshalAndRedactPolicyResp(resp any) string {
	respJSON, _ := json.MarshalIndent(resp, "", "  ")
	return apiKeyRedactionRegex.ReplaceAllString(string(respJSON), `"api_key": "[REDACTED_NOT_EXPOSED_IN_CHAT]"`)
}

func generateSecurePassword(length int) (string, error) {
	if length < 16 {
		length = 32
	} else if length > 256 {
		length = 256
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- Request DTOs ---

// DevEx DTOs
type RunTestArgs struct {
	VariableID string `json:"variable_id"`
	Command    string `json:"command"`
}

type ListVariablesArgs struct {
	Search string `json:"search,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type CreateVariableArgs struct {
	Branch      string `json:"branch"`
	VariableID  string `json:"variable_id"`
	Description string `json:"description,omitempty"`
}

type CreateAndSetSecretArgs struct {
	VariableID  string `json:"variable_id"`
	Branch      string `json:"branch,omitempty"`
	Description string `json:"description,omitempty"`
	Length      int    `json:"length,omitempty"`
	Overwrite   bool   `json:"overwrite"`
}

// Policy DTOs
type ValidatePolicyArgs struct {
	YAMLContent string `json:"yaml_content"`
}

type LoadPolicyArgs struct {
	Branch      string `json:"branch"`
	Mode        string `json:"mode"`
	YAMLContent string `json:"yaml_content"`
}

type CheckPermissionArgs struct {
	Role      string `json:"role"`
	Privilege string `json:"privilege"`
	Resource  string `json:"resource"`
}

type GetResourceTreeArgs struct {
	Branch string `json:"branch,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// SecOps DTOs
type VariableOnlyArgs struct {
	VariableID string `json:"variable_id"`
}

type ListRotationArgs struct {
	MaxAgeDays int    `json:"max_age_days,omitempty"`
	Search     string `json:"search,omitempty"`
}

type RotateSecretArgs struct {
	VariableID string `json:"variable_id"`
	Length     int    `json:"length,omitempty"`
	Confirm    bool   `json:"confirm"`
}

type HostOnlyArgs struct {
	HostID string `json:"host_id"`
}

type RoleMembershipsArgs struct {
	RoleID string `json:"role_id"`
}

// Onboarding DTOs
type CreateHostArgs struct {
	HostID string `json:"host_id"`
	Branch string `json:"branch"`
}

type RotateHostAPIKeyArgs struct {
	HostID  string `json:"host_id"`
	Confirm bool   `json:"confirm"`
}

type PrepareWorkloadPolicyArgs struct {
	WorkloadID          string   `json:"workload_id"`
	Branch              string   `json:"branch"`
	AccessibleVariables []string `json:"accessible_variables"`
}

// conjurClient wraps the official *conjurapi.Client and maintains configuration
// needed to construct fully qualified resource IDs and annotations.
type conjurClient struct {
	api     *conjurapi.Client
	account string
	login   string
	native  *conjur.Client
}

// fullID constructs a qualified resource identifier in account:kind:id format.
func (c *conjurClient) fullID(kind, id string) string {
	return fmt.Sprintf("%s:%s:%s", c.account, kind, id)
}

// policyMode converts mode strings to conjurapi policy mode constants.
func policyMode(mode string) conjurapi.PolicyMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "put", "replace":
		return conjurapi.PolicyModePut
	case "patch":
		return conjurapi.PolicyModePatch
	default: // "post", "append"
		return conjurapi.PolicyModePost
	}
}

// GetAPIKeyLastRotated calls the native Conjur endpoint defined in config/routes.rb:
// GET /:authenticator/:account/api_key?role=:role (credentials#api_key_last_rotated)
// Returns the timestamp of the last API key rotation for the specified role.
func (c *conjurClient) GetAPIKeyLastRotated(role string) (string, error) {
	fullRole := role
	if !strings.Contains(fullRole, ":") {
		fullRole = c.fullID("host", fullRole)
	} else if strings.Count(fullRole, ":") == 1 {
		fullRole = fmt.Sprintf("%s:%s", c.account, fullRole)
	}

	applianceURL := strings.TrimRight(c.api.GetConfig().ApplianceURL, "/")
	reqURL := fmt.Sprintf("%s/authn/%s/api_key?role=%s",
		applianceURL,
		c.account,
		url.QueryEscape(fullRole),
	)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", err
	}

	// Use SDK client and session authorization token
	resp, err := c.api.SubmitRequest(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Conjur error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return strings.TrimSpace(string(bodyBytes)), nil
}

// parseArgs unmarshals MCP call arguments into a target typed struct.
func parseArgs[T any](req mcp.CallToolRequest) (T, error) {
	var target T
	rawBytes, err := json.Marshal(req.Params.Arguments)
	if err != nil {
		return target, err
	}
	if err := json.Unmarshal(rawBytes, &target); err != nil {
		return target, err
	}
	return target, nil
}

// --- Main Server Function ---

func main() {
	modeFlag := flag.String("mode", "all", "MCP server mode: devex, policy, secops, onboarding, all")
	flag.Parse()

	// Initialize official CyberArk Conjur SDK client
	cfg, err := conjurapi.LoadConfig()
	if err != nil {
		// Fallback: manual configuration from environment variables
		cfg = conjurapi.Config{
			Account:      os.Getenv("CONJUR_ACCOUNT"),
			ApplianceURL: os.Getenv("CONJUR_APPLIANCE_URL"),
		}
	}

	apiClient, err := conjurapi.NewClientFromKey(cfg, authn.LoginPair{
		Login:  os.Getenv("CONJUR_AUTHN_LOGIN"),
		APIKey: os.Getenv("CONJUR_AUTHN_API_KEY"),
	})
	if err != nil {
		log.Fatalf("Conjur client initialization error: %v", err)
	}

	nativeClient := conjur.NewClient(conjur.Config{
		ApplianceURL: cfg.ApplianceURL,
		Account:      cfg.Account,
		Login:        os.Getenv("CONJUR_AUTHN_LOGIN"),
		APIKey:       os.Getenv("CONJUR_AUTHN_API_KEY"),
	})

	client := &conjurClient{
		api:     apiClient,
		account: cfg.Account,
		login:   os.Getenv("CONJUR_AUTHN_LOGIN"),
		native:  nativeClient,
	}

	s := server.NewMCPServer("conjur-mcp-bridge", "1.2.0", server.WithToolCapabilities(true))

	modes := strings.Split(strings.ToLower(*modeFlag), ",")
	isModeActive := func(name string) bool {
		for _, m := range modes {
			trimmed := strings.TrimSpace(m)
			if trimmed == "all" || trimmed == name {
				return true
			}
		}
		return false
	}

	if isModeActive("devex") {
		registerDevExTools(s, client)
	}
	if isModeActive("policy") {
		registerPolicyTools(s, client)
	}
	if isModeActive("secops") {
		registerSecOpsTools(s, client)
	}
	if isModeActive("onboarding") {
		registerOnboardingTools(s, client)
	}

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

// ============================================================================
// Unified Timestamps & Secret Lifecycle Management
// ============================================================================

type SecretTimestamps struct {
	ID              string `json:"id"`
	CreatedAt       string `json:"created_at"`
	LastRotatedAt   string `json:"last_rotated_at,omitempty"`
	EffectiveTime   string `json:"effective_time"`
	AgeDays         int    `json:"age_days"`
	CurrentVersion  int    `json:"current_version"`
	TotalVersions   int    `json:"total_versions"`
	TimestampSource string `json:"timestamp_source"`
	NeedsRotation   bool   `json:"needs_rotation"`
}

func extractSecretTimestamps(meta map[string]any, maxAgeDays int) SecretTimestamps {
	now := time.Now()
	id, _ := meta["id"].(string)
	res := SecretTimestamps{
		ID:            id,
		NeedsRotation: false,
	}

	createdStr, _ := meta["created_at"].(string)
	res.CreatedAt = createdStr

	var createdTime time.Time
	if createdStr != "" {
		if t, err := time.Parse(time.RFC3339Nano, createdStr); err == nil {
			createdTime = t
		} else if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			createdTime = t
		}
	}

	// Read versions from "secrets" array
	if secretsList, ok := meta["secrets"].([]any); ok {
		res.TotalVersions = len(secretsList)
		maxVer := 0
		for _, s := range secretsList {
			if sMap, ok := s.(map[string]any); ok {
				if v, ok := sMap["version"].(float64); ok && int(v) > maxVer {
					maxVer = int(v)
				}
			}
		}
		res.CurrentVersion = maxVer
	}

	// Read annotations (both as array [{"name":..,"value":..}] and map)
	getAnn := func(keys ...string) string {
		annVal, ok := meta["annotations"]
		if !ok || annVal == nil {
			return ""
		}
		if slice, ok := annVal.([]any); ok {
			for _, item := range slice {
				if itemMap, ok := item.(map[string]any); ok {
					if name, ok := itemMap["name"].(string); ok {
						for _, k := range keys {
							if strings.EqualFold(name, k) {
								if val, ok := itemMap["value"].(string); ok {
									return val
								}
							}
						}
					}
				}
			}
		}
		if m, ok := annVal.(map[string]any); ok {
			for _, k := range keys {
				if val, ok := m[k].(string); ok {
					return val
				}
			}
		}
		return ""
	}

	rotatedStr := getAnn("last_rotated_at", "updated_at", "last_rotated", "rotated_at")

	var effectiveTime time.Time
	if rotatedStr != "" {
		res.LastRotatedAt = rotatedStr
		if t, err := time.Parse(time.RFC3339Nano, rotatedStr); err == nil {
			effectiveTime = t
			res.TimestampSource = "annotation"
		} else if t, err := time.Parse(time.RFC3339, rotatedStr); err == nil {
			effectiveTime = t
			res.TimestampSource = "annotation"
		}
	}

	if effectiveTime.IsZero() {
		if !createdTime.IsZero() {
			effectiveTime = createdTime
			if res.TotalVersions <= 1 {
				res.LastRotatedAt = createdStr
				res.TimestampSource = "created_at (initial version)"
			} else {
				res.LastRotatedAt = ""
				res.TimestampSource = "created_at (rotated version, missing annotation)"
			}
		} else {
			effectiveTime = now
			res.TimestampSource = "no data"
		}
	}

	res.EffectiveTime = effectiveTime.Format(time.RFC3339)
	res.AgeDays = int(now.Sub(effectiveTime).Hours() / 24)
	if maxAgeDays > 0 && res.AgeDays >= maxAgeDays {
		res.NeedsRotation = true
	}

	return res
}

// ============================================================================
// Module A: Developer Experience (DevEx)
// ============================================================================
func registerDevExTools(s *server.MCPServer, client *conjurClient) {
	// A1. Run test with injected secret
	runTestTool := mcp.NewTool("run_test_with_secret",
		mcp.WithDescription("Securely fetches a secret from Conjur and executes a test command with the secret injected as the APP_SECRET environment variable. Automatically redacts the secret from process output. Direct exfiltration commands (echo %APP_SECRET%, set, env, printenv) are strictly blocked by guardrails."),
		mcp.WithString("variable_id", mcp.Required(), mcp.Description("Conjur variable ID (e.g., dev/billing/stripe-key)")),
		mcp.WithString("command", mcp.Required(), mcp.Description("Test command or script to execute (e.g., 'python run_tests.py'). Constraints: shell operators and commands attempting direct secret printing are rejected.")),
	)
	s.AddTool(runTestTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[RunTestArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.VariableID, "variable_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		trimmedCmd := strings.TrimSpace(args.Command)
		if trimmedCmd == "" || len(trimmedCmd) > 512 {
			return mcp.NewToolResultError("Validation error: 'command' must be between 1 and 512 characters."), nil
		}

		// Block shell metacharacters and command chaining
		if strings.ContainsAny(trimmedCmd, ";|&><`\r\n$") {
			return mcp.NewToolResultError("Execution rejected: Shell metacharacters and command chaining operators are strictly prohibited."), nil
		}

		// Security Guardrail: block direct environment dumping, inline code execution, or encoding/network exfiltration
		lowerCmd := strings.ToLower(trimmedCmd)
		blockedPatterns := []string{
			"app_secret", "printenv", "base64", "certutil", "curl", "wget",
			"invoke-webrequest", "invoke-restmethod", " -c ", " -e ", " /c ",
		}
		for _, pattern := range blockedPatterns {
			if strings.Contains(lowerCmd, pattern) {
				return mcp.NewToolResultError("Execution rejected: Direct secret exfiltration, inline script evaluation, or environment dumping attempt detected."), nil
			}
		}

		cmdParts := strings.Fields(trimmedCmd)
		if len(cmdParts) == 0 {
			return mcp.NewToolResultError("Validation error: 'command' cannot be empty."), nil
		}
		baseBin := strings.ToLower(cmdParts[0])
		if baseBin == "set" || baseBin == "env" || baseBin == "echo" || baseBin == "printf" || baseBin == "cat" || baseBin == "type" {
			return mcp.NewToolResultError("Execution rejected: Direct environment or file dumping commands are not allowed."), nil
		}

		secretBytes, err := client.api.RetrieveSecret(args.VariableID)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Conjur error: %v", err)), nil
		}
		secretVal := string(secretBytes)

		execCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		cmd := exec.CommandContext(execCtx, cmdParts[0], cmdParts[1:]...)
		cmd.Env = []string{fmt.Sprintf("APP_SECRET=%s", secretVal)}
		output, err := cmd.CombinedOutput()

		redact := func(s string) string {
			if secretVal != "" {
				return strings.ReplaceAll(s, secretVal, "***REDACTED***")
			}
			return s
		}

		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Test execution failed: %s\nOutput: %s", redact(err.Error()), redact(string(output)))), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Success:\n%s", redact(string(output)))), nil
	})

	// A2. List available variables (without values)
	listVarsTool := mcp.NewTool("list_variables",
		mcp.WithDescription("Lists variable resource IDs and non-sensitive lifecycle metadata (creation date, age, policy owner, version) in Conjur without exposing confidential values."),
		mcp.WithString("search", mcp.Description("Optional substring filter for variable names (e.g., billing or db)")),
		mcp.WithInteger("limit", mcp.Description("Maximum number of results to return (default: 50, max: 200)")),
	)
	s.AddTool(listVarsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[ListVariablesArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if args.Search != "" {
			if err := validateIdentifier(args.Search, "search"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		limit := args.Limit
		if limit <= 0 || limit > 200 {
			limit = 50
		}

		resources, err := client.api.Resources(&conjurapi.ResourceFilter{
			Kind:   "variable",
			Search: args.Search,
			Limit:  limit,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error retrieving variables: %v", err)), nil
		}

		type VarSummary struct {
			ID             string `json:"id"`
			CreatedAt      string `json:"created_at,omitempty"`
			LastRotatedAt  string `json:"last_rotated_at,omitempty"`
			AgeDays        int    `json:"age_days"`
			CurrentVersion int    `json:"current_version,omitempty"`
			Owner          string `json:"owner,omitempty"`
			Policy         string `json:"policy,omitempty"`
		}

		var summaries []VarSummary
		for _, r := range resources {
			ts := extractSecretTimestamps(r, 0)
			owner, _ := r["owner"].(string)
			policy, _ := r["policy"].(string)
			summaries = append(summaries, VarSummary{
				ID:             ts.ID,
				CreatedAt:      ts.CreatedAt,
				LastRotatedAt:  ts.LastRotatedAt,
				AgeDays:        ts.AgeDays,
				CurrentVersion: ts.CurrentVersion,
				Owner:          owner,
				Policy:         policy,
			})
		}

		outJSON, _ := json.MarshalIndent(summaries, "", "  ")
		return mcp.NewToolResultText(fmt.Sprintf("Found %d variables:\n%s", len(summaries), string(outJSON))), nil
	})

	// A3. Create variable definition
	createVarTool := mcp.NewTool("create_variable",
		mcp.WithDescription("Creates a new variable declaration under the designated Conjur policy branch without setting an initial secret value."),
		mcp.WithString("branch", mcp.Required(), mcp.Description("Target policy branch (e.g., dev/billing or root)")),
		mcp.WithString("variable_id", mcp.Required(), mcp.Description("Variable identifier name (e.g., stripe-key or db-password)")),
		mcp.WithString("description", mcp.Description("Optional description annotation explaining the variable's purpose")),
	)
	s.AddTool(createVarTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[CreateVariableArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.Branch, "branch"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if err := validateIdentifier(args.VariableID, "variable_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if len(args.Description) > 500 {
			return mcp.NewToolResultError("Validation error: 'description' cannot exceed 500 characters."), nil
		}

		yamlDef := fmt.Sprintf("- !variable\n  id: %s\n", strconv.Quote(args.VariableID))
		if args.Description != "" {
			yamlDef += fmt.Sprintf("  annotations:\n    description: %s\n", strconv.Quote(args.Description))
		}

		report := validatePolicyYAML(yamlDef)
		if !report.Valid {
			issues := strings.Join(report.SecurityIssues, "; ")
			return mcp.NewToolResultError(fmt.Sprintf("Generated policy failed security validation: %s", issues)), nil
		}

		resp, err := client.api.LoadPolicy(conjurapi.PolicyModePost, args.Branch, strings.NewReader(yamlDef))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error creating variable: %v", err)), nil
		}

		safeResp := marshalAndRedactPolicyResp(resp)
		return mcp.NewToolResultText(fmt.Sprintf("Variable '%s' was successfully created in branch '%s'.\n%s", args.VariableID, args.Branch, safeResp)), nil
	})

	// A4. Create and securely set random secret
	createSecretTool := mcp.NewTool("create_and_set_secret",
		mcp.WithDescription("Declares a variable in policy if it does not exist, then generates a cryptographically secure random secret and saves it in Conjur without exposing it in chat."),
		mcp.WithString("variable_id", mcp.Required(), mcp.Description("Full Conjur variable ID (e.g., dev/billing/db-password)")),
		mcp.WithString("branch", mcp.Description("Optional target branch (automatically derived from variable_id if omitted, e.g., dev/billing)")),
		mcp.WithString("description", mcp.Description("Optional description of the secret's purpose")),
		mcp.WithInteger("length", mcp.Description("Byte length of the generated random secret (default: 32, min: 16, max: 256)")),
		mcp.WithBoolean("overwrite", mcp.Description("Set to true to allow overwriting an existing variable's secret value (default: false)")),
	)

	s.AddTool(createSecretTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[CreateAndSetSecretArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.VariableID, "variable_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if args.Branch != "" {
			if err := validateIdentifier(args.Branch, "branch"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		// 1. Validate length limits (DoS / OOM protection)
		length := args.Length
		if length == 0 {
			length = 32
		} else if length < 16 || length > 256 {
			return mcp.NewToolResultError("Validation error: 'length' must be between 16 and 256 bytes."), nil
		}

		// 2. Validate description length
		if len(args.Description) > 500 {
			return mcp.NewToolResultError("Validation error: 'description' cannot exceed 500 characters."), nil
		}

		// 3. Normalize branch, varName, and targetVarID
		branch := args.Branch
		varName := args.VariableID
		targetVarID := args.VariableID

		if branch == "" {
			if lastSlash := strings.LastIndex(args.VariableID, "/"); lastSlash != -1 {
				branch = args.VariableID[:lastSlash]
				varName = args.VariableID[lastSlash+1:]
			} else {
				branch = "root"
			}
		} else {
			if strings.HasPrefix(varName, branch+"/") {
				varName = strings.TrimPrefix(varName, branch+"/")
			} else if !strings.Contains(varName, "/") {
				if branch != "root" {
					targetVarID = branch + "/" + varName
				}
			} else {
				return mcp.NewToolResultError(fmt.Sprintf("Conflict: 'variable_id' (%s) does not match the specified 'branch' (%s).", args.VariableID, branch)), nil
			}
		}

		// 4. Check if variable already exists in Conjur
		fullVarID := client.fullID("variable", targetVarID)
		_, getErr := client.api.Resource(fullVarID)
		createdPolicy := false

		if getErr == nil {
			if !args.Overwrite {
				return mcp.NewToolResultError(fmt.Sprintf("Variable '%s' already exists. Pass 'overwrite: true' if you explicitly want to replace its secret value.", targetVarID)), nil
			}
		} else {
			errStr := strings.ToLower(getErr.Error())
			if !strings.Contains(errStr, "404") && !strings.Contains(errStr, "not found") {
				return mcp.NewToolResultError(fmt.Sprintf("Error checking variable '%s' in Conjur: %v", targetVarID, getErr)), nil
			}
			createdPolicy = true
		}

		// 5. Declare/update policy with safe YAML quoting and last_rotated_at annotation
		nowUTC := time.Now().UTC().Format(time.RFC3339)
		yamlDef := fmt.Sprintf("- !variable\n  id: %s\n  annotations:\n    last_rotated_at: %s\n",
			strconv.Quote(varName),
			strconv.Quote(nowUTC),
		)
		if args.Description != "" {
			yamlDef += fmt.Sprintf("    description: %s\n", strconv.Quote(args.Description))
		}

		report := validatePolicyYAML(yamlDef)
		if !report.Valid {
			issues := strings.Join(report.SecurityIssues, "; ")
			return mcp.NewToolResultError(fmt.Sprintf("Generated policy failed security validation: %s", issues)), nil
		}

		if _, loadErr := client.api.LoadPolicy(conjurapi.PolicyModePost, branch, strings.NewReader(yamlDef)); loadErr != nil {
			if _, nativeErr := client.native.LoadPolicy(ctx, branch, "post", yamlDef); nativeErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Policy declaration in branch '%s' failed: %v (fallback: %v)", branch, loadErr, nativeErr)), nil
			}
		}

		// 6. Generate and write secret with error redaction (Zero-Leakage)
		secretVal, err := generateSecurePassword(length)
		if err != nil {
			return mcp.NewToolResultError("Failed to generate cryptographically secure secret."), nil
		}

		if err := client.api.AddSecret(targetVarID, secretVal); err != nil {
			safeErr := err.Error()
			if secretVal != "" {
				safeErr = strings.ReplaceAll(safeErr, secretVal, "[REDACTED]")
			}
			return mcp.NewToolResultError(fmt.Sprintf("Error writing secret value to Conjur: %s", safeErr)), nil
		}

		if createdPolicy {
			return mcp.NewToolResultText(fmt.Sprintf("Success: Variable '%s' was declared in Conjur policy and its value was generated (%d bytes of entropy) and securely stored without being exposed in chat.", targetVarID, length)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Success: Value for existing variable '%s' was overwritten (%d bytes of entropy) and securely updated in Conjur without being exposed in chat.", targetVarID, length)), nil
	})
}

// ============================================================================
// Module B: Policy-as-Code
// ============================================================================
type PolicyValidationReport struct {
	Valid          bool     `json:"valid"`
	Warnings       []string `json:"warnings"`
	SecurityIssues []string `json:"security_issues"`
}

func validatePolicyYAML(content string) PolicyValidationReport {
	report := PolicyValidationReport{
		Valid:          true,
		Warnings:       []string{},
		SecurityIssues: []string{},
	}

	if len(content) > 65536 {
		report.Valid = false
		report.SecurityIssues = append(report.SecurityIssues, "Policy content exceeds maximum allowed size (64 KB)")
		return report
	}

	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		report.Valid = false
		report.SecurityIssues = append(report.SecurityIssues, "Policy content is empty")
		return report
	}

	// Block YAML Bombs (anchors & and aliases *)
	if yamlAnchorAliasRegex.MatchString(content) {
		report.Valid = false
		report.SecurityIssues = append(report.SecurityIssues, "YAML anchors (&) and aliases (*) are disallowed for security reasons")
		return report
	}

	var parsed any
	if err := yaml.Unmarshal([]byte(content), &parsed); err != nil {
		report.Valid = false
		report.SecurityIssues = append(report.SecurityIssues, fmt.Sprintf("YAML syntax error: %v", err))
		return report
	}

	// Policy Security Guardrails
	if adminAbuseRegex.MatchString(content) {
		report.Valid = false
		report.SecurityIssues = append(report.SecurityIssues, "Critical: Modifying or granting permissions to the admin user ('admin') is strictly prohibited.")
	}

	lower := strings.ToLower(content)
	if destructiveRegex.MatchString(lower) && (strings.Contains(lower, "root") || strings.Contains(lower, "production")) {
		report.Warnings = append(report.Warnings, "Warning: Destructive privileges (update/replace/delete) declared in a critical branch (root/production).")
	}

	return report
}

func registerPolicyTools(s *server.MCPServer, client *conjurClient) {
	// B1. Validate YAML policy
	validateTool := mcp.NewTool("validate_policy",
		mcp.WithDescription("Validates the YAML syntax of a Conjur policy and performs a security audit against dangerous or unauthorized permissions. Always call before load_policy."),
		mcp.WithString("yaml_content", mcp.Required(), mcp.Description("Conjur policy content in YAML format")),
	)
	s.AddTool(validateTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[ValidatePolicyArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}

		report := validatePolicyYAML(args.YAMLContent)
		resJSON, _ := json.MarshalIndent(report, "", "  ")
		return mcp.NewToolResultText(string(resJSON)), nil
	})

	// B2. Load policy into Conjur
	policyTool := mcp.NewTool("load_policy",
		mcp.WithDescription("Loads a YAML policy into Conjur under the specified branch with automatic pre-validation and protection for critical branches."),
		mcp.WithString("branch", mcp.Required(), mcp.Description("Target branch path (e.g., root, dev/billing)")),
		mcp.WithString("mode", mcp.Required(), mcp.Description("Policy loading mode: patch (incremental), post (append/safe), or put (replace; blocked on root/production)")),
		mcp.WithString("yaml_content", mcp.Required(), mcp.Description("YAML policy definition")),
	)
	s.AddTool(policyTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[LoadPolicyArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.Branch, "branch"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Local pre-validation
		report := validatePolicyYAML(args.YAMLContent)
		if !report.Valid {
			issues := strings.Join(report.SecurityIssues, "; ")
			return mcp.NewToolResultError(fmt.Sprintf("Policy rejected: %s", issues)), nil
		}

		// Protect root and production branches from destructive replace mode
		lowerMode := strings.ToLower(strings.TrimSpace(args.Mode))
		cleanBranch := strings.Trim(strings.ToLower(strings.TrimSpace(args.Branch)), "/")
		if (lowerMode == "put" || lowerMode == "replace") && (cleanBranch == "root" || cleanBranch == "production" || strings.HasPrefix(cleanBranch, "production/")) {
			return mcp.NewToolResultError("Refusal: Replacing (mode=put/replace) branch 'root' or 'production' is blocked for security reasons. Use 'post' or 'patch' mode."), nil
		}

		resp, err := client.api.LoadPolicy(policyMode(args.Mode), cleanBranch, strings.NewReader(args.YAMLContent))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error loading policy: %v", err)), nil
		}

		// Redact any newly created host/user API keys from response
		safeResp := marshalAndRedactPolicyResp(resp)
		return mcp.NewToolResultText(fmt.Sprintf("Conjur response:\n%s", safeResp)), nil
	})

	// B3. Check permission
	checkPermTool := mcp.NewTool("check_permission",
		mcp.WithDescription("Checks whether a role has a specific privilege (e.g., read, execute, update) on a target Conjur resource."),
		mcp.WithString("role", mcp.Required(), mcp.Description("Role identifier (e.g., host:mcp-system/bridge-runner or billing-service; defaults to host:<id> if unqualified)")),
		mcp.WithString("privilege", mcp.Required(), mcp.Description("Privilege to verify: read, execute, update, create")),
		mcp.WithString("resource", mcp.Required(), mcp.Description("Resource identifier (e.g., variable:dev/billing/stripe-key or dev/billing/stripe-key)")),
	)
	s.AddTool(checkPermTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[CheckPermissionArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateQualifiedIdentifier(args.Role, "role"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if err := validateIdentifier(args.Privilege, "privilege"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if err := validateQualifiedIdentifier(args.Resource, "resource"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Normalize resource identifier to account:kind:id
		resParts := strings.SplitN(args.Resource, ":", 2)
		kind := "variable"
		identifier := args.Resource
		if len(resParts) == 2 {
			kind = resParts[0]
			identifier = resParts[1]
		}
		fullResourceID := client.fullID(kind, identifier)

		// Normalize role identifier to account:kind:id
		fullRole := args.Role
		if !strings.Contains(fullRole, ":") {
			fullRole = client.fullID("host", fullRole)
		} else if strings.Count(fullRole, ":") == 1 {
			fullRole = fmt.Sprintf("%s:%s", client.account, fullRole)
		}

		allowed, err := client.native.CheckPermission(ctx, fullRole, args.Privilege, kind, identifier)
		if err != nil {
			allowed, err = client.api.CheckPermission(fullResourceID, args.Privilege)
		}
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error checking permission: %v", err)), nil
		}

		if allowed {
			return mcp.NewToolResultText(fmt.Sprintf("ACCESS GRANTED: Role '%s' HAS privilege '%s' on resource '%s:%s'.", fullRole, args.Privilege, kind, identifier)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("ACCESS DENIED: Role '%s' DOES NOT HAVE privilege '%s' on resource '%s:%s'.", fullRole, args.Privilege, kind, identifier)), nil
	})

	// B4. Get resource tree
	treeTool := mcp.NewTool("get_resource_tree",
		mcp.WithDescription("Returns the resource hierarchy or filtered list of resources in Conjur (variables, hosts, groups, policies, users)."),
		mcp.WithString("branch", mcp.Description("Optional branch prefix or search filter (e.g., dev or billing)")),
		mcp.WithString("kind", mcp.Description("Optional resource kind: variable, host, policy, group, user")),
		mcp.WithInteger("limit", mcp.Description("Maximum number of resources to return (default: 100, max: 300)")),
	)
	s.AddTool(treeTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[GetResourceTreeArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if args.Branch != "" {
			if err := validateIdentifier(args.Branch, "branch"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
		if args.Kind != "" {
			if err := validateIdentifier(args.Kind, "kind"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		limit := args.Limit
		if limit <= 0 || limit > 300 {
			limit = 100
		}

		resources, err := client.api.Resources(&conjurapi.ResourceFilter{
			Kind:   args.Kind,
			Search: args.Branch,
			Limit:  limit,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error retrieving resources: %v", err)), nil
		}

		resJSON, _ := json.MarshalIndent(resources, "", "  ")
		return mcp.NewToolResultText(fmt.Sprintf("Retrieved %d resources:\n%s", len(resources), string(resJSON))), nil
	})
}

// ============================================================================
// Module C: SecOps (Lifecycle, Rotation & Diagnostics)
// ============================================================================
func registerSecOpsTools(s *server.MCPServer, client *conjurClient) {
	// C1. Get variable metadata
	metaTool := mcp.NewTool("get_variable_metadata",
		mcp.WithDescription("Retrieves non-sensitive lifecycle metadata for a variable (creation date, last rotation, version, permissions) without exposing its value."),
		mcp.WithString("variable_id", mcp.Required(), mcp.Description("Conjur variable ID (e.g., dev/billing/stripe-key)")),
	)
	s.AddTool(metaTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[VariableOnlyArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.VariableID, "variable_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		meta, err := client.api.Resource(client.fullID("variable", args.VariableID))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Metadata retrieval error: %v", err)), nil
		}

		ts := extractSecretTimestamps(meta, 90)
		enhanced := map[string]any{
			"id":               ts.ID,
			"created_at":       ts.CreatedAt,
			"last_rotated_at":  ts.LastRotatedAt,
			"age_days":         ts.AgeDays,
			"current_version":  ts.CurrentVersion,
			"total_versions":   ts.TotalVersions,
			"needs_rotation":   ts.NeedsRotation,
			"timestamp_source": ts.TimestampSource,
			"owner":            meta["owner"],
			"policy":           meta["policy"],
			"permissions":      meta["permissions"],
			"annotations":      meta["annotations"],
			"secrets":          meta["secrets"],
		}

		resJSON, _ := json.MarshalIndent(enhanced, "", "  ")
		return mcp.NewToolResultText(string(resJSON)), nil
	})

	// C2. List secrets for rotation
	listRotTool := mcp.NewTool("list_secrets_for_rotation",
		mcp.WithDescription("Identifies secrets older than a specified threshold (in days) to plan rotation, evaluating both native timestamps and last_rotated_at annotations without reading values."),
		mcp.WithInteger("max_age_days", mcp.Description("Age threshold in days to trigger rotation recommendation (default: 90)")),
		mcp.WithString("search", mcp.Description("Optional search filter for variable IDs")),
	)
	s.AddTool(listRotTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[ListRotationArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if args.Search != "" {
			if err := validateIdentifier(args.Search, "search"); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		maxDays := args.MaxAgeDays
		if maxDays <= 0 {
			maxDays = 90
		}

		resources, err := client.api.Resources(&conjurapi.ResourceFilter{
			Kind:   "variable",
			Search: args.Search,
			Limit:  300,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error retrieving variables: %v", err)), nil
		}

		type RotationCandidate struct {
			ID              string `json:"id"`
			CreatedAt       string `json:"created_at"`
			LastRotatedAt   string `json:"last_rotated_at,omitempty"`
			AgeDays         int    `json:"age_days"`
			CurrentVersion  int    `json:"current_version"`
			TimestampSource string `json:"timestamp_source"`
			Recommendation  string `json:"recommendation"`
		}

		var candidates []RotationCandidate
		for _, r := range resources {
			ts := extractSecretTimestamps(r, maxDays)
			if ts.NeedsRotation {
				candidates = append(candidates, RotationCandidate{
					ID:              ts.ID,
					CreatedAt:       ts.CreatedAt,
					LastRotatedAt:   ts.LastRotatedAt,
					AgeDays:         ts.AgeDays,
					CurrentVersion:  ts.CurrentVersion,
					TimestampSource: ts.TimestampSource,
					Recommendation:  fmt.Sprintf("Secret is %d days old since last rotation (threshold: %d days, source: %s). Rotation recommended.", ts.AgeDays, maxDays, ts.TimestampSource),
				})
			}
		}

		outJSON, _ := json.MarshalIndent(candidates, "", "  ")
		return mcp.NewToolResultText(fmt.Sprintf("Found %d secrets requiring rotation (threshold: %d days):\n%s", len(candidates), maxDays, string(outJSON))), nil
	})

	// C3. Rotate secret
	rotateSecretTool := mcp.NewTool("rotate_secret",
		mcp.WithDescription("Securely rotates a secret value: generates a new cryptographically secure random value and updates Conjur without revealing it in chat. Requires confirm: true."),
		mcp.WithString("variable_id", mcp.Required(), mcp.Description("Variable ID to rotate")),
		mcp.WithInteger("length", mcp.Description("Byte length of the new secret (default: 32, min: 16)")),
		mcp.WithBoolean("confirm", mcp.Description("Must be set to true to confirm rotation and prevent accidental execution.")),
	)
	s.AddTool(rotateSecretTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[RotateSecretArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.VariableID, "variable_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Sprawdzenie czy użytkownik/model potwierdził operację
		if !args.Confirm {
			return mcp.NewToolResultError(fmt.Sprintf("Refusal: Rotating secret for '%s' is a destructive operation. Please explicitly ask the user for confirmation and retry with 'confirm: true'.", args.VariableID)), nil
		}

		length := args.Length
		if length == 0 {
			length = 32
		} else if length < 16 || length > 256 {
			return mcp.NewToolResultError("Validation error: 'length' must be between 16 and 256 bytes."), nil
		}

		newVal, err := generateSecurePassword(length)
		if err != nil {
			return mcp.NewToolResultError("Failed to generate cryptographically secure secret."), nil
		}

		if err := client.api.AddSecret(args.VariableID, newVal); err != nil {
			safeErr := err.Error()
			if newVal != "" {
				safeErr = strings.ReplaceAll(safeErr, newVal, "[REDACTED]")
			}
			return mcp.NewToolResultError(fmt.Sprintf("Error rotating secret in Conjur: %s", safeErr)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Success: Variable '%s' value was successfully rotated (%d bytes of entropy) in Conjur. The new value was not exposed in chat.", args.VariableID, length)), nil
	})

	// C4. Check host status
	checkHostTool := mcp.NewTool("check_host_status",
		mcp.WithDescription("Checks host identity status, policy branch, role memberships, and API key last rotation timestamp via GET /authn/:account/api_key."),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("Host ID (e.g., test-host-1 or mcp-system/bridge-runner)")),
	)
	s.AddTool(checkHostTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[HostOnlyArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.HostID, "host_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		meta, err := client.api.Resource(client.fullID("host", args.HostID))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error retrieving host '%s': %v (verify that the host exists in Conjur)", args.HostID, err)), nil
		}

		// Retrieve role memberships
		memberships, err := client.api.RoleMembers(client.fullID("host", args.HostID))
		var memberList []string
		if err == nil {
			for _, m := range memberships {
				if mid, ok := m["member"].(string); ok {
					memberList = append(memberList, mid)
				}
			}
		}

		// Retrieve API key last rotation timestamp from native endpoint routes.rb: GET /authn/:account/api_key
		apiKeyLastRotated, _ := client.GetAPIKeyLastRotated(client.fullID("host", args.HostID))

		result := map[string]any{
			"metadata":             meta,
			"memberships":          memberList,
			"api_key_last_rotated": apiKeyLastRotated,
		}
		outJSON, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(outJSON)), nil
	})

	// C5. Role memberships
	roleMembershipsTool := mcp.NewTool("get_role_memberships",
		mcp.WithDescription("Retrieves roles and groups associated with an identity to audit access and troubleshoot 403 Forbidden errors."),
		mcp.WithString("role_id", mcp.Required(), mcp.Description("Role identifier (e.g., host:mcp-system/bridge-runner or group:developers)")),
	)
	s.AddTool(roleMembershipsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[RoleMembershipsArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateQualifiedIdentifier(args.RoleID, "role_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		parts := strings.SplitN(args.RoleID, ":", 2)
		kind := "host"
		identifier := args.RoleID
		if len(parts) == 2 {
			kind = parts[0]
			identifier = parts[1]
		}
		fullRoleID := client.fullID(kind, identifier)

		memberships, err := client.api.RoleMembers(fullRoleID)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error retrieving roles: %v", err)), nil
		}

		var memberList []string
		for _, m := range memberships {
			if mid, ok := m["member"].(string); ok {
				memberList = append(memberList, mid)
			}
		}

		outJSON, _ := json.MarshalIndent(memberList, "", "  ")
		return mcp.NewToolResultText(fmt.Sprintf("Memberships for identity '%s':\n%s", args.RoleID, string(outJSON))), nil
	})

	// C6. API key last rotated
	apiKeyRotTool := mcp.NewTool("get_api_key_last_rotated",
		mcp.WithDescription("Retrieves the last rotation timestamp of a role's API key using Conjur's native endpoint (GET /authn/<account>/api_key?role=<role>)."),
		mcp.WithString("role", mcp.Required(), mcp.Description("Role identifier (e.g., host:mcp-system/bridge-runner or user:admin)")),
	)
	s.AddTool(apiKeyRotTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		type APIKeyRotArgs struct {
			Role string `json:"role"`
		}
		args, err := parseArgs[APIKeyRotArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateQualifiedIdentifier(args.Role, "role"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		lastRotated, err := client.GetAPIKeyLastRotated(args.Role)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error retrieving key rotation timestamp for role '%s': %v", args.Role, err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("API key last rotated for role '%s': %s (source: Conjur native endpoint GET /authn/:account/api_key)", args.Role, lastRotated)), nil
	})
}

// ============================================================================
// Module D: Workload Onboarding (CI/CD, Kubernetes, Containers)
// ============================================================================
func registerOnboardingTools(s *server.MCPServer, client *conjurClient) {
	// D1. Register new host
	createHostTool := mcp.NewTool("create_host",
		mcp.WithDescription("Registers a new host identity in Conjur for a container or CI/CD runner. Automatically redacts the initial API key from chat output."),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("Host identifier (e.g., payment-worker-01)")),
		mcp.WithString("branch", mcp.Required(), mcp.Description("Target policy branch (e.g., prod/services or dev/apps)")),
	)
	s.AddTool(createHostTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[CreateHostArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.HostID, "host_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if err := validateIdentifier(args.Branch, "branch"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		yamlDef := fmt.Sprintf("- !host %s\n", strconv.Quote(args.HostID))
		resp, err := client.api.LoadPolicy(conjurapi.PolicyModePost, args.Branch, strings.NewReader(yamlDef))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error creating host: %v", err)), nil
		}

		// Secure serialization: mask API keys from Conjur response
		safeResp := marshalAndRedactPolicyResp(resp)

		return mcp.NewToolResultText(fmt.Sprintf("Host '%s' was registered in branch '%s'.\nThe API key has been redacted and is not displayed in chat. Use a secure bootstrap mechanism for CI/CD.\nConjur result:\n%s", args.HostID, args.Branch, safeResp)), nil
	})

	// D2. Rotate host API key
	rotateHostKeyTool := mcp.NewTool("rotate_host_api_key",
		mcp.WithDescription("Rotates a host API key in Conjur via PUT /authn/:account/api_key. Requires confirm: true. The new key is securely masked and not displayed in chat history."),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("Host identifier (e.g., test-host-1)")),
		mcp.WithBoolean("confirm", mcp.Description("Must be set to true to confirm host API key rotation and prevent accidental execution.")),
	)
	s.AddTool(rotateHostKeyTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[RotateHostAPIKeyArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.HostID, "host_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Wymóg potwierdzenia operacji
		if !args.Confirm {
			return mcp.NewToolResultError(fmt.Sprintf("Refusal: Rotating API key for host '%s' is a destructive operation. Please explicitly ask the user for confirmation and retry with 'confirm: true'.", args.HostID)), nil
		}

		// SDK RotateAPIKey accepts role in "host:<id>" format (PUT /authn/:account/api_key)
		newKeyBytes, err := client.api.RotateAPIKey("host:" + args.HostID)
		keyLen := len(newKeyBytes)
		newKeyStr := string(newKeyBytes)
		for i := range newKeyBytes {
			newKeyBytes[i] = 0
		}

		if err != nil {
			safeErr := err.Error()
			if newKeyStr != "" {
				safeErr = strings.ReplaceAll(safeErr, newKeyStr, "[REDACTED]")
			}
			return mcp.NewToolResultError(fmt.Sprintf("Error rotating API key for host '%s': %s", args.HostID, safeErr)), nil
		}

		// Verify new rotation timestamp from native endpoint
		lastRotated, _ := client.GetAPIKeyLastRotated(client.fullID("host", args.HostID))

		msg := fmt.Sprintf("Success: API key for host '%s' was successfully rotated (key length: %d chars). In accordance with security policy, the raw key is not displayed in the chat window.", args.HostID, keyLen)
		if lastRotated != "" {
			msg += fmt.Sprintf(" New rotation timestamp from Conjur: %s.", lastRotated)
		}

		return mcp.NewToolResultText(msg), nil
	})

	// D3. Least-privilege policy scaffolding
	preparePolicyTool := mcp.NewTool("prepare_workload_policy",
		mcp.WithDescription("Generates a recommended Least Privilege YAML policy definition for a new workload/container, declaring the host and permitted variables."),
		mcp.WithString("workload_id", mcp.Required(), mcp.Description("Workload identifier (e.g., billing-service)")),
		mcp.WithString("branch", mcp.Required(), mcp.Description("Policy branch (e.g., dev/billing)")),
		mcp.WithArray("accessible_variables", mcp.Required(), mcp.Description("List of Conjur variable IDs required by the workload"), mcp.WithStringItems()),
	)
	s.AddTool(preparePolicyTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := parseArgs[PrepareWorkloadPolicyArgs](req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
		}
		if err := validateIdentifier(args.WorkloadID, "workload_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if err := validateIdentifier(args.Branch, "branch"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if len(args.AccessibleVariables) > 100 {
			return mcp.NewToolResultError("Validation error: 'accessible_variables' cannot exceed 100 items."), nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("# Least Privilege Policy for: %s\n", args.WorkloadID))
		sb.WriteString(fmt.Sprintf("- !host %s\n\n", args.WorkloadID))

		if len(args.AccessibleVariables) > 0 {
			sb.WriteString("- !permit\n")
			sb.WriteString(fmt.Sprintf("  role: !host %s\n", args.WorkloadID))
			sb.WriteString("  privileges: [read, execute]\n")
			sb.WriteString("  resources:\n")
			for _, v := range args.AccessibleVariables {
				cleanV := strings.TrimSpace(v)
				if cleanV != "" {
					if err := validateIdentifier(cleanV, "accessible_variables item"); err != nil {
						return mcp.NewToolResultError(err.Error()), nil
					}
					sb.WriteString(fmt.Sprintf("  - !variable %s\n", cleanV))
				}
			}
		}

		return mcp.NewToolResultText(fmt.Sprintf("Generated recommended YAML policy:\n\n```yaml\n%s```\n\nYou can verify its syntax with 'validate_policy', then load it using 'load_policy'.", sb.String())), nil
	})
}
