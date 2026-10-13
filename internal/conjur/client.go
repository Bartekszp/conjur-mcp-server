package conjur

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	ApplianceURL string
	Account      string
	Login        string
	APIKey       string
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

func NewClient(cfg Config) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// authenticate retrieves a short-lived session token from Conjur
func (c *Client) authenticate(ctx context.Context) (string, error) {
	escapedLogin := url.QueryEscape(c.cfg.Login)
	authURL := fmt.Sprintf("%s/authn/%s/%s/authenticate", c.cfg.ApplianceURL, c.cfg.Account, escapedLogin)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, strings.NewReader(c.cfg.APIKey))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("authentication request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("authentication failed (status %d): %s", resp.StatusCode, string(body))
	}

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(tokenBytes), nil
}

// GetSecret retrieves raw secret value
func (c *Client) GetSecret(ctx context.Context, variableID string) (string, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return "", err
	}

	reqURL := fmt.Sprintf("%s/secrets/%s/variable/%s", c.cfg.ApplianceURL, c.cfg.Account, url.PathEscape(variableID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to retrieve secret (status %d)", resp.StatusCode)
	}

	val, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(val), nil
}

// SetSecret updates a variable's secret value in Conjur
func (c *Client) SetSecret(ctx context.Context, variableID, value string) error {
	token, err := c.authenticate(ctx)
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s/secrets/%s/variable/%s", c.cfg.ApplianceURL, c.cfg.Account, url.PathEscape(variableID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(value))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))
	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to store secret (status %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// GetResourceMetadata retrieves resource metadata without exposing content
func (c *Client) GetResourceMetadata(ctx context.Context, kind, identifier string) (map[string]any, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/resources/%s/%s/%s", c.cfg.ApplianceURL, c.cfg.Account, kind, url.PathEscape(identifier))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error retrieving resource metadata (status %d)", resp.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// LoadPolicy applies a YAML definition to the specified Conjur branch
func (c *Client) LoadPolicy(ctx context.Context, branch, mode, policyYAML string) (string, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return "", err
	}

	// method: POST = append, PATCH = patch, PUT = replace
	method := http.MethodPost
	switch strings.ToLower(mode) {
	case "patch":
		method = http.MethodPatch
	case "put", "replace":
		method = http.MethodPut
	}

	reqURL := fmt.Sprintf("%s/policies/%s/policy/%s", c.cfg.ApplianceURL, c.cfg.Account, url.QueryEscape(branch))
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewBufferString(policyYAML))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))
	req.Header.Set("Content-Type", "application/x-yaml")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("error loading policy (status %d): %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

// ListResources returns metadata for resources matching a kind/search filter
func (c *Client) ListResources(ctx context.Context, kind, search string, limit int) ([]map[string]any, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	queryParams := url.Values{}
	if kind != "" {
		queryParams.Set("kind", kind)
	}
	if search != "" {
		queryParams.Set("search", search)
	}
	if limit <= 0 {
		limit = 100
	}
	queryParams.Set("limit", fmt.Sprintf("%d", limit))

	reqURL := fmt.Sprintf("%s/resources/%s?%s", c.cfg.ApplianceURL, c.cfg.Account, queryParams.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("error retrieving resources (status %d): %s", resp.StatusCode, string(body))
	}

	var results []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	return results, nil
}

// CheckPermission checks whether a role has a privilege on a resource
func (c *Client) CheckPermission(ctx context.Context, role, privilege, kind, identifier string) (bool, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return false, err
	}

	fullRole := role
	if !strings.Contains(fullRole, ":") {
		fullRole = fmt.Sprintf("%s:host:%s", c.cfg.Account, role)
	} else if strings.Count(fullRole, ":") == 1 {
		fullRole = fmt.Sprintf("%s:%s", c.cfg.Account, role)
	}

	queryParams := url.Values{}
	queryParams.Set("check", "true")
	queryParams.Set("privilege", privilege)
	queryParams.Set("role", fullRole)

	reqURL := fmt.Sprintf("%s/resources/%s/%s/%s?%s",
		c.cfg.ApplianceURL,
		c.cfg.Account,
		kind,
		url.PathEscape(identifier),
		queryParams.Encode(),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("error checking permission (status %d): %s", resp.StatusCode, string(body))
}

// GetRoleMemberships returns roles and groups to which an identity belongs
func (c *Client) GetRoleMemberships(ctx context.Context, kind, identifier string) ([]string, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/roles/%s/%s/%s?all", c.cfg.ApplianceURL, c.cfg.Account, kind, url.PathEscape(identifier))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("error retrieving role memberships (status %d): %s", resp.StatusCode, string(body))
	}

	var memberships []string
	if err := json.NewDecoder(resp.Body).Decode(&memberships); err != nil {
		return nil, err
	}
	return memberships, nil
}

// RotateHostAPIKey rotates the API key of a host in Conjur
func (c *Client) RotateHostAPIKey(ctx context.Context, hostID string) (string, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return "", err
	}

	fullRole := hostID
	if !strings.Contains(fullRole, ":") {
		fullRole = fmt.Sprintf("%s:host:%s", c.cfg.Account, hostID)
	}

	reqURL := fmt.Sprintf("%s/authn/%s/api_key?role=%s", c.cfg.ApplianceURL, c.cfg.Account, url.QueryEscape(fullRole))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("error rotating host API key (status %d): %s", resp.StatusCode, string(body))
	}

	newKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(newKey)), nil
}

// GetLogin returns the configured login
func (c *Client) GetLogin() string {
	return c.cfg.Login
}

// SetVariableAnnotation stores annotations (e.g. updated_at, last_rotated_at) for a variable
func (c *Client) SetVariableAnnotation(ctx context.Context, variableID string, annotations map[string]string) error {
	if len(annotations) == 0 {
		return nil
	}

	lastSlash := strings.LastIndex(variableID, "/")
	branch := "root"
	varName := variableID
	if lastSlash != -1 {
		branch = variableID[:lastSlash]
		varName = variableID[lastSlash+1:]
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("- !variable\n  id: %s\n  annotations:\n", varName))
	for k, v := range annotations {
		sb.WriteString(fmt.Sprintf("    %s: %s\n", k, strings.ReplaceAll(v, "\n", " ")))
	}

	_, err := c.LoadPolicy(ctx, branch, "patch", sb.String())
	return err
}

// GetAccount returns the configured account name
func (c *Client) GetAccount() string {
	return c.cfg.Account
}

// FullID builds the fully qualified resource ID account:kind:id
func (c *Client) FullID(kind, id string) string {
	return fmt.Sprintf("%s:%s:%s", c.cfg.Account, kind, id)
}

// GetAPIKeyLastRotated calls native endpoint GET /authn/:account/api_key?role=:role
func (c *Client) GetAPIKeyLastRotated(ctx context.Context, role string) (string, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return "", err
	}

	fullRole := role
	if !strings.Contains(fullRole, ":") {
		fullRole = c.FullID("host", fullRole)
	} else if strings.Count(fullRole, ":") == 1 {
		fullRole = fmt.Sprintf("%s:%s", c.cfg.Account, fullRole)
	}

	applianceURL := strings.TrimRight(c.cfg.ApplianceURL, "/")
	reqURL := fmt.Sprintf("%s/authn/%s/api_key?role=%s",
		applianceURL,
		c.cfg.Account,
		url.QueryEscape(fullRole),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error from Conjur (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return strings.TrimSpace(string(bodyBytes)), nil
}