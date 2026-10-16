# CyberArk Conjur MCP Server

An enterprise-grade **Model Context Protocol (MCP)** server providing secure, policy-driven Secrets-as-a-Service, Role-Based Access Control (RBAC), and Workload Identity management for AI coding assistants and automated workflows.

Built in Go using the official [CyberArk Conjur Go SDK](https://github.com/cyberark/conjur-api-go) and [`mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go).

---

## Architecture & Functional Domains

The server organizes its capabilities into four functional modules:

| Domain | Description | Included Tools |
| :--- | :--- | :--- |
| **Developer Experience (DevEx)** | Secure variable discovery, automated secret generation, and isolated execution. | `list_variables`, `create_variable`, `create_and_set_secret`, `run_test_with_secret` |
| **Policy-as-Code** | Declarative YAML policy authoring, syntax verification, guardrail enforcement, and RBAC permission checks. | `validate_policy`, `load_policy`, `check_permission`, `get_resource_tree` |
| **SecOps & Lifecycle** | Secret age tracking, rotation compliance audits, and native API key diagnostics. | `get_variable_metadata`, `list_secrets_for_rotation`, `rotate_secret`, `check_host_status`, `get_role_memberships`, `get_api_key_last_rotated` |
| **Workload Onboarding** | Least-privilege identity provisioning for CI/CD runners, containers, and Kubernetes pods. | `create_host`, `rotate_host_api_key`, `prepare_workload_policy` |

---

## Security Guardrails (Zero-Leakage Policy)

This MCP server enforces strict enterprise guardrails to prevent credential exposure:

* **Zero Secret Leakage:** Raw secret values and generated host API keys are never exposed in the chat context or tool outputs. Generation and rotation occur entirely server-side, returning operational metadata and entropy confirmations only.
* **Anti-Exfiltration Guardrail on Tests:** The `run_test_with_secret` tool securely injects secrets into subprocesses as `APP_SECRET`. Direct exfiltration attempts (`echo %APP_SECRET%`, `set`, `env`, `printenv`) are actively rejected by server guardrails, and secret substrings in standard output/stderr are automatically replaced with `***REDACTED***`.
* **Critical Branch Protection:** Destructive replacement operations (`mode: put` or `mode: replace`) are strictly blocked on core branches (`root`, `production`).
* **Root Admin Protection:** Grants or modifications targeting the root administrative identity (`!user admin`) are rejected during policy validation.

---

## Known Limitations & Roadmap: Two-Step Confirmation Gate

### The LLM Boolean Bypass Problem
Currently, destructive tools (`rotate_secret`, `rotate_host_api_key`, and `create_and_set_secret` when overwriting existing variables) rely on boolean parameters (`confirm: bool` / `overwrite: bool`) and prompt instructions in the MCP tool description to request user consent.

In practice, **AI agents frequently bypass boolean confirmation flags on the first call**. Because the user's initial prompt asks to rotate or update a secret, the LLM infers intent and automatically sets `confirm: true` in its very first tool invocation without pausing to ask the user in chat.

### How to Implement Hard Enforcement (Challenge-Response Pattern)
Because MCP communicates over `stdio` JSON-RPC, interactive terminal prompts (`fmt.Scanln`) cannot be used. To strictly force the AI agent to pause and ask the user in chat, replace the boolean flag with a **server-side, two-step Challenge-Response token**:

1. **Change the DTO and Tool Parameter:** Replace `Confirm bool` with `ConfirmationToken string` (`confirmation_token`).
2. **Generate a Short-Lived Token in Memory:** On the first tool call (when `confirmation_token` is empty), the server aborts execution, generates a random 4-character hex code (e.g., `A7F2`), stores it in an in-memory map (`pendingConfirmations[actionKey] = token`), and returns a tool error instructing the LLM to ask the user for that exact code.
3. **Verify on Second Call:** Since the LLM cannot guess a cryptographically random token on the first turn, it is forced to stop and display the code to the user. Once the user replies with confirmation, the LLM passes the token in the second call, unlocking the operation.

```go
var pendingConfirmations = make(map[string]string)

func verifyConfirmationToken(actionKey, providedToken, questionPrompt string) (bool, string) {
	expectedToken, exists := pendingConfirmations[actionKey]
	cleanedProvided := strings.TrimSpace(strings.ToUpper(providedToken))

	if exists && expectedToken != "" && cleanedProvided == expectedToken {
		delete(pendingConfirmations, actionKey)
		return true, ""
	}

	b := make([]byte, 2)
	_, _ = rand.Read(b)
	newToken := strings.ToUpper(hex.EncodeToString(b))
	pendingConfirmations[actionKey] = newToken

	msg := fmt.Sprintf(
		"CONFIRMATION REQUIRED: Stop and ask the user in chat: \"%s To confirm, reply with code: %s\".",
		questionPrompt, newToken,
	)
	return false, msg
}
```

---

## Pre-Flight Environment & Identity Verification

The `./scripts/preflight.ps1` script validates environment health and authentication readiness before running MCP operations or tests:
1. **Container Health:** Automatically checks and starts required Podman containers if stopped (`postgres_database`, `conjur_server`, `conjur_client`).
2. **Database Readiness:** Verifies that PostgreSQL is actively accepting connections via `pg_isready`.
3. **Session Verification:** Confirms an active Conjur authentication session inside the `conjur_client` container.

---

### Dual-Mode Authentication: Local Dev vs. Zero Trust (CI/CD)

CyberArk Conjur maintains a strict separation between two identity types:
* **Administrative User (`admin`):** Superuser identity with unrestricted permissions to manage policies, provision resources, and rotate credentials.
* **Workload Identity (`host/*`):** Machine identity constrained by Least Privilege policies (scoped strictly to specific secrets and actions).

#### The "Zero Trust Violation" Problem
When testing Conjur with a client container, a common dilemma arises:
* **The Conflict:** If the pre-flight check enforces machine identity (`host/*`), an active `admin` session triggers a `Zero Trust violation!` error.
* **The Developer Friction:** If enforced in local development, it creates an endless re-authentication loop: you must log in as `admin` to modify policies or rotate host keys, which immediately breaks the pre-flight check, forcing you to re-authenticate as `host/...` just to run a test.

#### 1. Local Development Mode (Default)
* **Configuration:** In `./scripts/preflight.ps1`, the strict host regex check (`if ($whoamiJson.username -notlike "host/*")`) is commented out.
* **Behavior:** The script accepts any valid active session, including `admin`.
* **Rationale:** Maximizes developer velocity and eliminates authentication churn during local development. Security risk is negligible since local sandboxes use mock secrets and the local MCP server already connects using administrative API credentials.

#### 2. Strict Zero Trust Mode (CI/CD Pipelines & Compliance Audits)
* **Configuration:** Uncomment lines 71–75 in `./scripts/preflight.ps1`.
* **Behavior:** Rejects `admin` sessions with `exit 3` and mandates authentication strictly as a workload identity (`host/*`).
* **Rationale:** Critical for verifying RBAC policy boundaries. Running tests as `admin` masks permission bugs because `admin` bypasses all access checks (it will never trigger a `403 Forbidden`).
* **How to Authenticate as Host:**
  ```powershell
  # 1. Rotate and retrieve a fresh API key for the host:
  podman exec -u 0 conjur_client conjur host rotate-api-key -i dev/billing/billing-runner-01

  # 2. Authenticate the container using the host identity:
  podman exec -it -u 0 conjur_client conjur login -i host/dev/billing/billing-runner-01
  ```
## Getting Started

### Prerequisites

* [Go 1.22+](https://golang.org/dl/)
* [Podman](https://podman.io/) (tested; Docker is currently untested as pre-flight scripts rely on the Podman CLI)
* CyberArk Conjur Open Source (tested locally; Conjur Enterprise / DAP is currently untested)

### Environment Variables

Configure the following environment variables before launching the server:

```bash
CONJUR_APPLIANCE_URL="http://localhost:8080"
CONJUR_ACCOUNT="myorg"
CONJUR_AUTHN_LOGIN="admin"
CONJUR_AUTHN_API_KEY="<your-conjur-api-key>"
```

### Running the Pre-Flight Check

Verify that all containers and database connections are operational:

```powershell
powershell -ExecutionPolicy Bypass -File ./scripts/preflight.ps1
```

### Building and Running the MCP Server

```bash
# Build binary
go build -o bin/conjur-mcp-server.exe main.go

# Run with all tool modules enabled (default)
./bin/conjur-mcp-server.exe --mode=all

# Run specific modules only (e.g., DevEx and SecOps)
./bin/conjur-mcp-server.exe --mode=devex,secops

# Run security unit test suite
go test -v .
```

---

## Author & Maintainer

* **Author:** Bartek Szpargała
* **Focus:** Cloud Security / DevSecOps / Identity & Access Management (IAM)
* **GitHub:** [@Bartekszp](https://github.com/Bartekszp)
* **LinkedIn:** [bartek-szpargala](https://linkedin.com/in/bartek-szpargala)

---

## License

This project is licensed under the [MIT License](LICENSE).