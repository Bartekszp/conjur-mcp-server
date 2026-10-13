# CyberArk Conjur MCP Server — Operational Best Practices & AI Instructions

## Mandatory Pre-Flight Rule (Environment Readiness)
Before executing any commands, modifying code, or starting any assigned task:
1. Always run `powershell -ExecutionPolicy Bypass -File ./scripts/preflight.ps1` first.
2. If the command exits with code 0, proceed normally with the task.
3. If the command fails (non-zero exit code), STOP immediately, report the script error output to the user, and wait for instructions.

---

## Role and Architecture Overview
The CyberArk Conjur MCP server provides secure, enterprise-grade Secrets-as-a-Service, Policy-as-Code, Role-Based Access Control (RBAC), and Workload Identity management for AI agents and automated workflows.

The server operates under strict zero-trust security guardrails with four modular functional domains:
1. **Developer Experience (DevEx)**: Safe secret consumption testing, variable discovery, and automated provisioning.
2. **Policy-as-Code**: YAML-based declarative policy authoring, syntax verification, guardrail enforcement, and RBAC audits.
3. **Security Operations (SecOps)**: Secret lifecycle tracking, age-based rotation compliance, API key audits, and access diagnostics.
4. **Workload Onboarding**: Least-privilege identity provisioning for CI/CD runners, Kubernetes pods, and containerized microservices.

---

## Non-Negotiable Security Guardrails (Zero-Leakage Policy)
1. **No Raw Secrets in Chat**: Never attempt to print, display, or reveal raw secret values or API keys in the chat context. All generation and rotation tools execute server-side and return confirmation metadata only.
2. **Anti-Exfiltration Guardrail on Tests**:
   - In `run_test_with_secret`, the secret is injected into the subprocess environment as `APP_SECRET`.
   - Any test command that directly inspects or dumps environment variables (e.g., `echo %APP_SECRET%`, `set`, `env`, `printenv`) is **actively rejected by the server guardrail**.
   - Use commands that execute automated test suites or application scripts consuming `APP_SECRET` (e.g., `python run_tests.py`, `pytest -k billing`).
   - The server automatically redacts secret substrings from stdout/stderr with `***REDACTED***`.
3. **Admin User Protection**: Modifying or granting permissions to the root administrative identity (`!user admin`) is strictly forbidden and rejected during policy validation.
4. **Critical Branch Protection**: The destructive replacement mode (`mode: "put"` or `mode: "replace"`) is blocked on `root` and `production` branches.

---

## Standard Workflows & Tool Chaining

### 1. Declaring and Setting Secrets
- To check existing variables before declaring a new one:
  `list_variables(search="billing")`
- To declare and immediately populate a new secret with cryptographically secure entropy:
  `create_and_set_secret(variable_id="dev/billing/db-password", length=32)`
  *(Note: If the branch is omitted, it is automatically derived from the variable ID path).*
- To retrieve non-sensitive lifecycle metadata (age, version count, last rotated timestamp):
  `get_variable_metadata(variable_id="dev/billing/db-password")`

### 2. Policy-as-Code Workflow
Always follow this 2-step verification chain:
1. **Validate First**:
   `validate_policy(yaml_content="...")`
   Inspect the report for `valid: true`, security issues, and warnings.
2. **Apply Policy**:
   `load_policy(branch="dev/billing", mode="post", yaml_content="...")`
   - Use `mode: "post"` (append) to add resources without risking deletions.
   - Use `mode: "patch"` for incremental updates.
   - Never use `mode: "put"` unless explicit replacement of a non-critical leaf branch is intended.

### 3. Workload Identity Onboarding (Least Privilege)
To onboard a new service, container, or CI/CD job:
1. Generate the least-privilege YAML policy template:
   `prepare_workload_policy(workload_id="billing-worker", branch="dev/billing", accessible_variables=["dev/billing/stripe-key"])`
2. Validate the generated YAML using `validate_policy`.
3. Load the policy using `load_policy(branch="dev/billing", mode="post", ...)`.
4. Verify the host's actual RBAC permissions:
   `check_permission(role="host:billing-worker", privilege="execute", resource="variable:dev/billing/stripe-key")`

### 4. SecOps Compliance Audits & Credential Rotation
- Find stale secrets exceeding compliance age:
  `list_secrets_for_rotation(max_age_days=90)`
- Rotate identified secret variables safely:
  `rotate_secret(variable_id="dev/billing/api-key", length=32)`
- Check host identity status and API key rotation timestamp:
  `check_host_status(host_id="test-host-1")`
- Rotate host API keys when necessary:
  `rotate_host_api_key(host_id="test-host-1")`
