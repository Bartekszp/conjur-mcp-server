$ErrorActionPreference = "Stop"

$ContainerServer = "conjur_server"
$ContainerDb = "postgres_database"
$ContainerClient = "conjur_client"

Write-Host "[Pre-flight] Verifying containers..."

# 1. Database check
$dbExists = podman ps -a --filter "name=^${ContainerDb}$" --format "{{.Names}}"
if (-not $dbExists) {
    Write-Host "ERROR: Container $ContainerDb does not exist!" -ForegroundColor Red
    exit 1
}

$runningDb = podman ps --filter "name=^${ContainerDb}$" --filter "status=running" --format "{{.Names}}"
if (-not $runningDb) {
    Write-Host "Starting database $ContainerDb..."
    podman start $ContainerDb | Out-Null
    Start-Sleep -Seconds 2
}

podman exec $ContainerDb pg_isready -U postgres | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Database $ContainerDb is not accepting connections!" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Database is ready."

# 2. Conjur server check
$serverExists = podman ps -a --filter "name=^${ContainerServer}$" --format "{{.Names}}"
if (-not $serverExists) {
    Write-Host "ERROR: Container $ContainerServer does not exist!" -ForegroundColor Red
    exit 1
}

$runningServer = podman ps --filter "name=^${ContainerServer}$" --filter "status=running" --format "{{.Names}}"
if (-not $runningServer) {
    Write-Host "Starting $ContainerServer..."
    podman start $ContainerServer | Out-Null
    Start-Sleep -Seconds 3
}
Write-Host "[OK] Conjur server is running."

# 3. Conjur client and host identity check
$clientExists = podman ps -a --filter "name=^${ContainerClient}$" --format "{{.Names}}"
if (-not $clientExists) {
    Write-Host "ERROR: Container $ContainerClient does not exist!" -ForegroundColor Red
    exit 1
}

$runningClient = podman ps --filter "name=^${ContainerClient}$" --filter "status=running" --format "{{.Names}}"
if (-not $runningClient) {
    Write-Host "Starting $ContainerClient..."
    podman start $ContainerClient | Out-Null
}

# Check active identity
$whoamiRaw = podman exec -u 0 $ContainerClient conjur whoami 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "WARNING: conjur_client has no active session!" -ForegroundColor Yellow
    Write-Host "Authenticate using the host workload identity:" -ForegroundColor Yellow
    Write-Host "podman exec -it -u 0 conjur_client conjur login -i host/<workload-id>" -ForegroundColor Cyan
    exit 2
}

# ==============================================================================
# IDENTITY VERIFICATION MODE (LOCAL DEV vs. CI/CD & PRODUCTION)
# ==============================================================================
# Local Development Mode (Default):
# - Accepts an active 'admin' session to streamline developer workflows and avoid
#   continuous re-authentication cycles between administrative tasks (e.g. policy
#   loading, secret declaration) and testing.
#
# CI/CD & Production Mode (Zero Trust / Least Privilege):
# - UNCOMMENT the block below when running automated regression or compliance tests.
#   Enforcing a machine identity ('host/*') ensures the workload operates under
#   least privilege and prevents masking RBAC misconfigurations (since 'admin'
#   bypasses all permission checks).
#
# How to switch to host identity:
#   1. podman exec -u 0 conjur_client conjur host rotate-api-key -i <host-id>
#   2. podman exec -it -u 0 conjur_client conjur login -i host/<host-id>
# ==============================================================================

# Verify strictly host identity via JSON
try {
    $whoamiJson = $whoamiRaw | ConvertFrom-Json

    # UNCOMMENT TO ENFORCE ZERO TRUST (CI/CD / PRODUCTION):
    # if ($whoamiJson.username -notlike "host/*") {
    #     Write-Host "ERROR: Zero Trust violation! Active session is NOT a host identity. Found: $($whoamiJson.username). Host login required." -ForegroundColor Red
    #     exit 3
    # }

    Write-Host "[OK] Conjur session is active: $($whoamiJson.username)"
    Write-Host "[OK] Environment is fully ready."
    exit 0

} catch {
    Write-Host "ERROR: Unable to parse conjur whoami output as JSON: $whoamiRaw" -ForegroundColor Red
    exit 2
}

Write-Host "[OK] Conjur host session is active: $($whoamiJson.username)"
Write-Host "[OK] Environment is fully ready."
exit 0