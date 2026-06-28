# Start Platform V2 with real AWS collector.
# Requires AWS_* hub creds in platform-collectors/.env (account 744698194074).
param(
    [int]$ApiPort = 0,
    [switch]$UseS3
)

$ErrorActionPreference = "Stop"
$backendRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$collectorsRoot = Join-Path (Split-Path -Parent $backendRoot) "platform-collectors"
$collectorsEnv = Join-Path $collectorsRoot ".env"

. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "import_dotenv.ps1")

if (-not (Test-Path $collectorsEnv)) {
    Write-Error "Missing platform-collectors\.env — copy from .env.example and set AWS_* hub creds"
}

Import-DotEnv (Join-Path $backendRoot ".env") | Out-Null
Import-DotEnv $collectorsEnv | Out-Null

if (-not $env:AWS_ACCESS_KEY_ID -or -not $env:AWS_SECRET_ACCESS_KEY) {
    Write-Error "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in platform-collectors\.env"
}

$env:COLLECTOR_MOCK = "false"
$env:AWS_EC2_METADATA_DISABLED = "true"
if (-not $env:AWS_DEFAULT_REGION) {
    $env:AWS_DEFAULT_REGION = "us-east-1"
}

if ($UseS3) {
    $env:USE_LOCAL_STORAGE = "false"
    if (-not $env:S3_BUCKET) { $env:S3_BUCKET = "steampipe-data-storage" }
    if (-not $env:S3_REGION) { $env:S3_REGION = "us-east-1" }
    if (-not $env:S3_PREFIX) { $env:S3_PREFIX = "platform-v2" }
} else {
    $env:USE_LOCAL_STORAGE = "true"
    if (-not $env:LOCAL_STORAGE_PATH) {
        $env:LOCAL_STORAGE_PATH = Join-Path $backendRoot "local\snapshots"
    }
}

if ($ApiPort -gt 0) {
    $env:API_PORT = "$ApiPort"
}

& "$backendRoot\scripts\stop_platform_v2.ps1"

$pythonBackend = "$backendRoot\.venv\Scripts\python.exe"
$pythonCollector = "$collectorsRoot\.venv\Scripts\python.exe"

Write-Host "Hub AWS identity (744698194074 expected):"
& $pythonBackend -c "import boto3; i=boto3.client('sts').get_caller_identity(); print(i.get('Account'), i.get('Arn'))"

Write-Host "Starting ingest worker..."
Start-Process -FilePath $pythonBackend -ArgumentList "scripts/run_ingest_worker.py" -WorkingDirectory $backendRoot -WindowStyle Minimized

Start-Sleep -Seconds 2

Write-Host "Starting policy worker..."
Start-Process -FilePath $pythonBackend -ArgumentList "scripts/run_policy_worker.py" -WorkingDirectory $backendRoot -WindowStyle Minimized

Start-Sleep -Seconds 2

Write-Host "Starting collector worker (REAL AWS)..."
Start-Process -FilePath $pythonCollector -ArgumentList "scripts/run_collector_worker.py" -WorkingDirectory $collectorsRoot -WindowStyle Minimized

Start-Sleep -Seconds 2

$port = if ($env:API_PORT) { $env:API_PORT } else { "8090" }
Write-Host "Starting API on port $port..."
Start-Process -FilePath $pythonBackend -ArgumentList "scripts/run_api.py" -WorkingDirectory $backendRoot -WindowStyle Minimized

Start-Sleep -Seconds 3

try {
    $health = Invoke-RestMethod -Uri "http://localhost:$port/health" -TimeoutSec 10
    $ready = Invoke-RestMethod -Uri "http://localhost:$port/ready" -TimeoutSec 10
    Write-Host "API health: $($health.status)"
    Write-Host "API ready: $($ready.status)"
    Write-Host ""
    Write-Host "Mode: REAL collector | local storage: $($env:USE_LOCAL_STORAGE -eq 'true')"
    Write-Host "Trigger scan: UI Scans -> Run scan  OR  python scripts/run_phase2_e2e.py"
} catch {
    Write-Warning "API not responding yet on port $port."
}
