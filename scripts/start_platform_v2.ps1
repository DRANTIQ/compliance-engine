# Start Platform V2 dev stack: API + ingest worker + collector (mock/local).
param(
    [int]$ApiPort = 8090
)

$ErrorActionPreference = "Stop"
$backendRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$collectorsRoot = Join-Path (Split-Path -Parent $backendRoot) "platform-collectors"
$steampipeEnv = Join-Path (Split-Path -Parent $backendRoot) "steampipe\.env"

if (-not (Test-Path "$backendRoot\.venv\Scripts\python.exe")) {
    Write-Error "Run: cd compliance-engine; python -m venv .venv; pip install -e .[dev]"
}
if (-not (Test-Path "$collectorsRoot\.venv\Scripts\python.exe")) {
    Write-Error "Run: cd platform-collectors; python -m venv .venv; pip install -e ."
}

& "$backendRoot\scripts\stop_platform_v2.ps1"

if (Test-Path $steampipeEnv) {
    $dbLine = Get-Content $steampipeEnv | Where-Object { $_ -match '^DATABASE_URL=' } | Select-Object -First 1
    if ($dbLine) {
        $url = ($dbLine -replace '^DATABASE_URL=', '').Trim()
        if ($url -notmatch 'sslmode=') { $url += '?sslmode=require' }
        $env:DATABASE_URL = $url
    }
}

$env:REDIS_URL = "redis://localhost:6379/0"
$env:EXTERNAL_ID_ENCRYPTION_KEY = "dev-local-key-change-before-prod"
$env:USE_LOCAL_STORAGE = "true"
$env:LOCAL_STORAGE_PATH = Join-Path $backendRoot "local\snapshots"
$env:COLLECTOR_MOCK = "true"
$env:API_PORT = "$ApiPort"
$env:PLATFORM_EVENTS_KEY = "platform:events"
$env:COLLECT_QUEUE_KEY = "platform:collect.aws"
$env:POLICY_QUEUE_KEY = "platform:policy.evaluate"

$pythonBackend = "$backendRoot\.venv\Scripts\python.exe"
$pythonCollector = "$collectorsRoot\.venv\Scripts\python.exe"

Write-Host "Starting ingest worker..."
Start-Process -FilePath $pythonBackend -ArgumentList "scripts/run_ingest_worker.py" -WorkingDirectory $backendRoot -WindowStyle Minimized

Start-Sleep -Seconds 2

Write-Host "Starting policy worker..."
Start-Process -FilePath $pythonBackend -ArgumentList "scripts/run_policy_worker.py" -WorkingDirectory $backendRoot -WindowStyle Minimized

Start-Sleep -Seconds 2

Write-Host "Starting collector worker (mock)..."
Start-Process -FilePath $pythonCollector -ArgumentList "scripts/run_collector_worker.py" -WorkingDirectory $collectorsRoot -WindowStyle Minimized

Start-Sleep -Seconds 2

Write-Host "Starting API on port $ApiPort..."
Start-Process -FilePath $pythonBackend -ArgumentList "scripts/run_api.py" -WorkingDirectory $backendRoot -WindowStyle Minimized

Start-Sleep -Seconds 3

try {
    $health = Invoke-RestMethod -Uri "http://localhost:$ApiPort/health" -TimeoutSec 10
    $ready = Invoke-RestMethod -Uri "http://localhost:$ApiPort/ready" -TimeoutSec 10
    Write-Host "API health: $($health.status)"
    Write-Host "API ready: $($ready.status)"
    Write-Host ""
    Write-Host "Swagger: http://localhost:$ApiPort/docs"
    Write-Host "Use X-Tenant-ID header (seed via: python scripts/seed_dev_tenant.py)"
} catch {
    Write-Warning "API not responding yet on port $ApiPort. Check python processes in Task Manager."
}
