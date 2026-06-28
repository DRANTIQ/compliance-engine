# Start Platform V2 dev stack: API + ingest + policy + collector.
# Config: compliance-engine/.env and platform-collectors/.env only.
param(
    [int]$ApiPort = 0
)

$ErrorActionPreference = "Stop"
$backendRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$collectorsRoot = Join-Path (Split-Path -Parent $backendRoot) "platform-collectors"
$backendEnv = Join-Path $backendRoot ".env"
$collectorsEnv = Join-Path $collectorsRoot ".env"

. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "import_dotenv.ps1")

if (-not (Test-Path "$backendRoot\.venv\Scripts\python.exe")) {
    Write-Error "Run: cd compliance-engine; python -m venv .venv; pip install -e .[dev]"
}
if (-not (Test-Path "$collectorsRoot\.venv\Scripts\python.exe")) {
    Write-Error "Run: cd platform-collectors; python -m venv .venv; pip install -e ."
}
if (-not (Import-DotEnv $backendEnv)) {
    Write-Error "Missing compliance-engine\.env — copy from .env.example"
}
if (-not (Import-DotEnv $collectorsEnv)) {
    Write-Warning "Missing platform-collectors\.env — copy from .env.example (collector uses pydantic defaults)"
}

if ($ApiPort -gt 0) {
    $env:API_PORT = "$ApiPort"
} elseif (-not $env:API_PORT) {
    $env:API_PORT = "8090"
}

if (-not $env:LOCAL_STORAGE_PATH) {
    $env:LOCAL_STORAGE_PATH = Join-Path $backendRoot "local\snapshots"
}

& "$backendRoot\scripts\stop_platform_v2.ps1"

$pythonBackend = "$backendRoot\.venv\Scripts\python.exe"
$pythonCollector = "$collectorsRoot\.venv\Scripts\python.exe"
$mockMode = if ($env:COLLECTOR_MOCK -eq "false") { "real AWS" } else { "mock" }

Write-Host "Starting ingest worker..."
Start-Process -FilePath $pythonBackend -ArgumentList "scripts/run_ingest_worker.py" -WorkingDirectory $backendRoot -WindowStyle Minimized

Start-Sleep -Seconds 2

Write-Host "Starting policy worker..."
Start-Process -FilePath $pythonBackend -ArgumentList "scripts/run_policy_worker.py" -WorkingDirectory $backendRoot -WindowStyle Minimized

Start-Sleep -Seconds 2

Write-Host "Starting collector worker ($mockMode)..."
Start-Process -FilePath $pythonCollector -ArgumentList "scripts/run_collector_worker.py" -WorkingDirectory $collectorsRoot -WindowStyle Minimized

Start-Sleep -Seconds 2

Write-Host "Starting API on port $($env:API_PORT)..."
Start-Process -FilePath $pythonBackend -ArgumentList "scripts/run_api.py" -WorkingDirectory $backendRoot -WindowStyle Minimized

Start-Sleep -Seconds 3

$port = $env:API_PORT
try {
    $health = Invoke-RestMethod -Uri "http://localhost:$port/health" -TimeoutSec 10
    $ready = Invoke-RestMethod -Uri "http://localhost:$port/ready" -TimeoutSec 10
    Write-Host "API health: $($health.status)"
    Write-Host "API ready: $($ready.status)"
    Write-Host ""
    Write-Host "Swagger: http://localhost:$port/docs"
    Write-Host "Collector: COLLECTOR_MOCK=$($env:COLLECTOR_MOCK) (set in platform-collectors/.env)"
} catch {
    Write-Warning "API not responding yet on port $port. Check python processes in Task Manager."
}
