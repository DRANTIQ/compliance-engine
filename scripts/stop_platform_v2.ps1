# Stop Platform V2 dev processes (API, ingest, collector workers only).
$ErrorActionPreference = "SilentlyContinue"

$patterns = @(
    "run_api.py",
    "run_ingest_worker.py",
    "run_policy_worker.py",
    "run_collector_worker.py",
    "run_phase1_local_pipeline.py"
)

Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
    Where-Object {
        $cmd = $_.CommandLine
        if (-not $cmd) { return $false }
        foreach ($p in $patterns) {
            if ($cmd -like "*$p*") { return $true }
        }
        return $false
    } |
    ForEach-Object {
        Write-Host "Stopping PID $($_.ProcessId): $($_.CommandLine.Substring(0, [Math]::Min(80, $_.CommandLine.Length)))..."
        Stop-Process -Id $_.ProcessId -Force
    }

Write-Host "Platform V2 workers stopped."
