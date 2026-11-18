# ============================================================================
# Team 14 - Network Traffic Monitoring and Alert System
# Application Launcher (PowerShell)
# ============================================================================

$WorkspaceRoot = $PSScriptRoot
Set-Location -Path $WorkspaceRoot

$PythonExe = Join-Path $WorkspaceRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $AltVenv = "$env:USERPROFILE\Downloads\d1\Network Traffic Monitoring And Alert System\.venv\Scripts\python.exe"
    if (Test-Path $AltVenv) {
        $PythonExe = $AltVenv
    } else {
        $PythonExe = "python"
    }
}

Write-Host "Starting Team 14 Network Traffic Monitoring and Alert System..." -ForegroundColor Green
Write-Host "Target Pipeline: E4 Dashboard -> PipelineCoordinator -> E1 -> E3 -> E2 -> E3 -> E4" -ForegroundColor Cyan
Write-Host "Dashboard will be available at: http://127.0.0.1:8000" -ForegroundColor Yellow

$env:PYTHONPATH = "$WorkspaceRoot;$WorkspaceRoot\E1_Concurrent_Log_Processing;$WorkspaceRoot\E3_E4_Backend\backend;$WorkspaceRoot\E2_Threat_Detection;$WorkspaceRoot\Integration\Contracts"
& $PythonExe (Join-Path $WorkspaceRoot "E3_E4_Backend\backend\main.py")
