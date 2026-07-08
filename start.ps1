# start.ps1 — ThreatMap full stack launcher (Windows PowerShell)
# Run from c:\ThreatMap with: powershell -ExecutionPolicy Bypass -File start.ps1
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

# ── 1. Launch SpiderFoot Deep OSINT engine in the background ──────────────────
$sfPort = 5001
$sfRunning = netstat -ano | Select-String ":$sfPort " | Select-String "LISTENING"
if (-not $sfRunning) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting SpiderFoot API on 127.0.0.1:$sfPort ..." -ForegroundColor Magenta
    Start-Process -FilePath ".\backend\venv\Scripts\python.exe" `
        -ArgumentList ".\spiderfoot\sf.py -l 127.0.0.1:$sfPort" `
        -WorkingDirectory $PSScriptRoot `
        -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] SpiderFoot started." -ForegroundColor Green
} else {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] SpiderFoot already running on port $sfPort." -ForegroundColor Green
}

# ── 2. Auto-restarting backend loop ───────────────────────────────────────────
while ($true) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting ThreatMap backend..." -ForegroundColor Cyan
    Push-Location ".\backend"
    & ".\venv\Scripts\uvicorn.exe" main:app `
        --host 0.0.0.0 `
        --port 8000 `
        --timeout-keep-alive 75 `
        --workers 1
    Pop-Location
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Backend stopped. Restarting in 3 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
}
