param(
    [Parameter(Mandatory=$true)]
    [int]$Port
)

$ErrorActionPreference = "Continue"

$metaPath = "e2e/artifacts/processes/test-app-$Port.json"
if (-not (Test-Path $metaPath)) {
    Write-Host "No ADAS process metadata found for port $Port. Refusing to kill an unknown process."
    exit 1
}

$meta = Get-Content $metaPath -Raw | ConvertFrom-Json
$rootPid = [int]$meta.root_pid
$listenerPid = [int]$meta.listener_pid
$owned = @($meta.owned_pids | ForEach-Object { [int]$_ }) | Sort-Object -Unique

# Prefer terminating the exact recorded root tree. This is safer than killing by
# executable name and usually includes npm/cmd/node descendants.
$rootProc = Get-Process -Id $rootPid -ErrorAction SilentlyContinue
if ($rootProc) {
    taskkill /PID $rootPid /T /F | Out-Null
    Start-Sleep -Milliseconds 500
}

# A listener may have detached from the wrapper. Kill it only if it was explicitly
# recorded as owned by this run.
foreach ($pidValue in $owned) {
    $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($proc) {
        Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
    }
}

Start-Sleep -Milliseconds 500
$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    $remainingPid = [int]($listener | Select-Object -First 1).OwningProcess
    Write-Host "WARNING: port $Port remains occupied by PID $remainingPid."
    Write-Host "Refusing to kill it because ownership after teardown is not proven."
    exit 2
}

Remove-Item $metaPath -Force -ErrorAction SilentlyContinue
Write-Host "Stopped recorded ADAS process tree; port $Port is free."
