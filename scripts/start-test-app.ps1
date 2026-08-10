param(
    [Parameter(Mandatory=$true)]
    [string]$Command,

    [Parameter(Mandatory=$true)]
    [int]$Port,

    [string]$ReadyUrl = "",

    [string]$WorkingDirectory = "."
)

$ErrorActionPreference = "Stop"

$artifactDir = "e2e/artifacts/processes"
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null

$existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    throw "Port $Port is already in use. Refusing to kill or reuse an unrelated process."
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "cmd.exe"
$psi.Arguments = "/d /s /c `"$Command`""
$psi.WorkingDirectory = (Resolve-Path $WorkingDirectory).Path
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$root = [System.Diagnostics.Process]::Start($psi)
$rootPid = $root.Id

$deadline = (Get-Date).AddSeconds(45)
$listenerPid = $null
$ready = $false

while ((Get-Date) -lt $deadline) {
    if ($ReadyUrl) {
        try {
            $response = Invoke-WebRequest -Uri $ReadyUrl -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                $ready = $true
            }
        } catch {}
    }

    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listener) {
        $listenerPid = [int]$listener.OwningProcess
        if (-not $ReadyUrl) { $ready = $true }
    }

    if ($ready -and $listenerPid) { break }
    if ($root.HasExited -and -not $listenerPid) {
        throw "Root launcher exited before a listener appeared. Exit code: $($root.ExitCode)"
    }
    Start-Sleep -Milliseconds 250
}

if (-not $ready -or -not $listenerPid) {
    try { taskkill /PID $rootPid /T /F | Out-Null } catch {}
    throw "Application did not become ready with an identifiable listener on port $Port."
}

function Get-Descendants([int]$ParentPid) {
    $result = New-Object System.Collections.Generic.List[int]
    $queue = New-Object System.Collections.Generic.Queue[int]
    $queue.Enqueue($ParentPid)
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$current" -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            $id = [int]$child.ProcessId
            if (-not $result.Contains($id)) {
                $result.Add($id)
                $queue.Enqueue($id)
            }
        }
    }
    return @($result)
}

$descendants = @(Get-Descendants $rootPid)
if ($listenerPid -ne $rootPid -and $listenerPid -notin $descendants) {
    # The listener may have detached from the wrapper. Record it explicitly, but
    # do not infer ownership of unrelated port users because the port was free
    # immediately before this run started.
    $descendants += $listenerPid
}

$meta = @{
    root_pid = $rootPid
    listener_pid = $listenerPid
    owned_pids = @($rootPid) + @($descendants | Sort-Object -Unique)
    port = $Port
    command = $Command
    started_at = (Get-Date).ToString("o")
}
$metaPath = Join-Path $artifactDir ("test-app-{0}.json" -f $Port)
$meta | ConvertTo-Json -Depth 4 | Set-Content -Path $metaPath -Encoding UTF8

Write-Host "Started test application. Root PID $rootPid; listener PID $listenerPid; port $Port"
Write-Host "Ownership metadata: $metaPath"
