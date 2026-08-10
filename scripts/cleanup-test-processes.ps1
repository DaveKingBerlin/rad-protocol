param()
$dir="e2e/artifacts/processes"
if(-not(Test-Path $dir)){Write-Host "No ADAS process metadata.";exit 0}

Get-ChildItem $dir -Filter "test-app-*.json" -File | ForEach-Object {
    try {
        $m = Get-Content $_.FullName -Raw | ConvertFrom-Json

        # Current metadata schema records all process identities explicitly.
        $recorded = @()
        if ($null -ne $m.owned_pids) {
            $recorded += @($m.owned_pids | ForEach-Object { [int]$_ })
        }
        if ($null -ne $m.root_pid) { $recorded += [int]$m.root_pid }
        if ($null -ne $m.listener_pid) { $recorded += [int]$m.listener_pid }

        # Backward-compatible read only for older metadata. Never infer ownership.
        if ($recorded.Count -eq 0 -and $null -ne $m.pid) {
            $recorded += [int]$m.pid
        }

        $recorded = @($recorded | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
        $alive = @($recorded | Where-Object {
            $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue)
        })

        if ($alive.Count -gt 0) {
            Write-Host "Recorded ADAS process PID(s) $($alive -join ', ') still exist; leaving metadata untouched."
        } else {
            Remove-Item $_.FullName -Force
            Write-Host "Removed stale metadata $($_.Name)"
        }
    } catch {
        Write-Host "Could not process $($_.FullName): $($_.Exception.Message)"
    }
}
