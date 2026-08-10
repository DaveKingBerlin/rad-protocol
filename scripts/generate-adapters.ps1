param([switch]$Check,[string]$Runtime="all")
$ErrorActionPreference="Stop"
$argsList=@()
if ($Check) { $argsList += "--check" }
if ($Runtime -eq "all") { $argsList += "--all" } else { $argsList += @("--runtime",$Runtime) }
python "$PSScriptRoot\..\tools\generate_adapters.py" @argsList
exit $LASTEXITCODE
