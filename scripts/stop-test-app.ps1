param(
    [Parameter(Mandatory=$true)]
    [ValidateRange(1, 65535)]
    [int]$Port,

    [string]$WorkingDirectory = ".",
    [string]$TrustedHelperPath = $env:RAD_TRUSTED_PROCESS_HELPER,
    [string]$PythonExecutable = $env:RAD_TRUSTED_PYTHON,
    [string]$StateDirectory = $env:RAD_PROCESS_STATE_DIRECTORY,
    [string]$TrustKeyFile = $env:RAD_PROCESS_TRUST_KEY
)

$ErrorActionPreference = "Stop"
$project = (Resolve-Path -LiteralPath $WorkingDirectory).Path
if ([string]::IsNullOrWhiteSpace($TrustedHelperPath) -or [string]::IsNullOrWhiteSpace($PythonExecutable)) {
    throw "Trusted helper and Python executable absolute paths are required."
}
$helper = (Resolve-Path -LiteralPath $TrustedHelperPath).Path
$python = (Resolve-Path -LiteralPath $PythonExecutable).Path
if ($helper.StartsWith($project + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
    $python.StartsWith($project + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Secure process management refuses helper or interpreter code from the untrusted project."
}
if ([string]::IsNullOrWhiteSpace($StateDirectory)) {
    $StateDirectory = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "RAD\security\processes"
}
$state = (Resolve-Path -LiteralPath $StateDirectory).Path
if ([string]::IsNullOrWhiteSpace($TrustKeyFile)) {
    $TrustKeyFile = Join-Path $state "process-control.key"
}

& $python -I -B $helper stop --port "$Port" --project $project --state-directory $state --trust-key-file $TrustKeyFile
if ($LASTEXITCODE -ne 0) {
    throw "RAD refused teardown because ownership was not proven (exit $LASTEXITCODE)."
}
