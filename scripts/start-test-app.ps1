param(
    [Parameter(Mandatory=$true)]
    [string]$Command,

    [Parameter(Mandatory=$true)]
    [ValidateRange(1, 65535)]
    [int]$Port,

    [string]$ReadyUrl = "",
    [string]$WorkingDirectory = ".",
    [string]$TrustedHelperPath = $env:RAD_TRUSTED_PROCESS_HELPER,
    [string]$PythonExecutable = $env:RAD_TRUSTED_PYTHON,
    [string]$StateDirectory = $env:RAD_PROCESS_STATE_DIRECTORY,
    [string]$TrustKeyFile = $env:RAD_PROCESS_TRUST_KEY,
    [string[]]$Environment = @()
)

$ErrorActionPreference = "Stop"
$project = (Resolve-Path -LiteralPath $WorkingDirectory).Path

if ([string]::IsNullOrWhiteSpace($TrustedHelperPath)) {
    throw "RAD_TRUSTED_PROCESS_HELPER is required. Use the absolute helper path from the trusted RAD installation."
}
if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    throw "RAD_TRUSTED_PYTHON is required. Secure process management never resolves Python through project-controlled PATH."
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
[System.IO.Directory]::CreateDirectory($StateDirectory) | Out-Null
$state = (Resolve-Path -LiteralPath $StateDirectory).Path
if ([string]::IsNullOrWhiteSpace($TrustKeyFile)) {
    $TrustKeyFile = Join-Path $state "process-control.key"
}

$arguments = @(
    "-I", "-B",
    $helper,
    "start",
    "--command", $Command,
    "--port", "$Port",
    "--project", $project,
    "--working-directory", $project,
    "--state-directory", $state,
    "--trust-key-file", $TrustKeyFile
)
if (-not [string]::IsNullOrWhiteSpace($ReadyUrl)) {
    $arguments += @("--ready-url", $ReadyUrl)
}
foreach ($entry in $Environment) {
    $arguments += @("--environment", $entry)
}

& $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Trusted RAD process guardian failed with exit code $LASTEXITCODE."
}
