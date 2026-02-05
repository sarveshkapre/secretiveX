param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,
    [string]$ServiceName = "SecretiveXAgent",
    [string]$PipeName = "\\.\pipe\secretive-agent"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    throw "Binary not found: $BinaryPath"
}
if (-not (Test-Path $ConfigPath)) {
    throw "Config not found: $ConfigPath"
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    throw "Service '$ServiceName' already exists. Run scripts/uninstall_windows_service.ps1 first."
}

$binary = '"' + $BinaryPath + '"'
$args = '--config "' + $ConfigPath + '" --socket "' + $PipeName + '" --no-watch'
$binPath = $binary + " " + $args

New-Service `
    -Name $ServiceName `
    -DisplayName $ServiceName `
    -BinaryPathName $binPath `
    -Description "SecretiveX SSH agent service" `
    -StartupType Automatic

sc.exe failure $ServiceName reset= 86400 actions= restart/5000 | Out-Null
Start-Service -Name $ServiceName
Write-Host "Installed and started service '$ServiceName'."
