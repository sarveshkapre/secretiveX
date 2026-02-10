$ErrorActionPreference = "Stop"

# Example Windows GUI prompt for `policy.confirm_command`.
#
# Run it via:
#   - pwsh (PowerShell 7) or
#   - powershell.exe (Windows PowerShell)
#
# Behavior:
# - exit 0 to allow signing
# - exit 1 to deny signing (including on prompt errors)

function Get-Env([string]$Name) {
  $value = [System.Environment]::GetEnvironmentVariable($Name)
  if ($null -eq $value) { return "" }
  return $value
}

$keyId = Get-Env "SECRETIVE_CONFIRM_KEY_ID"
$fingerprint = Get-Env "SECRETIVE_CONFIRM_KEY_FINGERPRINT"
$comment = Get-Env "SECRETIVE_CONFIRM_KEY_COMMENT"
$flags = Get-Env "SECRETIVE_CONFIRM_FLAGS"
$dataLen = Get-Env "SECRETIVE_CONFIRM_DATA_LEN"

$lines = @(
  "Allow SSH signing request?",
  "",
  "Key: $keyId",
  "Fingerprint: $fingerprint",
  "Comment: $comment",
  "Flags: $flags",
  "Data length: $dataLen"
)
$text = ($lines -join "`r`n")

try {
  Add-Type -AssemblyName PresentationFramework | Out-Null
  $result = [System.Windows.MessageBox]::Show($text, "SecretiveX", "YesNo", "Warning")
  if ($result -eq "Yes") { exit 0 }
  exit 1
} catch {
  # Headless sessions / services won't have a desktop to present UI.
  [Console]::Error.WriteLine("[confirm-prompt] prompt failed; denying")
  exit 1
}

