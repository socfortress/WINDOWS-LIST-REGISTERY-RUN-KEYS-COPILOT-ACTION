[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\ListRegistryRunKeys-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep  = 5
$runStart = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length/1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"
        $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Check-Signature {
  param([string]$Path)
  try {
    if (-not (Test-Path $Path)) { return @{ signed = $false; trusted = $false } }
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    return @{
      signed  = ($sig.Status -eq 'Valid')
      trusted = ($sig.SignerCertificate.Subject -like '*Microsoft*')
    }
  } catch {
    return @{ signed = $false; trusted = $false }
  }
}

Rotate-Log
Write-Log "=== SCRIPT START : List Registry Run Keys ==="

$keysToCheck = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)

$entries = @()

foreach ($key in $keysToCheck) {
  try {
    if (Test-Path $key) {
      $vals = Get-ItemProperty -Path $key
      foreach ($name in $vals.PSObject.Properties.Name | Where-Object { $_ -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') }) {
        $rawPath = $vals.$name
        if (-not $rawPath) { continue }
        # Try to extract the executable path (handles quoted and unquoted)
        $exe = $rawPath
        if ($exe -match '^\s*"(.*?)"') { $exe = $Matches[1] } else { $exe = ($exe -split '\s+')[0] }
        $sigInfo = Check-Signature -Path $exe
        $entries += [PSCustomObject]@{
          registry_key      = $key
          value_name        = $name
          command           = $rawPath
          executable        = $exe
          signed            = $sigInfo.signed
          trusted_microsoft = $sigInfo.trusted
        }
      }
    }
  } catch {
    Write-Log "Failed to read ${key}: $_" 'WARN'
  }
}

# Build NDJSON: summary + one line per entry
$timestamp = (Get-Date).ToString('o')
$lines = @()

$lines += ([pscustomobject]@{
  timestamp      = $timestamp
  host           = $HostName
  action         = "list_registry_run_keys_summary"
  entry_count    = $entries.Count
  copilot_action = $true
} | ConvertTo-Json -Compress -Depth 3)

foreach ($e in $entries) {
  $lines += ([pscustomobject]@{
    timestamp         = $timestamp
    host              = $HostName
    action            = "list_registry_run_keys"
    registry_key      = $e.registry_key
    value_name        = $e.value_name
    command           = $e.command
    executable        = $e.executable
    signed            = $e.signed
    trusted_microsoft = $e.trusted_microsoft
    copilot_action    = $true
  } | ConvertTo-Json -Compress -Depth 4)
}

$ndjson  = [string]::Join("`n", $lines)
$tempFile = "$env:TEMP\arlog.tmp"
Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force

$recordCount = $lines.Count
try {
  Move-Item -Path $tempFile -Destination $ARLog -Force
  Write-Log "Wrote $recordCount NDJSON record(s) to $ARLog" 'INFO'
} catch {
  Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
  Write-Log "ARLog locked; wrote to $($ARLog).new" 'WARN'
}

$dur = [int]((Get-Date) - $runStart).TotalSeconds
Write-Log "=== SCRIPT END : duration ${dur}s ==="
