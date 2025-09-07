[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\ListRegistryRunKeys-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [string]$KeyFilter = "",
  [string]$Arg1 = ""
)

if ($Arg1) { $KeyFilter = $Arg1 }

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
  Add-Content -Path $LogPath -Value $line -Encoding utf8
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

function To-ISO8601 {
  param($dt)
  if ($dt -and $dt -is [datetime] -and $dt.Year -gt 1900) { $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force }
  catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Check-Signature {
  param([string]$Path)
  try {
    if (-not (Test-Path $Path)) { return @{ signed = $false; trusted = $false } }
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    return @{ signed = ($sig.Status -eq 'Valid'); trusted = ($sig.SignerCertificate.Subject -like '*Microsoft*') }
  } catch { return @{ signed = $false; trusted = $false } }
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

if ($KeyFilter) { $keysToCheck = $keysToCheck | Where-Object { $_ -like "*$KeyFilter*" } }

$entries = @()

foreach ($key in $keysToCheck) {
  try {
    if (Test-Path $key) {
      $vals = Get-ItemProperty -Path $key
      foreach ($name in $vals.PSObject.Properties.Name | Where-Object { $_ -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') }) {
        $rawPath = $vals.$name
        if (-not $rawPath) { continue }
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
    Write-Log "Failed to read ${key}: $($_.Exception.Message)" 'WARN'
  }
}

$tsNow = To-ISO8601 (Get-Date)
$lines = New-Object System.Collections.ArrayList

[void]$lines.Add( (New-NdjsonLine @{
  timestamp      = $tsNow
  host           = $HostName
  action         = 'list_registry_run_keys'
  copilot_action = $true
  item           = 'summary'
  description    = 'Run summary and counts'
  entry_count    = ($entries | Measure-Object).Count
  key_filter     = $KeyFilter
}) )

if (($entries | Measure-Object).Count -eq 0) {
  $nores = New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'list_registry_run_keys'
    copilot_action = $true
    item           = 'status'
    status         = 'no_results'
    description    = 'No registry Run/RunOnce entries found'
    key_filter     = $KeyFilter
  }
  Write-NDJSONLines -JsonLines @($nores) -Path $ARLog
  Write-Log "No entries found; wrote status line to AR log" 'INFO'
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
  return
}

foreach ($e in $entries) {
  $desc = "Run entry '$($e.value_name)' at key '$($e.registry_key)' signed=$($e.signed) microsoft_trusted=$($e.trusted_microsoft)"
  [void]$lines.Add( (New-NdjsonLine @{
    timestamp         = $tsNow
    host              = $HostName
    action            = 'list_registry_run_keys'
    copilot_action    = $true
    item              = 'entry'
    description       = $desc
    registry_key      = $e.registry_key
    value_name        = $e.value_name
    command           = $e.command
    executable        = $e.executable
    signed            = $e.signed
    trusted_microsoft = $e.trusted_microsoft
  }) )
}

Write-NDJSONLines -JsonLines $lines -Path $ARLog
Write-Log ("Wrote {0} NDJSON record(s) to {1}" -f $lines.Count, $ARLog) 'INFO'
$dur = [int]((Get-Date) - $runStart).TotalSeconds
Write-Log "=== SCRIPT END : duration ${dur}s ==="
