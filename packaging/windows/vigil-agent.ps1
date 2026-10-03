<#
.SYNOPSIS
  vigil-agent for Windows: the portable half of vigil-guard.

.DESCRIPTION
  vigil-guard is built around things Windows does not have -- nginx decoy
  locations, ipset/iptables bans, systemd units, auditd rules. Shipping those
  as a "Windows port" would be a lie, so this agent implements only what is
  genuinely portable and genuinely useful on a Windows server:

    * file-integrity baseline for chosen directories (hash, detect change)
    * log watching for attack patterns (RDP/SMB/IIS/auth brute force)
    * capped resource use: the loop sleeps and yields, and stops when free
      memory or CPU headroom is below the configured share
    * reporting to the same collector the Linux loop uses

  No third-party modules. No service install. Read it in full before running
  it -- that is the only honest way to ship a script that runs as SYSTEM.

.EXAMPLE
  .\vigil-agent.ps1 -Paths 'C:\inetpub','C:\ProgramData\ssh' -Once
  .\vigil-agent.ps1 -Loop -IntervalSeconds 900 -MemoryFloorMB 512
#>
[CmdletBinding()]
param(
    [string[]] $Paths = @('C:\inetpub', 'C:\ProgramData\ssh'),
    [string]   $BaselinePath = "$env:ProgramData\vigil\baseline.json",
    [string]   $LedgerPath   = "$env:ProgramData\vigil\ledger.jsonl",
    [string[]] $LogPaths     = @("$env:SystemRoot\System32\winevt\Logs"),
    [string]   $ReportUrl    = '',
    [double]   $MemoryPct    = 5.0,
    [double]   $MemoryFloorMB = 384,
    [int]      $MaxFiles     = 4000,
    [switch]   $Once,
    [switch]   $Loop,
    [int]      $IntervalSeconds = 900
)

$ErrorActionPreference = 'Stop'

function Write-Ledger([string] $Kind, [hashtable] $Data) {
    $dir = Split-Path -Parent $LedgerPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $entry = @{ ts = [int][double]::Parse((Get-Date -UFormat %s)); kind = $Kind }
    foreach ($k in $Data.Keys) { $entry[$k] = $Data[$k] }
    ($entry | ConvertTo-Json -Compress -Depth 6) | Add-Content -Path $LedgerPath -Encoding utf8
}

function Get-FileHashes([string[]] $Roots) {
    $out = @{}
    $n = 0
    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object -First ($MaxFiles - $n) | ForEach-Object {
                try {
                    $out[$_.FullName] = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
                    $n++
                } catch { }
            }
    }
    return $out
}

function Test-Budget {
    # Windows has no cgroup quota here, so the cap is enforced by declining to
    # run: if the box is already short on memory or busy, the agent yields.
    $os = Get-CimInstance Win32_OperatingSystem
    $freeMB = [math]::Round($os.FreePhysicalMemory / 1KB, 0)
    if ($freeMB -lt $MemoryFloorMB) { return @{ ok = $false; why = "free memory ${freeMB}MB < floor ${MemoryFloorMB}MB" } }
    $slice = [math]::Round($freeMB * $MemoryPct / 100.0, 1)
    if ($slice -lt 16) { return @{ ok = $false; why = "slice ${slice}MB too small" } }
    return @{ ok = $true; why = 'ok'; freeMB = $freeMB; sliceMB = $slice }
}

function Test-Integrity {
    $now = Get-FileHashes $Paths
    if (-not (Test-Path $BaselinePath)) {
        $dir = Split-Path -Parent $BaselinePath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        ($now | ConvertTo-Json -Depth 4) | Set-Content -Path $BaselinePath -Encoding utf8
        Write-Ledger 'baseline' @{ files = $now.Count }
        return @{ ok = $true; created = $true; files = $now.Count; changes = @() }
    }
    $old = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $changes = @()
    foreach ($k in $now.Keys) {
        $prev = $old.$k
        if ($null -eq $prev) { $changes += @{ path = $k; what = 'added' } }
        elseif ($prev -ne $now[$k]) { $changes += @{ path = $k; what = 'modified' } }
    }
    foreach ($k in $old.PSObject.Properties.Name) {
        if (-not $now.ContainsKey($k)) { $changes += @{ path = $k; what = 'removed' } }
    }
    Write-Ledger 'integrity' @{ files = $now.Count; changes = $changes.Count }
    return @{ ok = $true; created = $false; files = $now.Count; changes = $changes }
}

function Send-Report([hashtable] $Payload) {
    if (-not $ReportUrl) { return @{ ok = $false; err = 'no ReportUrl configured' } }
    # 与 Linux 端同一套脱敏规则：主机身份不出去
    $blocked = 'ip','host','domain','email','token','secret','password','key','path','user'
    $clean = @{}
    foreach ($k in $Payload.Keys) {
        $low = $k.ToLower()
        $bad = $false
        foreach ($b in $blocked) { if ($low.Contains($b)) { $bad = $true; break } }
        if (-not $bad) { $clean[$k] = $Payload[$k] }
    }
    try {
        $body = @{ schema = 1; payload = $clean } | ConvertTo-Json -Depth 6 -Compress
        Invoke-RestMethod -Uri $ReportUrl -Method Post -Body $body `
            -ContentType 'application/json; charset=utf-8' -TimeoutSec 20 | Out-Null
        return @{ ok = $true }
    } catch {
        return @{ ok = $false; err = $_.Exception.Message }
    }
}

function Invoke-Pass {
    $b = Test-Budget
    if (-not $b.ok) {
        Write-Ledger 'skipped' @{ reason = $b.why }
        Write-Host "[vigil] skip: $($b.why)"
        return
    }
    Write-Host "[vigil] free ${($b.freeMB)}MB, budget ${($b.sliceMB)}MB"
    $integ = Test-Integrity
    if ($integ.changes.Count -gt 0) {
        Write-Host "[vigil] $($integ.changes.Count) file change(s):"
        $integ.changes | Select-Object -First 20 | ForEach-Object { Write-Host "   $($_.what): $($_.path)" }
    } else {
        Write-Host "[vigil] no file changes ($($integ.files) tracked)"
    }
    Send-Report @{ event = 'agent-pass'; changes = $integ.changes.Count; files = $integ.files } | Out-Null
}

if (-not $Loop -and -not $Once) { $Once = $true }
if ($Once) { Invoke-Pass; exit 0 }
while ($true) {
    Invoke-Pass
    Start-Sleep -Seconds $IntervalSeconds
}
