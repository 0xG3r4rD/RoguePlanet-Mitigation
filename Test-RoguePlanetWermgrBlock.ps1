<#
.SYNOPSIS
Safely tests the RoguePlanet fake wermgr.exe AppLocker mitigation.

.DESCRIPTION
This does not run the RoguePlanet PoC. It copies a benign Windows binary to a
temporary path named wermgr.exe, attempts to launch it, and records whether
AppLocker blocked it.
#>

[CmdletBinding()]
param(
    [string]$LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $LogPath) {
    $basePath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $LogPath = Join-Path $basePath 'RoguePlanet-Mitigation-Test.log'
}

function Write-Log {
    param([string]$Message)

    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $line | Tee-Object -FilePath $LogPath -Append
}

function Get-AppLockerExeEvents {
    param(
        [datetime]$StartTime,
        [string]$Path
    )

    $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'
    $leaf = Split-Path -Leaf $Path
    $parentLeaf = Split-Path -Leaf (Split-Path -Parent $Path)
    try {
        Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $StartTime } -ErrorAction Stop |
            Where-Object {
                ($_.Message -like "*$Path*") -or
                (($_.Message -like "*$leaf*") -and ($_.Message -like "*$parentLeaf*"))
            } |
            Select-Object TimeCreated, Id, ProviderName, Message
    }
    catch {
        Write-Log "Could not read AppLocker event log: $($_.Exception.Message)"
        @()
    }
}

Remove-Item -LiteralPath $LogPath -Force -ErrorAction SilentlyContinue

$testRoot = Join-Path $env:TEMP ('RoguePlanet-Mitigation-Test-{0}' -f [guid]::NewGuid().ToString('N'))
$testExe = Join-Path $testRoot 'wermgr.exe'
$sourceExe = Join-Path $env:WINDIR 'System32\cmd.exe'
$startTime = Get-Date

Write-Log 'Starting safe fake wermgr.exe mitigation test.'
Write-Log "Test path: $testExe"
Write-Log "Source binary: $sourceExe"

try {
    New-Item -Path $testRoot -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $sourceExe -Destination $testExe -Force

    Write-Log 'Attempting to execute benign temp-path wermgr.exe.'
    try {
        $process = Start-Process -FilePath $testExe -ArgumentList '/c', 'exit 0' -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
        Write-Log "RESULT: EXECUTED. Process exited with code $($process.ExitCode). The mitigation did not block this launch."
    }
    catch {
        $nativeErrorProperty = $_.Exception.PSObject.Properties['NativeErrorCode']
        $nativeCode = if ($nativeErrorProperty) { $nativeErrorProperty.Value } else { 'n/a' }
        Write-Log "RESULT: BLOCKED_OR_FAILED. Exception: $($_.Exception.Message)"
        Write-Log "Native error code: $nativeCode"
    }

    Start-Sleep -Seconds 2
    $events = @(Get-AppLockerExeEvents -StartTime $startTime.AddSeconds(-5) -Path $testExe)
    if ($events.Count -eq 0) {
        Write-Log 'No matching AppLocker EXE/DLL events were found for the test path.'
    }
    else {
        Write-Log "Matching AppLocker events: $($events.Count)"
        foreach ($event in $events) {
            Write-Log ('Event {0} at {1}: {2}' -f $event.Id, $event.TimeCreated, ($event.Message -replace '\s+', ' ').Trim())
        }
    }
}
finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log 'Cleaned up test files.'
    Write-Log "Log written to: $LogPath"
}
