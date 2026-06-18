<#
.SYNOPSIS
Removes the RoguePlanet fake wermgr.exe AppLocker mitigation.

.DESCRIPTION
Removes only the AppLocker rules created by Add-RoguePlanetWermgrBlock.ps1 and
the related compatibility adjustments that were added while testing this
mitigation. Unrelated AppLocker rules are preserved.

The script writes a backup of the current local AppLocker policy before applying
the rollback.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PolicyDirectory = "$env:ProgramData\RoguePlanet-Mitigation",

    [switch]$LeaveAppIdSvcRunning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ruleIdsToRemove = @(
    '2F5E8B9F-3A28-4D3D-95CB-64120E18F9E8', # Compatibility Allow - All users - All executables
    '65D1A7D2-64D8-4AF2-8B39-E6B97B5C0A9D', # Compatibility Allow - All users - All packaged apps
    '9F73CF05-9795-45DF-A4FA-6593B2F01016', # Compatibility Allow - Microsoft Teams packaged app
    'A86E4D7E-2147-46F0-B5AF-A7F9670A3D71', # Legacy default allow - Administrators
    '0D2EA50A-92BC-47C4-B544-9980E80EB90A', # Legacy default allow - Windows directory
    '50B3D746-23E2-40D9-8461-42D0D987F4F7', # Legacy default allow - Program Files
    'F3451271-AB52-45F5-A34D-6779E6516343'  # RoguePlanet mitigation - block fake wermgr.exe
) | ForEach-Object { $_.ToLowerInvariant() }

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell prompt.'
}

if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
    throw 'The AppLocker PowerShell module is not available on this system.'
}

function Get-AppLockerRuleNodes {
    param([xml]$Policy)

    @($Policy.AppLockerPolicy.RuleCollection |
        ForEach-Object { $_.ChildNodes } |
        Where-Object { $_.NodeType -eq 'Element' -and $_.GetAttribute('Id') })
}

New-Item -Path $PolicyDirectory -ItemType Directory -Force | Out-Null

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupPath = Join-Path $PolicyDirectory "Rollback-Backup-$timestamp.xml"
$rollbackPath = Join-Path $PolicyDirectory "Rollback-Policy-$timestamp.xml"

$currentXml = Get-AppLockerPolicy -Local -Xml
$currentXml | Set-Content -Path $backupPath -Encoding UTF8

[xml]$policy = $currentXml
$removedRules = New-Object System.Collections.Generic.List[string]

foreach ($collection in @($policy.AppLockerPolicy.RuleCollection)) {
    foreach ($rule in @($collection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })) {
        $ruleId = $rule.GetAttribute('Id').ToLowerInvariant()
        if ($ruleIdsToRemove -contains $ruleId) {
            $removedRules.Add(('{0} [{1}]' -f $rule.GetAttribute('Name'), $rule.GetAttribute('Id')))
            [void]$collection.RemoveChild($rule)
        }
    }
}

foreach ($collection in @($policy.AppLockerPolicy.RuleCollection)) {
    $remainingRules = @($collection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })
    if ($remainingRules.Count -eq 0) {
        [void]$policy.AppLockerPolicy.RemoveChild($collection)
    }
}

$policy.OuterXml | Set-Content -Path $rollbackPath -Encoding UTF8

if ($removedRules.Count -eq 0) {
    Write-Host 'No RoguePlanet mitigation rules were found in the local AppLocker policy.'
    Write-Host "Backup written to: $backupPath"
    return
}

if ($PSCmdlet.ShouldProcess('local AppLocker policy', "remove $($removedRules.Count) RoguePlanet mitigation rule(s)")) {
    Set-AppLockerPolicy -XmlPolicy $rollbackPath

    $remainingRuleCount = @(Get-AppLockerRuleNodes -Policy $policy).Count
    if (-not $LeaveAppIdSvcRunning -and $remainingRuleCount -eq 0) {
        Stop-Service -Name AppIDSvc -ErrorAction SilentlyContinue
        try {
            Set-Service -Name AppIDSvc -StartupType Manual -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not reset AppIDSvc startup type: $($_.Exception.Message)"
        }
    }
}

Write-Host "Backup written to: $backupPath"
Write-Host "Rollback policy written to: $rollbackPath"
Write-Host "Removed rules:"
foreach ($removedRule in $removedRules) {
    Write-Host " - $removedRule"
}
