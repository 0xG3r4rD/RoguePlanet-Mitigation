<#
.SYNOPSIS
Adds a local AppLocker mitigation for RoguePlanet-style fake wermgr.exe execution.

.DESCRIPTION
Blocks executables named wermgr.exe unless they are the real Windows Error
Reporting binaries in System32 or SysWOW64. Microsoft Defender Antivirus does
not expose this as a local AV switch, so this uses AppLocker.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Audit', 'Enforce')]
    [string]$Mode = 'Audit',

    [string]$PolicyDirectory = "$env:ProgramData\RoguePlanet-Mitigation"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Language-neutral identifiers. AppLocker accepts SIDs and environment
# variables regardless of the Windows display language.
$sidAllUsers = 'S-1-1-0'

$ids = @{
    AllowAll     = '2F5E8B9F-3A28-4D3D-95CB-64120E18F9E8'
    AllowAppxAll = '65D1A7D2-64D8-4AF2-8B39-E6B97B5C0A9D'
    Admin        = 'A86E4D7E-2147-46F0-B5AF-A7F9670A3D71'
    Win          = '0D2EA50A-92BC-47C4-B544-9980E80EB90A'
    Pf           = '50B3D746-23E2-40D9-8461-42D0D987F4F7'
    Wermgr       = 'F3451271-AB52-45F5-A34D-6779E6516343'
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell prompt.'
}

if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
    throw 'The AppLocker PowerShell module is not available on this system.'
}

function Get-ExeRuleIds {
    try {
        [xml]$current = Get-AppLockerPolicy -Local -Xml
        $exe = @($current.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'Exe' | Select-Object -First 1)
        if (-not $exe) {
            return @()
        }

        return @($exe[0].ChildNodes |
            Where-Object { $_.LocalName -like 'File*Rule' } |
            ForEach-Object { $_.Id.ToLowerInvariant() })
    }
    catch {
        return @()
    }
}

$enforcement = if ($Mode -eq 'Enforce') { 'Enabled' } else { 'AuditOnly' }
$existingRuleIds = @(Get-ExeRuleIds)
$knownRuleIds = @($ids.Values | ForEach-Object { $_.ToLowerInvariant() })
$unknownRuleIds = @($existingRuleIds | Where-Object { $_ -notin $knownRuleIds })
$addCompatibilityAllow = ($existingRuleIds.Count -eq 0) -or ($unknownRuleIds.Count -eq 0)
$compatibilityRule = if ($addCompatibilityAllow) {
@"
    <FilePathRule Id="$($ids.AllowAll)" Name="Compatibility Allow - All users - All executables" Description="Keeps this mitigation focused on denying fake wermgr.exe without turning on broad application lockdown." UserOrGroupSid="$sidAllUsers" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
"@
} else {
    ''
}

$xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="$enforcement">
$compatibilityRule
    <FilePathRule Id="$($ids.Wermgr)" Name="RoguePlanet mitigation - block fake wermgr.exe" Description="Blocks executables named wermgr.exe unless launched from the real Windows Error Reporting binary locations." UserOrGroupSid="$sidAllUsers" Action="Deny">
      <Conditions><FilePathCondition Path="*\wermgr.exe" /></Conditions>
      <Exceptions>
        <FilePathCondition Path="%WINDIR%\System32\wermgr.exe" />
        <FilePathCondition Path="%WINDIR%\SysWOW64\wermgr.exe" />
      </Exceptions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="$enforcement">
    <FilePublisherRule Id="$($ids.AllowAppxAll)" Name="Compatibility Allow - All users - All packaged apps" Description="Keeps this mitigation focused on fake wermgr.exe blocking without packaged-app collateral damage." UserOrGroupSid="$sidAllUsers" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
"@

New-Item -Path $PolicyDirectory -ItemType Directory -Force | Out-Null
$policyPath = Join-Path $PolicyDirectory "Block-Fake-wermgr-$Mode.xml"
$xml | Set-Content -Path $policyPath -Encoding UTF8

if ($PSCmdlet.ShouldProcess('local AppLocker policy', "merge $policyPath in $Mode mode")) {
    Set-AppLockerPolicy -XmlPolicy $policyPath -Merge

    $appIdSvc = Get-Service -Name AppIDSvc
    if ($appIdSvc.StartType -ne 'Automatic') {
        Set-Service -Name AppIDSvc -StartupType Automatic
    }
    if ($appIdSvc.Status -ne 'Running') {
        Start-Service -Name AppIDSvc
    }
}

Write-Host "Created policy: $policyPath"
Write-Host "Mode: $Mode"
Write-Host "Added compatibility allow rule: $addCompatibilityAllow"
Write-Host "Locale-neutral policy: uses SIDs, AppLocker event IDs, and Windows environment variables instead of localized group or folder names."
Write-Host 'Review events: Applications and Services Logs\Microsoft\Windows\AppLocker\EXE and DLL'
