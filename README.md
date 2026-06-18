# RoguePlanet - Mitigation

Defensive mitigation helpers for blocking RoguePlanet-style fake `wermgr.exe`
execution.

## What This Blocks

The mitigation uses Windows AppLocker to deny executables named `wermgr.exe`
unless they are launched from the legitimate Windows Error Reporting locations:

- `%WINDIR%\System32\wermgr.exe`
- `%WINDIR%\SysWOW64\wermgr.exe`

This targets a high-signal behavior in the public RoguePlanet PoC: staging or
redirecting execution through a fake `wermgr.exe`.

## Files

- `Add-RoguePlanetWermgrBlock.ps1` - installs the AppLocker mitigation.
- `Test-RoguePlanetWermgrBlock.ps1` - safely validates the rule using a benign
  copied Windows binary named `wermgr.exe`.

## Install

Run PowerShell as Administrator.

Start in audit mode:

```powershell
.\Add-RoguePlanetWermgrBlock.ps1 -Mode Audit
```

After reviewing AppLocker events, enforce the block:

```powershell
.\Add-RoguePlanetWermgrBlock.ps1 -Mode Enforce
```

The script starts the `AppIDSvc` service because AppLocker requires the
Application Identity service to evaluate rules.

## Safe Validation

Run:

```powershell
.\Test-RoguePlanetWermgrBlock.ps1
```

Expected result in enforce mode:

- process launch fails with a Group Policy / AppLocker block message
- AppLocker event `8004` reports that `WERMGR.EXE` was prevented from running

The test does not run the RoguePlanet PoC. It copies a benign Windows binary to
a temporary path named `wermgr.exe`, attempts to launch it, logs the result, and
removes the temporary files.

## Notes

This is a focused local mitigation. In enterprise environments, prefer deploying
equivalent controls through your normal EDR, Intune, GPO, WDAC, or AppLocker
management pipeline.
