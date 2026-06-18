# Changes

## 2026-06-18

- Created the `RoguePlanet - Mitigation` project for defensive AppLocker-based controls.
- Added `Add-RoguePlanetWermgrBlock.ps1` to block fake `wermgr.exe` execution outside the legitimate Windows Error Reporting paths.
- Added `Remove-RoguePlanetWermgrBlock.ps1` as a failsafe rollback script for removing the mitigation and compatibility rules.
- Added `Test-RoguePlanetWermgrBlock.ps1` to safely validate the mitigation with a benign copied Windows binary.
- Added compatibility allow rules so the mitigation stays focused on fake `wermgr.exe` blocking instead of broadly locking down the endpoint.
- Added packaged-app compatibility support so Microsoft Store/MSIX apps, including Microsoft Teams and its sign-in dependencies, keep working.
- Made the mitigation language-neutral by using SIDs, Windows environment variables, executable names, and AppLocker event IDs instead of localized group or folder names.
- Published the project to GitHub at `0xG3r4rD/RoguePlanet-Mitigation`.
