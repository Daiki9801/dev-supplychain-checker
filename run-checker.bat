@echo off
setlocal

set "BASE=%~dp0"
set "SCRIPT=%BASE%Scan-DevSupplyChain.ps1"
set "REPORTS=%BASE%reports"
set "MANIFEST=%BASE%tests\samples\manifest.json"
set "IOCDIR=%BASE%iocs"
set "MODE=%~1"
set "TARGET=%~2"
set "CHECKS=Recommended"
set "NO_PAUSE="

if /I "%~1"=="--no-pause" (
  set "NO_PAUSE=1"
  set "MODE="
)
if /I "%~2"=="--no-pause" (
  set "NO_PAUSE=1"
  set "TARGET="
)
if /I "%~3"=="--no-pause" (
  set "NO_PAUSE=1"
)

if /I "%MODE%"=="help" goto Usage
if /I "%MODE%"=="/?" goto Usage
if /I "%MODE%"=="-h" goto Usage
if /I "%MODE%"=="--help" goto Usage

if not exist "%SCRIPT%" (
  echo ERROR: Scanner script was not found.
  echo Expected: %SCRIPT%
  exit /b 4
)

set "DIST_WARN="
if not exist "%BASE%README.md" set "DIST_WARN=1"
if not exist "%MANIFEST%" set "DIST_WARN=1"
if not exist "%IOCDIR%\" set "DIST_WARN=1"

if defined DIST_WARN (
  echo WARNING: This checker folder looks incomplete.
  echo.
  echo Expected scanner path: %SCRIPT%
  echo Expected README: %BASE%README.md
  echo Expected IOC folder: %IOCDIR%
  echo Expected sample manifest: %MANIFEST%
  echo.
  echo Use the extracted release folder and run this run-checker.bat for distributed use.
  echo A script-only copy can still run, but sample-skip and IOC context may be less clear.
  echo.
  if defined NO_PAUSE (
    echo Non-interactive execution requires a complete distribution.
    exit /b 4
  )
  set /p DIST_CONFIRM=Type YES to continue anyway:
  if /I not "%DIST_CONFIRM%"=="YES" (
    echo Cancelled.
    exit /b 4
  )
)

if /I "%MODE%"=="current" goto ScanCurrent
if /I "%MODE%"=="path" goto ScanPath
if /I "%MODE%"=="packages" goto ScanPackages
if /I "%MODE%"=="ai" goto ScanAi
if /I "%MODE%"=="cicd" goto ScanCiCd
if /I "%MODE%"=="npmstatic" goto ScanNpmStatic
if /I "%MODE%"=="major" goto ScanMajor
if /I "%MODE%"=="userprofile" goto ScanUserProfile
if /I "%MODE%"=="full" goto ScanFull

:Menu
echo Dev Supply Chain IOC Checker
echo.
echo 1. Recommended project scan
echo 2. Scan selected path
echo 3. Package / lockfile risks only
echo 4. AI / MCP / IDE config risks only
echo 5. CI/CD and hooks risks only
echo 6. npm global/cache static check
echo 7. Major PC locations scan
echo 8. Custom checks for current folder
echo 9. Full scan current folder + user profile + endpoint telemetry
echo 10. Exit
echo.
set /p MODE=Select mode: 

if "%MODE%"=="1" goto ScanCurrent
if "%MODE%"=="2" goto PromptPath
if "%MODE%"=="3" goto ScanPackages
if "%MODE%"=="4" goto ScanAi
if "%MODE%"=="5" goto ScanCiCd
if "%MODE%"=="6" goto ScanNpmStatic
if "%MODE%"=="7" goto ScanMajor
if "%MODE%"=="8" goto PromptCustomChecks
if "%MODE%"=="9" goto ScanFull
if "%MODE%"=="10" exit /b 0

echo Unknown selection.
goto Menu

:Usage
echo Usage:
echo   run-checker.bat
echo   run-checker.bat current [path] [--no-pause]
echo   run-checker.bat path ^<path^> [--no-pause]
echo   run-checker.bat packages [path] [--no-pause]
echo   run-checker.bat ai [path] [--no-pause]
echo   run-checker.bat cicd [path] [--no-pause]
echo   run-checker.bat npmstatic
echo   run-checker.bat major
echo   run-checker.bat userprofile
echo   run-checker.bat full [path]
echo.
echo npmstatic, major, userprofile, and full modes require typing YES and do not support --no-pause.
exit /b 0

:PromptPath
set "TARGET="
set /p TARGET=Path to scan: 
if "%TARGET%"=="" (
  echo Cancelled.
  exit /b 0
)
goto RunPath

:ScanCurrent
if "%TARGET%"=="" (
  set "TARGET=%CD%"
)
goto RunPath

:ScanPath
if "%TARGET%"=="" (
  echo Path mode requires a target path.
  exit /b 4
)
goto RunPath

:RunPath
if "%CHECKS%"=="" set "CHECKS=Recommended"
echo.
echo Scanner path: %SCRIPT%
echo Target path: %TARGET%
echo Report dir: %REPORTS%
echo Checks: %CHECKS%
echo.
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -Path "%TARGET%" ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ScanPackages
set "CHECKS=Packages,LifecycleScripts,ScannerSelf"
if "%TARGET%"=="" set "TARGET=%CD%"
goto RunPath

:ScanAi
set "CHECKS=AiMcp,IdeExtensions,SecretsInventory,ScannerSelf"
if "%TARGET%"=="" set "TARGET=%CD%"
goto RunPath

:ScanCiCd
set "CHECKS=CiCd,HooksAndTasks,ScannerSelf"
if "%TARGET%"=="" set "TARGET=%CD%"
goto RunPath

:PromptCustomChecks
echo.
echo Available checks:
echo   Packages,LifecycleScripts,InvisibleUnicode,CiCd,AiMcp,IdeExtensions,HooksAndTasks,SecretsInventory,NpmGlobal,NpmCache,ScannerSelf
echo Example:
echo   Packages,AiMcp,CiCd
echo.
set /p CHECKS=Checks to run:
if "%CHECKS%"=="" (
  echo Cancelled.
  exit /b 0
)
set "TARGET=%CD%"
goto RunPath

:ScanNpmStatic
set "CHECKS=NpmGlobal,NpmCache"
echo This mode statically inspects common npm global and npm cache metadata paths.
echo It does not execute npm root -g or npm cache ls.
echo Cache findings are weak context unless paired with installed package or executable findings.
echo.
echo Scanner path: %SCRIPT%
echo Target path: npm global/cache static paths
echo Report dir: %REPORTS%
echo Checks: %CHECKS%
echo.
if defined NO_PAUSE (
  echo Non-interactive execution is not allowed for npm global/cache static checks.
  exit /b 4
)
set /p CONFIRM=Type YES to continue:
if /I not "%CONFIRM%"=="YES" (
  echo Cancelled.
  exit /b 0
)

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ScanMajor
set "CHECKS=MajorRecommended"
echo This mode scans common developer folders plus user profile IDE and AI-agent metadata.
echo It does not scan the whole C: drive and does not read endpoint telemetry.
echo Secret values are not read or printed, but paths and findings may be reported.
echo.
echo Scanner path: %SCRIPT%
echo Target path: Major PC locations
echo Report dir: %REPORTS%
echo Checks: %CHECKS%
echo.
if defined NO_PAUSE (
  echo Non-interactive execution is not allowed for Major PC locations scan.
  exit /b 4
)
set /p CONFIRM=Type YES to continue: 
if /I not "%CONFIRM%"=="YES" (
  echo Cancelled.
  exit /b 0
)

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -MajorLocations ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ScanUserProfile
set "CHECKS=Recommended"
echo This mode scans your real user profile metadata and credential-file inventory.
echo Secret values are not read or printed, but paths and findings may be reported.
echo.
echo Scanner path: %SCRIPT%
echo Target path: %USERPROFILE%
echo Report dir: %REPORTS%
echo Checks: %CHECKS%
echo.
if defined NO_PAUSE (
  echo Non-interactive execution is not allowed for user profile scan.
  exit /b 4
)
set /p CONFIRM=Type YES to continue: 
if /I not "%CONFIRM%"=="YES" (
  echo Cancelled.
  exit /b 0
)

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -UserProfile ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ScanFull
set "CHECKS=AllSafe"
if "%TARGET%"=="" (
  set "TARGET=%CD%"
)

echo Full mode scans the target path, your real user profile, and endpoint telemetry.
echo Endpoint telemetry may read DNS cache, event logs, startup entries, and scheduled task metadata.
echo Secret values are not read or printed, but paths and findings may be reported.
echo.
echo Scanner path: %SCRIPT%
echo Target path: %TARGET%
echo Report dir: %REPORTS%
echo Checks: %CHECKS%
echo.
if defined NO_PAUSE (
  echo Non-interactive execution is not allowed for full scan.
  exit /b 4
)
set /p CONFIRM=Type YES to continue: 
if /I not "%CONFIRM%"=="YES" (
  echo Cancelled.
  exit /b 0
)

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -Path "%TARGET%" ^
  -UserProfile ^
  -EndpointTelemetry ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:Finish
set "EXITCODE=%ERRORLEVEL%"
echo.
echo Scan finished with exit code %EXITCODE%.
echo Reports are under: %REPORTS%
echo.
if not defined NO_PAUSE pause
exit /b %EXITCODE%
