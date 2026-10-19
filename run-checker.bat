@echo off
setlocal

rem Test-only host-root overrides are never inherited by distributed launcher runs.
set "DEV_SUPPLYCHAIN_CHECKER_TEST_NODE_RUNTIME_ROOTS="
set "DEV_SUPPLYCHAIN_CHECKER_TEST_NPM_GLOBAL_ROOTS="
set "DEV_SUPPLYCHAIN_CHECKER_TEST_NPM_CACHE_ROOTS="

set "BASE=%~dp0"
set "POWERSHELL_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "SCRIPT=%BASE%Scan-DevSupplyChain.ps1"
set "REPORTS=%BASE%reports"
set "MANIFEST=%BASE%tests\samples\manifest.json"
set "IOCDIR=%BASE%iocs"
set "CAMPAIGNIOC=%IOCDIR%\campaign-keyv-chaindrop-20260806.json"
set "MODE=%~1"
set "TARGET=%~2"
set "ARG3=%~3"
set "ARG4=%~4"
set "CHECKS=Recommended"
set "NO_PAUSE="

if not exist "%POWERSHELL_EXE%" (
  echo ERROR: Windows PowerShell 5.1 was not found at the expected system path.
  exit /b 3
)

"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "$allowed=@('help','/?','-h','--help','current','path','deep','packages','ai','cicd','npmstatic','major','userprofile','full','--no-pause'); if((-not [string]::IsNullOrEmpty($env:MODE) -and $allowed -inotcontains $env:MODE) -or (-not [string]::IsNullOrEmpty($env:ARG3) -and $env:ARG3 -ine '--no-pause') -or (-not [string]::IsNullOrEmpty($env:ARG4)) -or (-not [string]::IsNullOrEmpty($env:TARGET) -and $env:TARGET.IndexOf([char]34) -ge 0)){exit 4}"
if errorlevel 1 (
  echo ERROR: Unsupported mode, extra argument, or quoted target path.
  exit /b 4
)

if /I "%MODE%"=="--no-pause" (
  set "NO_PAUSE=1"
  set "MODE="
)
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "if($env:TARGET -ieq '--no-pause'){exit 0}else{exit 1}"
if not errorlevel 1 (
  set "NO_PAUSE=1"
  set "TARGET="
)
if /I "%ARG3%"=="--no-pause" (
  set "NO_PAUSE=1"
)

if /I "%MODE%"=="help" goto Usage
if /I "%MODE%"=="/?" goto Usage
if /I "%MODE%"=="-h" goto Usage
if /I "%MODE%"=="--help" goto Usage

if not exist "%SCRIPT%" (
  echo ERROR: Scanner script was not found.
  echo Expected: "%SCRIPT%"
  exit /b 4
)

set "DIST_WARN="
if not exist "%BASE%README.md" set "DIST_WARN=1"
if not exist "%MANIFEST%" set "DIST_WARN=1"
if not exist "%IOCDIR%\" set "DIST_WARN=1"
if not exist "%CAMPAIGNIOC%" set "DIST_WARN=1"

if defined DIST_WARN (
  echo WARNING: This checker folder looks incomplete.
  echo.
  echo Expected scanner path: "%SCRIPT%"
  echo Expected README: "%BASE%README.md"
  echo Expected IOC folder: "%IOCDIR%"
  echo Expected campaign IOC: "%CAMPAIGNIOC%"
  echo Expected sample manifest: "%MANIFEST%"
  echo.
  echo Use the extracted release folder and run this run-checker.bat for distributed use.
  echo A script-only copy can still run, but sample-skip and IOC context may be less clear.
  echo.
  if defined NO_PAUSE (
    echo Non-interactive execution requires a complete distribution.
    exit /b 4
  )
  set "DIST_CONFIRM="
  set /p DIST_CONFIRM=Type YES to continue anyway:
  "%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "if($env:DIST_CONFIRM -ieq 'YES'){exit 0}else{exit 1}"
  if errorlevel 1 (
    echo Cancelled.
    exit /b 4
  )
)

if /I "%MODE%"=="current" goto ScanCurrent
if /I "%MODE%"=="path" goto ScanPath
if /I "%MODE%"=="deep" goto ScanDeep
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
echo 1. Recommended project scan - current folder
echo 2. Scan selected path - choose folder, then Recommended or Deep
echo 3. Package / Node runtime risks - current folder
echo 4. AI / MCP / IDE config risks only - current folder
echo 5. CI/CD and hooks risks only - current folder
echo 6. npm global/cache static check - PC metadata; confirm
echo 7. Major PC locations scan - PC folders/profile; confirm
echo 8. Custom checks for current folder - advanced
echo 9. Comprehensive bounded scan ^(target + major locations + profile + endpoint^) - confirm
echo 10. Exit
echo.
echo Start with 1 for the current folder, or 2 to select your project folder.
echo Modes 6, 7, and 9 read PC locations outside the project. Mode 9 also reads endpoint logs.
echo Deep in mode 2 is separate and requires confirmation.
echo Ctrl+C interrupts the scan; review Execution and Completion in any saved report.
echo.
set "MODE="
set /p MODE=Select mode: 
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "$allowed=@('1','2','3','4','5','6','7','8','9','10'); if($allowed -notcontains $env:MODE){exit 4}"
if errorlevel 1 (
  echo Unknown selection.
  goto Menu
)

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
echo   run-checker.bat deep ^<path^>
echo   run-checker.bat packages [path] [--no-pause]
echo   run-checker.bat ai [path] [--no-pause]
echo   run-checker.bat cicd [path] [--no-pause]
echo   run-checker.bat npmstatic
echo   run-checker.bat major
echo   run-checker.bat userprofile
echo   run-checker.bat full [path]  ^(bounded comprehensive scan; not full-disk or Deep^)
echo.
echo deep, npmstatic, major, userprofile, and full modes require typing YES and do not support --no-pause.
exit /b 0

:PromptPath
set "TARGET="
set /p TARGET=Path to scan: 
if not defined TARGET (
  echo Cancelled.
  exit /b 0
)
echo.
echo 1. Recommended traversal
echo 2. Deep traversal ^(dependencies, build, and cache; higher load^)
set "TRAVERSAL="
set /p TRAVERSAL=Traversal mode [1]:
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "if(@('','1','2') -notcontains $env:TRAVERSAL){exit 4}"
if errorlevel 1 (
  echo ERROR: Unsupported traversal selection.
  exit /b 4
)
if "%TRAVERSAL%"=="2" goto ConfirmDeep
goto RunPath

:ScanCurrent
if not defined TARGET (
  set "TARGET=%CD%"
)
goto RunPath

:ScanPath
if not defined TARGET (
  echo Path mode requires a target path.
  exit /b 4
)
goto RunPath

:RunPath
if not defined CHECKS set "CHECKS=Recommended"
call :ValidateTarget
if errorlevel 1 exit /b 4
echo.
echo Scanner path: "%SCRIPT%"
echo Target path: "%TARGET%"
echo Report dir: "%REPORTS%"
echo Checks: "%CHECKS%"
echo.
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -Path "%TARGET%" ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ScanPackages
set "CHECKS=Packages,LifecycleScripts,NodeRuntime,InvisibleUnicode,ScannerSelf"
if not defined TARGET set "TARGET=%CD%"
goto RunPath

:ScanDeep
if not defined TARGET (
  echo Deep mode requires a target path.
  exit /b 4
)
goto ConfirmDeep

:ConfirmDeep
set "CHECKS=Recommended"
call :ValidateTarget
if errorlevel 1 exit /b 4
if defined NO_PAUSE (
  echo Non-interactive execution is not allowed for Deep traversal.
  exit /b 4
)
if not exist "%TARGET%" (
  echo ERROR: Deep target path was not found: "%TARGET%"
  exit /b 4
)
echo.
echo Deep traversal enters dependency, build, and cache directories that a recommended scan skips.
echo It remains read-only and does not add npm global/cache, user profile, or endpoint telemetry.
echo Scanner path: "%SCRIPT%"
echo Target path: "%TARGET%"
echo Report dir: "%REPORTS%"
echo Checks: "%CHECKS%"
echo MaxFiles: 200000
echo.
set "CONFIRM="
set /p CONFIRM=Type YES to continue:
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "if($env:CONFIRM -ieq 'YES'){exit 0}else{exit 1}"
if errorlevel 1 (
  echo Cancelled.
  exit /b 0
)
goto RunDeep

:RunDeep
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -Path "%TARGET%" ^
  -Deep ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ScanAi
set "CHECKS=AiMcp,IdeExtensions,InvisibleUnicode,SecretsInventory,ScannerSelf"
if not defined TARGET set "TARGET=%CD%"
goto RunPath

:ScanCiCd
set "CHECKS=CiCd,HooksAndTasks,InvisibleUnicode,ScannerSelf"
if not defined TARGET set "TARGET=%CD%"
goto RunPath

:PromptCustomChecks
echo.
echo Available checks:
echo   Packages,LifecycleScripts,NodeRuntime,InvisibleUnicode,CiCd,AiMcp,IdeExtensions,HooksAndTasks,SecretsInventory,ScannerSelf
echo Host-scoped npm checks are available only through confirmed modes 6, 7, and 9.
echo Example:
echo   Packages,AiMcp,CiCd
echo.
set "CHECKS="
set /p CHECKS=Checks to run:
if not defined CHECKS (
  echo Cancelled.
  exit /b 0
)
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "$allowed=@('Packages','LifecycleScripts','NodeRuntime','InvisibleUnicode','CiCd','AiMcp','IdeExtensions','HooksAndTasks','SecretsInventory','ScannerSelf','Recommended'); foreach($item in @($env:CHECKS -split ',')){if($allowed -notcontains $item.Trim()){exit 4}}"
if errorlevel 1 (
  echo ERROR: Unsupported or unsafe check list.
  exit /b 4
)
set "TARGET=%CD%"
goto RunPath

:ScanNpmStatic
set "CHECKS=NpmGlobal,NpmCache"
echo This mode statically inspects common npm global and npm cache metadata paths.
echo It does not execute npm root -g or npm cache ls.
echo Cache findings are weak context unless paired with installed package or executable findings.
echo.
echo Scanner path: "%SCRIPT%"
echo Target path: npm global/cache static paths
echo Report dir: "%REPORTS%"
echo Checks: "%CHECKS%"
echo.
if defined NO_PAUSE (
  echo Non-interactive execution is not allowed for npm global/cache static checks.
  exit /b 4
)
set "CONFIRM="
set /p CONFIRM=Type YES to continue:
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "if($env:CONFIRM -ieq 'YES'){exit 0}else{exit 1}"
if errorlevel 1 (
  echo Cancelled.
  exit /b 0
)

"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ScanMajor
set "CHECKS=MajorRecommended"
echo This mode scans common developer folders plus user profile IDE and AI-agent metadata.
echo It also inspects static npm global metadata and bounded Program Files/PATH/version-manager Node.js file metadata.
echo It does not scan the whole C: drive and does not read endpoint telemetry.
echo Known credential files are inventory-only and are not read. Other configuration text is statically read; secret-like report evidence is redacted.
echo.
echo Scanner path: "%SCRIPT%"
echo Target path: Major PC locations
echo Report dir: "%REPORTS%"
echo Checks: "%CHECKS%"
echo.
if defined NO_PAUSE (
  echo Non-interactive execution is not allowed for Major PC locations scan.
  exit /b 4
)
set "CONFIRM="
set /p CONFIRM=Type YES to continue: 
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "if($env:CONFIRM -ieq 'YES'){exit 0}else{exit 1}"
if errorlevel 1 (
  echo Cancelled.
  exit /b 0
)

"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -MajorLocations ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ScanUserProfile
set "CHECKS=Recommended"
echo This mode scans your real user profile metadata and credential-file inventory.
echo It also inspects bounded Program Files/PATH/version-manager Node.js file metadata.
echo Known credential files are inventory-only and are not read. Other configuration text is statically read; secret-like report evidence is redacted.
echo.
echo Scanner path: "%SCRIPT%"
echo Target path: "%USERPROFILE%"
echo Report dir: "%REPORTS%"
echo Checks: "%CHECKS%"
echo.
if defined NO_PAUSE (
  echo Non-interactive execution is not allowed for user profile scan.
  exit /b 4
)
set "CONFIRM="
set /p CONFIRM=Type YES to continue: 
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "if($env:CONFIRM -ieq 'YES'){exit 0}else{exit 1}"
if errorlevel 1 (
  echo Cancelled.
  exit /b 0
)

"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -UserProfile ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ScanFull
set "CHECKS=AllSafe"
if not defined TARGET (
  set "TARGET=%CD%"
)

call :ValidateTarget
if errorlevel 1 exit /b 4

echo Comprehensive mode scans the target path, common developer locations, your real user profile, and endpoint telemetry.
echo It also performs static npm global/cache checks and bounded known-path/PATH Node.js metadata checks.
echo Endpoint telemetry may read DNS cache, event logs, startup entries, and scheduled task metadata.
echo This is not a full-disk scan. Deep dependency/build/cache recursion remains disabled.
echo Use the separate Deep mode on a trusted project when recursive dependency content is required.
echo Known credential files are inventory-only and are not read. Other configuration text is statically read; secret-like report evidence is redacted.
echo.
echo Scanner path: "%SCRIPT%"
echo Target path: "%TARGET%"
echo Report dir: "%REPORTS%"
echo Checks: "%CHECKS%"
echo.
if defined NO_PAUSE (
  echo Non-interactive execution is not allowed for full scan.
  exit /b 4
)
set "CONFIRM="
set /p CONFIRM=Type YES to continue: 
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "if($env:CONFIRM -ieq 'YES'){exit 0}else{exit 1}"
if errorlevel 1 (
  echo Cancelled.
  exit /b 0
)

"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%SCRIPT%" ^
  -Path "%TARGET%" ^
  -MajorLocations ^
  -UserProfile ^
  -EndpointTelemetry ^
  -Checks "%CHECKS%" ^
  -ReportDir "%REPORTS%" ^
  -LauncherPath "%~f0"
goto Finish

:ValidateTarget
"%POWERSHELL_EXE%" -NoLogo -NoProfile -NonInteractive -Command "if([string]::IsNullOrWhiteSpace($env:TARGET) -or $env:TARGET.IndexOf([char]34) -ge 0){exit 4}"
set "VALIDATION_EXIT=%ERRORLEVEL%"
if not "%VALIDATION_EXIT%"=="0" echo ERROR: Target path is empty or contains an invalid quote character.
exit /b %VALIDATION_EXIT%

:Finish
set "EXITCODE=%ERRORLEVEL%"
echo.
echo Scan process returned exit code %EXITCODE%.
if "%EXITCODE%"=="0" echo No WARN/CAUTION/DANGER findings; also verify Completion.
if "%EXITCODE%"=="1" echo Review WARN/CAUTION findings and any coverage limitations.
if "%EXITCODE%"=="2" echo Review DANGER findings first; this is not automatic proof of infection.
if "%EXITCODE%"=="3" echo Scanner or report failure; do not use this as a completed result.
if "%EXITCODE%"=="4" echo Invalid input or declined confirmation.
echo Severity and execution completion are separate; counts are findings, not infections.
echo Reports are under: "%REPORTS%"
echo.
if not defined NO_PAUSE pause
exit /b %EXITCODE%
