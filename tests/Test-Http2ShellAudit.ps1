[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repoRoot=Split-Path -Parent $PSScriptRoot
$scanner=Join-Path $repoRoot 'Scan-DevSupplyChain.ps1'
$winPS=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$artifactRoot=Join-Path $repoRoot ('reports/http2shell-regression-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($artifactRoot)
$assertions=0
function Assert-H2S { param([bool]$Condition,[string]$Message); $script:assertions++; if (-not $Condition) {throw $Message} }
function Write-NewH2SFile {
    param([string]$Relative,[string]$Text)
    $path=Join-Path $artifactRoot $Relative
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Text); $stream.Write($bytes,0,$bytes.Length) } finally {$stream.Dispose()}
    return $path
}
function Invoke-H2SScan {
    param([string]$Name,[string]$Target,[string[]]$Extra=@(),[string]$Checks='Http2Shell,ScannerSelf',[int]$ExpectedExit=-1)
    $json=Join-Path $artifactRoot ($Name+'.json'); $txt=Join-Path $artifactRoot ($Name+'.txt')
    $scanArgs=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$scanner,'-Checks',$Checks,'-JsonOut',$json,'-TextOut',$txt,'-Quiet','-NoColor')
    if ($Target) {$scanArgs+=@('-Path',$Target)}
    & $winPS @scanArgs @Extra | Out-Null
    $code=$LASTEXITCODE; $global:LASTEXITCODE=0
    if ($ExpectedExit -ge 0) {Assert-H2S ($code -eq $ExpectedExit) ($Name+': exit code '+$code)} else {Assert-H2S ($code -in @(0,1,2)) ($Name+': scanner failed, exit '+$code)}
    Assert-H2S ([IO.File]::Exists($json)) ($Name+': missing JSON report')
    $report=[IO.File]::ReadAllText($json,[Text.Encoding]::UTF8) | ConvertFrom-Json
    Assert-H2S ($report.executionSafety.networkAccess -eq 'none' -and $report.executionSafety.externalCommands -eq 'none' -and $report.executionSafety.targetCodeExecution -eq 'none') ($Name+': execution safety')
    Assert-H2S (-not $report.mode.userProfile -and -not $report.mode.majorLocations -and -not $report.mode.endpointTelemetry) ($Name+': unrelated host scope')
    if ($ExpectedExit -lt 3) {Assert-H2S (@($report.findings | Where-Object {$_.category -in @('SCANNER_ERROR','SCANNER_FILE_ERROR','REGEX_SCAN_TIMEOUT')}).Count -eq 0) ($Name+': scanner/analysis error')}
    foreach ($output in @($json,$txt)) { $bytes=[IO.File]::ReadAllBytes($output); Assert-H2S ($bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) ($Name+': missing report UTF-8 BOM') }
    return $report
}

# Pure baseline tests never evaluate scanner startup, executable metadata or host discovery.
$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($scanner,[ref]$tokens,[ref]$parseErrors)
Assert-H2S ($parseErrors.Count -eq 0) 'Scanner parse errors'
$allow=@('Get-Http2ShellVersionAssessment','Expand-CheckMacro')
foreach ($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $allow},$true)) { . ([scriptblock]::Create($definition.Extent.Text)) }
$script:LeafCheckOrder=@('Packages','Http2Shell','ScannerSelf')
foreach ($macro in @('Recommended','MajorRecommended','AllSafe')) {Assert-H2S ('Http2Shell' -notin @(Expand-CheckMacro $macro)) ($macro+': special audit implicitly enabled')}
$versionCases=@(
    @('brotli-native','1.0.2','unknown'),@('brotli-native','1.0.3','upstream-affected-version'),
    @('brotli-native','1.0.9','upstream-affected-version'),@('brotli-native','1.0.10','upstream-fixed-version'),
    @('brotli-native','1.1.0','upstream-affected-version'),@('brotli-native','1.1.1','upstream-fixed-version'),
    @('brotli-native','1.2.0','upstream-affected-version'),@('brotli-native','1.2.1','upstream-fixed-version'),
    @('brotli-native','2.0.0','unknown'),@('python-brotli','1.2.0','upstream-affected-version'),
    @('python-brotli','1.2.1','upstream-fixed-version'),@('python-brotlicffi','1.2.0.0','upstream-affected-version'),
    @('python-brotlicffi','1.2.1.0','upstream-fixed-version'),@('python-brotli','1.2.1rc1','unknown'),
    @('node','22.23.3','upstream-affected-version'),@('node','22.23.4','upstream-fixed-version'),
    @('node','24.22.0','upstream-affected-version'),@('node','24.22.1','upstream-fixed-version'),
    @('node','26.12.0','upstream-affected-version'),@('node','26.12.1','upstream-fixed-version'),
    @('node','16.20.2','unknown'),@('node','27.0.0','unknown'),@('node','24.22.1-custom','unknown'),
    @('bun','1.4.3','upstream-affected-version'),@('bun','1.4.4','upstream-fixed-version'),
    @('dotnet-runtime','8.0.32','upstream-affected-version'),@('dotnet-runtime','8.0.33','upstream-fixed-version'),
    @('dotnet-runtime','9.0.21','upstream-affected-version'),@('dotnet-runtime','9.0.22','upstream-fixed-version'),
    @('dotnet-runtime','10.0.13','upstream-affected-version'),@('dotnet-runtime','10.0.14','upstream-fixed-version'),
    @('dotnet-runtime','11.0.0-preview.1.26104.118','upstream-affected-version'),
    @('dotnet-runtime','11.0.0-rc.2.26504.105','upstream-affected-version'),
    @('dotnet-runtime','11.0.0-rc.3.26522.148','upstream-fixed-version'),
    @('dotnet-runtime','11.0.0-rc.3.26522.147','unknown'),@('dotnet-runtime','11.0.0','unknown'),
    @('electron','44.9.2','upstream-fixed-version'),@('electron','44.9.3','upstream-fixed-version'),
    @('electron','44.10.2','upstream-fixed-version'),@('electron','45.0.0','upstream-fixed-version'),
    @('electron','45.2.3','upstream-fixed-version'),@('electron','45.2.4','unknown'),
    @('electron','45.2.3-custom','unknown'),@('claude-code-embedded-runtime','2.1.309','unknown'),
    @('codex-embedded-runtime','1.4.4','unknown'),@('node','>=24.22.1','unknown')
)
foreach ($case in $versionCases) { $r=Get-Http2ShellVersionAssessment $case[0] $case[1]; Assert-H2S ($r.status -eq $case[2]) ('Version mapping: '+[string]::Join(' / ',[string[]]$case)) }

# Exercise the real selection helpers with all path probes replaced by recording
# adapters. No drive, share, directory or host metadata is accessed by these cases.
& {
    $rootHelpers=@('Test-Http2ShellLocalDrive','Resolve-Http2ShellHostRoot')
    foreach ($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $rootHelpers},$true)) { . ([scriptblock]::Create($definition.Extent.Text)) }
    function Get-Http2ShellDriveType { param([string]$RootPath); [void]$probes.Add('drive'); return $driveType }
    function Test-PathHasReparsePointBelowRoot { param($RootPath,$CandidatePath); [void]$probes.Add('attributes'); return $reparse }
    function Test-Path { param($LiteralPath,$PathType); [void]$probes.Add('exists'); return $true }
    foreach ($driveType in [Enum]::GetValues([IO.DriveType])) {
        $probes=New-Object Collections.ArrayList; $reparse=$false
        $root=Resolve-Http2ShellHostRoot -CandidatePath 'Z:\synthetic-tools' -Depth 2
        $isLocal=$driveType -in @([IO.DriveType]::Fixed,[IO.DriveType]::Removable,[IO.DriveType]::CDRom,[IO.DriveType]::Ram)
        Assert-H2S (($null -ne $root) -eq $isLocal) ('Drive selection: '+$driveType)
        $expected=if ($isLocal) {'drive,attributes,exists'} else {'drive'}
        Assert-H2S (($probes -join ',') -eq $expected) ('Path probed before local drive classification: '+$driveType)
    }
    foreach ($candidate in @('\\synthetic.invalid\share\tools','\\?\UNC\synthetic.invalid\share\tools','\\?\Z:\tools')) {
        $probes=New-Object Collections.ArrayList
        Assert-H2S ($null -eq (Resolve-Http2ShellHostRoot -CandidatePath $candidate -Depth 0)) 'UNC/device root was accepted'
        Assert-H2S ($probes.Count -eq 0) 'UNC/device root caused a metadata probe'
    }
    $probes=New-Object Collections.ArrayList; $driveType=[IO.DriveType]::Fixed; $reparse=$true
    Assert-H2S ($null -eq (Resolve-Http2ShellHostRoot -CandidatePath 'Z:\synthetic-junction' -Depth 0)) 'Local reparse root was accepted'
    Assert-H2S (($probes -join ',') -eq 'drive,attributes') 'Reparse root reached existence probe'
}

# npm v2/v3 normally includes packages[""]. Both entrypoints must parse it on
# Windows PowerShell 5.1 and must not inventory the root project as a dependency.
foreach ($lockName in @('package-lock.json','npm-shrinkwrap.json')) {
    foreach ($lockVersion in @(2,3)) {
        $caseName=$lockName.Replace('.json','')+'-v'+$lockVersion
        $lockText='{"name":"synthetic-project","lockfileVersion":'+$lockVersion+',"packages":{"":{"name":"brotli","version":"1.2.0"},"node_modules/electron":{"version":"45.2.3"}}}'
        $lockFile=Write-NewH2SFile ($caseName+'/'+$lockName) $lockText
        $lockHash=(Get-FileHash -LiteralPath $lockFile -Algorithm SHA256).Hash
        $lockReport=Invoke-H2SScan -Name $caseName -Target $lockFile -ExpectedExit 0
        Assert-H2S ($lockReport.scanComplete -and $lockReport.completionStatus -eq 'complete') ($caseName+': valid root key was rejected')
        Assert-H2S ($lockReport.http2ShellAssessment.entries.Count -eq 1 -and $lockReport.http2ShellAssessment.entries[0].component -eq 'electron' -and $lockReport.http2ShellAssessment.entries[0].componentAssessment -eq 'upstream-fixed-version') ($caseName+': incorrect component inventory')
        Assert-H2S ((Get-FileHash -LiteralPath $lockFile -Algorithm SHA256).Hash -eq $lockHash) ($caseName+': input was changed')
        Assert-H2S (-not $lockReport.iocData.releaseReady -and $lockReport.iocData.currentCount -eq 6 -and $lockReport.iocData.notCheckedCount -eq 1 -and $lockReport.iocData.notCheckedDatasets[0] -eq 'known-node-runtimes.json') ($caseName+': incomplete IOC inventory passed publication gate')
    }
}

$project=Join-Path $artifactRoot 'project'
[void](Write-NewH2SFile 'project/.nvmrc' '24.22.0')
[void](Write-NewH2SFile 'project/.bun-version' '1.4.4')
[void](Write-NewH2SFile 'project/package.json' '{"name":"synthetic-project","volta":{"node":"22.23.4"},"engines":{"node":">=24 <27"},"dependencies":{"electron":"45.2.3","brotli-wasm":"3.0.1"},"scripts":{"postinstall":"this-command-must-never-run"}}')
[void](Write-NewH2SFile 'project/package-lock.json' '{"lockfileVersion":3,"packages":{"":{"name":"synthetic-project","version":"1.0.0"},"node_modules/electron":{"version":"45.2.3"},"node_modules/brotli":{"version":"1.3.0"}}}')
[void](Write-NewH2SFile 'project/.venv/pyvenv.cfg' 'include-system-site-packages = false')
[void](Write-NewH2SFile 'project/.venv/Lib/site-packages/brotli-1.2.0.dist-info/METADATA' "Metadata-Version: 2.1`nName: Brotli`nVersion: 1.2.0`n`nExample only: Version: 1.2.1`n")
[void](Write-NewH2SFile 'project/requirements.txt' "brotlicffi==1.2.1.0`nBrotli==1.2.0`n")
[void](Write-NewH2SFile 'project/uv.lock' "version = 1`n[[package]]`nname = 'brotli'`nversion = '1.2.1'`n[[package]]`nname = 'brotlicffi'`nversion = '1.2.0.0'`n")
[void](Write-NewH2SFile 'project/shared/Microsoft.NETCore.App/8.0.32/.version' "synthetic-commit`n8.0.32`n")
[void](Write-NewH2SFile 'project/shared/Microsoft.NETCore.App/11.0.0-rc.2.26504.105/.version' "synthetic-commit`n11.0.0-rc.2.26504.105`n")
[void](Write-NewH2SFile 'project/app.runtimeconfig.json' '{"runtimeOptions":{"framework":{"name":"Microsoft.NETCore.App","version":"8.0.0"}}}')
[void](Write-NewH2SFile 'project/self-contained.runtimeconfig.json' '{"runtimeOptions":{"includedFrameworks":[{"name":"Microsoft.NETCore.App","version":"10.0.13"}]}}')
[void](Write-NewH2SFile 'project/app.deps.json' '{"libraries":{"Microsoft.NETCore.App.Runtime.NativeAOT.win-x64/9.0.21":{"type":"package"}}}')
[void](Write-NewH2SFile 'project/global.json' '{"sdk":{"version":"8.0.427"}}')
[void](Write-NewH2SFile 'project/Dockerfile' "FROM node:26.12.0-alpine`nFROM node:26.12.1-bookworm`nFROM node:16`nFROM oven/bun:1.4.3`n")
[void](Write-NewH2SFile 'project/.github/workflows/build.yml' "jobs:`n  build:`n    steps:`n      - uses: actions/setup-node@v6`n        with:`n          node-version: '22.23.3'`n")
[void](Write-NewH2SFile 'project/input.ts' "// Static text only; no input flow proof.`ncreateBrotliDecompress(); fetch('https://example.invalid');`n")
[void](Write-NewH2SFile 'project/font.woff2' 'SYNTHETIC FONT - NEVER DECOMPRESS')
[void](Write-NewH2SFile 'project/claude.exe' 'SYNTHETIC UNKNOWN BINARY - NEVER EXECUTE')
[void](Write-NewH2SFile 'project/.env' 'H2S_SYNTHETIC_SECRET=must-not-appear-in-any-report-647208')
$before=@{}
foreach ($file in Get-ChildItem -LiteralPath $project -Recurse -File -Force) { $before[$file.FullName]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
$report=Invoke-H2SScan -Name 'project-audit' -Target $project
Assert-H2S ($report.scanComplete -and $report.executionStatus -eq 'completed') 'Project audit incomplete'
Assert-H2S ($report.http2ShellAssessment.enabled -and -not $report.http2ShellAssessment.hostScanPerformed) 'Project scan discovered host roots'
Assert-H2S ($report.http2ShellAssessment.knownExploitation.listed -and $report.http2ShellAssessment.knownExploitation.dateAdded -eq '2026-10-27' -and 'H2S-CISA-KEV' -in $report.http2ShellAssessment.sources.id) 'KEV evidence missing'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.component -eq 'node' -and $_.version -eq '24.22.0' -and $_.componentAssessment -eq 'upstream-affected-version'}).Count -eq 1) 'Node affected pin missing'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.component -eq 'python-brotli' -and $_.evidenceKind -eq 'installed-package-metadata' -and $_.version -eq '1.2.0'}).Count -eq 1) 'Targeted Python METADATA missing/header boundary lost'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.component -eq 'dotnet-runtime' -and $_.evidenceKind -eq 'installed-runtime-metadata' -and $_.version -eq '8.0.32'}).Count -eq 1) '.NET installed runtime metadata missing'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.version -eq '11.0.0-rc.2.26504.105' -and $_.evidenceKind -eq 'installed-runtime-metadata' -and $_.componentAssessment -eq 'upstream-affected-version'}).Count -eq 1) '.NET preview installed runtime classification missing'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.component -eq 'electron' -and $_.version -eq '45.2.3' -and $_.evidenceKind -eq 'lockfile-exact' -and $_.componentAssessment -eq 'upstream-fixed-version'}).Count -eq 1) 'Reviewed Electron lockfile version missing'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.evidenceKind -eq 'runtime-minimum-reference' -and $_.componentAssessment -ne 'unresolved-reference'}).Count -eq 0) '.NET minimum treated as selected runtime'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.evidenceKind -eq 'bundled-runtime-reference' -and $_.version -eq '10.0.13' -and $_.componentAssessment -eq 'upstream-affected-version'}).Count -eq 1) 'Self-contained runtime reference missing'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.component -eq 'dotnet-sdk-runtime-selection-review' -and $_.componentAssessment -eq 'unknown'}).Count -eq 1) 'SDK pin used as runtime version'
Assert-H2S (@($report.findings | Where-Object {$_.check -eq 'Http2Shell' -and $_.severity -eq 'DANGER'}).Count -eq 0) 'Version-only audit emitted DANGER'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.usageStatus -ne 'not-observed' -or $_.inputReachability -ne 'not-established'}).Count -eq 0) 'Runtime/reachability claim without evidence'
Assert-H2S ($report.http2ShellAssessment.summary.remediationConfirmed -eq 0 -and $report.http2ShellAssessment.inputSignals.Count -ge 3) 'Input evidence or remediation separation lost'
Assert-H2S (@($report.http2ShellAssessment.entries | Where-Object {$_.path -match '\.exe$' -and $_.componentAssessment -ne 'unknown'}).Count -eq 0) 'Unknown binary treated as a proven runtime'
Assert-H2S (-not ([IO.File]::ReadAllText((Join-Path $artifactRoot 'project-audit.json')) -match 'must-not-appear-in-any-report-647208')) 'Known secret file was read/reported'
Assert-H2S ([IO.File]::ReadAllText((Join-Path $artifactRoot 'project-audit.txt')) -match 'HTTP2Shell: CVE-2026-111497') 'TXT audit summary missing'
foreach ($file in $before.Keys) { Assert-H2S ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -eq $before[$file]) 'Target file changed during audit' }

$inherited=Join-Path $artifactRoot 'inherited'
[void](Write-NewH2SFile 'inherited/.venv/pyvenv.cfg' "include-system-site-packages = true`nhome = C:\DO-NOT-FOLLOW-SYNTHETIC-BASE`n")
$inheritReport=Invoke-H2SScan -Name 'inherited-audit' -Target $inherited
Assert-H2S (-not $inheritReport.scanComplete -and 'inherited-python-environment-not-followed' -in $inheritReport.http2ShellAssessment.limits.reasons) 'Inherited environment silently treated as fully covered'

$malformed=Write-NewH2SFile 'bad/package-lock.json' '{"packages":'
$badReport=Invoke-H2SScan -Name 'malformed-audit' -Target $malformed
Assert-H2S (-not $badReport.scanComplete -and 'metadata-parse-error' -in $badReport.http2ShellAssessment.limits.reasons) 'Malformed metadata became a completed negative'

$binaryLock=Write-NewH2SFile 'binary-lock/bun.lockb' 'SYNTHETIC UNSUPPORTED BINARY LOCK'
$binaryReport=Invoke-H2SScan -Name 'binary-lock-audit' -Target $binaryLock
Assert-H2S (-not $binaryReport.scanComplete -and @($binaryReport.findings | Where-Object {$_.category -eq 'BUN_LOCKB_UNSUPPORTED' -and $_.check -eq 'Http2Shell'}).Count -eq 1) 'Binary lock silently counted as covered'

$manyBlocks=New-Object Text.StringBuilder
foreach ($number in 1..205) { [void]$manyBlocks.Append("[[package]]`nname = 'brotli'`nversion = '1.2.0'`n") }
$limitedFile=Write-NewH2SFile 'limited/uv.lock' $manyBlocks.ToString()
$limitedReport=Invoke-H2SScan -Name 'inventory-limit' -Target $limitedFile
Assert-H2S (-not $limitedReport.scanComplete -and $limitedReport.http2ShellAssessment.entries.Count -eq 200 -and $limitedReport.http2ShellAssessment.limits.entriesOmitted -eq 5) 'Inventory truncation was not reported as incomplete'

$oldTestRoot=[Environment]::GetEnvironmentVariable('DEV_SUPPLYCHAIN_CHECKER_TEST_HTTP2SHELL_ROOTS','Process')
try {
    $hostRoot=Join-Path $artifactRoot 'host'
    [void](Write-NewH2SFile 'host/shared/Microsoft.NETCore.App/10.0.13/.version' "synthetic`n10.0.13`n")
    [void](Write-NewH2SFile 'host/Lib/site-packages/brotlicffi-1.2.1.0.dist-info/METADATA' "Metadata-Version: 2.1`nName: brotlicffi`nVersion: 1.2.1.0`n`n")
    [Environment]::SetEnvironmentVariable('DEV_SUPPLYCHAIN_CHECKER_TEST_HTTP2SHELL_ROOTS',$hostRoot,'Process')
    $hostReport=Invoke-H2SScan -Name 'synthetic-host' -Extra @('-Http2ShellHost','-SyntheticValidation')
    Assert-H2S ($hostReport.scanComplete -and -not $hostReport.mode.path -and $hostReport.http2ShellAssessment.hostScanPerformed) 'Synthetic host mode failed'
    Assert-H2S ($hostReport.scanRoots.Count -eq 1 -and $hostReport.scanRoots[0] -like '*http2shell-regression-*\host') 'Synthetic host scope escaped'
    Assert-H2S ($hostReport.http2ShellAssessment.entries.Count -eq 2) 'Synthetic host metadata not inspected'
    Assert-H2S ($hostReport.checkStats.Http2Shell.executionStatus -eq 'completed') 'Completed host audit check status missing'
    [Environment]::SetEnvironmentVariable('DEV_SUPPLYCHAIN_CHECKER_TEST_HTTP2SHELL_ROOTS','', 'Process')
    $missing=Invoke-H2SScan -Name 'missing-host-root' -Extra @('-Http2ShellHost','-SyntheticValidation') -ExpectedExit 3
    Assert-H2S (-not $missing.http2ShellAssessment.hostScanPerformed -and $missing.scanRoots.Count -eq 0) 'Missing synthetic root fell back to host'
    [Environment]::SetEnvironmentVariable('DEV_SUPPLYCHAIN_CHECKER_TEST_HTTP2SHELL_ROOTS',$repoRoot,'Process')
    $rejected=Invoke-H2SScan -Name 'rejected-host-root' -Extra @('-Http2ShellHost','-SyntheticValidation') -ExpectedExit 3
    Assert-H2S (-not $rejected.http2ShellAssessment.hostScanPerformed -and $rejected.scanRoots.Count -eq 0) 'Rejected synthetic root fell back to host'
    $ordinary=Invoke-H2SScan -Name 'ordinary-mode' -Target (Join-Path $project '.nvmrc') -Checks 'Recommended'
    Assert-H2S (-not $ordinary.http2ShellAssessment.enabled -and -not $ordinary.mode.http2ShellHost) 'Ambient variable enabled special audit'
    $nodeFindings = @($ordinary.findings | Where-Object {$_.category -eq 'NODE_RUNTIME_VULNERABILITY_VERSION' -and $_.severity -eq 'WARN'})
    Assert-H2S ($nodeFindings.Count -eq 1 -and 'CVE-2026-111497' -in $nodeFindings[0].vulnerability.advisoryIds) 'Recommended missed the Node.js Brotli advisory'
}
finally { [Environment]::SetEnvironmentVariable('DEV_SUPPLYCHAIN_CHECKER_TEST_HTTP2SHELL_ROOTS',$oldTestRoot,'Process') }

$cmd=Join-Path $env:SystemRoot 'System32\cmd.exe'; $launcher=Join-Path $repoRoot 'run-checker.bat'
$launcherOutput=& $cmd /d /c ('""'+$launcher+'" http2shell "'+$project+'" --no-pause"') 2>&1 | Out-String
$launcherExit=$LASTEXITCODE; $global:LASTEXITCODE=0
Assert-H2S ($launcherExit -in @(0,1) -and $launcherOutput -match 'HTTP2Shell:') 'Folder launcher did not run audit'
$refused=& $cmd /d /c ('""'+$launcher+'" http2shellpc --no-pause"') 2>&1 | Out-String
$refusedExit=$LASTEXITCODE; $global:LASTEXITCODE=0
Assert-H2S ($refusedExit -eq 4 -and $refused -match 'Non-interactive execution is not allowed for HTTP2Shell' -and $refused -notmatch 'Phase 1/') 'PC launcher did not refuse unattended host scan'
# Feed each prompt separately: cmd.exe set /p does not reliably preserve several
# pre-buffered pipe lines across the launcher's child PowerShell validations.
$menuInfo=New-Object Diagnostics.ProcessStartInfo
$menuInfo.FileName=$cmd; $menuInfo.Arguments='/d /c ""'+$launcher+'" --no-pause"'
$menuInfo.UseShellExecute=$false; $menuInfo.CreateNoWindow=$true
$menuInfo.RedirectStandardInput=$true; $menuInfo.RedirectStandardOutput=$true; $menuInfo.RedirectStandardError=$true
$menuProcess=New-Object Diagnostics.Process; $menuProcess.StartInfo=$menuInfo
$menuText=New-Object Text.StringBuilder
try {
    [void]$menuProcess.Start()
    foreach ($inputStep in @(@('Select mode:','11'),@('Audit scope [1]:','1'),@('Folder to audit:',$project))) {
        while (-not $menuText.ToString().EndsWith($inputStep[0],[StringComparison]::Ordinal)) {
            $buffer=New-Object char[] 1
            $readTask=$menuProcess.StandardOutput.ReadAsync($buffer,0,1)
            if (-not $readTask.Wait(30000) -or $readTask.Result -ne 1) {throw ('Menu did not reach prompt: '+$inputStep[0])}
            [void]$menuText.Append($buffer[0])
        }
        $menuProcess.StandardInput.WriteLine($inputStep[1]); $menuProcess.StandardInput.Flush()
    }
    $menuProcess.StandardInput.Close()
    [void]$menuText.Append($menuProcess.StandardOutput.ReadToEnd())
    $menuProcess.WaitForExit(); $menuExit=$menuProcess.ExitCode; $menuOutput=$menuText.ToString()
}
finally { $menuProcess.Dispose() }
Assert-H2S ($menuExit -in @(0,1) -and $menuOutput -match 'HTTP2Shell:') 'Menu 11 did not dispatch selected folder audit'
Write-Host ("HTTP2Shell audit regressions passed: {0} assertions. Artifacts: {1}" -f $assertions,$artifactRoot)
