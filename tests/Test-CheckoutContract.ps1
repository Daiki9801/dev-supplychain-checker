[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repoRoot=Split-Path -Parent $PSScriptRoot
$workflow=[IO.File]::ReadAllText((Join-Path $repoRoot '.github/workflows/validate.yml'))
$assertions=0
function Assert-Checkout {
    param([bool]$Condition,[string]$Message)
    $script:assertions++
    if (-not $Condition) { throw $Message }
}
function Get-CheckoutGuard {
    param([string]$Name)
    $pattern='(?ms)^      - name: '+[regex]::Escape($Name)+'\r?\n        shell: powershell\r?\n(?:        env:\r?\n(?:          [^\r\n]+\r?\n)+)?        run: \|\r?\n(?<code>.*?)(?=^      - name:|\z)'
    $match=[regex]::Match($workflow,$pattern)
    Assert-Checkout $match.Success ('Missing workflow guard: '+$Name)
    return [scriptblock]::Create(($match.Groups['code'].Value -replace '(?m)^          ',''))
}
$checkoutGuard=Get-CheckoutGuard 'Fetch event commit with Git'
Assert-Checkout ($workflow.IndexOf('Fetch event commit with Git') -lt $workflow.IndexOf('Check checkout guard regressions')) 'Checkout runs after repository code'
Assert-Checkout ($workflow -notmatch '(?m)^        uses:') 'Workflow executes an external Action'
foreach ($setting in @("GIT_CONFIG_NOSYSTEM: '1'",'GIT_CONFIG_GLOBAL: NUL',"GIT_CONFIG_COUNT: '0'","GIT_CONFIG_PARAMETERS: ''","GIT_TERMINAL_PROMPT: '0'",'GCM_INTERACTIVE: Never',"GIT_ASKPASS: ''","SSH_ASKPASS: ''","GIT_SSL_NO_VERIFY: '0'")) {
    Assert-Checkout ($workflow.Contains('          '+$setting)) ('Missing checkout environment setting: '+$setting)
}
Assert-Checkout ($checkoutGuard.ToString() -notmatch 'Invoke-WebRequest|Invoke-RestMethod|Expand-Archive|GITHUB_TOKEN|Remove-Item') 'Checkout gained a network fallback, token or cleanup path'

# All executable discovery, Git execution and path queries below are mocks.
# No actual Git command, network connection or host path probe runs.
& {
    function Get-Command { param($Name,$CommandType,$ErrorAction); if ($case.missing) { throw 'synthetic missing Git' }; return @{Path='git.exe'} }
    function Get-Item {
        param($LiteralPath,[switch]$Force,$ErrorAction)
        if ($case.missingWorkspace) { throw 'synthetic missing workspace' }
        return @{PSIsContainer=(-not $case.workspaceFile);Attributes=$(if($case.reparse){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Directory})}
    }
    function Get-ChildItem { param($LiteralPath,[switch]$Force,$ErrorAction); if ($case.nonempty) { return '.existing-hidden-file' } }
    function git.exe {
        $call=[string[]]$args
        [void]$calls.Add($call)
        $global:LASTEXITCODE=0
        if ($call[0] -eq 'version') {
            if ($case.failAt -eq 'version') { $global:LASTEXITCODE=1 }
            if ($case.ContainsKey('version')) { return $case.version }
            return 'git version 2.52.0.windows.1'
        }
        $commandIndex=[Array]::IndexOf($call,'-C')+2
        $stage=$call[$commandIndex]
        if ($stage -eq 'rev-parse') { $stage=$call[-1] }
        if ($stage -eq $case.failAt) { $global:LASTEXITCODE=1; return '' }
        if ($stage -eq 'FETCH_HEAD^{commit}') { if($case.ContainsKey('fetched')){return $case.fetched}; return ('a'*40) }
        if ($stage -eq 'HEAD') { if($case.ContainsKey('head')){return $case.head}; return ('a'*40) }
    }
    $baseEnvironment=@{GITHUB_SERVER_URL='https://github.com';GITHUB_REPOSITORY='Daiki9801/dev-supplychain-checker';GITHUB_EVENT_NAME='push';GITHUB_SHA=('a'*40);GITHUB_WORKSPACE='C:\synthetic-runner\workspace'}
    $savedEnvironment=@{}
    foreach($name in $baseEnvironment.Keys) { $savedEnvironment[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
    $cases=@(
        @{name='push';pass=$true;count=7},
        @{name='pull-request merge SHA';environment=@{GITHUB_EVENT_NAME='pull_request'};pass=$true;count=7},
        @{name='manual';environment=@{GITHUB_EVENT_NAME='workflow_dispatch'};pass=$true;count=7},
        @{name='minimum Git';version='git version 2.32.0';pass=$true;count=7},
        @{name='minimum Windows Git';version='git version 2.32.0.windows.1';pass=$true;count=7},
        @{name='future Git';version='git version 3.0.0';pass=$true;count=7},
        @{name='old Git';version='git version 2.31.9';count=1},
        @{name='legacy Git';version='git version 1.9.5';count=1},
        @{name='incomplete version';version='git version 2.52';count=1},
        @{name='release candidate';version='git version 2.52.0-rc1';count=1},
        @{name='unexpected version prefix';version='unexpected git version 2.52.0';count=1},
        @{name='empty version';version='';count=1},
        @{name='version error';failAt='version';count=1},
        @{name='Git absent';missing=$true;count=0},
        @{name='wrong server';environment=@{GITHUB_SERVER_URL='https://example.invalid'};count=0},
        @{name='wrong repository';environment=@{GITHUB_REPOSITORY='other/repository'};count=0},
        @{name='unexpected event';environment=@{GITHUB_EVENT_NAME='pull_request_target'};count=0},
        @{name='short SHA';environment=@{GITHUB_SHA=('a'*39)};count=0},
        @{name='option-like SHA';environment=@{GITHUB_SHA='--upload-pack=unexpected'};count=0},
        @{name='uppercase SHA';environment=@{GITHUB_SHA=('A'*40)};count=0},
        @{name='empty workspace';environment=@{GITHUB_WORKSPACE=''};count=0},
        @{name='relative workspace';environment=@{GITHUB_WORKSPACE='relative'};count=0},
        @{name='UNC workspace';environment=@{GITHUB_WORKSPACE='\\server\share\workspace'};count=0},
        @{name='drive root';environment=@{GITHUB_WORKSPACE='C:\'};count=0},
        @{name='missing workspace';missingWorkspace=$true;count=0},
        @{name='file workspace';workspaceFile=$true;count=0},
        @{name='reparse workspace';reparse=$true;count=0},
        @{name='existing files';nonempty=$true;count=0},
        @{name='init error';failAt='init';count=2},
        @{name='remote error';failAt='remote';count=3},
        @{name='fetch error';failAt='fetch';count=4},
        @{name='fetched identity error';failAt='FETCH_HEAD^{commit}';count=5},
        @{name='fetched identity mismatch';fetched=('b'*40);count=5},
        @{name='empty fetched identity';fetched='';count=5},
        @{name='checkout error';failAt='checkout';count=6},
        @{name='HEAD error';failAt='HEAD';count=7},
        @{name='HEAD mismatch';head=('b'*40);count=7},
        @{name='empty HEAD';head='';count=7}
    )
    try {
        foreach ($case in $cases) {
            foreach($name in $baseEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name,$baseEnvironment[$name],'Process') }
            if($case.environment) { foreach($name in $case.environment.Keys) { [Environment]::SetEnvironmentVariable($name,$case.environment[$name],'Process') } }
            $calls=New-Object Collections.ArrayList
            $passed=$true
            $failure=''
            try { & $checkoutGuard } catch { $passed=$false; $failure=$_.Exception.Message }
            Assert-Checkout ($passed -eq [bool]$case.pass) ('Checkout case failed: '+$case.name+'; '+$failure)
            Assert-Checkout ($calls.Count -eq $case.count) ('Checkout continued after failure or skipped a stage: '+$case.name)
            if($case.pass) {
                $commands=@($calls | Select-Object -Skip 1 | ForEach-Object { $i=[Array]::IndexOf($_,'-C')+2; ,([string[]]$_[$i..($_.Length-1)]) })
                Assert-Checkout (($commands | ForEach-Object { $_[0] }) -join ',' -eq 'init,remote,fetch,rev-parse,checkout,rev-parse') 'Git command ordering changed'
                Assert-Checkout (($commands[0] -join ' ') -ceq 'init --quiet --template=') 'Git templates are enabled'
                Assert-Checkout (($commands[1] -join ' ') -ceq 'remote add origin https://github.com/Daiki9801/dev-supplychain-checker.git') 'Remote URL changed'
                Assert-Checkout (($commands[2] -join ' ') -ceq ('fetch --no-tags --depth=1 --no-recurse-submodules origin '+('a'*40))) 'Fetch does not select the exact event commit'
                Assert-Checkout (($commands[4] -join ' ') -ceq ('checkout --detach '+('a'*40))) 'Checkout is not detached at the event commit'
                foreach($call in @($calls | Select-Object -Skip 1)) {
                    foreach($option in @('credential.helper=','http.extraHeader=','http.sslVerify=true','http.followRedirects=false','protocol.allow=never','protocol.https.allow=always','core.autocrlf=true')) {
                        Assert-Checkout ($call -ccontains $option) ('Missing Git option: '+$option)
                    }
                }
            }
        }
        $script:caseCount=$cases.Count
    }
    finally { foreach($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name,$savedEnvironment[$name],'Process') } }
}

# Parse every inline PowerShell step, retaining static launcher assertions while
# rejecting host-mode command parameters/argument literals and profile rewrites.
function Get-UnsafeCiScopeNode {
    param([string]$Source)
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($Source,[ref]$tokens,[ref]$errors)
    if(@($errors).Count -ne 0) { throw 'CI PowerShell parser failed.' }
    return @($ast.FindAll({
        param($node)
        if($node -is [Management.Automation.Language.CommandParameterAst]) {
            return $node.ParameterName -in @('UserProfile','MajorLocations','EndpointTelemetry')
        }
        if($node -is [Management.Automation.Language.StringConstantExpressionAst] -and
            $node.Value -in @('-UserProfile','-MajorLocations','-EndpointTelemetry')) {
            return -not ($node.Parent -is [Management.Automation.Language.BinaryExpressionAst])
        }
        if($node -is [Management.Automation.Language.AssignmentStatementAst]) {
            return $node.Left.Extent.Text -match '(?i)^\$env:(USERPROFILE|APPDATA|LOCALAPPDATA|CODEX_HOME|CLAUDE_CONFIG_DIR|OneDrive(?:Commercial|Consumer)?)$'
        }
        return $false
    },$true))
}
$runBlocks=@([regex]::Matches($workflow,'(?ms)^        run: \|\r?\n(?<code>.*?)(?=^      - name:|\z)'))
Assert-Checkout ($runBlocks.Count -gt 10) 'CI run blocks were not extracted'
foreach($block in $runBlocks) {
    $code=$block.Groups['code'].Value -replace '(?m)^          ',''
    Assert-Checkout (@(Get-UnsafeCiScopeNode $code).Count -eq 0) 'CI contains an automated host mode or profile environment rewrite'
}
$boundarySource=[IO.File]::ReadAllText((Join-Path $repoRoot 'tests/Test-SecurityBoundaryRegressions.ps1'))
Assert-Checkout (@(Get-UnsafeCiScopeNode $boundarySource).Count -eq 0) 'Security boundary suite contains a host invocation'
Assert-Checkout (@(Get-UnsafeCiScopeNode '& scanner.ps1 -UserProfile').Count -eq 1) 'Scope guard missed a direct host switch'
Assert-Checkout (@(Get-UnsafeCiScopeNode '$arguments = @(''-MajorLocations'')').Count -eq 1) 'Scope guard missed an argument-array host switch'
Assert-Checkout (@(Get-UnsafeCiScopeNode '$env:USERPROFILE = ''synthetic''').Count -eq 1) 'Scope guard missed a profile rewrite'
Assert-Checkout (@(Get-UnsafeCiScopeNode '$text -notmatch ''-EndpointTelemetry''').Count -eq 0) 'Scope guard rejected a static launcher assertion'
$global:LASTEXITCODE=0
Write-Host ("Git checkout regressions passed: {0} cases, {1} CI blocks, {2} assertions." -f $caseCount,$runBlocks.Count,$assertions)
