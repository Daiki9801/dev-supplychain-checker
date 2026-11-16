[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repoRoot=Split-Path -Parent $PSScriptRoot
$scanner=Join-Path $repoRoot 'Scan-DevSupplyChain.ps1'
$winPS=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$artifactRoot=Join-Path $repoRoot ('reports/node-security-20261116-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($artifactRoot)
$assertions=0; $boundaries=0; $scans=0
function Assert-NodeReview {param([bool]$Condition,[string]$Message);$script:assertions++;if(-not $Condition){throw $Message}}
function Write-NewNodeReviewFile {
    param([string]$Relative,[string]$Text)
    $path=[IO.Path]::GetFullPath((Join-Path $artifactRoot $Relative))
    if(-not $path.StartsWith($artifactRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Synthetic path escaped'}
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
    return $path
}
# Load pure helpers only. Scanner startup and automatic host discovery do not run.
$allow=@('New-ArrayList','Add-ListItem','Get-PropertyValue','New-NodeRuntimeRange','New-NodeRuntimeFixedVersion','New-NodeRuntimeAdvisory','Load-BuiltinNodeRuntimeIocs','ConvertTo-NodeRuntimeVersion','Compare-NodeRuntimePrerelease','Compare-NodeRuntimeVersion','Test-NodeRuntimeVersionInRange','Get-NodeRuntimeFixedVersionForMajor','Get-NodeRuntimeConditionStatus','Get-NodeRuntimeAdvisoryMatches','Get-Http2ShellVersionAssessment')
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($scanner,[ref]$tokens,[ref]$parseErrors)
Assert-NodeReview ($parseErrors.Count -eq 0) 'Scanner parser failed'
$definitions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $allow},$true))
Assert-NodeReview ($definitions.Count -eq $allow.Count) 'Pure helper allowlist mismatch'
foreach($definition in $definitions){. ([scriptblock]::Create($definition.Extent.Text))}
$script:Context=@{iocs=@{nodeRuntimes=Load-BuiltinNodeRuntimeIocs}}
$allNovember=@('CVE-2026-123863','CVE-2026-123864','CVE-2026-123865','CVE-2026-123866','CVE-2026-126051','CVE-2026-123872','CVE-2026-123874')
$node22=@('CVE-2026-123864','CVE-2026-123865','CVE-2026-123866','CVE-2026-123872')
$fixed=@{22='22.23.5';24='24.22.3';26='26.13.1'}
$before=@{22='22.23.4';24='24.22.2';26='26.13.0'}
Assert-NodeReview ($script:Context.iocs.nodeRuntimes.advisories.Count -eq 24) 'Expected 17 retained plus seven November advisories'
foreach($id in $allNovember){
    $advisory=@($script:Context.iocs.nodeRuntimes.advisories | Where-Object id -eq $id)
    Assert-NodeReview ($advisory.Count -eq 1 -and $advisory[0].upstreamSeverity -eq 'HIGH' -and $advisory[0].published -eq '2026-11-11') ('Missing November advisory: '+$id)
    foreach($major in @(22,24,26)){
        $affected=($major -ne 22 -or $id -in $node22)
        foreach($versionCase in @(
            @(([string]$major+'.0.0'),$affected),@($before[$major],$affected),
            @(($fixed[$major]+'-rc.1'),$affected),@($fixed[$major],$false),@(($fixed[$major]+'+build.1'),$false)
        )){
            $matches=@(Get-NodeRuntimeAdvisoryMatches (ConvertTo-NodeRuntimeVersion $versionCase[0]) | Where-Object {$_.advisory.id -eq $id})
            Assert-NodeReview (($matches.Count -eq 1) -eq [bool]$versionCase[1]) ($id+': boundary '+$versionCase[0])
            if($matches.Count -eq 1){Assert-NodeReview ($matches[0].fixedVersion -eq $fixed[$major] -and $matches[0].conditionStatus -eq 'unknown') ($id+': fix or unverified preconditions lost')}
            $boundaries++
        }
    }
    foreach($version in @('20.20.2','21.0.0','23.0.0','25.8.2','27.0.0')){
        Assert-NodeReview (@(Get-NodeRuntimeAdvisoryMatches (ConvertTo-NodeRuntimeVersion $version) | Where-Object {$_.advisory.id -eq $id}).Count -eq 0) ($id+': guessed unsupported major '+$version)
        $boundaries++
    }
}
Assert-NodeReview ((Get-Http2ShellVersionAssessment 'node' '24.22.1').status -eq 'upstream-fixed-version') 'November Node update incorrectly changed the Brotli CVE fix boundary'

$pins=@(
    @{name='before-22';version='22.23.4';ids=$node22},
    @{name='before-24-a';version='24.22.1';ids=$allNovember},
    @{name='before-24-b';version='24.22.2';ids=$allNovember},
    @{name='before-26-a';version='26.12.1';ids=$allNovember},
    @{name='before-26-b';version='26.13.0';ids=$allNovember},
    @{name='fixed-22';version='22.23.5';ids=@()},
    @{name='fixed-24';version='24.22.3';ids=@()},
    @{name='fixed-26';version='26.13.1';ids=@()},
    @{name='fixed-build';version='22.23.5+build.1';ids=@()},
    @{name='prerelease';version='24.22.3-rc.1';ids=$allNovember}
)
foreach($pin in $pins){[void](Write-NewNodeReviewFile ('pins/'+$pin.name+'/.nvmrc') ($pin.version+"`n"))}
function Invoke-NodeReviewScan {
    param([string]$Name,[string]$Executable)
    $json=Join-Path $artifactRoot ($Name+'.json');$txt=Join-Path $artifactRoot ($Name+'.txt')
    & $winPS -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Executable -Path (Join-Path $artifactRoot 'pins') -Checks NodeRuntime,Http2Shell,ScannerSelf -ReportDir (Join-Path $artifactRoot 'output') -JsonOut $json -TextOut $txt -Quiet -NoColor | Out-Null
    $code=$LASTEXITCODE;$global:LASTEXITCODE=0
    Assert-NodeReview ($code -eq 1) ($Name+': expected WARN exit 1, got '+$code)
    $r=[IO.File]::ReadAllText($json,[Text.Encoding]::UTF8) | ConvertFrom-Json
    Assert-NodeReview ($r.scanComplete -and $r.completionStatus -eq 'complete') ($Name+': incomplete scan')
    Assert-NodeReview (-not $r.mode.userProfile -and -not $r.mode.majorLocations -and -not $r.mode.endpointTelemetry -and -not $r.mode.syntheticValidation -and -not $r.mode.http2ShellHost) ($Name+': host mode enabled')
    Assert-NodeReview ($r.nodeRuntimeScope -eq 'project-static' -and $r.nodeRuntimeAssessment.installedBinaries.inspected -eq 0) ($Name+': automatic host discovery enabled')
    Assert-NodeReview ($r.executionSafety.networkAccess -eq 'none' -and $r.executionSafety.externalCommands -eq 'none' -and $r.executionSafety.targetCodeExecution -eq 'none') ($Name+': execution safety')
    Assert-NodeReview (@($r.findings | Where-Object {$_.category -in @('SCANNER_ERROR','SCANNER_FILE_ERROR','REGEX_SCAN_TIMEOUT')}).Count -eq 0) ($Name+': scanner error')
    $text=[IO.File]::ReadAllText($txt,[Text.Encoding]::UTF8)
    foreach($pin in $pins){
        $suffix='[\\/]'+[regex]::Escape($pin.name)+'[\\/]\.nvmrc$'
        $findings=@($r.findings | Where-Object {$_.check -eq 'NodeRuntime' -and $_.riskType -eq 'vulnerability' -and $_.path -match $suffix})
        if($pin.ids.Count -eq 0){
            Assert-NodeReview ($findings.Count -eq 0) ($Name+': fixed version matched '+$pin.name)
            Assert-NodeReview (@($r.nodeRuntimeAssessment.inventory.entries | Where-Object {$_.path -match $suffix -and $_.advisoryStatus -eq 'not-affected-in-offline-baseline'}).Count -eq 1) ($Name+': fixed version inventory missing '+$pin.name)
        }else{
            Assert-NodeReview ($findings.Count -eq 1) ($Name+': missing aggregated finding '+$pin.name)
            $f=$findings[0]
            $actual=@($f.vulnerability.advisoryIds | Sort-Object)
            Assert-NodeReview (($actual -join ',') -eq (($pin.ids | Sort-Object) -join ',')) ($Name+': incorrect CVE set '+$pin.name)
            Assert-NodeReview ($f.severity -eq 'WARN' -and $f.vulnerability.upstreamSeverity -eq 'HIGH' -and $f.vulnerability.conditionStatus -eq 'unknown') ($Name+': severity/preconditions overstated')
            Assert-NodeReview ($text.Contains($f.title) -and $text.Contains($f.evidence)) ($Name+': TXT/JSON mismatch')
        }
    }
    Assert-NodeReview (@($r.findings | Where-Object severity -eq 'DANGER').Count -eq 0) ($Name+': version-only evidence became DANGER')
    Assert-NodeReview ($r.http2ShellAssessment.lastReviewed -eq '2026-11-16') ($Name+': HTTP2Shell review date missing')
    $script:scans++
}
Invoke-NodeReviewScan 'shipped' $scanner
# New synthetic distributions exercise fallback without removing any source file.
foreach($mode in @('missing','invalid')){
    $copy=Write-NewNodeReviewFile ($mode+'/Scan-DevSupplyChain.ps1') ([IO.File]::ReadAllText($scanner))
    if($mode -eq 'invalid'){[void](Write-NewNodeReviewFile ($mode+'/iocs/known-node-runtimes.json') '{invalid')}
    Invoke-NodeReviewScan $mode $copy
}
[void](Write-NewNodeReviewFile 'result.json' (@{status='passed';powerShell=$PSVersionTable.PSVersion.ToString();boundaries=$boundaries;scans=$scans;assertions=$assertions} | ConvertTo-Json))
Write-Output ('Node November regressions passed: {0} boundaries, {1} scans, {2} assertions. Artifacts: {3}' -f $boundaries,$scans,$assertions,$artifactRoot)
