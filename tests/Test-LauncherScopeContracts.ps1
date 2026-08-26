[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$launcherPath = Join-Path $repoRoot 'run-checker.bat'
$scannerPath = Join-Path $repoRoot 'Scan-DevSupplyChain.ps1'
$readmePath = Join-Path $repoRoot 'README.md'
$gitignorePath = Join-Path $repoRoot '.gitignore'
$gitattributesPath = Join-Path $repoRoot '.gitattributes'

function Assert-Contract {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Get-BatchBlock {
    param(
        [string]$Text,
        [string]$StartLabel,
        [string]$EndLabel
    )
    $pattern = '(?ims)^:' + [regex]::Escape($StartLabel) + '[ \t]*\r?$.*?(?=^:' + [regex]::Escape($EndLabel) + '[ \t]*\r?$)'
    $match = [regex]::Match($Text, $pattern)
    Assert-Contract -Condition $match.Success -Message ("Launcher block was not found: {0} -> {1}" -f $StartLabel, $EndLabel)
    return $match.Value
}

$launcher = [System.IO.File]::ReadAllText($launcherPath)
$scanner = [System.IO.File]::ReadAllText($scannerPath)
$readme = [System.IO.File]::ReadAllText($readmePath)
$gitignore = [System.IO.File]::ReadAllText($gitignorePath)
$gitattributes = [System.IO.File]::ReadAllText($gitattributesPath)

Assert-Contract -Condition ([bool]($launcher -match '(?m)^set "POWERSHELL_EXE=%SystemRoot%\\System32\\WindowsPowerShell\\v1[.]0\\powershell[.]exe"\r?$')) -Message 'Launcher does not pin Windows PowerShell 5.1 to the expected system path.'
Assert-Contract -Condition (-not [bool]($launcher -match '(?im)^\s*powershell[.]exe(?:\s|$)')) -Message 'Launcher still invokes powershell.exe through the current-directory executable search path.'
Assert-Contract -Condition ([regex]::Matches($launcher, '(?im)^\s*"%POWERSHELL_EXE%"\s+-NoLogo').Count -eq 18) -Message 'Not every launcher PowerShell invocation uses the pinned executable path.'
Assert-Contract -Condition (-not [bool]($scanner -match 'Test-IsStandaloneCheckerReferenceText')) -Message 'A filename/marker-based legacy checker exemption remains in the scanner.'
Assert-Contract -Condition (-not [bool]($scanner -match "Join-Path \`$script:BaseDir '[.]github\\workflows\\validate[.]yml'")) -Message 'The active validation workflow is still trusted only by scanner-relative path.'
Assert-Contract -Condition (-not [bool]($scanner -match "Join-Path \`$script:BaseDir 'tests\\Test-LauncherScopeContracts[.]ps1'")) -Message 'The active launcher contract is still trusted only by scanner-relative path.'
Assert-Contract -Condition (-not [bool]($scanner -match '\^reports\.\*\$')) -Message 'The scanner still excludes every reports-prefixed directory.'
Assert-Contract -Condition ([bool]($scanner -match 'reportPaths\.directory')) -Message 'Own report exclusion is not bound to the configured report directory.'
Assert-Contract -Condition ([bool]($gitignore -match '(?m)^/reports/\r?$')) -Message '.gitignore does not ignore the exact default report directory.'
Assert-Contract -Condition (-not [bool]($gitignore -match '(?m)^reports\*/\r?$')) -Message '.gitignore still hides arbitrary reports-prefixed source directories.'
Assert-Contract -Condition ([bool]($gitattributes -match '(?m)^reports/\*\*\s+export-ignore\r?$')) -Message '.gitattributes does not exclude the exact default report directory from source archives.'
Assert-Contract -Condition (-not [bool]($gitattributes -match '(?m)^reports\*/\*\*\s+export-ignore\r?$')) -Message '.gitattributes still hides reports-prefixed source directories from source archives.'

Assert-Contract -Condition ([bool]($scanner -match '\[switch\]\$SyntheticValidation')) -Message 'The explicit synthetic validation gate is missing.'
Assert-Contract -Condition ([bool]($scanner -match 'if \(-not \$SyntheticValidation\)')) -Message 'Ambient test-root variables are not gated by SyntheticValidation.'
Assert-Contract -Condition (-not [bool]($scanner -match 'DEV_SUPPLYCHAIN_CHECKER_TEST_NODE_RUNTIME_HOST_SCOPE')) -Message 'The ambient Node host-scope override remains active.'
Assert-Contract -Condition (-not [bool]($launcher -match '(?i)-SyntheticValidation')) -Message 'The distributed launcher exposes the test-only SyntheticValidation switch.'
foreach ($testRootVariable in @(
    'DEV_SUPPLYCHAIN_CHECKER_TEST_NODE_RUNTIME_ROOTS',
    'DEV_SUPPLYCHAIN_CHECKER_TEST_NPM_GLOBAL_ROOTS',
    'DEV_SUPPLYCHAIN_CHECKER_TEST_NPM_CACHE_ROOTS'
)) {
    Assert-Contract -Condition ([bool]($launcher -match ('(?m)^set "' + [regex]::Escape($testRootVariable) + '="\r?$'))) -Message ("Launcher does not clear inherited test-only root variable: {0}" -f $testRootVariable)
}

$packageBlock = Get-BatchBlock -Text $launcher -StartLabel 'ScanPackages' -EndLabel 'ScanDeep'
$aiBlock = Get-BatchBlock -Text $launcher -StartLabel 'ScanAi' -EndLabel 'ScanCiCd'
$cicdBlock = Get-BatchBlock -Text $launcher -StartLabel 'ScanCiCd' -EndLabel 'PromptCustomChecks'
foreach ($entry in @(
    @{ name='Package / Node'; text=$packageBlock },
    @{ name='AI / MCP / IDE'; text=$aiBlock },
    @{ name='CI/CD and hooks'; text=$cicdBlock }
)) {
    Assert-Contract -Condition ([bool]($entry.text -match '(?i)CHECKS=[^\r\n]*InvisibleUnicode')) -Message ("{0} launcher profile omitted the cross-cutting InvisibleUnicode check." -f $entry.name)
}

$customBlock = Get-BatchBlock -Text $launcher -StartLabel 'PromptCustomChecks' -EndLabel 'ScanNpmStatic'
foreach ($hostScopedCheck in @('NpmGlobal','NpmCache','MajorRecommended','AllSafe')) {
    Assert-Contract -Condition (-not [bool]($customBlock -match ("(?i)'?" + [regex]::Escape($hostScopedCheck) + "'?"))) -Message ("Custom current-folder mode still accepts host-scoped check: {0}" -f $hostScopedCheck)
}
foreach ($projectLocalCheck in @('Packages','NodeRuntime','InvisibleUnicode','ScannerSelf','Recommended')) {
    Assert-Contract -Condition ([bool]($customBlock -match ("(?i)'" + [regex]::Escape($projectLocalCheck) + "'"))) -Message ("Custom current-folder mode lost supported local check: {0}" -f $projectLocalCheck)
}
Assert-Contract -Condition ([bool]($customBlock -match '(?i)confirmed modes 6, 7, and 9')) -Message 'Custom mode does not direct host-scoped checks to confirmed modes.'

$majorBlock = Get-BatchBlock -Text $launcher -StartLabel 'ScanMajor' -EndLabel 'ScanUserProfile'
Assert-Contract -Condition ([bool]($majorBlock -match '(?i)static npm global metadata')) -Message 'Major mode confirmation omitted static npm global scope.'
Assert-Contract -Condition ([bool]($majorBlock -match '(?i)Program Files/PATH/version-manager Node[.]js file metadata')) -Message 'Major mode confirmation omitted bounded host Node.js scope.'

$userProfileBlock = Get-BatchBlock -Text $launcher -StartLabel 'ScanUserProfile' -EndLabel 'ScanFull'
Assert-Contract -Condition ([bool]($userProfileBlock -match '(?i)Program Files/PATH/version-manager Node[.]js file metadata')) -Message 'UserProfile confirmation omitted bounded host Node.js scope.'

Assert-Contract -Condition (-not [bool]($launcher -match '(?i)Secret values are not read or printed')) -Message 'Launcher still makes an absolute secret-content no-read claim.'
Assert-Contract -Condition ([bool]($launcher -match '(?i)Known credential files are inventory-only and are not read')) -Message 'Launcher omitted the known-credential inventory boundary.'
Assert-Contract -Condition ([bool]($launcher -match '(?i)Other configuration text is statically read; secret-like report evidence is redacted')) -Message 'Launcher omitted the static config-read and redaction disclosure.'

Assert-Contract -Condition ([bool]($scanner -match 'Add-ListItem \$excluded ''known-credential-file-contents''')) -Message 'scanScope omitted the known credential-content exclusion.'
Assert-Contract -Condition (-not [bool]($scanner -match 'Add-ListItem \$excluded ''secret-file-contents''')) -Message 'scanScope still overstates that all secret-file contents are excluded.'
Assert-Contract -Condition ([bool]($scanner -match 'function Get-SafeAutomaticProfileRoot')) -Message 'Environment-defined automatic roots do not pass through a shared profile-boundary validator.'
foreach ($environmentRoot in @('CODEX_HOME','CLAUDE_CONFIG_DIR')) {
    Assert-Contract -Condition ([bool]($scanner -match ('Get-SafeAutomaticProfileRoot[^\r\n]+' + [regex]::Escape($environmentRoot)))) -Message ("Automatic environment root bypasses the profile-boundary validator: {0}" -f $environmentRoot)
}
Assert-Contract -Condition ([bool]($scanner -match 'Get-SafeAutomaticProfileRoot[^\r\n]+-EnvironmentName \$oneDriveEnv')) -Message 'OneDrive automatic roots bypass the profile-boundary validator.'

Assert-Contract -Condition ([bool]($readme -match '(?i)Project-local `Recommended` scans[^\r\n]+without searching host locations')) -Message 'README does not distinguish project-local NodeRuntime scope.'
Assert-Contract -Condition ([bool]($readme -match '(?i)MajorRecommended[^\r\n]+local process-PATH[^\r\n]+version-manager')) -Message 'README does not disclose broader host NodeRuntime scope.'
Assert-Contract -Condition ([bool]($readme -match '(?i)Custom menu item `8` accepts project-local checks only')) -Message 'README does not document the custom-mode scope boundary.'

Write-Host 'Launcher scope contracts passed.'
