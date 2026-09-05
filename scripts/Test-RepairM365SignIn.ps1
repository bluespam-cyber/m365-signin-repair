#Requires -Version 5.1
<#
.SYNOPSIS
    Offline test for Repair-M365SignIn.ps1. Runs the whole ladder against a fake, broken sign-in state without touching
    the real machine: every Windows dependency the tool calls is shadowed by a function in this file, so nothing real is
    read or changed. Windows only (the tool is Windows only). Safe to run on any PC, elevated or not.

.DESCRIPTION
    Scenarios
      1  Diagnose, healthy device             expects no High findings, exit 0
      2  Diagnose, broken broker + stale PRT  expects APPX-BROKER and PRT-STALE, exit 1, nothing changed
      3  Repair with -WhatIf                  expects WhatIf actions only, nothing moved
      4  Repair, approved                     expects caches moved to quarantine, registry exported, actions Verified, exit 0
      5  Decode only                          expects the decoder table for three codes
    Each scenario runs the tool in a child PowerShell process with the shadow module preloaded, then inspects result.json.

.NOTES
    Version 3.0. Arwaz Khan, Microsoft Support Engineer.
#>
[CmdletBinding()]
param([string]$ScriptPath = (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Repair-M365SignIn.ps1'))

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ScriptPath)) { $ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Repair-M365SignIn.ps1' }
if (-not (Test-Path -LiteralPath $ScriptPath)) { throw "Repair-M365SignIn.ps1 not found next to or above this test." }

$lab = Join-Path -Path $env:TEMP -ChildPath ('M365SignInRepair-test-' + (Get-Date -Format 'HHmmss'))
New-Item -Path $lab -ItemType Directory -Force | Out-Null
$fakeLocal = Join-Path $lab 'AppData\Local'; $fakeRoam = Join-Path $lab 'AppData\Roaming'
$out = Join-Path $lab 'out'
$shadow = Join-Path $lab 'Shadow.psm1'

# ---------------------------------------------------------------------------------------------
# Shadow module: fakes for everything the tool touches. Controlled by environment variables set per scenario.
#   M365TEST_BROKEN=1     broker package missing, PRT stale, OneDrive PreSignIn present, Office identities present
#   M365TEST_ELEVATED=1   report as elevated
# ---------------------------------------------------------------------------------------------
$shadowSrc = @'
$script:State = @{ Appx = @{ 'Microsoft.AAD.BrokerPlugin' = ($env:M365TEST_BROKEN -ne '1'); 'Microsoft.Windows.CloudExperienceHost' = $true; 'Microsoft.AccountsControl' = $true; 'MSTeams' = $true }; Services = @{}; Procs = @() }
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter, [string]$Namespace, [string]$Class)
    switch ($ClassName) {
        'Win32_OperatingSystem' { return [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro (test)' } }
        'Win32_UserProfile' { return @([pscustomobject]@{ SID = $env:M365TEST_SID; LocalPath = $env:M365TEST_PROFILE; Loaded = $true; Special = $false }) }
        'Win32_Process' { return @() }
        'Win32_Service' { $n = if ($Filter -match "Name='([^']+)'") { $matches[1] } else { '' }; $m = if ($script:State.Services.ContainsKey($n)) { $script:State.Services[$n] } else { 'Manual' }; return [pscustomobject]@{ Name = $n; StartMode = $m } }
        'Win32_ComputerSystem' { return [pscustomobject]@{ PartOfDomain = $false } }
    }
    return $null
}
function Get-Service { param([string]$Name) return [pscustomobject]@{ Name = $Name; Status = 'Running'; StartType = 'Manual' } }
function Set-Service { param([string]$Name, [string]$StartupType) $script:State.Services[$Name] = $StartupType }
function Start-Service { param([string]$Name) }
function Get-WinEvent { param($FilterHashtable, [int]$MaxEvents) return @() }
function Resolve-DnsName { param([string]$Name, [string]$Type, [switch]$DnsOnly) return @([pscustomobject]@{ QueryType = 'A'; IPAddress = '20.190.160.1' }) }
function Invoke-WebRequest { param([string]$Uri, [string]$Method, [switch]$UseBasicParsing, [int]$TimeoutSec, [string]$OutFile) return [pscustomobject]@{ StatusCode = 200 } }
function Clear-DnsClientCache { }
function Get-AppxPackage { param([string]$Name, [string]$User) if ($script:State.Appx.ContainsKey($Name) -and $script:State.Appx[$Name]) { return [pscustomobject]@{ Name = $Name; Version = '1000.0.0.0' } } return $null }
function Add-AppxPackage { param([string]$Register, [switch]$DisableDevelopmentMode, [switch]$ForceApplicationShutdown) if (-not (Test-Path -LiteralPath $Register)) { throw "manifest missing: $Register" }; $script:State.Appx['Microsoft.AAD.BrokerPlugin'] = $true }
function Reset-AppxPackage { param([Parameter(ValueFromPipeline)]$InputObject) }
function Get-TimeZone { return [pscustomobject]@{ Id = 'UTC' } }
function Get-PSDrive { param([string]$Name) return [pscustomobject]@{ Free = 50GB; Used = 50GB } }
function Get-AuthenticodeSignature { param([string]$FilePath) return [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Microsoft Corporation' } } }
function Start-Process { param([string]$FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, [string]$WindowStyle, [switch]$NoNewWindow) $o = [pscustomobject]@{ ExitCode = 0; Id = 4242; Path = $FilePath }; $o | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) return $true } -Force; return $o }
function Get-Process { param([string]$Name, [int]$Id) if ($Name -eq 'OneDrive') { return $null }; return [pscustomobject]@{ Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Id = $PID } }
function Stop-Process { param([int]$Id, [switch]$Force) }
function Start-ThreadJob { param([string]$Name, $ArgumentList, [scriptblock]$ScriptBlock) return $null }
Export-ModuleMember -Function *
'@
Set-Content -Path $shadow -Value $shadowSrc -Encoding UTF8

# Fake dsregcmd, w32tm, netsh, cmdkey, reg through a fake System32 on PATH is not possible (the tool calls them by full path),
# so the tool's Invoke-Native is shadowed by a wrapper script that the child process dot-sources after the tool defines it.
$wrapper = Join-Path $lab 'Wrapper.ps1'
$wrapperSrc = @'
param([string]$Tool, [string]$ToolArgsJson)
Import-Module (Join-Path $env:M365TEST_LAB 'Shadow.psm1') -Force -DisableNameChecking
# The tool's native-process helper and a few fixed paths are swapped by text substitution before the copy runs,
# so dsregcmd, w32tm, netsh, cmdkey and reg are faked and the registry work lands under a test key.
$src = Get-Content -LiteralPath $Tool -Raw
$src = $src -replace 'function Invoke-Native \{', 'function Invoke-Native-Real {'
$fake = @"
function Invoke-Native {
    param([string]`$File, [string[]]`$Arguments = @(), [int]`$TimeoutSec = 60)
    `$leaf = [System.IO.Path]::GetFileName(`$File).ToLower()
    `$a = (`$Arguments -join ' ')
    switch (`$leaf) {
        'dsregcmd.exe' {
            if (`$a -match 'refreshprt') { `$env:M365TEST_PRTFRESH = '1'; return [pscustomobject]@{ ExitCode = 0; Output = '' } }
            `$upd = if (`$env:M365TEST_PRTFRESH -eq '1') { (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.000 UTC') } elseif (`$env:M365TEST_BROKEN -eq '1') { (Get-Date).ToUniversalTime().AddHours(-30).ToString('yyyy-MM-dd HH:mm:ss.000 UTC') } else { (Get-Date).ToUniversalTime().AddMinutes(-20).ToString('yyyy-MM-dd HH:mm:ss.000 UTC') }
            `$o = @('+----------------------------------------------------------------------+','| Device State |','             AzureAdJoined : YES','          EnterpriseJoined : NO','              DomainJoined : NO','                  DeviceId : 11111111-2222-3333-4444-555555555555','                TenantName : Contoso','          DeviceAuthStatus : SUCCESS','               KeySignTest : PASSED','              TpmProtected : YES','| SSO State |','                AzureAdPrt : YES','      AzureAdPrtUpdateTime : ' + `$upd,'| User State |','                    NgcSet : YES','                  CanReset : DestructiveAndNonDestructive','           WorkplaceJoined : NO','             WamDefaultSet : YES') -join [Environment]::NewLine
            return [pscustomobject]@{ ExitCode = 0; Output = `$o }
        }
        'w32tm.exe' { if (`$a -match 'stripchart') { return [pscustomobject]@{ ExitCode = 0; Output = '12:00:00, +00.0123456s' } }; if (`$a -match 'resync') { return [pscustomobject]@{ ExitCode = 0; Output = 'The command completed successfully.' } }; return [pscustomobject]@{ ExitCode = 0; Output = "Source: time.windows.com`nLast Successful Sync Time: 1/1/2026 12:00:00 PM" } }
        'netsh.exe' { return [pscustomobject]@{ ExitCode = 0; Output = 'Current WinHTTP proxy settings: Direct access (no proxy server).' } }
        'cmdkey.exe' { if (`$a -match '/delete') { `$env:M365TEST_CREDDELETED = '1'; return [pscustomobject]@{ ExitCode = 0; Output = 'CMDKEY: Credential deleted successfully.' } }; if (`$env:M365TEST_CREDDELETED -eq '1') { return [pscustomobject]@{ ExitCode = 0; Output = "Currently stored credentials:`n    Target: WindowsLive:target=virtualapp/didlogical" } }; return [pscustomobject]@{ ExitCode = 0; Output = "Currently stored credentials:`n    Target: MicrosoftOffice16_Data:ADAL:1234`n    Type: Generic`n    Target: WindowsLive:target=virtualapp/didlogical" } }
        'reg.exe' { `$m = [regex]::Match(`$a, '"([^"]+\.reg)"'); if (`$m.Success) { Set-Content -Path `$m.Groups[1].Value -Value 'Windows Registry Editor Version 5.00' }; return [pscustomobject]@{ ExitCode = 0; Output = '' } }
        'powershell.exe' { return [pscustomobject]@{ ExitCode = 0; Output = '' } }
    }
    return [pscustomobject]@{ ExitCode = 0; Output = '' }
}
"@
$src = $src.Replace("function Invoke-Native-Real {", $fake + "`nfunction Invoke-Native-Real {")
# Registry: point the user hive at a test key so identity keys can be created and removed without touching the real HKCU.
$src = $src.Replace("if (`$Sid -eq `$script:CurrentSid) { return 'HKCU:' }", "if (`$Sid -eq `$script:CurrentSid) { return 'HKCU:\Software\M365SignInRepairTest' }")
$src = $src.Replace("`$key = `"HKCU:\Software\Microsoft\Office\16.0\Common\Identity\`$k`"", "`$key = `"HKCU:\Software\M365SignInRepairTest\Software\Microsoft\Office\16.0\Common\Identity\`$k`"")
$src = $src.Replace("`$k = 'HKCU:\Software\Microsoft\OneDrive'", "`$k = 'HKCU:\Software\M365SignInRepairTest\Software\Microsoft\OneDrive'")
# Elevation is reported as true so rung 3 (package re-registration) is exercised against the fake Appx state.
$src = $src.Replace('$script:IsElevated = ([System.Security.Principal.WindowsPrincipal]$script:Identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)', '$script:IsElevated = $true')
# In-box package manifests come from a lab folder so rung 3 does not depend on the runner's Windows edition.
$src = $src.Replace('Join-Path -Path $env:SystemRoot -ChildPath ("SystemApps\', 'Join-Path -Path $env:M365TEST_LAB -ChildPath ("SystemApps\')
# Profile paths: the tool uses LOCALAPPDATA/APPDATA for the current user; the scenario sets those to the lab.
$tmp = Join-Path $env:M365TEST_LAB 'Repair-M365SignIn.test.ps1'
Set-Content -Path $tmp -Value $src -Encoding UTF8
# Named parameters travel as JSON and are splatted as a hashtable, so -Mode, -ErrorCode and the switches bind by name.
$splat = @{}
$json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ToolArgsJson)) | ConvertFrom-Json
foreach ($prop in $json.PSObject.Properties) { $v = $prop.Value; if ($v -is [System.Array] -or $v -is [System.Collections.IList]) { $v = @($v) }; $splat[$prop.Name] = $v }
& $tmp @splat
exit $LASTEXITCODE
'@
Set-Content -Path $wrapper -Value $wrapperSrc -Encoding UTF8

function Reset-Lab {
    param([switch]$Broken)
    foreach ($p in @($fakeLocal, $fakeRoam)) { if (Test-Path $p) { Remove-Item $p -Recurse -Force }; New-Item $p -ItemType Directory -Force | Out-Null }
    $testKey = 'HKCU:\Software\M365SignInRepairTest'
    if (Test-Path $testKey) { Remove-Item $testKey -Recurse -Force }
    New-Item -Path "$testKey\Software\Microsoft\Office\16.0\Common\Identity" -Force | Out-Null
    if ($Broken) {
        New-Item -Path "$testKey\Software\Microsoft\Office\16.0\Common\Identity\Identities\ABC_ADAL" -Force | Out-Null
        New-Item -Path "$testKey\Software\Microsoft\Office\16.0\Common\Identity\Profiles\ABC" -Force | Out-Null
        New-Item -Path "$testKey\Software\Microsoft\OneDrive" -Force | Out-Null
        Set-ItemProperty -Path "$testKey\Software\Microsoft\OneDrive" -Name OneAuthUnrecoverableTimestamp -Value 1700000000 -Type QWord
        Set-ItemProperty -Path "$testKey\Software\Microsoft\OneDrive" -Name ClientEverSignedIn -Value 1 -Type DWord
        Set-ItemProperty -Path "$testKey\Software\Microsoft\OneDrive" -Name Version -Value '24.000.0000.0001'
        foreach ($d in @('Microsoft\OneAuth', 'Microsoft\IdentityCache', 'Microsoft\Office\Licenses\1', 'Microsoft\OneDrive\settings', 'Microsoft\OneDrive')) { New-Item (Join-Path $fakeLocal $d) -ItemType Directory -Force | Out-Null }
        Set-Content (Join-Path $fakeLocal 'Microsoft\OneAuth\accounts.db') 'x'
        Set-Content (Join-Path $fakeLocal 'Microsoft\IdentityCache\token.bin') 'x'
        Set-Content (Join-Path $fakeLocal 'Microsoft\Office\Licenses\1\lic.bin') 'x'
        Set-Content (Join-Path $fakeLocal 'Microsoft\OneDrive\settings\PreSignInSettingsConfig.json') '{}'
        Set-Content (Join-Path $fakeLocal 'Microsoft\OneDrive\OneDrive.exe') 'fake'
    }
    foreach ($pkg in @('Microsoft.AAD.BrokerPlugin', 'Microsoft.Windows.CloudExperienceHost')) { $m = Join-Path $lab ("SystemApps\{0}_cw5n1h2txyewy" -f $pkg); New-Item $m -ItemType Directory -Force | Out-Null; Set-Content (Join-Path $m 'AppxManifest.xml') '<Package />' }
    $env:M365TEST_BROKEN = $(if ($Broken) { '1' } else { '0' })
    $env:M365TEST_PRTFRESH = '0'; $env:M365TEST_CREDDELETED = '0'
}

$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$env:M365TEST_LAB = $lab; $env:M365TEST_SID = $sid; $env:M365TEST_PROFILE = $lab
$results = [System.Collections.Generic.List[object]]::new()
function Check { param([string]$Name, [bool]$Ok, [string]$Detail = '') $results.Add([pscustomobject]@{ Check = $Name; Ok = $Ok; Detail = $Detail }); Write-Host ("  [{0}] {1} {2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $Detail) -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' }) }

function Run-Tool {
    param([hashtable]$ToolArgs)
    $env:NO_COLOR = '1'; $env:LOCALAPPDATA = $fakeLocal; $env:APPDATA = $fakeRoam
    $pwsh = (Get-Process -Id $PID).Path
    $all = @{ OutputRoot = $out; NonInteractive = $true; Quiet = $true; NoOpenReport = $true; SkipNetwork = $true }
    foreach ($k in $ToolArgs.Keys) { $all[$k] = $ToolArgs[$k] }
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($all | ConvertTo-Json -Compress)))
    $p = Start-Process -FilePath $pwsh -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $wrapper), '-Tool', ('"{0}"' -f $ScriptPath), '-ToolArgsJson', $b64) -Wait -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $lab 'stdout.txt') -RedirectStandardError (Join-Path $lab 'stderr.txt')
    Remove-Item Env:\LOCALAPPDATA -ErrorAction SilentlyContinue; Remove-Item Env:\APPDATA -ErrorAction SilentlyContinue
    $env:LOCALAPPDATA = [Environment]::GetFolderPath('LocalApplicationData'); $env:APPDATA = [Environment]::GetFolderPath('ApplicationData')
    $run = Get-ChildItem -Path $out -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $json = if ($run) { Join-Path $run.FullName 'result.json' } else { '' }
    $res = if ($json -and (Test-Path $json)) { Get-Content $json -Raw | ConvertFrom-Json } else { $null }
    return [pscustomobject]@{ Exit = $p.ExitCode; Result = $res; RunDir = $(if ($run) { $run.FullName } else { '' }); StdErr = (Get-Content (Join-Path $lab 'stderr.txt') -Raw -ErrorAction SilentlyContinue) }
}

Write-Host "`nM365 Sign-In Repair offline test  ($ScriptPath)`n" -ForegroundColor Cyan

Write-Host 'Scenario 1: Diagnose, healthy' -ForegroundColor Yellow
Reset-Lab
$r = Run-Tool -ToolArgs @{ Mode = 'Diagnose' }
Check 'tool ran and wrote result.json' ($null -ne $r.Result) $r.StdErr
if ($r.Result) { $highs = @($r.Result.Findings | Where-Object { $_.Severity -eq 'High' -and $_.Id -notin @('WEBVIEW2', 'ROOT-MISSING', 'TLS12-OFF', 'WINHTTP-NOTLS12') }); Check 'no High findings (machine TLS and WebView2 state excluded)' ($highs.Count -eq 0) (($highs | ForEach-Object Title) -join '; '); Check 'exit code 0' ($r.Exit -eq 0) "exit $($r.Exit)"; Check 'no actions' (@($r.Result.Actions).Count -eq 0) }

Write-Host 'Scenario 2: Diagnose, broken broker and stale PRT' -ForegroundColor Yellow
Reset-Lab -Broken
$r = Run-Tool -ToolArgs @{ Mode = 'Diagnose'; ErrorCode = @('CAA50021') }
Check 'tool ran' ($null -ne $r.Result) $r.StdErr
if ($r.Result) {
    $ids = @($r.Result.Findings | ForEach-Object Id)
    Check 'APPX-BROKER found' ($ids -contains 'APPX-BROKER'); Check 'PRT-STALE found' ($ids -contains 'PRT-STALE'); Check 'OD-ONEAUTH found' ($ids -contains 'OD-ONEAUTH'); Check 'OD-PRESIGNIN found' ($ids -contains 'OD-PRESIGNIN')
    Check 'code decoded' (@($r.Result.Codes).Count -eq 1 -and $r.Result.Codes[0].Rung -eq 3)
    Check 'exit code 1 (issue found, nothing changed)' ($r.Exit -eq 1) "exit $($r.Exit)"
    Check 'nothing moved' ((Test-Path (Join-Path $fakeLocal 'Microsoft\OneAuth\accounts.db')) -and (Test-Path "HKCU:\Software\M365SignInRepairTest\Software\Microsoft\Office\16.0\Common\Identity\Identities"))
}

Write-Host 'Scenario 3: Repair with -WhatIf' -ForegroundColor Yellow
Reset-Lab -Broken
$r = Run-Tool -ToolArgs @{ Mode = 'Repair'; ErrorCode = @('CAA50021'); Approve = @('Nudge', 'Reset', 'Reregister'); WhatIf = $true }
Check 'tool ran' ($null -ne $r.Result) $r.StdErr
if ($r.Result) {
    $st = @($r.Result.Actions | ForEach-Object Status | Select-Object -Unique)
    Check 'only WhatIf actions' (($st.Count -gt 0) -and (@($st | Where-Object { $_ -notin @('WhatIf', 'Skipped') }).Count -eq 0)) ($st -join ',')
    Check 'nothing moved' ((Test-Path (Join-Path $fakeLocal 'Microsoft\OneAuth\accounts.db')) -and (Test-Path (Join-Path $fakeLocal 'Microsoft\OneDrive\settings\PreSignInSettingsConfig.json')))
}

Write-Host 'Scenario 4: Repair, approved' -ForegroundColor Yellow
Reset-Lab -Broken
$r = Run-Tool -ToolArgs @{ Mode = 'Repair'; ErrorCode = @('CAA50021', '0x801C0451'); Approve = @('Nudge', 'Reset', 'Reregister') }
Check 'tool ran' ($null -ne $r.Result) $r.StdErr
if ($r.Result) {
    $acts = @($r.Result.Actions)
    Check 'PRT refreshed and verified' (@($acts | Where-Object { $_.Id -eq 'PRT-REFRESH' -and $_.Status -eq 'Verified' }).Count -eq 1)
    Check 'OneAuth cache moved' (-not (Test-Path (Join-Path $fakeLocal 'Microsoft\OneAuth\accounts.db')))
    Check 'IdentityCache moved' (-not (Test-Path (Join-Path $fakeLocal 'Microsoft\IdentityCache\token.bin')))
    Check 'Office licence files moved' (-not (Test-Path (Join-Path $fakeLocal 'Microsoft\Office\Licenses\1\lic.bin')))
    Check 'identity registry removed' (-not (Test-Path 'HKCU:\Software\M365SignInRepairTest\Software\Microsoft\Office\16.0\Common\Identity\Identities'))
    Check 'identity registry exported' ((Get-ChildItem (Join-Path $r.RunDir 'quarantine') -Filter '*.reg' -ErrorAction SilentlyContinue | Measure-Object).Count -ge 2)
    Check 'OneDrive PreSignIn moved' (-not (Test-Path (Join-Path $fakeLocal 'Microsoft\OneDrive\settings\PreSignInSettingsConfig.json')))
    Check 'OneAuthUnrecoverableTimestamp cleared' ($null -eq (Get-ItemProperty 'HKCU:\Software\M365SignInRepairTest\Software\Microsoft\OneDrive' -Name OneAuthUnrecoverableTimestamp -ErrorAction SilentlyContinue))
    Check 'quarantine holds the moved items' ((Get-ChildItem (Join-Path $r.RunDir 'quarantine') -Recurse -File | Measure-Object).Count -ge 4)
    Check 'RESTORE-INSTRUCTIONS written' (Test-Path (Join-Path $r.RunDir 'RESTORE-INSTRUCTIONS.txt'))
    Check 'CASE-NOTES written' (Test-Path (Join-Path $r.RunDir 'CASE-NOTES.txt'))
    Check 'report.html written' (Test-Path (Join-Path $r.RunDir 'report.html'))
    Check 'credential entries removed and verified' (@($acts | Where-Object { $_.Id -eq 'CREDMAN' -and $_.Status -eq 'Verified' }).Count -eq 1)
    $failed = @($acts | Where-Object { $_.Status -eq 'Failed' })
    Check 'no failed actions' ($failed.Count -eq 0) (($failed | ForEach-Object { "$($_.Title): $($_.Detail)" }) -join '; ')
    Check 'exit code 0 or 2' ($r.Exit -in @(0, 2)) "exit $($r.Exit)"
}

Write-Host 'Scenario 5: Decode only' -ForegroundColor Yellow
$env:NO_COLOR = '1'
$dec = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ScriptPath -DecodeOnly -ErrorCode '0x8004de40,AADSTS50076,-2147024809' -Quiet 2>&1 | Out-String
Check 'decoder prints all three' (($dec -match '8004de40') -and ($dec -match 'AADSTS50076') -and ($dec -match '2147024809'))
Check 'AADSTS50076 marked tenant' ($dec -match 'owner Tenant')

$pass = @($results | Where-Object Ok).Count; $total = $results.Count
Write-Host ("`n{0}/{1} checks passed. Lab: {2}" -f $pass, $total, $lab) -ForegroundColor $(if ($pass -eq $total) { 'Green' } else { 'Red' })
Remove-Item 'HKCU:\Software\M365SignInRepairTest' -Recurse -Force -ErrorAction SilentlyContinue
exit $(if ($pass -eq $total) { 0 } else { 1 })
