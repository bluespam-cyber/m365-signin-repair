#Requires -Version 5.1
<#
.SYNOPSIS
    M365 Sign-In Repair: diagnoses and repairs Microsoft 365 sign-in failures on Windows (Office, Outlook, OneDrive, Teams, Windows Hello and the Web Account Manager broker).

.DESCRIPTION
    Read everything first, change nothing until the plan has been shown and approved. Every repair is the one Microsoft
    documents for that exact condition, runs least-destructive first, is done in the affected user's own context, keeps a
    quarantine copy of anything it removes, and is verified afterwards. Anything that is a deliberate organisation control
    (Conditional Access, Group Policy, TLS hardening, tenant lists, licences) or that Microsoft lists as a last resort
    (dsregcmd /leave, Clear-Tpm, Ngc deletion) is reported, never changed.

    Modes
      Diagnose   Read-only. Produces the report and a plan. Exit 1 when a repairable issue was found (Intune detection contract).
      Repair     Shows the plan, then applies the per-user rungs (nudge, reset caches, re-register broker) after approval.
      Full       Repair plus the elevated machine-level rungs that are safe on unmanaged devices (time resync, service start types,
                 WebView2 install, Office activation reset through GetHelpCmd). Managed-device controls stay report-only.

    Ladder (each rung is approved separately in interactive runs)
      0  Report only     policy, tenant, TLS hardening, device join, TPM, Ngc
      1  Nudge           PRT refresh, DNS cache flush, restart Click-to-Run, start stopped services that should run
      2  Reset caches    OneAuth, IdentityCache, TokenBroker cache and Accounts, Office Licenses, Teams cache, OneDrive PreSignIn file, Credential Manager (Office, OneDrive, Teams entries), OneDrive /reset
      3  Re-register     Microsoft.AAD.BrokerPlugin, Microsoft.Windows.CloudExperienceHost, Microsoft.AccountsControl (only when missing), Reset-AppxPackage for new Teams
      4  Microsoft tool  GetHelpCmd.exe -S ResetOfficeActivation (elevated, downloaded fresh, exit 80 = success)

.PARAMETER Mode
    Diagnose, Repair or Full. When omitted in an interactive window the tool shows a start menu and asks; in an unattended run it defaults to Diagnose.

.PARAMETER Apps
    Which workloads to include: Office, Outlook, OneDrive, Teams, Broker. Default all.

.PARAMETER Approve
    Pre-approves the rungs listed (Nudge, Reset, Reregister, Tool) for unattended runs. Without it, interactive runs ask per rung and
    non-interactive runs (RMM, Intune, -NonInteractive) apply nothing and exit 1 if issues were found.

.PARAMETER TargetUserSid
    Repair this user only. Honoured whenever the script is elevated. Default: the console user (or the current user when not elevated).

.PARAMETER AllUsers
    Elevated only. Diagnose (and with -Approve, repair) every loaded profile that has a sign-in cache.

.PARAMETER ErrorCode
    One or more error codes from the sign-in dialog (0x8004de40, CAA50021, AADSTS50076, 80090016 ...). Decoded, routed to the right rung,
    and used to focus the plan.

.PARAMETER OutputRoot
    Where the run folder goes. Default %ProgramData%\M365SignInRepair when elevated, else %LOCALAPPDATA%\M365SignInRepair.

.PARAMETER CaseNumber
    Written into the report and case notes.

.PARAMETER SkipNetwork
    Skip the endpoint, TLS interception, time and DNS probes.

.PARAMETER NonInteractive
    Never prompt. Implied when the host has no console (RMM, Intune, scheduled task).

.PARAMETER Quiet
    Plain text output only (also honours NO_COLOR).

.PARAMETER DecodeOnly
    Decode -ErrorCode and exit; nothing is inspected.

.PARAMETER WhatIf
    Standard dry run. Every change is printed as it would be made.

.EXAMPLE
    .\Repair-M365SignIn.ps1
    Read-only diagnosis of the current user, report opened at the end.

.EXAMPLE
    .\Repair-M365SignIn.ps1 -Mode Repair -Apps Outlook,Broker -ErrorCode CAA50021
    Plan and repair for a "We couldn't sign you in" in Outlook, per-rung approval.

.EXAMPLE
    .\Repair-M365SignIn.ps1 -Mode Full -AllUsers -Approve Nudge,Reset,Reregister -NonInteractive
    Intune remediation (run as SYSTEM): repairs each signed-in user in their own session; exit 0 healthy, 1 issue left, 2 not verified.

.NOTES
    Version 3.0. Arwaz Khan, Microsoft Support Engineer.
    Windows PowerShell 5.1 and PowerShell 7 on Windows 10 and 11. Every repair traces to a Microsoft article listed in docs/sources.md.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Diagnose', 'Repair', 'Full', '')]
    [string]$Mode = '',

    [ValidateSet('Office', 'Outlook', 'OneDrive', 'Teams', 'Broker')]
    [string[]]$Apps = @(),

    [ValidateSet('Nudge', 'Reset', 'Reregister', 'Tool')]
    [string[]]$Approve = @(),

    [ValidatePattern('^(S-1-(5-21|12-1)-[0-9-]+)?$')]
    [string]$TargetUserSid = '',

    [switch]$AllUsers,

    [string[]]$ErrorCode = @(),

    [string]$OutputRoot = '',

    [string]$CaseNumber = '',

    [switch]$SkipNetwork,

    [switch]$NonInteractive,

    [switch]$Quiet,

    [switch]$DecodeOnly,

    [switch]$NoOpenReport,

    # Internal: set when the script re-launches itself inside a user's session from SYSTEM.
    [Parameter(DontShow)]
    [string]$ChildOfRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Version = '3.0'
$script:Started = Get-Date

# ---------------------------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------------------------
$script:IsPS7 = $PSVersionTable.PSVersion.Major -ge 7
if ($script:IsPS7 -and -not $IsWindows) { throw 'M365 Sign-In Repair runs on Windows only.' }
$script:Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$script:IsElevated = ([System.Security.Principal.WindowsPrincipal]$script:Identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$script:IsSystem = ($script:Identity.User.Value -eq 'S-1-5-18')
$script:CurrentSid = $script:Identity.User.Value
$script:HasConsole = $true
# The console API throws inside the PowerShell ISE and the VS Code integrated console; both still take Read-Host input.
try { $null = [Console]::KeyAvailable; if ([Console]::IsInputRedirected) { $script:HasConsole = $false } } catch { $script:HasConsole = ($Host.Name -in @('Windows PowerShell ISE Host', 'Visual Studio Code Host')) }
if ([Environment]::UserInteractive -eq $false) { $script:HasConsole = $false }
if ($NonInteractive -or $script:IsSystem -or -not $script:HasConsole) { $script:Interactive = $false } else { $script:Interactive = $true }
$script:AllApps = @('Office', 'Outlook', 'OneDrive', 'Teams', 'Broker')
$script:MenuUsed = $false
$script:Quit = $false
# Mode and Apps are resolved by the start menu (interactive, nothing given) or fall back to the unattended defaults.
if (-not $Mode) { if (-not $script:Interactive -or $DecodeOnly) { $Mode = 'Diagnose' } }
if ($Apps.Count -eq 0) { $Apps = $script:AllApps }
$script:Is64BitOS = [Environment]::Is64BitOperatingSystem
$script:ProgramFiles32 = if ($script:Is64BitOS) { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles }
$script:ProgramFiles64 = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }

if (-not $OutputRoot) {
    $OutputRoot = if ($script:IsElevated) { Join-Path -Path $env:ProgramData -ChildPath 'M365SignInRepair' } else { Join-Path -Path $env:LOCALAPPDATA -ChildPath 'M365SignInRepair' }
}
$script:RunId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $env:COMPUTERNAME
if ($ChildOfRun) { $script:RunId = $ChildOfRun + '-' + $script:CurrentSid.Substring([math]::Max(0, $script:CurrentSid.Length - 6)) }
$script:RunDir = Join-Path -Path $OutputRoot -ChildPath $script:RunId
New-Item -Path $script:RunDir -ItemType Directory -Force | Out-Null
$script:LogFile = Join-Path -Path $script:RunDir -ChildPath 'run.log'
$script:Quarantine = Join-Path -Path $script:RunDir -ChildPath 'quarantine'

$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:Actions = [System.Collections.Generic.List[object]]::new()
$script:Facts = [ordered]@{}
$script:Users = @()
$script:ConsoleUsers = @()
$script:DecodedCodes = @()
$script:ExitCode = 0
$script:PhaseStart = $null
$script:Stopped = $false

# ---------------------------------------------------------------------------------------------
# Terminal UI layer (shared design with SPO UID). Degrades to plain text when output is redirected,
# NO_COLOR is set, -Quiet is given, or there is no console (RMM, Intune, SYSTEM). Never blocks work.
# ---------------------------------------------------------------------------------------------
$script:Ansi = $true
try {
    if ($Quiet -or $env:NO_COLOR -or $env:TERM -eq 'dumb' -or -not $script:HasConsole) { $script:Ansi = $false }
    if ([Console]::IsOutputRedirected) { $script:Ansi = $false }
    if ($Host.UI.SupportsVirtualTerminal -eq $false) { $script:Ansi = $false }
    if ($script:Ansi) { try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { } }
} catch { $script:Ansi = $false }
$script:Esc = [char]27
$script:C = @{
    Reset = "$($script:Esc)[0m"; Bold = "$($script:Esc)[1m"; Dim = "$($script:Esc)[2m"
    Red = "$($script:Esc)[91m"; Green = "$($script:Esc)[92m"; Yellow = "$($script:Esc)[93m"; Blue = "$($script:Esc)[94m"
    Magenta = "$($script:Esc)[95m"; Cyan = "$($script:Esc)[96m"; White = "$($script:Esc)[97m"; Gray = "$($script:Esc)[90m"
    Teal = "$($script:Esc)[38;5;44m"; Violet = "$($script:Esc)[38;5;141m"; Orange = "$($script:Esc)[38;5;214m"; Mint = "$($script:Esc)[38;5;121m"
    ClearLine = "$($script:Esc)[2K"
}
$script:Unicode = $script:Ansi
try { if (-not $script:Unicode -or [Console]::OutputEncoding.CodePage -notin @(65001, 1200)) { $script:Unicode = $false } } catch { $script:Unicode = $false }
$script:Fancy = $script:Unicode -and [bool]$env:WT_SESSION
$script:Glyph = if ($script:Fancy) {
    @{ Ok = '✔'; Fail = '✖'; Warn = '▲'; Info = '•'; Step = '➜'; Bar = '█'; BarEmpty = '░'; TL = '╭'; TR = '╮'; BL = '╰'; BR = '╯'; H = '─'; V = '│'; Dot = '·'; Arrow = '→'; Spark = '✦'; Ellipsis = '…' }
} elseif ($script:Unicode) {
    @{ Ok = '√'; Fail = '×'; Warn = '▲'; Info = '•'; Step = '»'; Bar = '█'; BarEmpty = '░'; TL = '┌'; TR = '┐'; BL = '└'; BR = '┘'; H = '─'; V = '│'; Dot = '·'; Arrow = '→'; Spark = '◆'; Ellipsis = '…' }
} else {
    @{ Ok = '+'; Fail = 'x'; Warn = '!'; Info = '-'; Step = '>'; Bar = '#'; BarEmpty = '.'; TL = '+'; TR = '+'; BL = '+'; BR = '+'; H = '-'; V = '|'; Dot = '.'; Arrow = '->'; Spark = '*'; Ellipsis = '...' }
}
$script:SpinnerFrames = if ($script:Fancy) { @('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏') } elseif ($script:Unicode) { @('▏', '▎', '▍', '▌', '▋', '▊', '▉', '█', '▉', '▊', '▋', '▌', '▍', '▎') } else { @('|', '/', '-', '\') }
$script:PhaseTotal = 6
$script:UiWidth = 78
try { $w = $Host.UI.RawUI.WindowSize.Width; if ($w -ge 60) { $script:UiWidth = [math]::Min(100, $w - 2) } } catch { }

function Get-Plain { param([string]$Text) return [regex]::Replace($Text, "$([char]27)\[[0-9;?]*[A-Za-z]", '') }
function Get-Tinted { param([string]$Text, [string]$Color) if ($script:Ansi -and $script:C.ContainsKey($Color)) { return ($script:C[$Color] + $Text + $script:C.Reset) } return $Text }
function Write-Ui { param([string]$Text = '') Write-Host $(if ($script:Ansi) { $Text } else { Get-Plain $Text }) }

function Write-Log {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet('INFO', 'OK', 'WARN', 'FAIL', 'STEP', 'DEBUG')][string]$Level = 'INFO')
    $stamp = Get-Date -Format 'HH:mm:ss'
    try { Add-Content -Path $script:LogFile -Value ("[{0}] [{1}] {2}" -f $stamp, $Level, (Get-Plain $Message)) -Encoding utf8 } catch { }
    if ($Level -eq 'DEBUG') { return }
    # A log line interrupts the spinner for one line, then the spinner resumes with its current text.
    $resume = ''; $resumeStart = [long]0
    if ($script:Ansi -and $script:Spin.Active) { $resume = $script:Spin.Text; $resumeStart = $script:Spin.Started }
    Stop-Spinner
    $icon = switch ($Level) { 'OK' { Get-Tinted $script:Glyph.Ok 'Green' } 'WARN' { Get-Tinted $script:Glyph.Warn 'Yellow' } 'FAIL' { Get-Tinted $script:Glyph.Fail 'Red' } 'STEP' { Get-Tinted $script:Glyph.Step 'Cyan' } default { Get-Tinted $script:Glyph.Info 'Gray' } }
    $color = switch ($Level) { 'OK' { 'Mint' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } 'STEP' { 'Cyan' } default { 'Gray' } }
    Write-Ui ("  {0} {1} {2}" -f (Get-Tinted $stamp 'Gray'), $icon, (Get-Tinted $Message $color))
    if ($resume) { Start-Spinner -Text $resume -StartedTicks $resumeStart }
}

function Set-SpinnerText {
    # Live sub-step text while a phase runs ("Probing login.microsoftonline.com (3/10)"). Silent in plain-text mode.
    param([Parameter(Mandatory)][string]$Text)
    if (-not $script:Ansi -or -not $script:Spin.Active) { return }
    $shown = Format-SpinnerText $Text
    [System.Threading.Monitor]::Enter($script:Spin)
    try { $script:Spin.Text = $shown } finally { [System.Threading.Monitor]::Exit($script:Spin) }
}

function Get-MiniBar {
    # A twelve-cell bar for the spinner line: Probing endpoints [######......] 6/10
    param([int]$Done, [int]$Total, [int]$Width = 12)
    if ($Total -le 0) { return '' }
    $f = [math]::Min($Width, [int][math]::Round($Width * $Done / $Total))
    return (Get-Tinted ($script:Glyph.Bar * $f) 'Cyan') + (Get-Tinted ($script:Glyph.BarEmpty * ($Width - $f)) 'Gray')
}

function Get-PhaseElapsed {
    if (-not $script:PhaseStart) { return '' }
    $s = ((Get-Date) - $script:PhaseStart).TotalSeconds
    return $(if ($s -ge 60) { ('{0}:{1:00}' -f [int][math]::Floor($s / 60), [int]($s % 60)) } else { ('{0:0.0}s' -f $s) })
}

function Write-Rule { param([string]$Color = 'Gray') Write-Ui (Get-Tinted ($script:Glyph.H * $script:UiWidth) $Color) }

function Write-Banner {
    param([string]$Text, [int]$Phase = 0)
    Stop-Spinner
    $script:PhaseStart = Get-Date
    Write-Ui ''
    if ($Phase -gt 0) {
        $track = ''
        for ($i = 1; $i -le $script:PhaseTotal; $i++) {
            $track += $(if ($i -lt $Phase) { Get-Tinted $script:Glyph.Bar 'Mint' } elseif ($i -eq $Phase) { Get-Tinted $script:Glyph.Bar 'Cyan' } else { Get-Tinted $script:Glyph.BarEmpty 'Gray' })
        }
        Write-Ui ("  {0}  {1} {2}" -f $track, (Get-Tinted ("PHASE {0}/{1}" -f $Phase, $script:PhaseTotal) 'Violet'), (Get-Tinted $Text 'White'))
    } else {
        Write-Ui ("  {0} {1}" -f (Get-Tinted $script:Glyph.Spark 'Violet'), (Get-Tinted $Text 'White'))
    }
    Write-Rule 'Gray'
}

function Show-Intro {
    $lines = @(
        '  ███╗   ███╗██████╗  ██████╗ ███████╗',
        '  ████╗ ████║╚════██╗██╔════╝ ██╔════╝',
        '  ██╔████╔██║ █████╔╝███████╗ ███████╗',
        '  ██║╚██╔╝██║ ╚═══██╗██╔═══██╗╚════██║',
        '  ██║ ╚═╝ ██║██████╔╝╚██████╔╝███████║',
        '  ╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚══════╝'
    )
    if (-not $script:Unicode) { $lines = @('  M365 SIGN-IN REPAIR', '  ') }
    $palette = @('Violet', 'Violet', 'Blue', 'Teal', 'Cyan', 'Mint')
    Write-Ui ''
    for ($i = 0; $i -lt $lines.Count; $i++) {
        Write-Ui (Get-Tinted $lines[$i] $palette[$i % $palette.Count])
        if ($script:Ansi) { Start-Sleep -Milliseconds 40 }
    }
    Write-Ui ("  {0}  {1}" -f (Get-Tinted 'Sign-In Repair for Microsoft 365 on Windows' 'White'), (Get-Tinted ("v{0}" -f $script:Version) 'Gray'))
    Write-Ui ("  {0}" -f (Get-Tinted 'Office, Outlook, OneDrive, Teams, Windows Hello and the account broker. Reads first, repairs what Microsoft documents, verifies every change.' 'Gray'))
    Write-Ui ''
    Write-Ui ("  {0} {1} {2} {3}" -f (Get-Tinted $script:Glyph.Spark 'Orange'), (Get-Tinted 'Crafted by' 'Gray'), (Get-Tinted 'Arwaz Khan' 'Orange'), (Get-Tinted 'Microsoft Support Engineer' 'Gray'))
    Write-Rule 'Violet'
    $ctx = @()
    $ctx += $(if ($Mode) { "Mode $Mode" } else { 'Mode: choose below' })
    $ctx += $(if ($script:IsSystem) { 'running as SYSTEM' } elseif ($script:IsElevated) { 'elevated' } else { 'not elevated' })
    $ctx += $(if ($script:Interactive) { 'interactive' } else { 'unattended' })
    $ctx += "PowerShell $($PSVersionTable.PSVersion.ToString())"
    Write-Ui ("  {0}" -f (Get-Tinted ($ctx -join '  |  ') 'Gray'))
    Write-Ui ("  {0}" -f (Get-Tinted 'Nothing changes until the plan is shown and each rung is approved. Ctrl+C stops safely; the report is still written.' 'Gray'))
}

function Show-Outro {
    Write-Ui ''
    Write-Rule 'Violet'
    Write-Ui ("  {0} {1}  {2}" -f (Get-Tinted $script:Glyph.Spark 'Orange'), (Get-Tinted 'Arwaz Khan' 'Orange'), (Get-Tinted ("Microsoft Support Engineer  |  M365 Sign-In Repair v{0}" -f $script:Version) 'Gray'))
    Write-Ui ''
}

# --- spinner (one background thread, synchronized state, never draws over real output) -------------
$script:Spin = [hashtable]::Synchronized(@{ Active = $false; Quit = $false; Text = ''; Started = [long]0; Frames = @($script:SpinnerFrames); Palette = @($script:C.Violet, $script:C.Blue, $script:C.Teal, $script:C.Cyan, $script:C.Mint); Gray = $script:C.Gray; Reset = $script:C.Reset; Clear = $script:C.ClearLine })
$script:SpinJob = $null
$script:CanThreadJob = [bool](Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue)
function Format-SpinnerText {
    # Fits the text on one line next to the frame and the elapsed counter; plain text is tinted grey, pre-tinted text is kept.
    param([string]$Text)
    $plain = Get-Plain $Text
    $max = [math]::Max(20, $script:UiWidth - 16)
    if ($plain.Length -gt $max) { return (Get-Tinted ($plain.Substring(0, $max - $script:Glyph.Ellipsis.Length) + $script:Glyph.Ellipsis) 'Gray') }
    if ($Text -notmatch "$([char]27)\[") { return (Get-Tinted $Text 'Gray') }
    return $Text
}

function Start-Spinner {
    # Starts (or retargets) the one spinner. The elapsed counter starts now unless -StartedTicks carries an earlier start over.
    param([string]$Text, [long]$StartedTicks = 0)
    if (-not $script:Ansi -or -not $script:CanThreadJob) { Write-Host ("  ... {0}" -f (Get-Plain $Text)) -ForegroundColor DarkGray; return }
    $shown = Format-SpinnerText $Text
    [System.Threading.Monitor]::Enter($script:Spin)
    try {
        if ($StartedTicks -gt 0) { $script:Spin.Started = $StartedTicks } elseif (-not $script:Spin.Active) { $script:Spin.Started = [DateTime]::UtcNow.Ticks }
        $script:Spin.Text = $shown; $script:Spin.Active = $true
    } finally { [System.Threading.Monitor]::Exit($script:Spin) }
    if ($script:Spin.Quit) { return }
    if (-not $script:SpinJob -or $script:SpinJob.State -ne 'Running') {
        try {
            if ($script:SpinJob) { Remove-Job -Job $script:SpinJob -Force -ErrorAction SilentlyContinue }
            $script:SpinJob = Start-ThreadJob -Name 'M365SignInSpinner' -ArgumentList $script:Spin -ScriptBlock {
                param($S)
                $i = 0
                while (-not $S.Quit) {
                    [System.Threading.Monitor]::Enter($S)
                    try {
                        if ($S.Active -and -not $S.Quit) {
                            $f = $S.Frames[$i % $S.Frames.Count]
                            $c = $S.Palette[[int][math]::Floor($i / 5) % $S.Palette.Count]
                            $i++
                            $el = ''
                            if ($S.Started -gt 0) {
                                $sec = ([DateTime]::UtcNow.Ticks - $S.Started) / 10000000.0
                                $el = if ($sec -ge 60) { ('  {0}:{1:00}' -f [int][math]::Floor($sec / 60), [int]($sec % 60)) } else { ('  {0:0.0}s' -f $sec) }
                            }
                            [Console]::Write(("`r{0}  {1}{2}{3} {4}{5}{6}{7}" -f $S.Clear, $c, $f, $S.Reset, $S.Text, $S.Gray, $el, $S.Reset))
                        }
                    } finally { [System.Threading.Monitor]::Exit($S) }
                    Start-Sleep -Milliseconds 110
                }
            }
        } catch {
            $script:SpinJob = $null
            [System.Threading.Monitor]::Enter($script:Spin)
            try { $script:Spin.Active = $false } finally { [System.Threading.Monitor]::Exit($script:Spin) }
            Write-Host ("  ... {0}" -f $Text) -ForegroundColor DarkGray
        }
    }
}
function Stop-Spinner {
    param([string]$Result = '', [string]$Level = 'OK')
    if ($script:Ansi -and $script:Spin.Active) {
        [System.Threading.Monitor]::Enter($script:Spin)
        try { $script:Spin.Active = $false; [Console]::Write("`r" + $script:C.ClearLine) } finally { [System.Threading.Monitor]::Exit($script:Spin) }
    }
    if ($Result) { Write-Log $Result $Level }
}
function Remove-Spinner {
    Stop-Spinner
    [System.Threading.Monitor]::Enter($script:Spin)
    try { $script:Spin.Quit = $true } finally { [System.Threading.Monitor]::Exit($script:Spin) }
    if ($script:SpinJob) {
        try { Stop-Job -Job $script:SpinJob -ErrorAction SilentlyContinue; Remove-Job -Job $script:SpinJob -Force -ErrorAction SilentlyContinue } catch { }
        $script:SpinJob = $null
    }
}
function Invoke-WithSpinner {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][scriptblock]$Action, [string]$Done = '')
    Start-Spinner -Text $Text
    $oldProgress = $global:ProgressPreference
    $global:ProgressPreference = 'SilentlyContinue'
    try { $r = & $Action }
    finally {
        $global:ProgressPreference = $oldProgress
        if ($Done) { Stop-Spinner -Result $Done -Level 'OK' } else { Stop-Spinner }
    }
    return $r
}

function Write-Box {
    param([string]$Title, [string[]]$Lines, [string]$Color = 'Cyan', [switch]$Reveal)
    Stop-Spinner
    $w = $script:UiWidth; $inner = $w - 4; $g = $script:Glyph
    $titleTxt = if ($Title) { " $Title " } else { '' }
    Write-Ui ('  ' + (Get-Tinted ($g.TL + $g.H + $titleTxt + ($g.H * [math]::Max(0, $w - 3 - $titleTxt.Length)) + $g.TR) $Color))
    foreach ($l in $Lines) {
        $plain = Get-Plain $l
        $chunks = @($l)
        if ($plain.Length -gt $inner) {
            # Wrap at spaces; continuation lines keep the item's indent plus two spaces.
            $lead = ([regex]::Match($plain, '^\s*')).Value
            $indent = $lead + '  '
            $chunks = @(); $rest = $plain; $first = $true
            while ($rest.Length -gt 0) {
                $room = if ($first) { $inner } else { $inner - $indent.Length }
                if ($rest.Length -le $room) { $chunks += $(if ($first) { $rest } else { $indent + $rest }); break }
                $cut = $rest.LastIndexOf(' ', [math]::Min($room, $rest.Length - 1))
                if ($cut -lt [int]($room * 0.5)) { $cut = $room }
                $chunks += $(if ($first) { $rest.Substring(0, $cut) } else { $indent + $rest.Substring(0, $cut) })
                $rest = $rest.Substring($cut).TrimStart(); $first = $false
            }
        }
        foreach ($c in $chunks) {
            $pad = [math]::Max(0, $inner - (Get-Plain $c).Length)
            Write-Ui ('  ' + (Get-Tinted $g.V $Color) + ' ' + $c + (' ' * $pad) + ' ' + (Get-Tinted $g.V $Color))
            if ($Reveal -and $script:Ansi) { Start-Sleep -Milliseconds 18 }
        }
    }
    Write-Ui ('  ' + (Get-Tinted ($g.BL + ($g.H * ($w - 2)) + $g.BR) $Color))
}

function Read-MenuChoice {
    # Numbered menu. Returns the chosen key. Enter picks the default. Plain text when ANSI is off.
    param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][object[]]$Options, [string]$Default = '1')
    Stop-Spinner
    Write-Ui ''
    Write-Ui ("  {0} {1}" -f (Get-Tinted $script:Glyph.Spark 'Violet'), (Get-Tinted $Title 'White'))
    foreach ($o in $Options) {
        $isDefault = ($o.Key -eq $Default)
        Write-Ui ("    {0} {1}{2}" -f (Get-Tinted ("[{0}]" -f $o.Key) $(if ($isDefault) { 'Cyan' } else { 'Violet' })), (Get-Tinted $o.Label $(if ($isDefault) { 'White' } else { 'Gray' })), $(if ($o.PSObject.Properties['Detail'] -and $o.Detail) { '  ' + (Get-Tinted $o.Detail 'Gray') } else { '' }))
    }
    while ($true) {
        if ($script:Ansi) { Write-Host ("  {0} {1} " -f (Get-Tinted '?' 'Orange'), (Get-Tinted ("Choice [{0}]:" -f $Default) 'White')) -NoNewline; $a = Read-Host }
        else { $a = Read-Host -Prompt ("{0} (choice, Enter = {1})" -f $Title, $Default) }
        $a = ([string]$a).Trim()
        if (-not $a) { $a = $Default }
        $hit = $Options | Where-Object { $_.Key -eq $a } | Select-Object -First 1
        if ($hit) { Write-Ui ("    {0} {1}" -f (Get-Tinted $script:Glyph.Ok 'Mint'), (Get-Tinted $hit.Label 'Mint')); return $hit.Key }
        Write-Ui ("    {0} {1}" -f (Get-Tinted $script:Glyph.Warn 'Yellow'), (Get-Tinted ('Type one of: ' + (($Options | ForEach-Object { $_.Key }) -join ', ')) 'Yellow'))
    }
}

function Read-FreeText {
    param([Parameter(Mandatory)][string]$Prompt, [string]$Hint = '')
    Stop-Spinner
    if ($Hint) { Write-Ui ("    {0} {1}" -f (Get-Tinted $script:Glyph.Dot 'Gray'), (Get-Tinted $Hint 'Gray')) }
    if ($script:Ansi) { Write-Host ("  {0} {1} " -f (Get-Tinted '?' 'Orange'), (Get-Tinted $Prompt 'White')) -NoNewline; $a = Read-Host }
    else { $a = Read-Host -Prompt $Prompt }
    return ([string]$a).Trim()
}

function Show-StartMenu {
    # Interactive start: what to do, which apps, any error code. Only when -Mode was not given on the command line.
    $script:MenuUsed = $true
    $what = Read-MenuChoice -Title 'What would you like to do?' -Default '1' -Options @(
        [pscustomobject]@{ Key = '1'; Label = 'Diagnose'; Detail = 'read everything, change nothing, open the report' },
        [pscustomobject]@{ Key = '2'; Label = 'Repair'; Detail = 'diagnose, show the plan, then ask before each rung' },
        [pscustomobject]@{ Key = '3'; Label = 'Full'; Detail = 'repair plus elevated machine fixes and Microsoft tools (WebView2, Reset Office Activation)' },
        [pscustomobject]@{ Key = '4'; Label = 'Dry run'; Detail = 'repair with -WhatIf: print every change, make none' },
        [pscustomobject]@{ Key = '5'; Label = 'Decode an error code'; Detail = 'explain a code such as CAA50021 or 0x8004de40 and stop' },
        [pscustomobject]@{ Key = '6'; Label = 'Quit'; Detail = '' }
    )
    switch ($what) {
        '1' { $script:Mode = 'Diagnose' }
        '2' { $script:Mode = 'Repair' }
        '3' { $script:Mode = 'Full' }
        '4' { $script:Mode = 'Repair'; $script:WhatIfPreference = $true }
        '5' { $script:DecodeOnly = $true; $script:Mode = 'Diagnose' }
        '6' { $script:Quit = $true; return $false }
    }
    if ($what -eq '5') {
        $codes = Read-FreeText -Prompt 'Error code(s), separated by commas:'
        if ($codes) { $script:ErrorCode = @($codes -split '[,\s]+' | Where-Object { $_ }) }
        return $true
    }
    $scope = Read-MenuChoice -Title 'Which apps?' -Default '1' -Options @(
        [pscustomobject]@{ Key = '1'; Label = 'Everything'; Detail = 'Office, Outlook, OneDrive, Teams and the account broker' },
        [pscustomobject]@{ Key = '2'; Label = 'Office and Outlook'; Detail = 'plus the broker they sign in through' },
        [pscustomobject]@{ Key = '3'; Label = 'OneDrive'; Detail = 'plus the broker it signs in through' },
        [pscustomobject]@{ Key = '4'; Label = 'Teams'; Detail = 'plus the broker it signs in through' },
        [pscustomobject]@{ Key = '5'; Label = 'Account broker only'; Detail = 'Web Account Manager, device registration, Windows Hello' }
    )
    $script:Apps = switch ($scope) { '1' { $script:AllApps } '2' { @('Office', 'Outlook', 'Broker') } '3' { @('OneDrive', 'Broker') } '4' { @('Teams', 'Broker') } '5' { @('Broker') } }
    $code = Read-FreeText -Prompt 'Error code from the sign-in dialog (Enter to skip):' -Hint 'Examples: CAA50021, 0x8004de40, AADSTS50076, 80090016. The documented broker repairs are keyed to it.'
    if ($code) { $script:ErrorCode = @($code -split '[,\s]+' | Where-Object { $_ }) }
    if ($script:Mode -ne 'Diagnose' -and -not $script:IsElevated) { Write-Ui ("    {0} {1}" -f (Get-Tinted $script:Glyph.Warn 'Yellow'), (Get-Tinted 'Not elevated: package re-registration, service and clock fixes will be skipped. Run as administrator for those.' 'Yellow')) }
    return $true
}

function Confirm-Choice {
    # Interactive approval for one rung. Pre-approved rungs (-Approve) pass without asking; unattended runs never approve.
    param([Parameter(Mandatory)][string]$Prompt, [string]$Rung = '', [string]$Expected = 'YES')
    Stop-Spinner
    if ($Rung -and ($Approve -contains $Rung)) { Write-Log ("{0}: pre-approved with -Approve {1}" -f $Prompt, $Rung) 'INFO'; return $true }
    if (-not $script:Interactive) { Write-Log ("{0}: not approved (unattended run without -Approve {1})" -f $Prompt, $Rung) 'WARN'; return $false }
    if ($script:Ansi) {
        Write-Host ("  {0} {1} {2} " -f (Get-Tinted '?' 'Orange'), (Get-Tinted $Prompt 'White'), (Get-Tinted ("(type {0} to proceed, anything else to skip)" -f $Expected) 'Gray')) -NoNewline
        $answer = Read-Host
    } else { $answer = Read-Host -Prompt ("{0} (type {1} to proceed, anything else to skip)" -f $Prompt, $Expected) }
    return (([string]$answer).Trim() -ceq $Expected)
}

# ---------------------------------------------------------------------------------------------
# Findings and actions model
#   Finding: something observed. Severity High / Medium / Low / Info. Rung 0..4 says what could fix it.
#   Action:  a repair that was planned, applied, verified, skipped or failed. Always logged, always in the report.
# ---------------------------------------------------------------------------------------------
function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail = '',
        [string]$Evidence = '',
        [ValidateRange(0, 4)][int]$Rung = 0,
        [string]$Fix = '',
        [string]$Source = '',
        [string]$User = ''
    )
    $f = [pscustomobject]@{ Id = $Id; Severity = $Severity; Area = $Area; Title = $Title; Detail = $Detail; Evidence = $Evidence; Rung = $Rung; Fix = $Fix; Source = $Source; User = $User; Time = (Get-Date).ToString('s') }
    $script:Findings.Add($f)
    $lvl = switch ($Severity) { 'High' { 'FAIL' } 'Medium' { 'WARN' } 'Low' { 'WARN' } default { 'INFO' } }
    $who = if ($User) { "[$User] " } else { '' }
    Write-Log ("{0}{1}: {2}{3}" -f $who, $Area, $Title, $(if ($Evidence) { "  ($Evidence)" } else { '' })) $lvl
}

function Add-Action {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateRange(1, 4)][int]$Rung,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Planned', 'Applied', 'Verified', 'NotVerified', 'Skipped', 'Failed', 'WhatIf')][string]$Status,
        [string]$Detail = '',
        [string]$Restore = '',
        [string]$User = ''
    )
    $a = [pscustomobject]@{ Id = $Id; Rung = $Rung; Title = $Title; Status = $Status; Detail = $Detail; Restore = $Restore; User = $User; Time = (Get-Date).ToString('s') }
    $script:Actions.Add($a)
    $lvl = switch ($Status) { 'Verified' { 'OK' } 'Applied' { 'OK' } 'Failed' { 'FAIL' } 'NotVerified' { 'WARN' } 'Skipped' { 'INFO' } default { 'STEP' } }
    $who = if ($User) { "[$User] " } else { '' }
    Write-Log ("{0}{1}: {2}{3}" -f $who, $Status, $Title, $(if ($Detail) { "  ($Detail)" } else { '' })) $lvl
}

function Get-ErrorText {
    # Safe under StrictMode on both engines: no property access on objects that may not have it.
    param($Err)
    try {
        if ($null -eq $Err) { return '' }
        $ex = $null
        if ($Err -is [System.Management.Automation.ErrorRecord]) { $ex = $Err.Exception } elseif ($Err -is [Exception]) { $ex = $Err }
        if ($ex) {
            # Aggregate and wrapped exceptions carry the useful text one level down.
            if (($ex -is [System.AggregateException] -or $ex.Message -match '^One or more errors occurred|^Exception calling') -and $ex.InnerException) { $ex = $ex.InnerException }
            return $ex.Message
        }
        return [string]$Err
    } catch { return 'unknown error' }
}

# ---------------------------------------------------------------------------------------------
# Registry access that works for the current user, a target user's hive (HKEY_USERS\<SID>) and machine keys.
# Every read is optional-safe: missing keys or values return $null, never throw.
# ---------------------------------------------------------------------------------------------
function Get-RegValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}
function Test-RegKey { param([Parameter(Mandatory)][string]$Path) try { return (Test-Path -LiteralPath $Path) } catch { return $false } }
function Get-RegSubKeyNames { param([Parameter(Mandatory)][string]$Path) try { if (Test-Path -LiteralPath $Path) { return @((Get-ChildItem -LiteralPath $Path -ErrorAction Stop).PSChildName) } } catch { } return @() }

function Get-UserHive {
    # Registry provider path for a user's hive. The current user is HKCU; other users go through HKEY_USERS
    # (only loaded hives are visible, which is exactly the set of users we can act on).
    param([Parameter(Mandatory)][string]$Sid)
    if ($Sid -eq $script:CurrentSid) { return 'HKCU:' }
    if (-not (Test-Path -LiteralPath 'HKU:\')) { try { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script -ErrorAction Stop | Out-Null } catch { } }
    return ("HKU:\{0}" -f $Sid)
}

function Export-RegKeyToQuarantine {
    # reg.exe export is the documented, restorable form (double-click or reg import to put back).
    param([Parameter(Mandatory)][string]$RegPath, [Parameter(Mandatory)][string]$Name)
    try {
        New-Quarantine
        $file = Join-Path -Path $script:Quarantine -ChildPath ("{0}.reg" -f $Name)
        $native = $RegPath -replace '^HKCU:', 'HKEY_CURRENT_USER' -replace '^HKLM:', 'HKEY_LOCAL_MACHINE' -replace '^HKU:\\', 'HKEY_USERS\'
        $r = Invoke-Native -File "$env:SystemRoot\System32\reg.exe" -Arguments @('export', ('"{0}"' -f $native), ('"{0}"' -f $file), '/y') -TimeoutSec 60
        if ($r.ExitCode -eq 0 -and (Test-Path -LiteralPath $file)) { return $file }
    } catch { Write-Log ("registry export of {0} failed: {1}" -f $RegPath, (Get-ErrorText $_)) 'DEBUG' }
    return ''
}

# ---------------------------------------------------------------------------------------------
# Quarantine: nothing is deleted. Folders and files move (same volume, atomic rename) into the run's
# quarantine folder with RESTORE-INSTRUCTIONS.txt written before the first move. The quarantine is
# never placed under a OneDrive-synced folder (the run folder lives in LOCALAPPDATA or ProgramData).
# ---------------------------------------------------------------------------------------------
$script:RestoreLines = [System.Collections.Generic.List[string]]::new()
function Write-RestoreInstructions {
    $file = Join-Path -Path $script:RunDir -ChildPath 'RESTORE-INSTRUCTIONS.txt'
    $head = @(
        'M365 Sign-In Repair: how to undo this run',
        ("Run: {0}    Computer: {1}    Time: {2}" -f $script:RunId, $env:COMPUTERNAME, $script:Started.ToString('s')),
        '',
        'Nothing was deleted. Every folder or file the tool removed was moved into the quarantine folder next to this file.',
        'To restore an item, close the app that owns it, then move the item back to its original path listed below.',
        'Registry exports (.reg) can be restored by double-clicking them or with: reg import "<file>".',
        'Credential Manager entries are recreated automatically at the next successful sign-in; the exported list is for reference only.',
        'Re-registered Store packages (Microsoft.AAD.BrokerPlugin, CloudExperienceHost, AccountsControl) need no restore: nothing was removed.',
        '',
        'Items moved or exported:'
    )
    Set-Content -Path $file -Value ($head + @($script:RestoreLines)) -Encoding UTF8
}

function New-Quarantine {
    # Creates the quarantine once and, when elevated, locks it to SYSTEM, Administrators and the current user:
    # exported registry keys and credential lists must not inherit the Users read permission from ProgramData.
    if (Test-Path -LiteralPath $script:Quarantine) { return }
    New-Item -Path $script:Quarantine -ItemType Directory -Force | Out-Null
    # Outside the user's own profile (ProgramData, a shared -OutputRoot) the folder would inherit Users:Read; the creator owns it and can lock it down without elevation.
    $inProfile = $env:USERPROFILE -and ([System.IO.Path]::GetFullPath($script:Quarantine)).StartsWith([System.IO.Path]::GetFullPath($env:USERPROFILE), [System.StringComparison]::OrdinalIgnoreCase)
    if ($script:IsElevated -or -not $inProfile) {
        $null = Invoke-Native -File "$env:SystemRoot\System32\icacls.exe" -Arguments @(('"{0}"' -f $script:Quarantine), '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', ('"*{0}:(OI)(CI)F"' -f $script:CurrentSid)) -TimeoutSec 20
    }
}

function Test-InsideOneDrive {
    # A quarantine copy inside a synced folder would upload token caches to the cloud. Refuse.
    param([Parameter(Mandatory)][string]$Path, [string]$ProfilePath = '')
    $lower = $Path.ToLowerInvariant()
    if ($lower -match '\\onedrive( - [^\\]+)?\\') { return $true }
    foreach ($v in @('OneDrive', 'OneDriveCommercial', 'OneDriveConsumer')) {
        $od = [Environment]::GetEnvironmentVariable($v)
        if ($od -and $lower.StartsWith($od.ToLowerInvariant())) { return $true }
    }
    foreach ($acct in (Get-RegSubKeyNames 'HKCU:\Software\Microsoft\OneDrive\Accounts')) {
        $uf = Get-RegValue ("HKCU:\Software\Microsoft\OneDrive\Accounts\{0}" -f $acct) 'UserFolder'
        if ($uf -and $lower.StartsWith(([string]$uf).ToLowerInvariant())) { return $true }
    }
    return $false
}

function Move-ToQuarantine {
    # Moves a file or a folder's contents into the quarantine. Same-volume moves are atomic renames; a cross-volume
    # quarantine is refused (copy-then-delete is exactly the failure mode we avoid). Returns $true on success.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label, [string]$User = '', [switch]$ContentsOnly)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    if (Test-InsideOneDrive -Path $script:Quarantine) { throw "Quarantine folder is inside a OneDrive synced folder; refusing to move sign-in caches there." }
    $srcRoot = [System.IO.Path]::GetPathRoot((Resolve-Path -LiteralPath $Path).ProviderPath)
    $dstRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($script:Quarantine))
    if ($srcRoot -ne $dstRoot) { throw ("Quarantine is on {0} but the item is on {1}; choose -OutputRoot on the same volume." -f $dstRoot, $srcRoot) }
    New-Quarantine
    $safe = ($Label -replace '[^A-Za-z0-9._-]', '_')
    $dest = Join-Path -Path $script:Quarantine -ChildPath ("{0}_{1}_{2}" -f $safe, $(if ($User) { $User.Substring([math]::Max(0, $User.Length - 6)) } else { 'u' }), (Get-Date -Format 'HHmmssfff'))
    if ($PSCmdlet.ShouldProcess($Path, ("Move to quarantine as {0}" -f $dest))) {
        if ($ContentsOnly -and (Get-Item -LiteralPath $Path).PSIsContainer) {
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            $failed = 0
            foreach ($child in Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue) {
                try { Move-Item -LiteralPath $child.FullName -Destination $dest -Force -ErrorAction Stop } catch { $failed++; Write-Log ("could not move {0}: {1}" -f $child.FullName, (Get-ErrorText $_)) 'DEBUG' }
            }
            $script:RestoreLines.Add(("{0}  <-  contents of {1}" -f $dest, $Path)); Write-RestoreInstructions
            if ($failed -gt 0) { Write-Log ("{0} item(s) under {1} are still in use and were left in place" -f $failed, $Path) 'WARN' }
            return ($failed -eq 0)
        }
        Move-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop
        $script:RestoreLines.Add(("{0}  <-  {1}" -f $dest, $Path)); Write-RestoreInstructions
        return $true
    }
    return $false
}

# ---------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------
function Invoke-Native {
    # Runs a console tool, captures stdout and stderr, never throws on a non-zero exit code.
    param([Parameter(Mandatory)][string]$File, [string[]]$Arguments = @(), [int]$TimeoutSec = 60)
    $out = ''; $code = -1
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $File; $psi.Arguments = ($Arguments -join ' '); $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $stdout = $p.StandardOutput.ReadToEndAsync(); $stderr = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; $out = 'timed out'; $code = -2 }
        else { $code = $p.ExitCode; $out = ($stdout.Result + "`n" + $stderr.Result).Trim() }
    } catch { $out = Get-ErrorText $_; $code = -1 }
    return [pscustomobject]@{ ExitCode = $code; Output = $out }
}

function Get-FolderSizeMB {
    param([Parameter(Mandatory)][string]$Path)
    try { if (-not (Test-Path -LiteralPath $Path)) { return 0 }; $b = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; return [math]::Round(($(if ($b) { $b } else { 0 })) / 1MB, 1) } catch { return 0 }
}

function Get-ProcessesForUser {
    # Processes owned by one SID, by name. Owner lookup needs elevation for other users' processes; a process whose owner cannot be read is never counted.
    param([Parameter(Mandatory)][string[]]$Names, [Parameter(Mandatory)][string]$Sid)
    $result = @()
    try {
        $procs = Get-CimInstance -ClassName Win32_Process -Filter ("Name='{0}'" -f ($Names -join "' OR Name='")) -ErrorAction Stop
        foreach ($p in $procs) {
            $owner = $null
            try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop; $owner = $o.Sid } catch { }
            if ($owner -eq $Sid) { $result += $p }
        }
    } catch { }
    return $result
}

function Test-Newer {
    param([string]$A, [string]$B)
    try { return ([version]$A -gt [version]$B) } catch { return $false }
}

# ---------------------------------------------------------------------------------------------
# Error code decoder. Each entry: meaning, owner (Client / Tenant / Network / Device), rung that addresses it, source.
# Codes Microsoft does not document individually carry Family = $true and are routed to the read-only ladder only.
# Sources: docs/sources.md (Entra error codes, OneDrive error codes, Teams sign-in errors, Windows Hello PIN errors,
# Authentication automatically fails, PRT troubleshooting, TLS 1.2 guidance).
# ---------------------------------------------------------------------------------------------
$script:Codes = @{
    # Web Account Manager / broker (client)
    'CAA50021'  = @{ M = 'WAM could not complete the sign-in (often a broken Microsoft.AAD.BrokerPlugin registration or stale Office credentials)'; O = 'Client'; R = 3; S = 'Authentication automatically fails in Microsoft 365 services' }
    'CAA2000C'  = @{ M = 'Sign-in loop in the modern-auth broker; stale cache or credentials'; O = 'Client'; R = 2; S = 'Resolve sign-in errors in Teams' ; F = $true }
    'CAA20003'  = @{ M = 'Token time or validity problem; check clock, then clear Office identity cache'; O = 'Client'; R = 2; S = 'Resolve sign-in errors in Teams'; F = $true }
    'CAA20004'  = @{ M = 'Blocked by a Conditional Access policy for Teams'; O = 'Tenant'; R = 0; S = 'Resolve sign-in errors in Teams' }
    'CAA70004'  = @{ M = 'Office sign-in or login loop (Teams); clear cache, then reinstall if it persists'; O = 'Client'; R = 2; S = 'Resolve sign-in errors in Teams' }
    'CAA70007'  = @{ M = 'Office sign-in / login loop family (Teams)'; O = 'Client'; R = 2; S = 'Resolve sign-in errors in Teams' }
    'CAA82EE7'  = @{ M = 'Cannot reach the sign-in service (name not resolved). Network, proxy or DNS'; O = 'Network'; R = 0; S = 'Resolve sign-in errors in Teams' }
    'CAA82EE2'  = @{ M = 'Timed out reaching the sign-in service. Network, proxy or firewall'; O = 'Network'; R = 0; S = 'Resolve sign-in errors in Teams' }
    'CAA90018'  = @{ M = 'Interaction or consent needed in the broker; user must complete the prompt'; O = 'Client'; R = 2; S = 'Resolve sign-in errors in Teams'; F = $true }
    'CAA5001C'  = @{ M = 'Token broker operation failed (AAD Operational event 1098)'; O = 'Client'; R = 3; S = 'Event 1098 error 0xCAA5001C' }
    '80070520'  = @{ M = 'WamDefaultSet ERROR: the logon session does not exist; stale Windows Credentials'; O = 'Client'; R = 2; S = 'Microsoft Q&A (community)'; F = $true }
    '80070057'  = @{ M = 'WAM FindAllAccountsAsync failed (-2147024809); broker package registration'; O = 'Client'; R = 3; S = 'Authentication automatically fails in Microsoft 365 services' }
    '8007007E'  = @{ M = 'A module or package is missing; re-register the broker packages'; O = 'Client'; R = 3; S = 'inferred'; F = $true }
    '801C0451'  = @{ M = 'Token broker account cache conflict (user token switch account)'; O = 'Client'; R = 2; S = 'Windows Hello errors during PIN creation' }
    '801C004D'  = @{ M = 'No default WAM account for Windows Hello provisioning; add the work account in Settings first'; O = 'Client'; R = 0; S = 'Windows Hello errors during PIN creation' }
    '80180018'  = @{ M = 'MDM enrollment blocked: licence or device limit'; O = 'Tenant'; R = 0; S = 'Microsoft Q&A (community)'; F = $true }
    # Windows Hello / TPM
    '80090016'  = @{ M = 'Keyset does not exist (TPM). Use Settings > I forgot my PIN; never delete the Ngc folder'; O = 'Device'; R = 0; S = 'Windows Hello errors during PIN creation' }
    'C0090016'  = @{ M = 'Keyset does not exist (TPM). Use Settings > I forgot my PIN; never delete the Ngc folder'; O = 'Device'; R = 0; S = 'Windows Hello errors during PIN creation' }
    '8009000F'  = @{ M = 'Container or key already exists; PIN reset, or unjoin and rejoin through Settings'; O = 'Device'; R = 0; S = 'Windows Hello errors during PIN creation' }
    '80090011'  = @{ M = 'Container or key was not found; PIN reset, or unjoin and rejoin through Settings'; O = 'Device'; R = 0; S = 'Windows Hello errors during PIN creation' }
    '80090029'  = @{ M = 'TPM is not set up; prepare it in tpm.msc as an administrator'; O = 'Device'; R = 0; S = 'Windows Hello errors during PIN creation' }
    '80090030'  = @{ M = 'TPM device is not ready for use'; O = 'Device'; R = 0; S = 'Windows Hello errors during PIN creation' }
    '80090031'  = @{ M = 'TPM authentication ignored; reboot, then manual TPM reset only as a last resort'; O = 'Device'; R = 0; S = 'Windows Hello errors during PIN creation' }
    '80090325'  = @{ M = 'Certificate chain issued by an untrusted root (SEC_E_UNTRUSTED_ROOT): TLS interception or a missing Microsoft root'; O = 'Network'; R = 0; S = 'Network connectivity principles; Azure CA details' }
    'C000006D'  = @{ M = 'PRT acquisition logon failure (bad credentials, server AADSTS50126)'; O = 'Client'; R = 1; S = 'Troubleshoot primary refresh token issues' }
    # Office activation
    '8004FC12'  = @{ M = '"Something went wrong and we can''t do this for you right now" after a Windows upgrade'; O = 'Device'; R = 0; S = 'Office error code 0x8004FC12 when activating Office' }
    'C004F074'  = @{ M = 'No Key Management Service could be contacted (volume licence only)'; O = 'Network'; R = 0; S = 'Tools to manage volume activation of Office' }
    '8007000D'  = @{ M = 'Licensing data invalid; Office licence files are recreated after removal'; O = 'Client'; R = 2; S = 'vnextdiag.ps1 licensing tool' }
    '80070005'  = @{ M = 'Access denied. Office: run once as administrator; OneDrive update or Known Folder Move blocked by policy'; O = 'Client'; R = 0; S = 'Unlicensed Product and activation errors; OneDrive error codes' }
    # OneDrive
    '8004DE40'  = @{ M = 'OneDrive cannot connect to the cloud: TLS 1.2, cipher order, proxy'; O = 'Network'; R = 0; S = 'Error 0x8004de40 or 0x8004de88 in OneDrive' }
    '8004DE88'  = @{ M = 'OneDrive cannot sign in to the account: same TLS or network causes as 0x8004de40'; O = 'Network'; R = 0; S = 'Error 0x8004de40 or 0x8004de88 in OneDrive' }
    '8004DE85'  = @{ M = 'OneDrive account problem: missing account or personal and work account mismatch'; O = 'Client'; R = 2; S = 'What do the OneDrive error codes mean' }
    '8004DE8A'  = @{ M = 'OneDrive account problem: missing account or personal and work account mismatch'; O = 'Client'; R = 2; S = 'What do the OneDrive error codes mean' }
    '8004DE80'  = @{ M = 'OneDrive generic sign-in fault; reset, then reinstall'; O = 'Client'; R = 2; S = 'What do the OneDrive error codes mean' }
    '8004DE86'  = @{ M = 'OneDrive generic sign-in fault; reset, then reinstall'; O = 'Client'; R = 2; S = 'What do the OneDrive error codes mean' }
    '8004DE90'  = @{ M = 'OneDrive has not been set up fully'; O = 'Client'; R = 2; S = 'What do the OneDrive error codes mean' }
    '8004DE96'  = @{ M = 'Seen after a Microsoft account password change; stale credentials'; O = 'Client'; R = 2; S = 'What do the OneDrive error codes mean' }
    '8004DED2'  = @{ M = 'Organisation does not support OneDrive (region or configuration)'; O = 'Tenant'; R = 0; S = 'What do the OneDrive error codes mean' }
    '8004DED7'  = @{ M = 'OneDrive version too old for work or school; update'; O = 'Client'; R = 0; S = 'What do the OneDrive error codes mean' }
    '8004DEDC'  = @{ M = 'Wrong region for the work or school account; admin-initiated move'; O = 'Tenant'; R = 0; S = 'What do the OneDrive error codes mean' }
    '8004DEF0'  = @{ M = 'Credentials changed or expired; sign in again'; O = 'Client'; R = 2; S = 'What do the OneDrive error codes mean' }
    '8004DEF1'  = @{ M = 'An update is required'; O = 'Client'; R = 0; S = 'What do the OneDrive error codes mean' }
    '8004DEF4'  = @{ M = 'Sync app and Store app conflict; remove all versions, reinstall the sync app'; O = 'Client'; R = 0; S = 'What do the OneDrive error codes mean' }
    '8004DEF7'  = @{ M = 'Storage exceeded or account frozen'; O = 'Tenant'; R = 0; S = 'What do the OneDrive error codes mean' }
    '80040C81'  = @{ M = 'OneDrive connectivity fault; reset'; O = 'Client'; R = 2; S = 'What do the OneDrive error codes mean' }
    '8007016A'  = @{ M = 'Files On-Demand provider not running; disable Save space, reset, re-enable'; O = 'Client'; R = 0; S = 'What do the OneDrive error codes mean' }
    '80070194'  = @{ M = 'Cloud provider fault; reset OneDrive'; O = 'Client'; R = 2; S = 'What do the OneDrive error codes mean' }
    '80071129'  = @{ M = 'Invalid reparse point; run chkdsk manually'; O = 'Device'; R = 0; S = 'What do the OneDrive error codes mean' }
    '80071128'  = @{ M = 'Invalid reparse point; run chkdsk manually'; O = 'Device'; R = 0; S = 'What do the OneDrive error codes mean' }
    '80072EE7'  = @{ M = 'WinINet: name not resolved (DNS or proxy)'; O = 'Network'; R = 0; S = 'generic Windows HRESULT'; F = $true }
    '80072EE2'  = @{ M = 'WinINet: request timed out (proxy or firewall)'; O = 'Network'; R = 0; S = 'generic Windows HRESULT'; F = $true }
    # Entra (server side: report and route, never repaired locally)
    'AADSTS50011'  = @{ M = 'Reply address missing or misconfigured for the application'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS50020'  = @{ M = 'User from another identity provider or tenant is not authorised for the application'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS50034'  = @{ M = 'User account not found in the directory (often a mistyped sign-in name)'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS50053'  = @{ M = 'Account locked (too many failed attempts or risky IP). Do not retry sign-in repeatedly'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS50072'  = @{ M = 'User must enrol for multifactor authentication'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS50076'  = @{ M = 'Multifactor authentication required by policy; the client is healthy'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS50079'  = @{ M = 'User must register multifactor authentication'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS50105'  = @{ M = 'User is not assigned to a role for the application'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS50126'  = @{ M = 'Invalid username or password'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS50155'  = @{ M = 'Device authentication failed: device deleted or disabled in Entra; re-register per join type'; O = 'Device'; R = 0; S = 'Troubleshoot primary refresh token issues' }
    'AADSTS50173'  = @{ M = 'Grant expired (password changed or token revoked); sign out and back in'; O = 'Client'; R = 2; S = 'Entra authentication and authorization error codes' }
    'AADSTS53000'  = @{ M = 'Conditional Access requires a compliant device'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS53001'  = @{ M = 'Conditional Access requires a domain or Entra joined device'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS53003'  = @{ M = 'Blocked by Conditional Access policy'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS65001'  = @{ M = 'User or administrator has not consented to the application'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS70008'  = @{ M = 'Refresh token expired due to inactivity (not clock skew); sign in again'; O = 'Client'; R = 1; S = 'Entra authentication and authorization error codes' }
    'AADSTS90072'  = @{ M = 'Account from another tenant is not permitted for this application'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS500011' = @{ M = 'Resource principal not found in the tenant; application not installed or consented'; O = 'Tenant'; R = 0; S = 'Error AADSTS500011' }
    'AADSTS500133' = @{ M = 'Assertion is not within its valid time range: clock skew on the device'; O = 'Device'; R = 1; S = 'Entra authentication and authorization error codes' }
    'AADSTS530003' = @{ M = 'Device does not meet the Conditional Access device policy'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
    'AADSTS700016' = @{ M = 'Application not found in the tenant or authority'; O = 'Tenant'; R = 0; S = 'Entra authentication and authorization error codes' }
}

function Resolve-ErrorCode {
    # Accepts 0x8004de40, 8004DE40, CAA50021, 0xCAA50021, AADSTS50076, -2147024809. Returns a decoded object or a family route.
    param([Parameter(Mandatory)][string]$Code)
    $raw = $Code.Trim()
    $key = $raw.ToUpperInvariant()
    # Only a signed decimal (as Windows prints -2147024809) is converted; a bare 8-digit value such as 80090016 is already hex.
    if ($key -match '^-\d{6,}$') { try { $key = ('{0:X8}' -f [int64]$raw); if ($key.Length -gt 8) { $key = $key.Substring($key.Length - 8) } } catch { } }
    $key = $key -replace '^0X', ''
    if ($key -match '^AADSTS\d+$' -eq $false -and $key -match '^[0-9A-F]{7,8}$') { $key = $key.PadLeft(8, '0') }
    if ($script:Codes.ContainsKey($key)) {
        $e = $script:Codes[$key]
        $fam = [bool]($e.ContainsKey('F') -and $e.F)
        # Codes Microsoft does not document individually only ever route to the read-only ladder.
        return [pscustomobject]@{ Code = $raw; Key = $key; Meaning = $e.M; Owner = $e.O; Rung = $(if ($fam) { 0 } else { $e.R }); Source = $e.S; Family = $fam; Known = $true }
    }
    $fam = 'unknown'
    $owner = 'Client'; $rung = 0
    if ($key -like 'AADSTS*') { $fam = 'Entra server response; tenant or policy side, report only'; $owner = 'Tenant' }
    elseif ($key -like 'CAA*') { $fam = 'Web Account Manager broker family; read-only ladder first, cache reset only when a finding supports it' }
    elseif ($key -like '8004DE*' -or $key -like '8004E4*' -or $key -like '80040C*') { $fam = 'OneDrive identity, token or configuration family; identity check, re-auth, then reset only when a finding supports it' }
    elseif ($key -like '80090*' -or $key -like 'C0090*') { $fam = 'Windows Hello, TPM or Schannel family; report only, supported flows through Settings'; $owner = 'Device' }
    elseif ($key -like '80072E*') { $fam = 'WinINet network family; DNS, proxy, firewall'; $owner = 'Network' }
    elseif ($key -like '801C*') { $fam = 'Device registration (DSREG) family; dsregcmd /status and User Device Registration log'; $owner = 'Device' }
    return [pscustomobject]@{ Code = $raw; Key = $key; Meaning = ('Not individually documented by Microsoft. ' + $fam); Owner = $owner; Rung = $rung; Source = 'family routing'; Family = $true; Known = $false }
}

# ---------------------------------------------------------------------------------------------
# PHASE 1  Device and platform (read-only)
# ---------------------------------------------------------------------------------------------
function Get-DeviceFacts {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = Get-RegValue $cv 'CurrentBuild'; $ubr = Get-RegValue $cv 'UBR'; $disp = Get-RegValue $cv 'DisplayVersion'
    $script:Facts['OS'] = if ($os) { $os.Caption } else { 'unknown' }
    $script:Facts['Build'] = "{0}.{1} ({2})" -f $build, $ubr, $disp
    $script:Facts['Computer'] = $env:COMPUTERNAME
    $script:Facts['Elevated'] = $script:IsElevated
    $script:Facts['System'] = $script:IsSystem
    $script:Facts['PowerShell'] = $PSVersionTable.PSVersion.ToString()
    $script:Facts['Architecture'] = $env:PROCESSOR_ARCHITECTURE
    if ($build -and [int]$build -lt 19045) {
        Add-Finding -Id 'OS-OLD' -Severity Medium -Area 'Platform' -Title 'Windows build is older than Windows 10 22H2' -Evidence $script:Facts['Build'] -Rung 0 -Fix 'Windows 10 support ended 14 October 2025; move to Windows 11 or 22H2 with ESU' -Source 'Windows 10 end of support and Microsoft 365 Apps'
    }

    Set-SpinnerText 'Pending reboot and disk space'
    # Pending reboot (heuristic keys used by Windows servicing)
    $pending = @()
    if (Test-RegKey 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS' }
    if (Test-RegKey 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'WindowsUpdate' }
    $pfro = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
    if ($pfro) { $pending += 'PendingFileRename' }
    $script:Facts['PendingReboot'] = ($pending.Count -gt 0)
    if ($pending.Count -gt 0) { Add-Finding -Id 'REBOOT-PENDING' -Severity Medium -Area 'Platform' -Title 'A reboot is pending' -Evidence ($pending -join ', ') -Rung 0 -Fix 'Restart, then run again; TLS, .NET and WebView2 changes only take effect after a restart' -Source 'Windows servicing behaviour' }

    # Disk space on the system volume
    try {
        $sys = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop
        $freeGB = [math]::Round($sys.Free / 1GB, 1)
        $script:Facts['FreeGB'] = $freeGB
        if ($freeGB -lt 2) { Add-Finding -Id 'DISK-LOW' -Severity High -Area 'Platform' -Title 'System volume nearly full; token caches and WebView2 cannot write' -Evidence ("{0} GB free" -f $freeGB) -Rung 0 -Fix 'Free at least 2 GB before repairing sign-in' -Source 'Distribute the WebView2 Runtime' }
    } catch { }

    Set-SpinnerText 'Services the sign-in stack depends on'
    # Services the sign-in stack depends on
    foreach ($svcName in @('TokenBroker', 'wlidsvc', 'ClickToRunSvc', 'CldFlt', 'NlaSvc', 'netprofm', 'w32time', 'Winmgmt')) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $start = try { (Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $svcName) -ErrorAction Stop).StartMode } catch { 'unknown' }
        $script:Facts["Svc.$svcName"] = "{0} / {1}" -f $svc.Status, $start
        switch ($svcName) {
            'TokenBroker' { if ($start -eq 'Disabled') { Add-Finding -Id 'SVC-TOKENBROKER' -Severity High -Area 'Broker' -Title 'Web Account Manager service (TokenBroker) is disabled' -Evidence $script:Facts["Svc.$svcName"] -Rung 1 -Fix 'Set start type back to Manual (trigger start); Stopped is normal when idle' -Source 'Windows service defaults' } }
            'wlidsvc' { if ($start -eq 'Disabled') { Add-Finding -Id 'SVC-WLIDSVC' -Severity Medium -Area 'Broker' -Title 'Microsoft Account Sign-in Assistant is disabled' -Evidence $script:Facts["Svc.$svcName"] -Rung 1 -Fix 'Set start type to Manual; personal-account and some WAM flows need it' -Source 'Microsoft Q&A (moderate confidence)' } }
            'ClickToRunSvc' { if ($svc.Status -ne 'Running' -and $start -ne 'Disabled') { Add-Finding -Id 'SVC-C2R' -Severity Medium -Area 'Office' -Title 'Office Click-to-Run service is not running' -Evidence $script:Facts["Svc.$svcName"] -Rung 1 -Fix 'Start the service (the Intune built-in remediation does the same)' -Source 'Intune Remediations built-in scripts' } elseif ($start -eq 'Disabled') { Add-Finding -Id 'SVC-C2R-DISABLED' -Severity High -Area 'Office' -Title 'Office Click-to-Run service is disabled; Office apps cannot start or activate' -Evidence $script:Facts["Svc.$svcName"] -Rung 1 -Fix 'Set start type to Automatic and start it' -Source 'Intune Remediations built-in scripts' } }
            'CldFlt' { if ($start -eq 'Disabled') { Add-Finding -Id 'SVC-CLDFLT' -Severity Medium -Area 'OneDrive' -Title 'Cloud Files filter driver is disabled; Files On-Demand cannot start' -Evidence $script:Facts["Svc.$svcName"] -Rung 0 -Fix 'Report to the device owner; do not reconfigure the driver from a tool' -Source 'What do the OneDrive error codes mean' } }
            'NlaSvc' { if ($svc.Status -ne 'Running') { Add-Finding -Id 'SVC-NLA' -Severity Medium -Area 'Network' -Title 'Network Location Awareness is not running' -Evidence $script:Facts["Svc.$svcName"] -Rung 1 -Fix 'Start the service' -Source 'Network Location Awareness service' } }
        }
    }

    Set-SpinnerText 'WebView2 Runtime'
    # WebView2 (Evergreen runtime) machine and current-user view
    $wvKey64 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $wvKey32 = 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $pv = Get-RegValue $(if ($script:Is64BitOS) { $wvKey64 } else { $wvKey32 }) 'pv'
    $script:Facts['WebView2.Machine'] = if ($pv -and $pv -ne '0.0.0.0') { $pv } else { 'not installed' }
    if (-not $pv -or $pv -eq '0.0.0.0') {
        $script:Facts['WebView2.MachineMissing'] = $true
    }

    Set-SpinnerText 'TLS 1.2 posture: Schannel, .NET, WinHTTP, cipher policy'
    # TLS 1.2 posture (report only; machine-wide hardening is an owner decision)
    $tlsClient = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $en = Get-RegValue $tlsClient 'Enabled'; $dbd = Get-RegValue $tlsClient 'DisabledByDefault'
    if (($null -ne $en -and $en -eq 0) -or ($null -ne $dbd -and $dbd -eq 1)) { Add-Finding -Id 'TLS12-OFF' -Severity High -Area 'TLS' -Title 'TLS 1.2 client is disabled in Schannel' -Evidence ("Enabled={0} DisabledByDefault={1}" -f $en, $dbd) -Rung 0 -Fix 'Set Enabled=1 and DisabledByDefault=0 under the TLS 1.2\Client key, then restart. Report-only: this is a machine hardening setting' -Source 'TLS registry settings' }
    $netKeys = @('HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')
    $weak = @()
    foreach ($k in $netKeys) { $sc = Get-RegValue $k 'SchUseStrongCrypto'; $sd = Get-RegValue $k 'SystemDefaultTlsVersions'; if (($null -ne $sc -and $sc -eq 0) -or ($null -ne $sd -and $sd -eq 0)) { $weak += $k } }
    if ($weak.Count -gt 0) { Add-Finding -Id 'NET-WEAKCRYPTO' -Severity Medium -Area 'TLS' -Title '.NET Framework is pinned to weak TLS' -Evidence ($weak -join '; ') -Rung 0 -Fix 'Set SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1 in the four .NETFramework keys, then restart' -Source 'TLS best practices with .NET Framework' }
    $dsp = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DefaultSecureProtocols'
    if ($null -ne $dsp -and (([int]$dsp -band 0x800) -eq 0) -and (([int]$dsp -band 0x2000) -eq 0)) { Add-Finding -Id 'WINHTTP-NOTLS12' -Severity High -Area 'TLS' -Title 'WinHTTP DefaultSecureProtocols excludes TLS 1.2 and 1.3' -Evidence ('0x{0:X}' -f [int]$dsp) -Rung 0 -Fix 'Set DefaultSecureProtocols to 0xAA0 (or 0x800) in both registry views, then restart' -Source 'Enable TLS 1.2 on clients' }
    $cipherGpo = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' 'Functions'
    if ($cipherGpo) {
        $needed = @('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')
        $list = ([string]$cipherGpo) -split ','
        $missing = @($needed | Where-Object { $list -notcontains $_ })
        if ($missing.Count -gt 0) { Add-Finding -Id 'CIPHER-GPO' -Severity Medium -Area 'TLS' -Title 'SSL Cipher Suite Order policy removes suites Azure Front Door needs' -Evidence ("missing: {0}" -f ($missing -join ', ')) -Rung 0 -Fix 'Security team: restore the ECDHE-RSA AES-GCM suites in the cipher order policy' -Source 'Error 0x8004de40 or 0x8004de88 in OneDrive' }
    }

    Set-SpinnerText 'Root certificate trust'
    # Root trust
    $noRootUpdate = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' 'DisableRootAutoUpdate'
    if ($noRootUpdate -eq 1) { Add-Finding -Id 'ROOT-AUTOUPDATE-OFF' -Severity Medium -Area 'TLS' -Title 'Automatic root certificate update is disabled by policy' -Evidence 'DisableRootAutoUpdate=1' -Rung 0 -Fix 'Deliberate in disconnected environments; make sure the Microsoft and DigiCert roots below are deployed' -Source 'Configure trusted roots and disallowed certificates' }
    $roots = @{
        'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4' = 'DigiCert Global Root G2'
        'A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436' = 'DigiCert Global Root CA'
        '999A64C37FF47D9FAB95F14769891460EEC4C3C5' = 'Microsoft RSA Root Certificate Authority 2017'
        '73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74' = 'Microsoft ECC Root Certificate Authority 2017'
        'D4DE20D05E66FC53FE1A50882C78DB2852CAE474' = 'Baltimore CyberTrust Root'
    }
    try {
        $present = @(Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop | Select-Object -ExpandProperty Thumbprint)
        $missingRoots = @($roots.Keys | Where-Object { $present -notcontains $_ } | ForEach-Object { $roots[$_] })
        $script:Facts['RootsMissing'] = $missingRoots
        # Windows keeps only the roots it has needed so far and downloads the rest on demand; absence is only a problem when that download is disabled by policy.
        if ($missingRoots.Count -gt 0) {
            if ($noRootUpdate -eq 1) { Add-Finding -Id 'ROOT-MISSING' -Severity High -Area 'TLS' -Title 'Microsoft 365 root certificates are missing and automatic root update is disabled' -Evidence ($missingRoots -join ', ') -Rung 0 -Fix 'Deploy the missing roots by thumbprint from the Azure CA list through the approved channel' -Source 'Azure Certificate Authority details; Configure trusted roots and disallowed certificates' }
            else { Add-Finding -Id 'ROOT-NOTCACHED' -Severity Info -Area 'TLS' -Title 'Some Microsoft 365 roots are not in the local store yet' -Evidence ($missingRoots -join ', ') -Rung 0 -Fix 'Normal: Windows downloads a root the first time a chain needs it, and automatic root update is enabled here' -Source 'Configure trusted roots and disallowed certificates' }
        }
    } catch { }

    Set-SpinnerText 'Policies that block sign-in or registration'
    # Policies that block sign-in or registration (report only)
    $ncu = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'NoConnectedUser'
    if ($ncu -in @(1, 3)) { Add-Finding -Id 'POL-NOCONNECTEDUSER' -Severity Low -Area 'Policy' -Title 'Microsoft accounts are blocked by policy (NoConnectedUser)' -Evidence ("value {0}" -f $ncu) -Rung 0 -Fix 'Irrelevant for work or school sign-in; explains personal account failures' -Source 'Accounts: Block Microsoft accounts' }
    $bwj = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin' 'BlockAADWorkplaceJoin'
    if ($bwj -eq 1) { Add-Finding -Id 'POL-BLOCKWPJ' -Severity Medium -Area 'Policy' -Title 'Device registration is blocked by policy (BlockAADWorkplaceJoin)' -Evidence 'HKLM WorkplaceJoin\BlockAADWorkplaceJoin=1' -Rung 0 -Fix 'Explains Conditional Access device failures; change only through the managing team' -Source 'Microsoft Entra devices FAQ' }
    foreach ($odPol in @(@{ N = 'DisableFileSyncNGSC'; K = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'; T = 'OneDrive is blocked by the legacy "Prevent the usage of OneDrive" policy' }, @{ N = 'DisablePersonalSync'; K = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'; T = 'Personal OneDrive accounts are blocked by policy' }, @{ N = 'IgnoreWebProxy'; K = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'; T = 'OneDrive is configured to bypass web proxy detection' })) {
        $v = Get-RegValue $odPol.K $odPol.N
        if ($v -eq 1) { Add-Finding -Id ("POL-" + $odPol.N.ToUpper()) -Severity Low -Area 'Policy' -Title $odPol.T -Evidence ("{0}={1}" -f $odPol.N, $v) -Rung 0 -Fix 'Organisation control; report only' -Source 'Use OneDrive policies' }
    }
    foreach ($listName in @('AllowTenantList', 'BlockTenantList')) {
        $k = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\$listName"
        if (Test-RegKey $k) { $ids = @((Get-Item -LiteralPath $k).GetValueNames()); if ($ids.Count -gt 0) { Add-Finding -Id ("POL-" + $listName.ToUpper()) -Severity Low -Area 'Policy' -Title ("OneDrive {0} is set" -f $listName) -Evidence ($ids -join ', ') -Rung 0 -Fix 'Sign-in for other tenants is restricted by design' -Source 'Use OneDrive policies' } }
    }
    $sca = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' 'SharedComputerLicensing'
    $script:Facts['Office.SCA'] = ($sca -eq 1 -or $sca -eq '1')
    $script:Facts['Office.Platform'] = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' 'Platform'
    $script:Facts['Office.Version'] = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' 'VersionToReport'
    $script:Facts['Office.Channel'] = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' 'UpdateChannel'
    $script:Facts['Office.Installed'] = [bool]$script:Facts['Office.Version']

    # Time
    if (-not $SkipNetwork) {
        Set-SpinnerText 'Windows Time status and offset against time.windows.com'
        $w = Invoke-Native -File "$env:SystemRoot\System32\w32tm.exe" -Arguments @('/query', '/status') -TimeoutSec 20
        $script:Facts['Time.Status'] = $w.Output
        if ($w.ExitCode -eq 0) {
            $src = [regex]::Match($w.Output, '(?im)^Source:\s*(.+)$').Groups[1].Value.Trim()
            $last = [regex]::Match($w.Output, '(?im)^Last Successful Sync Time:\s*(.+)$').Groups[1].Value.Trim()
            $script:Facts['Time.Source'] = $src; $script:Facts['Time.LastSync'] = $last
            if ($last -match 'unspecified' -or $src -match 'Local CMOS Clock|Free-running') { Add-Finding -Id 'TIME-NOSYNC' -Severity Medium -Area 'Time' -Title 'Windows Time is not synchronising' -Evidence ("source {0}; last sync {1}" -f $src, $last) -Rung 1 -Fix 'Resync (w32tm /resync /rediscover); domain members keep the domain hierarchy' -Source 'Windows Time service tools and settings' }
        }
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $dom = if ($cs) { [bool]$cs.PartOfDomain } else { $false }
        $script:Facts['DomainMember'] = $dom
        $peer = if ($dom) { $null } else { 'time.windows.com' }
        if ($peer) {
            $sc = Invoke-Native -File "$env:SystemRoot\System32\w32tm.exe" -Arguments @('/stripchart', "/computer:$peer", '/samples:2', '/dataonly') -TimeoutSec 25
            $m = [regex]::Matches($sc.Output, '([+-]\d+\.\d+)s')
            if ($m.Count -gt 0) {
                $off = [math]::Abs([double]$m[$m.Count - 1].Groups[1].Value)
                $script:Facts['Time.OffsetSec'] = [math]::Round($off, 1)
                if ($off -ge 300) { Add-Finding -Id 'TIME-SKEW' -Severity High -Area 'Time' -Title 'Clock is more than 5 minutes off; tokens fail with AADSTS500133' -Evidence ("{0}s against {1}" -f [math]::Round($off), $peer) -Rung 1 -Fix 'Resync the clock' -Source 'Entra error codes; Maximum tolerance for computer clock synchronization' }
                elseif ($off -ge 60) { Add-Finding -Id 'TIME-DRIFT' -Severity Low -Area 'Time' -Title 'Clock drift over one minute' -Evidence ("{0}s against {1}" -f [math]::Round($off), $peer) -Rung 1 -Fix 'Resync the clock' -Source 'Windows Time service tools and settings' }
            }
        }
    }
    $script:Facts['TimeZone'] = try { (Get-TimeZone).Id } catch { 'unknown' }
}

# ---------------------------------------------------------------------------------------------
# PHASE 2  Device registration (dsregcmd /status, parsed) and event logs
# ---------------------------------------------------------------------------------------------
function ConvertFrom-DsregTime {
    # dsregcmd prints '2026-09-04 10:11:12.000 UTC'; .NET does not accept the UTC suffix, so it is stripped and the value read as universal time.
    param([Parameter(Mandatory)][string]$Text)
    $t = ($Text -replace '\s*UTC\s*$', '').Trim()
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    foreach ($fmt in @('yyyy-MM-dd HH:mm:ss.fff', 'yyyy-MM-dd HH:mm:ss')) {
        $out = [datetime]::MinValue
        if ([datetime]::TryParseExact($t, $fmt, [cultureinfo]::InvariantCulture, $styles, [ref]$out)) { return $out }
    }
    return [datetime]::Parse($t, [cultureinfo]::InvariantCulture, $styles)
}

function ConvertFrom-DsregOutput {
    param([string]$Text)
    $h = @{}
    foreach ($line in ($Text -split "`r?`n")) { if ($line -match '^\s*([A-Za-z][A-Za-z0-9 ]*?)\s*:\s*(.*)$') { $k = $matches[1].Trim(); if (-not $h.ContainsKey($k)) { $h[$k] = $matches[2].Trim() } } }
    return $h
}

function Get-RegistrationFacts {
    # Run in the calling context. User-context fields (SSO State, User State, WamDefaultSet) are only meaningful when the
    # script runs as the user; the elevated run adds KeySignTest. Under SYSTEM only the device section is trusted.
    Set-SpinnerText 'dsregcmd /status'
    $r = Invoke-Native -File "$env:SystemRoot\System32\dsregcmd.exe" -Arguments @('/status') -TimeoutSec 60
    $script:Facts['Dsreg.Raw'] = $r.Output
    if ($r.ExitCode -ne 0 -and -not $r.Output) { Add-Finding -Id 'DSREG-FAIL' -Severity Medium -Area 'Registration' -Title 'dsregcmd /status did not run' -Evidence $r.Output -Rung 0; return }
    $d = ConvertFrom-DsregOutput -Text $r.Output
    $script:Facts['Dsreg'] = $d
    $aadj = $d['AzureAdJoined']; $ej = $d['EnterpriseJoined']; $dj = $d['DomainJoined']
    $wpj = $d['WorkplaceJoined']
    $join = if ($aadj -eq 'YES' -and $dj -eq 'YES') { 'Hybrid Entra joined' } elseif ($aadj -eq 'YES') { 'Entra joined' } elseif ($ej -eq 'YES') { 'On-premises DRS joined' } elseif ($dj -eq 'YES' -and $wpj -eq 'YES') { 'Domain joined, Entra registered' } elseif ($dj -eq 'YES') { 'Domain joined' } elseif ($wpj -eq 'YES') { 'Entra registered' } else { 'Not joined' }
    $script:Facts['JoinType'] = $join
    $script:Facts['TenantName'] = $d['TenantName']; $script:Facts['DeviceId'] = $d['DeviceId']
    if ($d.ContainsKey('DeviceAuthStatus') -and $d['DeviceAuthStatus'] -notmatch 'SUCCESS') { Add-Finding -Id 'DEVICE-AUTH' -Severity High -Area 'Registration' -Title 'Device authentication to Entra is failing' -Evidence ("DeviceAuthStatus {0}" -f $d['DeviceAuthStatus']) -Rung 0 -Fix 'Device object may be deleted or disabled in Entra (AADSTS50155). Re-register per join type through Settings or the admin; never dsregcmd /leave from a tool' -Source 'Troubleshoot primary refresh token issues' }
    if ($d.ContainsKey('KeySignTest') -and $d['KeySignTest'] -notmatch 'PASSED') { Add-Finding -Id 'KEYSIGN' -Severity Medium -Area 'Registration' -Title 'Device key health test failed; Entra will trigger recovery at the next sign-in' -Evidence ("KeySignTest {0}" -f $d['KeySignTest']) -Rung 0 -Fix 'Sign out and in (or lock and unlock); recovery re-registers automatically' -Source 'Troubleshoot devices by using the dsregcmd command' }
    if ($d.ContainsKey('WorkplaceJoined')) { $script:Facts['WorkplaceJoined'] = $d['WorkplaceJoined'] }
    if ($d.ContainsKey('TpmProtected')) { $script:Facts['TpmProtected'] = $d['TpmProtected'] }
    # SSO State, User State and WamDefaultSet describe the account running dsregcmd. They belong to the target user only
    # when that is the current account; an elevated admin inspecting someone else gets device facts only.
    $userCtx = (-not $script:IsSystem) -and ((-not $TargetUserSid) -or ($TargetUserSid -eq $script:CurrentSid))
    $ctxUser = $script:Identity.Name
    if ($userCtx) {
        # "You can ignore this section for Microsoft Entra registered devices" (dsregcmd troubleshooting): the PRT is judged only on joined devices.
        if ($d.ContainsKey('AzureAdPrt') -and $aadj -eq 'YES') {
            $script:Facts['PRT'] = $d['AzureAdPrt']
            if ($d['AzureAdPrt'] -eq 'NO') {
                $why = @(); foreach ($k in @('Attempt Status', 'Server Error Code', 'Server Error Description')) { if ($d.ContainsKey($k) -and $d[$k]) { $why += ("{0}: {1}" -f $k, $d[$k]) } }
                Add-Finding -Id 'PRT-MISSING' -Severity High -Area 'Registration' -Title 'No Primary Refresh Token for this user; single sign-on will prompt repeatedly' -Evidence ($why -join '; ') -Rung 1 -Fix 'Refresh the PRT (dsregcmd /refreshprt, or lock and unlock); if the server error persists, fix the cause it names' -Source 'Troubleshoot primary refresh token issues' -User $ctxUser
            } elseif ($d.ContainsKey('AzureAdPrtUpdateTime') -and $d['AzureAdPrtUpdateTime']) {
                try {
                    $upd = ConvertFrom-DsregTime -Text $d['AzureAdPrtUpdateTime']
                    $age = (Get-Date).ToUniversalTime() - $upd
                    $script:Facts['PRT.AgeHours'] = [math]::Round($age.TotalHours, 1)
                    if ($age.TotalHours -gt 4) { Add-Finding -Id 'PRT-STALE' -Severity Medium -Area 'Registration' -Title 'Primary Refresh Token has not refreshed for over four hours' -Evidence ("updated {0}" -f $d['AzureAdPrtUpdateTime']) -Rung 1 -Fix 'Refresh the PRT; check network to login.microsoftonline.com if it fails again' -Source 'Troubleshoot primary refresh token issues' -User $ctxUser }
                } catch { }
            }
        }
        if ($d.ContainsKey('WamDefaultSet') -and $d['WamDefaultSet'] -match 'ERROR') { Add-Finding -Id 'WAM-DEFAULT' -Severity High -Area 'Broker' -Title 'No usable default WAM account' -Evidence ("WamDefaultSet {0}" -f $d['WamDefaultSet']) -Rung 2 -Fix 'Remove stale Windows Credentials for Office and Teams, then add the work account again in Settings' -Source 'Microsoft Q&A (community); Authentication automatically fails' -User $ctxUser }
        if ($d.ContainsKey('NgcSet')) { $script:Facts['NgcSet'] = $d['NgcSet']; if ($d.ContainsKey('CanReset')) { $script:Facts['NgcCanReset'] = $d['CanReset'] } }
    }

    # Event logs: last 24 hours. AAD Operational holds CloudAP and broker failures; User Device Registration holds join failures.
    Set-SpinnerText 'AAD Operational and User Device Registration event logs, last 24 hours'
    $since = (Get-Date).AddHours(-24)
    try {
        $aad = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AAD/Operational'; StartTime = $since; Level = @(1, 2) } -MaxEvents 200 -ErrorAction Stop)
        $script:Facts['Events.AAD'] = $aad.Count
        $ids = $aad | Group-Object -Property Id | Sort-Object -Property Count -Descending | Select-Object -First 6
        if ($aad.Count -gt 0) {
            $summary = ($ids | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }) -join ', '
            $sample = ($aad | Select-Object -First 1).Message
            if ($sample) { $sample = ($sample -split "`r?`n")[0]; if ($sample.Length -gt 160) { $sample = $sample.Substring(0, 160) } }
            Add-Finding -Id 'EVT-AAD' -Severity $(if ($aad.Count -ge 10) { 'Medium' } else { 'Low' }) -Area 'Events' -Title ("{0} AAD Operational error(s) in the last 24 h" -f $aad.Count) -Evidence ("ids {0}; latest: {1}" -f $summary, $sample) -Rung 0 -Fix 'Event 1098 = token broker failure (0xCAA5001C); 1081/1088 = server error text; 1084 = network sub-error' -Source 'Troubleshoot primary refresh token issues; Event 1098'
            if ($aad | Where-Object { $_.Id -eq 1098 }) { $script:Facts['Events.1098'] = $true; $script:Facts['Events.1098.Count'] = @($aad | Where-Object { $_.Id -eq 1098 }).Count }
        }
    } catch { $script:Facts['Events.AAD'] = 'unavailable' }
    try {
        $udr = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-User Device Registration/Admin'; StartTime = $since; Level = @(1, 2) } -MaxEvents 100 -ErrorAction Stop)
        $script:Facts['Events.UDR'] = $udr.Count
        $hits = @($udr | Where-Object { $_.Id -in @(304, 305, 307, 220) })
        if ($hits.Count -gt 0) { Add-Finding -Id 'EVT-UDR' -Severity Medium -Area 'Events' -Title ("{0} device registration failure event(s) (304/305/307/220)" -f $hits.Count) -Evidence ((($hits | Select-Object -First 1).Message -split "`r?`n")[0]) -Rung 0 -Fix 'Registration failing: check network to enterpriseregistration.windows.net, Conditional Access and the BlockAADWorkplaceJoin policy' -Source 'Troubleshoot hybrid joined devices; Windows Hello deployment issues' }
    } catch { $script:Facts['Events.UDR'] = 'unavailable' }
}

# ---------------------------------------------------------------------------------------------
# PHASE 3  Network: proxy, endpoints through the effective stack, DNS, TLS interception
# ---------------------------------------------------------------------------------------------
function Get-TlsIssuer {
    # Reads the issuer of the certificate served by a host. First with a validation callback that accepts anything (so an
    # untrusted interception certificate can still be read), then, if that path is unavailable on this engine, with normal
    # validation, where a failure itself tells us the chain is not trusted. Never throws.
    param([Parameter(Mandatory)][string]$HostName)
    $result = [pscustomobject]@{ Issuer = ''; Protocol = ''; Untrusted = $false; Error = '' }
    foreach ($withCallback in @($true, $false)) {
        $tcp = $null; $ssl = $null
        try {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $connect = $tcp.ConnectAsync($HostName, 443)
            if (-not $connect.Wait(8000)) { $result.Error = 'connect timeout'; return $result }
            $stream = $tcp.GetStream()
            if ($withCallback) {
                $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $cert, $chain, $errors) return $true }
                $ssl = [System.Net.Security.SslStream]::new($stream, $false, $cb)
            } else { $ssl = [System.Net.Security.SslStream]::new($stream, $false) }
            $ssl.AuthenticateAsClient($HostName)
            $remote = $ssl.RemoteCertificate
            if ($null -eq $remote) { $result.Error = 'handshake completed without a certificate'; return $result }
            $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]$remote
            $result.Issuer = [string]$leaf.Issuer
            $result.Protocol = [string]$ssl.SslProtocol
            return $result
        } catch {
            $msg = Get-ErrorText $_
            $result.Error = ("{0} ({1})" -f $msg, $(if ($withCallback) { 'with callback' } else { 'validated' }))
            if (-not $withCallback -and $msg -match 'remote certificate is invalid|RemoteCertificateChainErrors|RemoteCertificateNameMismatch|untrusted|AuthenticationException') { $result.Untrusted = $true; return $result }
        } finally {
            if ($ssl) { try { $ssl.Dispose() } catch { } }
            if ($tcp) { try { $tcp.Dispose() } catch { } }
        }
    }
    return $result
}

function Get-NetworkFacts {
    if ($SkipNetwork) { $script:Facts['Network'] = 'skipped'; return }
    # WinHTTP (machine) and WinINet (user) proxies are independent; the broker follows WinHTTP, interactive apps follow WinINet.
    Set-SpinnerText 'WinHTTP and WinINet proxy settings'
    $wh = Invoke-Native -File "$env:SystemRoot\System32\netsh.exe" -Arguments @('winhttp', 'show', 'proxy') -TimeoutSec 15
    # netsh output is localised; read the WinHttpSettings value as the language-neutral source and fall back to the English text.
    $whBytes = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' 'WinHttpSettings'
    $whText = ''
    # Layout: version (0), counter (4), flags (8), proxy length (12), proxy string (16). Flag 0x2 means a manual proxy is set.
    if ($whBytes -is [byte[]] -and $whBytes.Length -ge 16) { try { $flags = [BitConverter]::ToInt32($whBytes, 8); if (($flags -band 0x2) -ne 0) { $len = [BitConverter]::ToInt32($whBytes, 12); if ($len -gt 0 -and (16 + $len) -le $whBytes.Length) { $whText = [System.Text.Encoding]::ASCII.GetString($whBytes, 16, $len) } } } catch { } }
    if ($whText) { $script:Facts['Proxy.WinHTTP'] = $whText }
    elseif ($wh.Output -match 'Direct access') { $script:Facts['Proxy.WinHTTP'] = 'direct' }
    else { $line = ($wh.Output -split "`r?`n") | Where-Object { $_ -match 'Proxy Server' } | Select-Object -First 1; $script:Facts['Proxy.WinHTTP'] = $(if ($line) { $line.Trim() } elseif ($whBytes) { 'direct' } else { 'unknown' }) }
    $proxyHive = 'HKCU:'
    if ($script:IsSystem) { $con = Get-ConsoleUserSid; if ($con) { $proxyHive = Get-UserHive -Sid $con } }
    $is = Join-Path $proxyHive 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $pe = Get-RegValue $is 'ProxyEnable'; $ps = Get-RegValue $is 'ProxyServer'; $pac = Get-RegValue $is 'AutoConfigURL'
    $script:Facts['Proxy.WinINet'] = if ($pac) { "PAC $pac" } elseif ($pe -eq 1 -and $ps) { $ps } else { 'direct' }
    $usesProxy = ($script:Facts['Proxy.WinINet'] -ne 'direct') -or ($script:Facts['Proxy.WinHTTP'] -ne 'direct')
    if ($pac) {
        try { $null = Invoke-WebRequest -Uri $pac -Method Head -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop; $script:Facts['Proxy.PACReachable'] = $true }
        catch { $script:Facts['Proxy.PACReachable'] = $false; Add-Finding -Id 'PROXY-PAC' -Severity High -Area 'Network' -Title 'Proxy auto-config script is not reachable' -Evidence $pac -Rung 0 -Fix 'Interactive sign-in follows this PAC; fix its host or the user proxy setting (policy-managed: report only)' -Source 'Network connectivity principles' }
    }

    # DNS sanity on the two hosts every sign-in needs
    foreach ($hostName in @('login.microsoftonline.com', 'aadcdn.msftauth.net')) {
        Set-SpinnerText ("DNS: {0}" -f $hostName)
        try {
            $ans = @(Resolve-DnsName -Name $hostName -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.QueryType -eq 'A' })
            $ips = @($ans | ForEach-Object { $_.IPAddress })
            $script:Facts["DNS.$hostName"] = ($ips -join ', ')
            $bad = @($ips | Where-Object { $_ -match '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)' })
            if ($ips.Count -eq 0 -or $bad.Count -gt 0) {
                # A flush only helps when the cached answer differs from what the server gives now.
                $cached = @(); try { $cached = @(Get-DnsClientCache -Entry $hostName -ErrorAction Stop | ForEach-Object { $_.Data }) } catch { }
                $stale = ($cached.Count -gt 0 -and @($cached | Where-Object { $ips -notcontains $_ }).Count -gt 0)
                Add-Finding -Id ("DNS-" + $hostName.ToUpper()) -Severity High -Area 'Network' -Title ("{0} resolves to a private or empty address" -f $hostName) -Evidence (("server: {0}; cache: {1}" -f ($ips -join ', '), ($cached -join ', '))) -Rung $(if ($stale) { 1 } else { 0 }) -Fix 'DNS sinkhole or split-DNS on the DNS server; the tool never edits hosts or DNS servers. Report to the network owner' -Source 'URLs and IP address ranges'
            }
        } catch { $script:Facts["DNS.$hostName"] = 'failed'; Add-Finding -Id ("DNS-" + $hostName.ToUpper()) -Severity High -Area 'Network' -Title ("{0} does not resolve" -f $hostName) -Evidence (Get-ErrorText $_) -Rung 1 -Fix 'Flush the DNS cache, then check the DNS server; sign-in is impossible without this name' -Source 'URLs and IP address ranges' }
    }

    # HTTPS reachability through the effective stack (system proxy honoured). HEAD; any HTTP status counts as reachable.
    $endpoints = @(
        @{ H = 'login.microsoftonline.com'; U = 'https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=https://login.microsoftonline.com/common/oauth2/v2.0/authorize'; Set = 56; Apps = 'all' },
        @{ H = 'login.microsoft.com'; U = 'https://login.microsoft.com/'; Set = 56; Apps = 'all' },
        @{ H = 'aadcdn.msftauth.net'; U = 'https://aadcdn.msftauth.net/'; Set = 59; Apps = 'all' },
        @{ H = 'enterpriseregistration.windows.net'; U = 'https://enterpriseregistration.windows.net/'; Set = 59; Apps = 'Broker' },
        @{ H = 'device.login.microsoftonline.com'; U = 'https://device.login.microsoftonline.com/'; Set = 56; Apps = 'Broker' },
        @{ H = 'graph.microsoft.com'; U = 'https://graph.microsoft.com/'; Set = 56; Apps = 'all' },
        @{ H = 'officeclient.microsoft.com'; U = 'https://officeclient.microsoft.com/'; Set = 86; Apps = 'Office' },
        @{ H = 'config.office.com'; U = 'https://config.office.com/'; Set = 147; Apps = 'Office' },
        @{ H = 'oneclient.sfx.ms'; U = 'https://oneclient.sfx.ms/'; Set = 36; Apps = 'OneDrive' },
        @{ H = 'teams.microsoft.com'; U = 'https://teams.microsoft.com/'; Set = 12; Apps = 'Teams' }
    )
    $failed = @(); $ok = 0
    $inScope = @($endpoints | Where-Object { $_.Apps -eq 'all' -or ($Apps -contains $_.Apps) })
    $n = 0
    foreach ($e in $inScope) {
        $n++
        Set-SpinnerText ((Get-Tinted 'Probing endpoints ' 'Gray') + (Get-MiniBar -Done ($n - 1) -Total $inScope.Count) + (Get-Tinted (" {0}/{1}  {2}" -f $n, $inScope.Count, $e.H) 'Gray'))
        try {
            $null = Invoke-WebRequest -Uri $e.U -Method Head -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            $ok++
        } catch {
            $msg = Get-ErrorText $_
            # HTTP status responses (403, 404, 405) prove reachability; only transport failures count.
            if ($msg -match '\b[45]\d\d\b' -or $msg -match 'Method Not Allowed|Not Found|Forbidden|Bad Request|Unauthorized') { $ok++ }
            else { $failed += ("{0} (set {1}): {2}" -f $e.H, $e.Set, $msg) }
        }
    }
    $script:Facts['Endpoints.OK'] = $ok; $script:Facts['Endpoints.Failed'] = $failed
    if ($failed.Count -gt 0) { Add-Finding -Id 'ENDPOINTS' -Severity High -Area 'Network' -Title ("{0} Microsoft 365 endpoint(s) unreachable" -f $failed.Count) -Evidence ($failed -join ' | ') -Rung 0 -Fix 'Hand the failing names and endpoint set numbers to the network owner; the tool never changes firewall or proxy rules' -Source 'URLs and IP address ranges' }

    # TLS interception: read the leaf issuer without trusting it. Only meaningful on a direct path; through a proxy the
    # CONNECT tunnel still ends at Microsoft unless the proxy inspects, which the same check reveals.
    Set-SpinnerText 'TLS handshake to login.microsoftonline.com: reading the certificate issuer'
    $probe = Get-TlsIssuer -HostName 'login.microsoftonline.com'
    $script:Facts['TLS.Issuer'] = $probe.Issuer
    $script:Facts['TLS.Protocol'] = $probe.Protocol
    if ($probe.Issuer -and $probe.Issuer -notmatch 'Microsoft|DigiCert|Entrust|Baltimore|GlobalSign|Sectigo') { Add-Finding -Id 'TLS-INTERCEPT' -Severity High -Area 'Network' -Title 'TLS traffic to login.microsoftonline.com is being intercepted' -Evidence ("issuer: {0}" -f $probe.Issuer) -Rung 0 -Fix 'Security team: add Microsoft 365 identity domains to the inspection bypass list. Never add the inspecting CA to trust from a tool' -Source 'Network connectivity principles' }
    if ($probe.Protocol -match '^(Tls|Tls11|Ssl2|Ssl3)$') { Add-Finding -Id 'TLS-OLD' -Severity High -Area 'TLS' -Title 'Only an old TLS version negotiated' -Evidence $probe.Protocol -Rung 0 -Fix 'Microsoft 365 requires TLS 1.2 or later' -Source 'Prepare for TLS 1.2 in Office 365' }
    if ($probe.Untrusted) { Add-Finding -Id 'TLS-UNTRUSTED' -Severity High -Area 'Network' -Title 'The certificate presented for login.microsoftonline.com is not trusted by this device' -Evidence $probe.Error -Rung 0 -Fix 'Either an interception proxy with a CA this device does not trust, or a missing root with automatic root update disabled. Report to the network and security owners' -Source 'Network connectivity principles' }
    if (-not $probe.Issuer -and -not $usesProxy -and $script:Facts['Endpoints.OK'] -eq 0) { Add-Finding -Id 'TLS-PROBE' -Severity Medium -Area 'Network' -Title 'Direct TLS handshake to login.microsoftonline.com failed' -Evidence $probe.Error -Rung 0 -Fix 'Check firewall and TLS 1.2 settings' -Source 'Network connectivity principles' }
    if (-not $probe.Issuer) { Write-Log ("TLS probe detail: {0}" -f $probe.Error) 'DEBUG' }
}

# ---------------------------------------------------------------------------------------------
# PHASE 4  Users: who to inspect, and their sign-in state read from their own hive and profile
# ---------------------------------------------------------------------------------------------
function Get-ConsoleUserSid {
    # The interactively signed-in user, from the owner of explorer.exe. Works from SYSTEM and from an elevated prompt.
    try {
        $ex = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)
        $owners = @()
        foreach ($p in $ex) { try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop; if ($o.Sid -match '^S-1-(5-21|12-1)-' -and $owners -notcontains $o.Sid) { $owners += $o.Sid } } catch { } }
        $script:ConsoleUsers = $owners
        if ($owners.Count -gt 0) { return $owners[0] }
    } catch { }
    return ''
}

function Get-TargetUsers {
    # Returns objects: Sid, Name, Profile, Hive, Loaded, IsCurrent.
    # Domain and local SIDs start S-1-5-21; Entra ID (cloud) user SIDs start S-1-12-1. Both are real users.
    $list = @()
    $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.SID -match '^S-1-(5-21|12-1)-' -and -not $_.Special })
    foreach ($p in $profiles) {
        $name = ''
        try { $name = ([System.Security.Principal.SecurityIdentifier]$p.SID).Translate([System.Security.Principal.NTAccount]).Value } catch { $name = Split-Path -Path $p.LocalPath -Leaf }
        $list += [pscustomobject]@{ Sid = $p.SID; Name = $name; Profile = $p.LocalPath; Hive = (Get-UserHive -Sid $p.SID); Loaded = [bool]$p.Loaded; IsCurrent = ($p.SID -eq $script:CurrentSid) }
    }
    if ($TargetUserSid) {
        if (-not $script:IsElevated -and $TargetUserSid -ne $script:CurrentSid) { throw 'Targeting another user needs an elevated PowerShell.' }
        $u = @($list | Where-Object { $_.Sid -eq $TargetUserSid })
        if ($u.Count -eq 0) { throw ("No profile found for SID {0}." -f $TargetUserSid) }
        return $u
    }
    if ($AllUsers) {
        if (-not $script:IsElevated) { throw '-AllUsers needs an elevated PowerShell.' }
        return @($list | Where-Object { $_.Loaded })
    }
    if ($script:IsSystem) {
        $con = Get-ConsoleUserSid
        if ($con -and $script:ConsoleUsers.Count -gt 1) { Write-Log ("{0} interactive sessions found; every signed-in user is inspected" -f $script:ConsoleUsers.Count) 'INFO'; return @($list | Where-Object { $script:ConsoleUsers -contains $_.Sid }) }
        if ($con) { return @($list | Where-Object { $_.Sid -eq $con }) }
        Write-Log 'Running as SYSTEM with no interactive user signed in: per-user checks are skipped (device checks still run).' 'WARN'
        return @()
    }
    if ($script:IsElevated) {
        # Elevated prompts often run as an admin account while the console user is someone else. Say so.
        $con = Get-ConsoleUserSid
        if ($con -and $con -ne $script:CurrentSid) { Write-Log ("Console user differs from the elevated account; inspecting the elevated account. Use -TargetUserSid {0} for the console user." -f $con) 'WARN' }
    }
    $me = @($list | Where-Object { $_.Sid -eq $script:CurrentSid })
    if ($me.Count -eq 0) { $me = @([pscustomobject]@{ Sid = $script:CurrentSid; Name = $script:Identity.Name; Profile = $env:USERPROFILE; Hive = 'HKCU:'; Loaded = $true; IsCurrent = $true }) }
    return $me
}

function Get-UserPaths {
    param([Parameter(Mandatory)]$User)
    $local = Join-Path -Path $User.Profile -ChildPath 'AppData\Local'
    $roam = Join-Path -Path $User.Profile -ChildPath 'AppData\Roaming'
    if ($User.IsCurrent) { $local = $env:LOCALAPPDATA; $roam = $env:APPDATA }
    return [ordered]@{
        Local = $local; Roaming = $roam
        OneAuth = Join-Path $local 'Microsoft\OneAuth'
        IdentityCache = Join-Path $local 'Microsoft\IdentityCache'
        TokenBrokerCache = Join-Path $local 'Microsoft\TokenBroker\Cache'
        BrokerAccounts = Join-Path $local 'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts'
        OfficeLicenses = Join-Path $local 'Microsoft\Office\Licenses'
        OfficeLicensing16 = Join-Path $local 'Microsoft\Office\16.0\Licensing'
        TeamsNew = Join-Path $local 'Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams'
        TeamsClassic = Join-Path $roam 'Microsoft\Teams'
        OneDriveExe = Join-Path $local 'Microsoft\OneDrive\OneDrive.exe'
        OneDrivePreSignIn = Join-Path $local 'Microsoft\OneDrive\settings\PreSignInSettingsConfig.json'
        OneDriveLogs = Join-Path $local 'Microsoft\OneDrive\logs'
        OutlookNew = Join-Path $local 'Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe'
    }
}

function Get-AppxForUser {
    # Get-AppxPackage -User works from an elevated session for any user; without elevation only the current user is visible.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$User)
    try {
        if ($script:IsPS7 -and -not (Get-Module -Name Appx)) { Import-Module -Name Appx -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue }
        if ($User.IsCurrent -and -not $script:IsSystem) { return @(Get-AppxPackage -Name $Name -ErrorAction Stop) }
        if ($script:IsElevated) { return @(Get-AppxPackage -Name $Name -User $User.Sid -ErrorAction Stop) }
    } catch { Write-Log ("Get-AppxPackage {0}: {1}" -f $Name, (Get-ErrorText $_)) 'DEBUG'; return $null }
    return @()
}

function Get-UserFacts {
    param([Parameter(Mandatory)]$User)
    $u = $User.Name
    $paths = Get-UserPaths -User $User
    $hive = $User.Hive
    $uf = [ordered]@{ Sid = $User.Sid; Name = $u; Paths = $paths; Processes = @(); Caches = [ordered]@{} }
    if (-not (Test-Path -LiteralPath $User.Profile)) { Add-Finding -Id 'USER-NOPROFILE' -Severity Medium -Area 'User' -Title 'Profile folder not found' -Evidence $User.Profile -User $u; return $uf }
    if (-not (Test-Path -LiteralPath $hive)) { Add-Finding -Id 'USER-HIVE' -Severity Medium -Area 'User' -Title 'User registry hive is not loaded; the user is not signed in' -Evidence $hive -Rung 0 -Fix 'Sign the user in and run again, or run in their session' -User $u }

    # Processes that hold the caches
    $names = @('OUTLOOK.exe', 'WINWORD.exe', 'EXCEL.exe', 'POWERPNT.exe', 'ONENOTE.exe', 'MSACCESS.exe', 'ms-teams.exe', 'Teams.exe', 'OneDrive.exe', 'olk.exe', 'lync.exe')
    $uf.Processes = @(Get-ProcessesForUser -Names $names -Sid $User.Sid | ForEach-Object { $_.Name })

    # Broker packages (Rung 3 if missing)
    if ($Apps -contains 'Broker') {
        Set-SpinnerText ("{0}: account broker packages and token caches" -f $u)
        $broker = Get-AppxForUser -Name 'Microsoft.AAD.BrokerPlugin' -User $User
        $ceh = Get-AppxForUser -Name 'Microsoft.Windows.CloudExperienceHost' -User $User
        $acc = Get-AppxForUser -Name 'Microsoft.AccountsControl' -User $User
        $inventoryOk = ($null -ne $broker) -and ($null -ne $ceh)
        $uf['Appx.BrokerPlugin'] = if ($null -eq $broker) { 'unknown' } else { (@($broker).Count -gt 0) }
        $uf['Appx.CloudExperienceHost'] = if ($null -eq $ceh) { 'unknown' } else { (@($ceh).Count -gt 0) }
        $uf['Appx.AccountsControl'] = if ($null -eq $acc) { 'unknown' } else { (@($acc).Count -gt 0) }
        $canSee = ($User.IsCurrent -or $script:IsElevated) -and $inventoryOk
        if (($User.IsCurrent -or $script:IsElevated) -and -not $inventoryOk) { Add-Finding -Id 'APPX-UNKNOWN' -Severity Info -Area 'Broker' -Title 'Store package inventory unavailable (Appx module or AppX service); broker registration not checked' -Evidence 'Get-AppxPackage failed' -Rung 0 -User $u }
        if ($canSee -and @($broker).Count -eq 0) { Add-Finding -Id 'APPX-BROKER' -Severity High -Area 'Broker' -Title 'Microsoft.AAD.BrokerPlugin is not registered for this user; work or school sign-in fails silently' -Evidence 'Get-AppxPackage returned nothing' -Rung 3 -Fix 'Re-register the in-box package from its AppxManifest in the user session' -Source 'Authentication automatically fails in Microsoft 365 services' -User $u }
        if ($canSee -and @($ceh).Count -eq 0) { Add-Finding -Id 'APPX-CEH' -Severity Medium -Area 'Broker' -Title 'Microsoft.Windows.CloudExperienceHost is not registered; personal account sign-in fails' -Evidence 'Get-AppxPackage returned nothing' -Rung 3 -Fix 'Re-register the in-box package from its AppxManifest in the user session' -Source 'Authentication automatically fails in Microsoft 365 services' -User $u }
        if ($canSee -and $null -ne $acc -and @($acc).Count -eq 0) { Add-Finding -Id 'APPX-ACCOUNTS' -Severity Low -Area 'Broker' -Title 'Microsoft.AccountsControl (account picker) is not registered' -Evidence 'Get-AppxPackage returned nothing' -Rung 0 -Fix 'Report only: re-register manually from %windir%\SystemApps\Microsoft.AccountsControl_cw5n1h2txyewy\AppxManifest.xml if the account picker fails to open' -Source 'MSAL WAM troubleshooting' -User $u }
        # Event 1098 (0xCAA5001C): Microsoft's documented cause is missing permissions or ownership on the broker's PSR key in the
        # user's hive; the fix is to restore inheritance (and SYSTEM ownership if needed) on that key.
        $psr = Join-Path $hive 'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\PSR'
        $uf['Broker.PSR'] = (Test-RegKey $psr)
        if ($uf['Broker.PSR']) {
            $acl = $null; try { $acl = Get-Acl -LiteralPath $psr -ErrorAction Stop } catch { Write-Log ("PSR ACL unreadable: {0}" -f (Get-ErrorText $_)) 'DEBUG' }
            if ($acl) {
                $inheritanceOff = $acl.AreAccessRulesProtected
                $ownerOk = ($acl.Owner -match 'SYSTEM|Administrators|' + [regex]::Escape($User.Name.Split('\\')[-1]))
                $systemFull = [bool]@($acl.Access | Where-Object { $_.IdentityReference.Value -match 'SYSTEM$' -and $_.RegistryRights.ToString() -match 'FullControl' -and $_.AccessControlType -eq 'Allow' }).Count
                $uf['Broker.PSR.Inherited'] = -not $inheritanceOff; $uf['Broker.PSR.Owner'] = $acl.Owner
                if ($inheritanceOff -or -not $systemFull -or -not $ownerOk) {
                    $sev = if ($script:Facts.Contains('Events.1098') -and $script:Facts['Events.1098']) { 'High' } else { 'Medium' }
                    Add-Finding -Id 'BROKER-PSR-ACL' -Severity $sev -Area 'Broker' -Title 'Token broker PSR registry key has broken permissions (documented cause of event 1098, 0xCAA5001C)' -Evidence ("inheritance {0}; owner {1}; SYSTEM full control {2}" -f $(if ($inheritanceOff) { 'disabled' } else { 'enabled' }), $acl.Owner, $(if ($systemFull) { 'yes' } else { 'no' })) -Rung 3 -Fix 'Re-enable permission inheritance on the PSR key and set the owner to SYSTEM (elevated, in the user session)' -Source 'Event 1098: Error 0xCAA5001C Token broker operation failed' -User $u
                }
            }
        } elseif ($script:Facts.Contains('Events.1098') -and $script:Facts['Events.1098']) {
            Add-Finding -Id 'BROKER-1098' -Severity Medium -Area 'Broker' -Title ("Token broker failures (event 1098) but the PSR key Microsoft names does not exist for this user" ) -Evidence $psr -Rung 0 -Fix 'Run Process Monitor while reproducing the sign-in and look for ACCESS DENIED on registry or file paths (Microsoft guidance); if a sign-in error code is shown, pass it with -ErrorCode' -Source 'Event 1098: Error 0xCAA5001C Token broker operation failed' -User $u
        }
        # Broker account blobs
        if (Test-Path -LiteralPath $paths.BrokerAccounts) { $n = @(Get-ChildItem -LiteralPath $paths.BrokerAccounts -Force -ErrorAction SilentlyContinue).Count; $uf.Caches['BrokerAccounts'] = $n; if ($n -gt 6) { Add-Finding -Id 'BROKER-ACCOUNTS' -Severity Low -Area 'Broker' -Title ("{0} cached account blob(s) in the token broker" -f $n) -Evidence $paths.BrokerAccounts -Rung 0 -Fix 'Cleared only when 0x801C0451 is reported (pass -ErrorCode 0x801C0451); reboot afterwards' -Source 'Windows Hello errors during PIN creation' -User $u } }
        foreach ($c in @('OneAuth', 'IdentityCache', 'TokenBrokerCache')) { $uf.Caches[$c] = Get-FolderSizeMB -Path $paths[$c] }
        # WebView2 per-user install
        $pvUser = Get-RegValue (Join-Path $hive 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}') 'pv'
        $uf['WebView2.User'] = if ($pvUser -and $pvUser -ne '0.0.0.0') { $pvUser } else { '' }
        if ($script:Facts['WebView2.MachineMissing'] -and -not $uf['WebView2.User']) { Add-Finding -Id 'WEBVIEW2' -Severity High -Area 'Platform' -Title 'Microsoft Edge WebView2 Runtime is not installed; sign-in windows render blank' -Evidence 'no pv value in HKLM (WOW6432Node) or the user hive' -Rung 4 -Fix 'Install the Evergreen runtime (MicrosoftEdgeWebview2Setup.exe /silent /install)' -Source 'Distribute the WebView2 Runtime' -User $u }
        # Registry policies affecting identity (both hives; Policies hive means admin-managed)
        foreach ($pol in @(@{ N = 'SignInOptions'; K = 'Software\Policies\Microsoft\Office\16.0\Common\SignIn'; K2 = 'Software\Microsoft\Office\16.0\Common\SignIn' }, @{ N = 'EnableADAL'; K = 'Software\Policies\Microsoft\Office\16.0\Common\Identity'; K2 = 'Software\Microsoft\Office\16.0\Common\Identity' }, @{ N = 'DisableAADWAM'; K = 'Software\Policies\Microsoft\Office\16.0\Common\Identity'; K2 = 'Software\Microsoft\Office\16.0\Common\Identity' }, @{ N = 'DisableADALatopWAMOverride'; K = 'Software\Policies\Microsoft\Office\16.0\Common\Identity'; K2 = 'Software\Microsoft\Office\16.0\Common\Identity' }, @{ N = 'BlockAADWorkplaceJoin'; K = 'Software\Policies\Microsoft\Office\16.0\Common\Identity'; K2 = 'Software\Microsoft\Office\16.0\Common\Identity' })) {
            $vp = Get-RegValue (Join-Path $hive $pol.K) $pol.N; $vu = Get-RegValue (Join-Path $hive $pol.K2) $pol.N
            $v = if ($null -ne $vp) { $vp } else { $vu }; $managed = ($null -ne $vp)
            if ($null -eq $v) { continue }
            $uf["Pol.$($pol.N)"] = "{0}{1}" -f $v, $(if ($managed) { ' (policy)' } else { '' })
            switch ($pol.N) {
                'SignInOptions' { if ($v -eq 3) { Add-Finding -Id 'POL-SIGNIN-NONE' -Severity High -Area 'Office' -Title 'Office sign-in is blocked for all account types (SignInOptions=3)' -Evidence $uf["Pol.$($pol.N)"] -Rung 0 -Fix 'Policy: users cannot sign in with either ID. Change through Group Policy or remove the value if it is a stray user setting' -Source 'Block signing into Office (ADMX)' -User $u } elseif ($v -eq 1) { Add-Finding -Id 'POL-SIGNIN-MSA' -Severity High -Area 'Office' -Title 'Office allows Microsoft accounts only (SignInOptions=1); work accounts cannot sign in' -Evidence $uf["Pol.$($pol.N)"] -Rung 0 -Fix 'Set to 0 (both) or 2 (organisation only) through policy' -Source 'Block signing into Office (ADMX)' -User $u } }
                'EnableADAL' { if ($v -eq 0) { Add-Finding -Id 'POL-ADAL-OFF' -Severity High -Area 'Office' -Title 'Modern authentication is disabled for Office (EnableADAL=0)' -Evidence $uf["Pol.$($pol.N)"] -Rung 0 -Fix 'Remove the value or set 1; basic auth is no longer accepted by Exchange Online' -Source 'Modern Authentication configuration requirements' -User $u } }
                'DisableAADWAM' { if ($v -eq 1) { Add-Finding -Id 'POL-WAM-OFF' -Severity Medium -Area 'Office' -Title 'Office is bypassing the Windows account broker (DisableAADWAM=1)' -Evidence $uf["Pol.$($pol.N)"] -Rung 0 -Fix 'Known RDS mitigation; disables broker SSO and device-based Conditional Access. Review whether still needed' -Source 'Microsoft Q&A (moderate confidence)' -User $u } }
                'DisableADALatopWAMOverride' { if ($v -eq 1) { Add-Finding -Id 'POL-WAMOVERRIDE' -Severity Medium -Area 'Office' -Title 'ADAL-on-WAM override is disabled (DisableADALatopWAMOverride=1)' -Evidence $uf["Pol.$($pol.N)"] -Rung 0 -Fix 'Legacy prompt workaround; review whether still needed' -Source 'Microsoft Q&A (moderate confidence)' -User $u } }
                'BlockAADWorkplaceJoin' { if ($v -eq 1) { Add-Finding -Id 'POL-OFFICE-WPJ' -Severity Low -Area 'Office' -Title 'Office is prevented from registering the device (BlockAADWorkplaceJoin=1)' -Evidence $uf["Pol.$($pol.N)"] -Rung 0 -Fix 'Deliberate in many organisations; explains "Allow my organization to manage my device" never completing' -Source 'Office identity policy' -User $u } }
            }
        }
        $aadStorage = Join-Path $hive 'Software\Microsoft\Windows\CurrentVersion\AAD\Storage'
        $uf['AAD.Storage'] = (Test-RegKey $aadStorage)
    }

    # Credential Manager (only for the current user; another user's vault is not readable)
    $uf['CredMan.M365'] = @()
    if ($User.IsCurrent) {
        Set-SpinnerText ("{0}: Credential Manager" -f $u)
        $ck = Invoke-Native -File "$env:SystemRoot\System32\cmdkey.exe" -Arguments @('/list') -TimeoutSec 15
        $targets = @([regex]::Matches($ck.Output, '(?im)^\s*Target:\s*(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() })
        $m365 = @($targets | Where-Object { $_ -match '^(LegacyGeneric:target=|Domain:target=|WindowsLive:target=)?(MicrosoftOffice1\d_|MicrosoftOfficeDeviceCode|OneDrive Cached Credential|msteams_adalsso|MSTeams\b)' })
        $uf['CredMan.All'] = $targets.Count; $uf['CredMan.M365'] = $m365
        if ($m365.Count -gt 0) { Add-Finding -Id 'CREDMAN' -Severity Info -Area 'Broker' -Title ("{0} Office, OneDrive or Teams credential(s) in Credential Manager" -f $m365.Count) -Evidence (($m365 | Select-Object -First 4) -join '; ') -Rung 0 -Fix 'Normal. Removed only as part of an approved identity reset; recreated at the next sign-in' -Source 'Reset activation state for Microsoft 365 Apps' -User $u }
    }
    # Office and Outlook
    if (($Apps -contains 'Office') -or ($Apps -contains 'Outlook')) {
        Set-SpinnerText ("{0}: Office identity, licensing and Outlook settings" -f $u)
        $ids = Join-Path $hive 'Software\Microsoft\Office\16.0\Common\Identity\Identities'
        $profilesKey = Join-Path $hive 'Software\Microsoft\Office\16.0\Common\Identity\Profiles'
        $uf['Office.Identities'] = @(Get-RegSubKeyNames $ids).Count
        $uf['Office.Profiles'] = @(Get-RegSubKeyNames $profilesKey).Count
        $uf.Caches['OfficeLicenses'] = Get-FolderSizeMB -Path $paths.OfficeLicenses
        $uf.Caches['OfficeLicensing16'] = Get-FolderSizeMB -Path $paths.OfficeLicensing16
        $ln = Get-RegValue (Join-Path $hive 'Software\Microsoft\Office\16.0\Common\Licensing') 'LicensingNext'
        $uf['Office.LicensingNext'] = $ln
        if ($script:Facts['Office.Installed'] -and $uf['Office.Identities'] -eq 0 -and $User.IsCurrent) { Add-Finding -Id 'OFFICE-NOIDENTITY' -Severity Info -Area 'Office' -Title 'No cached Office identity for this user' -Evidence 'Common\Identity\Identities is empty' -Rung 0 -Fix 'Normal on a fresh profile; the user has never signed in to Office here' -Source 'Reset activation state for Microsoft 365 Apps' -User $u }
        # vnextdiag (subscription licensing) when Office is installed and this is the current user
        if ($script:Facts['Office.Installed'] -and $User.IsCurrent) {
            $vn = $null
            foreach ($root in @($script:ProgramFiles64, $script:ProgramFiles32)) { if ($root) { $cand = Join-Path $root 'Microsoft Office\Office16\vnextdiag.ps1'; if (Test-Path -LiteralPath $cand) { $vn = $cand; break } } }
            if ($vn) {
                try {
                    $vr = Invoke-Native -File "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $vn), '-action', 'list') -TimeoutSec 90
                    $out = [string]$vr.Output
                    $uf['Office.vnextdiag'] = $out.Trim()
                    if ($out -match '(?im)^\s*State\s*:\s*(.+)$') { $states = @([regex]::Matches($out, '(?im)^\s*State\s*:\s*(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() }); $uf['Office.LicenseStates'] = $states; $bad = @($states | Where-Object { $_ -notmatch '^Licensed' }); if ($bad.Count -gt 0) { Add-Finding -Id 'OFFICE-LICENSE' -Severity High -Area 'Office' -Title 'Office licence is not in the Licensed state' -Evidence ($bad -join ', ') -Rung 4 -Fix 'Remove the licence files (recreated on next launch) or run the Reset Office Activation scenario, then sign in' -Source 'vnextdiag.ps1 licensing tool' -User $u } }
                } catch { $uf['Office.vnextdiag'] = 'failed: ' + (Get-ErrorText $_) }
            }
        }
        if ($Apps -contains 'Outlook') {
            $uf['Outlook.NewInstalled'] = (Test-Path -LiteralPath $paths.OutlookNew)
            $ad = Join-Path $hive 'Software\Microsoft\Office\16.0\Outlook\AutoDiscover'; $adp = Join-Path $hive 'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover'
            foreach ($ex in @('ExcludeExplicitO365Endpoint', 'ExcludeHttpsRootDomain', 'ExcludeHttpsAutoDiscoverDomain', 'ExcludeScpLookup', 'ExcludeLastKnownGoodURL', 'ExcludeSrvRecord', 'ExcludeHttpRedirect')) {
                $v = Get-RegValue $adp $ex; if ($null -eq $v) { $v = Get-RegValue $ad $ex }
                if ($v -eq 1) { $uf["Outlook.$ex"] = 1; if ($ex -eq 'ExcludeExplicitO365Endpoint') { Add-Finding -Id 'OUTLOOK-EXCLUDE-O365' -Severity High -Area 'Outlook' -Title 'Outlook is told to skip the Office 365 Autodiscover endpoint' -Evidence 'ExcludeExplicitO365Endpoint=1' -Rung 0 -Fix 'Correct for on-premises mailboxes; breaks discovery for Exchange Online mailboxes. Remove if the mailbox is in Microsoft 365' -Source 'Outlook 2016 implementation of Autodiscover' -User $u } }
            }
            $mso = Get-RegValue (Join-Path $hive 'Software\Microsoft\Exchange') 'AlwaysUseMSOAuthForAutoDiscover'
            $uf['Outlook.AlwaysUseMSOAuth'] = $mso
            $tm = Get-RegValue (Join-Path $hive 'Software\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect') 'LoadBehavior'
            if ($null -ne $tm) { $uf['Outlook.TeamsAddinLoadBehavior'] = $tm; if ($tm -ne 3) { Add-Finding -Id 'OUTLOOK-TEAMSADDIN' -Severity Low -Area 'Outlook' -Title 'Teams Meeting add-in is not set to load at startup' -Evidence ("LoadBehavior={0}" -f $tm) -Rung 0 -Fix 'Enable it under File > Options > Add-ins > COM Add-ins, or set LoadBehavior to 3' -Source 'Resolve Teams Meeting add-in issues in classic Outlook' -User $u } }
        }
    }

    # OneDrive
    if ($Apps -contains 'OneDrive') {
        Set-SpinnerText ("{0}: OneDrive account and state" -f $u)
        $odKey = Join-Path $hive 'Software\Microsoft\OneDrive'
        $exe = if (Test-Path -LiteralPath $paths.OneDriveExe) { $paths.OneDriveExe } else { $null }
        foreach ($root in @($script:ProgramFiles64, $script:ProgramFiles32)) { if (-not $exe -and $root) { $c = Join-Path $root 'Microsoft OneDrive\OneDrive.exe'; if (Test-Path -LiteralPath $c) { $exe = $c } } }
        $uf['OneDrive.Exe'] = $exe
        $uf['OneDrive.Version'] = Get-RegValue $odKey 'Version'
        $uf['OneDrive.EverSignedIn'] = Get-RegValue $odKey 'ClientEverSignedIn'
        $unrec = Get-RegValue $odKey 'OneAuthUnrecoverableTimestamp'
        $uf['OneDrive.OneAuthUnrecoverable'] = $unrec
        $uf['OneDrive.Business1'] = Get-RegValue (Join-Path $odKey 'Accounts\Business1') 'UserEmail'
        $uf['OneDrive.UserFolder'] = Get-RegValue (Join-Path $odKey 'Accounts\Business1') 'UserFolder'
        $uf['OneDrive.PreSignIn'] = (Test-Path -LiteralPath $paths.OneDrivePreSignIn)
        $uf['OneDrive.Running'] = ($uf.Processes -contains 'OneDrive.exe')
        if ($exe -and $unrec) { Add-Finding -Id 'OD-ONEAUTH' -Severity Medium -Area 'OneDrive' -Title 'OneDrive recorded an unrecoverable OneAuth sign-in failure' -Evidence ("OneAuthUnrecoverableTimestamp={0}" -f $unrec) -Rung 2 -Fix 'Delete the OneAuthUnrecoverableTimestamp value (documented) with OneDrive closed, then start OneDrive' -Source 'Silently configure user accounts' -User $u }
        if ($exe -and -not $uf['OneDrive.Business1'] -and $uf['OneDrive.EverSignedIn'] -eq 1) { Add-Finding -Id 'OD-NOACCOUNT' -Severity Medium -Area 'OneDrive' -Title 'OneDrive has no business account configured although it was signed in before' -Evidence 'Accounts\Business1 missing' -Rung 2 -Fix 'Reset OneDrive (files are kept) and sign in again' -Source 'Reset OneDrive' -User $u }
        if ($exe -and $uf['OneDrive.PreSignIn']) {
            # Presence alone is normal. It becomes a rung 2 item only for the documented codes (password change, expired credentials).
            $loopCode = [bool]@($script:DecodedCodes | Where-Object { $_.Key -in @('8004DE96', '8004DEF0') }).Count
            Add-Finding -Id 'OD-PRESIGNIN' -Severity $(if ($loopCode) { 'Medium' } else { 'Info' }) -Area 'OneDrive' -Title 'OneDrive pre-sign-in settings file present' -Evidence $paths.OneDrivePreSignIn -Rung $(if ($loopCode) { 2 } else { 0 }) -Fix 'Deleting PreSignInSettingsConfig.json is the documented fix for the sign-in loop and duplicate-file case (0x8004de96, 0x8004def0); recreated automatically' -Source 'What do the OneDrive error codes mean' -User $u
        }
        if (-not $exe -and (Test-Path -LiteralPath (Join-Path $paths.Local 'Microsoft\OneDrive'))) { Add-Finding -Id 'OD-NOEXE' -Severity Medium -Area 'OneDrive' -Title 'OneDrive folder exists but OneDrive.exe is missing' -Evidence (Join-Path $paths.Local 'Microsoft\OneDrive') -Rung 0 -Fix 'Reinstall with %SystemRoot%\SysWOW64\OneDriveSetup.exe' -Source 'Reinstall OneDrive' -User $u }
    }

    # Teams
    if ($Apps -contains 'Teams') {
        Set-SpinnerText ("{0}: Teams" -f $u)
        $newTeams = Get-AppxForUser -Name 'MSTeams' -User $User
        $uf['Teams.New'] = ($newTeams.Count -gt 0); $uf['Teams.NewVersion'] = if ($newTeams.Count -gt 0) { $newTeams[0].Version } else { '' }
        $uf['Teams.Classic'] = (Test-Path -LiteralPath $paths.TeamsClassic)
        $uf.Caches['TeamsNew'] = Get-FolderSizeMB -Path $paths.TeamsNew
        $uf.Caches['TeamsClassic'] = Get-FolderSizeMB -Path $paths.TeamsClassic
        $ct = Get-RegValue (Join-Path $hive 'Software\Policies\Microsoft\Office\16.0\Teams') 'CloudType'
        if ($null -ne $ct) { $uf['Teams.CloudType'] = $ct; if (($ct -in @(3, 4, 5, 7)) -and $script:Facts.Contains('Dsreg') -and $script:Facts['Dsreg'].ContainsKey('AzureAdPrtAuthority') -and $script:Facts['Dsreg']['AzureAdPrtAuthority'] -match 'login\.microsoftonline\.com') { Add-Finding -Id 'TEAMS-CLOUDTYPE' -Severity High -Area 'Teams' -Title 'Teams is pinned to a government or sovereign cloud but the device authenticates to the commercial cloud' -Evidence ("CloudType={0}" -f $ct) -Rung 0 -Fix 'Remove CloudType (policy) for commercial tenants' -Source 'Bulk deploy the Microsoft Teams client' -User $u } }
        $uf['Teams.MachineWideInstaller'] = [bool](Get-ChildItem -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | Where-Object { (Get-RegValue $_.PSPath 'DisplayName') -eq 'Teams Machine-Wide Installer' })
        if ($uf['Teams.Classic'] -and $uf['Teams.New']) { Add-Finding -Id 'TEAMS-BOTH' -Severity Low -Area 'Teams' -Title 'Classic Teams data and new Teams are both present' -Evidence $paths.TeamsClassic -Rung 0 -Fix 'Classic Teams reached end of support; the classic cache can be cleared, the Machine-Wide Installer removed through change control' -Source 'Bulk deploy the Microsoft Teams client' -User $u }
    }
    return $uf
}

# ---------------------------------------------------------------------------------------------
# PHASE 5  Repairs. Each function acts on one user or on the machine, only after its rung is approved,
# only for the current user's own caches (other users are handled by re-launching in their session), and
# verifies the result. WhatIf prints the change and records it as WhatIf.
# ---------------------------------------------------------------------------------------------
function Test-CanTouchUser {
    # Per-user caches, Appx registration and Credential Manager must be touched from inside that user's session.
    param([Parameter(Mandatory)]$User)
    return ($User.IsCurrent -and -not $script:IsSystem)
}

function Stop-UserApps {
    # Closes only the apps whose caches the approved rung will move, only for this user, only after ShouldProcess.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$User, [Parameter(Mandatory)][string[]]$Names)
    $procs = @(Get-ProcessesForUser -Names $Names -Sid $User.Sid)
    if ($procs.Count -eq 0) { return $true }
    $list = ($procs | Select-Object -ExpandProperty Name -Unique) -join ', '
    if (-not $PSCmdlet.ShouldProcess($list, 'Close applications that hold the sign-in caches')) { return $false }
    Start-Spinner ("Closing {0}" -f $list)
    foreach ($p in $procs) {
        try { $proc = Get-Process -Id $p.ProcessId -ErrorAction Stop; $null = $proc.CloseMainWindow() } catch { }
    }
    # Give the apps up to six seconds to close cleanly before forcing the ones that remain.
    $deadline = (Get-Date).AddSeconds(6)
    while ((Get-Date) -lt $deadline -and @(Get-ProcessesForUser -Names $Names -Sid $User.Sid).Count -gt 0) { Start-Sleep -Milliseconds 500 }
    $remaining = @(Get-ProcessesForUser -Names $Names -Sid $User.Sid)
    if ($remaining.Count -gt 0) { Set-SpinnerText ("Forcing {0} to close" -f (($remaining | Select-Object -ExpandProperty Name -Unique) -join ', ')); foreach ($p in $remaining) { try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch { } }; Start-Sleep -Seconds 2 }
    Stop-Spinner
    $left = @(Get-ProcessesForUser -Names $Names -Sid $User.Sid)
    if ($left.Count -gt 0) { Write-Log ("Still running: {0}" -f (($left | Select-Object -ExpandProperty Name -Unique) -join ', ')) 'WARN'; return $false }
    Add-Action -Id 'CLOSE-APPS' -Rung 2 -Title ("Closed {0}" -f $list) -Status Verified -User $User.Name -Detail 'no matching process left; reopen them after the repair' | Out-Null
    return $true
}

# ----- Rung 1: nudges ---------------------------------------------------------------------------
function Invoke-Nudges {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$User)
    $ids = @($script:Findings | Where-Object { $_.Rung -eq 1 } | Select-Object -ExpandProperty Id -Unique)
    if ($ids.Count -eq 0) { return }
    if (-not (Confirm-Choice -Prompt 'Apply rung 1 (nudges: PRT refresh, DNS cache, services, clock)?' -Rung 'Nudge')) { foreach ($i in $ids) { Add-Action -Id $i -Rung 1 -Title "Nudge for $i" -Status Skipped -Detail 'not approved' | Out-Null }; return }

    if ($ids -contains 'PRT-MISSING' -or $ids -contains 'PRT-STALE') {
        if (Test-CanTouchUser -User $User) {
            if ($PSCmdlet.ShouldProcess('dsregcmd /refreshprt', 'Refresh the Primary Refresh Token')) {
                Start-Spinner 'Refreshing the Primary Refresh Token (dsregcmd /refreshprt)'
                $r = Invoke-Native -File "$env:SystemRoot\System32\dsregcmd.exe" -Arguments @('/refreshprt') -TimeoutSec 60
                Start-Sleep -Seconds 3
                Set-SpinnerText 'Reading dsregcmd /status to confirm the new token'
                $after = @{}
                try { $after = ConvertFrom-DsregOutput -Text (Invoke-Native -File "$env:SystemRoot\System32\dsregcmd.exe" -Arguments @('/status') -TimeoutSec 60).Output } catch { }
                Stop-Spinner
                $prt = if ($after.ContainsKey('AzureAdPrt')) { $after['AzureAdPrt'] } else { '' }
                $fresh = $false
                if ($after.ContainsKey('AzureAdPrtUpdateTime')) { try { $fresh = (((Get-Date).ToUniversalTime() - (ConvertFrom-DsregTime -Text $after['AzureAdPrtUpdateTime'])).TotalMinutes -lt 10) } catch { } }
                if ($prt -eq 'YES' -and $fresh) { Add-Action -Id 'PRT-REFRESH' -Rung 1 -Title 'Primary Refresh Token refreshed' -Status Verified -User $User.Name -Detail ("AzureAdPrtUpdateTime {0}" -f $after['AzureAdPrtUpdateTime']) | Out-Null }
                else { Add-Action -Id 'PRT-REFRESH' -Rung 1 -Title 'PRT refresh requested' -Status NotVerified -User $User.Name -Detail ("AzureAdPrt {0}; lock and unlock the device, then check dsregcmd /status. Server error: {1}" -f $prt, $(if ($after.ContainsKey('Server Error Description')) { $after['Server Error Description'] } else { 'none reported' })) | Out-Null }
            } else { Add-Action -Id 'PRT-REFRESH' -Rung 1 -Title 'Refresh the Primary Refresh Token' -Status WhatIf -User $User.Name | Out-Null }
        } else { Add-Action -Id 'PRT-REFRESH' -Rung 1 -Title 'PRT refresh' -Status Skipped -User $User.Name -Detail 'must run in the user session' | Out-Null }
    }
    $dnsIds = @($ids | Where-Object { $_ -like 'DNS-*' })
    if ($dnsIds.Count -gt 0) {
        if ($PSCmdlet.ShouldProcess('DNS client cache', 'Flush')) {
            try {
                Clear-DnsClientCache -ErrorAction Stop
                $stillBad = 0
                foreach ($id in $dnsIds) { $h = $id.Substring(4).ToLowerInvariant(); try { $ips = @(Resolve-DnsName -Name $h -Type A -ErrorAction Stop | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress }); if ($ips.Count -eq 0 -or @($ips | Where-Object { $_ -match '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)' }).Count -gt 0) { $stillBad++ } } catch { $stillBad++ } }
                Add-Action -Id 'DNS-FLUSH' -Rung 1 -Title 'DNS client cache flushed' -Status $(if ($stillBad -eq 0) { 'Verified' } else { 'NotVerified' }) -Detail $(if ($stillBad -eq 0) { 'names now resolve to public addresses' } else { 'the DNS server still returns a bad answer; hosts file, DNS servers and NRPT are never changed by the tool' }) | Out-Null
            } catch { Add-Action -Id 'DNS-FLUSH' -Rung 1 -Title 'DNS cache flush' -Status Failed -Detail (Get-ErrorText $_) | Out-Null }
        } else { Add-Action -Id 'DNS-FLUSH' -Rung 1 -Title 'Flush DNS client cache' -Status WhatIf | Out-Null }
    }
    foreach ($svcFix in @(@{ Id = 'SVC-TOKENBROKER'; Svc = 'TokenBroker'; Start = 'Manual'; Run = $false }, @{ Id = 'SVC-WLIDSVC'; Svc = 'wlidsvc'; Start = 'Manual'; Run = $false }, @{ Id = 'SVC-C2R'; Svc = 'ClickToRunSvc'; Start = ''; Run = $true }, @{ Id = 'SVC-C2R-DISABLED'; Svc = 'ClickToRunSvc'; Start = 'Automatic'; Run = $true }, @{ Id = 'SVC-NLA'; Svc = 'NlaSvc'; Start = ''; Run = $true })) {
        if ($ids -notcontains $svcFix.Id) { continue }
        if (-not $script:IsElevated) { Add-Action -Id $svcFix.Id -Rung 1 -Title ("Service {0}" -f $svcFix.Svc) -Status Skipped -Detail 'needs elevation' | Out-Null; continue }
        # Changing a start type is machine configuration: Full mode only. Starting a service that should run is fine in Repair.
        $setStart = if ($svcFix.Start -and $Mode -eq 'Full') { $svcFix.Start } else { '' }
        if ($svcFix.Start -and -not $setStart) { Add-Action -Id $svcFix.Id -Rung 1 -Title ("Service {0} start type" -f $svcFix.Svc) -Status Skipped -Detail ("start type change to {0} needs -Mode Full" -f $svcFix.Start) | Out-Null; if (-not $svcFix.Run) { continue } }
        if (-not $PSCmdlet.ShouldProcess($svcFix.Svc, ("Set start type {0}, start service" -f $(if ($setStart) { $setStart } else { 'unchanged' })))) { Add-Action -Id $svcFix.Id -Rung 1 -Title ("Service {0}" -f $svcFix.Svc) -Status WhatIf | Out-Null; continue }
        try {
            Start-Spinner ("Service {0}: {1}" -f $svcFix.Svc, $(if ($svcFix.Run) { 'starting' } else { 'setting start type' }))
            $before = (Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $svcFix.Svc)).StartMode
            $beforePs = switch ($before) { 'Auto' { 'Automatic' } default { $before } }
            if ($setStart) { Set-Service -Name $svcFix.Svc -StartupType $setStart -ErrorAction Stop }
            if ($svcFix.Run) { Start-Service -Name $svcFix.Svc -ErrorAction Stop }
            Stop-Spinner
            $svc = Get-Service -Name $svcFix.Svc
            $modeNow = (Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $svcFix.Svc)).StartMode
            $wantMode = switch ($setStart) { 'Automatic' { 'Auto' } default { $setStart } }
            $okNow = ((-not $svcFix.Run) -or ($svc.Status -eq 'Running')) -and ((-not $setStart) -or ($modeNow -eq $wantMode))
            Add-Action -Id $svcFix.Id -Rung 1 -Title ("Service {0}: {1}, start type {2}" -f $svcFix.Svc, $svc.Status, $modeNow) -Status $(if ($okNow) { 'Verified' } else { 'NotVerified' }) -Detail ("start type was {0}" -f $before) -Restore $(if ($setStart) { "Set-Service {0} -StartupType {1}" -f $svcFix.Svc, $beforePs } else { '' }) | Out-Null
        } catch { Stop-Spinner; Add-Action -Id $svcFix.Id -Rung 1 -Title ("Service {0}" -f $svcFix.Svc) -Status Failed -Detail (Get-ErrorText $_) | Out-Null }
    }
    if ($ids -contains 'TIME-SKEW' -or $ids -contains 'TIME-DRIFT' -or $ids -contains 'TIME-NOSYNC') {
        if (-not $script:IsElevated) { Add-Action -Id 'TIME-RESYNC' -Rung 1 -Title 'Clock resync' -Status Skipped -Detail 'needs elevation' | Out-Null }
        elseif ($PSCmdlet.ShouldProcess('w32time', 'Start service and resync (domain members keep the domain hierarchy)')) {
            try {
                Start-Spinner 'Resynchronising the clock (w32tm /resync /rediscover)'
                $svc = Get-Service -Name w32time -ErrorAction Stop
                $w32Mode = (Get-CimInstance -ClassName Win32_Service -Filter "Name='w32time'").StartMode
                if ($w32Mode -eq 'Disabled') { if ($Mode -eq 'Full') { Set-Service -Name w32time -StartupType Manual -ErrorAction Stop } else { throw 'Windows Time service is disabled; enabling it needs -Mode Full' } }
                if ($svc.Status -ne 'Running') { Start-Service -Name w32time -ErrorAction Stop }
                $r = Invoke-Native -File "$env:SystemRoot\System32\w32tm.exe" -Arguments @('/resync', '/rediscover') -TimeoutSec 60
                # Verified by measurement, not by text: the offset against the reference must now be small (non-domain), or the sync time must have moved.
                $good = $false
                if ($script:Facts.Contains('DomainMember') -and -not $script:Facts['DomainMember']) {
                    $sc = Invoke-Native -File "$env:SystemRoot\System32\w32tm.exe" -Arguments @('/stripchart', '/computer:time.windows.com', '/samples:2', '/dataonly') -TimeoutSec 25
                    $m = [regex]::Matches($sc.Output, '([+-]\d+\.\d+)s')
                    if ($m.Count -gt 0) { $good = ([math]::Abs([double]$m[$m.Count - 1].Groups[1].Value) -lt 60) }
                } else {
                    $st = Invoke-Native -File "$env:SystemRoot\System32\w32tm.exe" -Arguments @('/query', '/status') -TimeoutSec 20
                    $lastNow = [regex]::Match($st.Output, '(?im)^Last Successful Sync Time:\s*(.+)$').Groups[1].Value.Trim()
                    $prev = if ($script:Facts.Contains('Time.LastSync')) { $script:Facts['Time.LastSync'] } else { '' }
                    $good = ([bool]$lastNow -and $lastNow -ne $prev -and $lastNow -notmatch 'unspecified')
                }
                Stop-Spinner
                Add-Action -Id 'TIME-RESYNC' -Rung 1 -Title 'Clock resynchronised' -Status $(if ($good) { 'Verified' } else { 'NotVerified' }) -Detail (($r.Output -split "`r?`n")[0]) | Out-Null
            } catch { Stop-Spinner; Add-Action -Id 'TIME-RESYNC' -Rung 1 -Title 'Clock resync' -Status Failed -Detail (Get-ErrorText $_) | Out-Null }
        } else { Add-Action -Id 'TIME-RESYNC' -Rung 1 -Title 'Resync the clock' -Status WhatIf | Out-Null }
    }
}

# ----- Rung 2: cache resets ----------------------------------------------------------------------
function Invoke-CacheReset {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$User, [Parameter(Mandatory)]$UserFacts)
    $u = $User.Name; $paths = $UserFacts.Paths
    # Only High or Medium findings and individually documented codes may open rung 2. Info rows describe normal state.
    $rung2 = @($script:Findings | Where-Object { $_.Rung -eq 2 -and $_.Severity -in @('High', 'Medium') -and ($_.User -eq $u -or -not $_.User) })
    # Documented client-side codes at rung 2 or 3: Microsoft's ladder for the broker codes (CAA50021 and relatives) is
    # re-register plus removal of stale Office credentials, so those codes open the identity reset as well.
    $codes = @($script:DecodedCodes | Where-Object { $_.Owner -eq 'Client' -and $_.Rung -in @(2, 3) -and -not $_.Family })
    if ($rung2.Count -eq 0 -and $codes.Count -eq 0) { return }
    if (-not (Test-CanTouchUser -User $User)) { Add-Action -Id 'CACHE-RESET' -Rung 2 -Title 'Cache reset' -Status Skipped -User $u -Detail 'must run in the user session' | Out-Null; return }

    # Decide the scope from the findings and the apps in scope. Office identity and broker caches go together
    # (Microsoft's reset procedure clears all four locations). OneDrive and Teams are separate decisions.
    $identityFindings = [bool]@($rung2 | Where-Object { $_.Area -in @('Broker', 'Office', 'Outlook') }).Count
    $identityCodes = [bool]@($codes | Where-Object { $_.Owner -eq 'Client' -and $_.Key -notlike '8004*' -and $_.Key -notlike '80040C*' -and $_.Key -notin @('80070194', 'CAA70004', 'CAA70007') }).Count
    $doIdentity = (($Apps -contains 'Office') -or ($Apps -contains 'Outlook') -or ($Apps -contains 'Broker')) -and ($identityFindings -or $identityCodes)
    $doBrokerAccounts = ([bool]@($codes | Where-Object { $_.Key -eq '801C0451' }).Count) -or ([bool]@($rung2 | Where-Object { $_.Id -eq 'BROKER-ACCOUNTS' }).Count)
    $oneDriveFindings = [bool]@($rung2 | Where-Object { $_.Area -eq 'OneDrive' }).Count
    $oneDriveCodes = [bool]@($codes | Where-Object { $_.Key -like '8004*' -or $_.Key -like '80040C*' -or $_.Key -eq '80070194' }).Count
    $doOneDrive = ($Apps -contains 'OneDrive') -and ($oneDriveFindings -or $oneDriveCodes)
    # Teams cache clear is Microsoft's step for the login-loop codes; the broker code CAA50021 is handled by the identity reset above.
    $teamsCodes = [bool]@($codes | Where-Object { $_.Key -in @('CAA70004', 'CAA70007') }).Count
    $teamsFindings = [bool]@($rung2 | Where-Object { $_.Area -eq 'Teams' }).Count
    $doTeams = ($Apps -contains 'Teams') -and ($teamsCodes -or $teamsFindings)
    # Full mode never wipes a healthy identity: it needs a finding or a reported code like every other mode.
    if (-not ($doIdentity -or $doBrokerAccounts -or $doOneDrive -or $doTeams)) { return }

    $toClose = @()
    if ($doIdentity -or $doBrokerAccounts) { $toClose += @('OUTLOOK.exe', 'WINWORD.exe', 'EXCEL.exe', 'POWERPNT.exe', 'ONENOTE.exe', 'MSACCESS.exe', 'olk.exe', 'lync.exe', 'ms-teams.exe', 'Teams.exe', 'OneDrive.exe') }
    if ($doOneDrive) { $toClose += 'OneDrive.exe' }
    if ($doTeams) { $toClose += @('ms-teams.exe', 'Teams.exe') }
    $toClose = @($toClose | Select-Object -Unique)
    $openNow = @(Get-ProcessesForUser -Names $toClose -Sid $User.Sid | Select-Object -ExpandProperty Name -Unique)
    $plan = @()
    if ($doIdentity) { $plan += 'Office identity: OneAuth, IdentityCache, Office Licenses (files kept in quarantine), identity registry keys (exported first), Office and Teams credentials in Credential Manager (listed first)' }
    if ($doBrokerAccounts) { $plan += 'Token broker account blobs (0x801C0451); a reboot is needed afterwards' }
    if ($doOneDrive) { $plan += 'OneDrive: PreSignInSettingsConfig.json, OneAuthUnrecoverableTimestamp, then OneDrive.exe /reset and relaunch (files are kept)' }
    if ($doTeams) { $plan += 'Teams cache (new Teams LocalCache\Microsoft\MSTeams and classic %APPDATA%\Microsoft\Teams); settings rebuild on next start' }
    if ($openNow.Count -gt 0) { $plan += ("Will close: {0} (save open work first; unsaved changes are lost)" -f ($openNow -join ', ')) }
    Write-Box -Title ("Rung 2 plan for {0}" -f $u) -Lines $plan -Color 'Orange'
    if (-not (Confirm-Choice -Prompt 'Apply rung 2 (reset sign-in caches, quarantined and reversible)?' -Rung 'Reset')) { Add-Action -Id 'CACHE-RESET' -Rung 2 -Title 'Cache reset' -Status Skipped -User $u -Detail 'not approved' | Out-Null; return }

    if (-not $WhatIfPreference) { if (-not (Stop-UserApps -User $User -Names $toClose)) { Add-Action -Id 'CACHE-RESET' -Rung 2 -Title 'Cache reset' -Status Skipped -User $u -Detail 'apps could not be closed; nothing moved' | Out-Null; return } }

    if ($doIdentity) {
        foreach ($k in @('Identities', 'Profiles')) {
            $key = "HKCU:\Software\Microsoft\Office\16.0\Common\Identity\$k"
            if (-not (Test-RegKey $key)) { continue }
            if ($PSCmdlet.ShouldProcess($key, 'Export to quarantine, then remove cached identities')) {
                $exp = Export-RegKeyToQuarantine -RegPath $key -Name ("Office-Identity-{0}" -f $k)
                if (-not $exp) { Add-Action -Id "REG-$k" -Rung 2 -Title ("Office identity key {0}" -f $k) -Status Failed -User $u -Detail 'export failed; key left in place' | Out-Null; continue }
                $script:RestoreLines.Add(("{0}  <-  reg import restores {1}" -f $exp, $key))
                try { Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop; Add-Action -Id "REG-$k" -Rung 2 -Title ("Cached Office identities removed ({0})" -f $k) -Status $(if (Test-RegKey $key) { 'NotVerified' } else { 'Verified' }) -User $u -Restore ("reg import `"{0}`"" -f $exp) | Out-Null }
                catch { Add-Action -Id "REG-$k" -Rung 2 -Title ("Office identity key {0}" -f $k) -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
            } else { Add-Action -Id "REG-$k" -Rung 2 -Title ("Remove cached Office identities ({0})" -f $k) -Status WhatIf -User $u | Out-Null }
        }
        # TokenBroker\Cache is read for size only: Microsoft's guidance is to sign out of WAM accounts with its script, not to hand-delete broker folders.
        foreach ($c in @('OneAuth', 'IdentityCache', 'OfficeLicenses', 'OfficeLicensing16')) {
            $p = $paths[$c]
            if (-not (Test-Path -LiteralPath $p)) { continue }
            try {
                if ($WhatIfPreference) { Add-Action -Id "CACHE-$c" -Rung 2 -Title ("Move {0} to quarantine" -f $p) -Status WhatIf -User $u | Out-Null; continue }
                Start-Spinner ("Moving {0} to quarantine" -f $c)
                $ok = Move-ToQuarantine -Path $p -Label $c -User $User.Sid -ContentsOnly
                Stop-Spinner
                Add-Action -Id "CACHE-$c" -Rung 2 -Title ("{0} cleared" -f $c) -Status $(if ($ok -and -not (Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue)) { 'Verified' } else { 'NotVerified' }) -User $u -Detail $p -Restore 'move the quarantined folder contents back' | Out-Null
            } catch { Stop-Spinner; Add-Action -Id "CACHE-$c" -Rung 2 -Title ("{0} clear" -f $c) -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
        }
        # Credential Manager: only Office, OneDrive and Teams namespaces. The list is saved first; entries return at next sign-in.
        $m365 = @($UserFacts['CredMan.M365'] | Where-Object { $_ })
        if ($m365.Count -gt 0) {
            if ($PSCmdlet.ShouldProcess(("{0} credential(s)" -f $m365.Count), 'Remove Office, OneDrive and Teams entries from Credential Manager')) {
                New-Quarantine
                $listFile = Join-Path -Path $script:Quarantine -ChildPath 'CredentialManager-removed.txt'
                Set-Content -Path $listFile -Value $m365 -Encoding UTF8
                $script:RestoreLines.Add(("{0}  <-  names of removed Credential Manager entries (recreated at next sign-in)" -f $listFile))
                $removed = 0
                Start-Spinner ("Removing {0} Credential Manager entr{1}" -f $m365.Count, $(if ($m365.Count -eq 1) { 'y' } else { 'ies' }))
                foreach ($t in $m365) { $r = Invoke-Native -File "$env:SystemRoot\System32\cmdkey.exe" -Arguments @(('/delete:"{0}"' -f $t)) -TimeoutSec 10; if ($r.Output -match 'successfully') { $removed++ } }
                $left = @([regex]::Matches((Invoke-Native -File "$env:SystemRoot\System32\cmdkey.exe" -Arguments @('/list') -TimeoutSec 15).Output, '(?im)^\s*Target:\s*(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() } | Where-Object { $m365 -contains $_ })
                Stop-Spinner
                Add-Action -Id 'CREDMAN' -Rung 2 -Title ("Credential Manager: {0} of {1} Microsoft 365 entries removed" -f $removed, $m365.Count) -Status $(if ($left.Count -eq 0) { 'Verified' } else { 'NotVerified' }) -User $u -Detail $(if ($left.Count) { "still present: " + ($left -join '; ') } else { 'recreated at next sign-in' }) | Out-Null
            } else { Add-Action -Id 'CREDMAN' -Rung 2 -Title ("Remove {0} Credential Manager entries" -f $m365.Count) -Status WhatIf -User $u | Out-Null }
        }
    }
    if ($doBrokerAccounts -and (Test-Path -LiteralPath $paths.BrokerAccounts)) {
        try {
            if ($WhatIfPreference) { Add-Action -Id 'BROKER-ACCOUNTS' -Rung 2 -Title 'Move token broker account blobs to quarantine' -Status WhatIf -User $u | Out-Null }
            else { Start-Spinner 'Moving the token broker account cache to quarantine'; $ok = Move-ToQuarantine -Path $paths.BrokerAccounts -Label 'BrokerAccounts' -User $User.Sid -ContentsOnly; Stop-Spinner; Add-Action -Id 'BROKER-ACCOUNTS' -Rung 2 -Title 'Token broker account cache cleared' -Status $(if ($ok) { 'Verified' } else { 'NotVerified' }) -User $u -Detail 'restart the computer to complete (documented)' | Out-Null; $script:Facts['RebootRecommended'] = $true }
        } catch { Stop-Spinner; Add-Action -Id 'BROKER-ACCOUNTS' -Rung 2 -Title 'Token broker account cache' -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
    }
    if ($doOneDrive) {
        $exe = $UserFacts['OneDrive.Exe']
        if ($UserFacts['OneDrive.PreSignIn']) {
            try { if ($WhatIfPreference) { Add-Action -Id 'OD-PRESIGNIN' -Rung 2 -Title 'Move PreSignInSettingsConfig.json to quarantine' -Status WhatIf -User $u | Out-Null } else { $ok = Move-ToQuarantine -Path $paths.OneDrivePreSignIn -Label 'OneDrive-PreSignIn' -User $User.Sid; Add-Action -Id 'OD-PRESIGNIN' -Rung 2 -Title 'OneDrive PreSignInSettingsConfig.json removed' -Status $(if ($ok -and -not (Test-Path -LiteralPath $paths.OneDrivePreSignIn)) { 'Verified' } else { 'NotVerified' }) -User $u | Out-Null } } catch { Add-Action -Id 'OD-PRESIGNIN' -Rung 2 -Title 'OneDrive PreSignIn file' -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
        }
        if ($UserFacts['OneDrive.OneAuthUnrecoverable']) {
            $k = 'HKCU:\Software\Microsoft\OneDrive'
            if ($PSCmdlet.ShouldProcess("$k\OneAuthUnrecoverableTimestamp", 'Delete value (documented reset of the OneAuth failure marker)')) {
                $exp = Export-RegKeyToQuarantine -RegPath $k -Name 'OneDrive-root'
                if (-not $exp) { Add-Action -Id 'OD-ONEAUTH' -Rung 2 -Title 'OneAuthUnrecoverableTimestamp' -Status Failed -User $u -Detail 'registry export failed; value left in place' | Out-Null }
                else { try { Remove-ItemProperty -LiteralPath $k -Name 'OneAuthUnrecoverableTimestamp' -ErrorAction Stop; Add-Action -Id 'OD-ONEAUTH' -Rung 2 -Title 'OneAuthUnrecoverableTimestamp cleared' -Status $(if ($null -eq (Get-RegValue $k 'OneAuthUnrecoverableTimestamp')) { 'Verified' } else { 'NotVerified' }) -User $u -Restore ("reg import `"{0}`"" -f $exp) | Out-Null } catch { Add-Action -Id 'OD-ONEAUTH' -Rung 2 -Title 'OneAuthUnrecoverableTimestamp' -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null } }
            } else { Add-Action -Id 'OD-ONEAUTH' -Rung 2 -Title 'Clear OneAuthUnrecoverableTimestamp' -Status WhatIf -User $u | Out-Null }
        }
        if ($exe) {
            if ($PSCmdlet.ShouldProcess($exe, 'OneDrive.exe /reset, wait for exit, relaunch')) {
                try {
                    Start-Spinner 'OneDrive /reset: waiting for OneDrive to finish and exit'
                    $p = Start-Process -FilePath $exe -ArgumentList '/reset' -PassThru -ErrorAction Stop
                    $null = $p.WaitForExit(90000)
                    $deadline = (Get-Date).AddSeconds(60)
                    while ((Get-Date) -lt $deadline -and @(Get-ProcessesForUser -Names @('OneDrive.exe') -Sid $User.Sid).Count -gt 0) { Start-Sleep -Seconds 2 }
                    Set-SpinnerText 'Relaunching OneDrive and waiting for it to come back'
                    # Relaunch at the user's normal integrity level even when the tool is elevated (explorer starts it non-elevated).
                    if ($script:IsElevated) { Start-Process -FilePath "$env:SystemRoot\explorer.exe" -ArgumentList ('"{0}"' -f $exe) -ErrorAction Stop | Out-Null } else { Start-Process -FilePath $exe -ArgumentList '/background' -ErrorAction Stop | Out-Null }
                    Start-Sleep -Seconds 8
                    $running = (@(Get-ProcessesForUser -Names @('OneDrive.exe') -Sid $User.Sid).Count -gt 0)
                    Stop-Spinner
                    Add-Action -Id 'OD-RESET' -Rung 2 -Title 'OneDrive reset and relaunched' -Status $(if ($running) { 'Verified' } else { 'NotVerified' }) -User $u -Detail 'files are kept; the user signs in again and re-selects folders to sync' | Out-Null
                } catch { Stop-Spinner; Add-Action -Id 'OD-RESET' -Rung 2 -Title 'OneDrive reset' -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
            } else { Add-Action -Id 'OD-RESET' -Rung 2 -Title 'OneDrive.exe /reset' -Status WhatIf -User $u | Out-Null }
        }
    }
    if ($doTeams) {
        foreach ($t in @(@{ N = 'TeamsNew'; P = $paths.TeamsNew }, @{ N = 'TeamsClassic'; P = $paths.TeamsClassic })) {
            if (-not (Test-Path -LiteralPath $t.P)) { continue }
            try {
                if ($WhatIfPreference) { Add-Action -Id "CACHE-$($t.N)" -Rung 2 -Title ("Move {0} to quarantine" -f $t.P) -Status WhatIf -User $u | Out-Null; continue }
                Start-Spinner ("Moving the {0} cache to quarantine" -f $t.N)
                $ok = Move-ToQuarantine -Path $t.P -Label $t.N -User $User.Sid -ContentsOnly
                Stop-Spinner
                Add-Action -Id "CACHE-$($t.N)" -Rung 2 -Title ("{0} cache cleared" -f $t.N) -Status $(if ($ok) { 'Verified' } else { 'NotVerified' }) -User $u -Detail $t.P | Out-Null
            } catch { Stop-Spinner; Add-Action -Id "CACHE-$($t.N)" -Rung 2 -Title ("{0} cache" -f $t.N) -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
        }
    }
    Write-RestoreInstructions
}

# ----- Rung 3: re-register in-box packages -------------------------------------------------------
function Invoke-Reregister {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$User, [Parameter(Mandatory)]$UserFacts)
    $u = $User.Name
    $need = @($script:Findings | Where-Object { $_.Rung -eq 3 -and $_.User -eq $u })
    # New Teams reset: only for the documented Teams login-loop codes (never for family codes), and only when new Teams is installed.
    $teamsReset = ($Apps -contains 'Teams') -and ($UserFacts['Teams.New'] -eq $true) -and ([bool]@($script:DecodedCodes | Where-Object { (-not $_.Family) -and ($_.Key -in @('CAA70004', 'CAA70007')) }).Count)
    if ($need.Count -eq 0 -and -not $teamsReset) { return }
    if (-not (Test-CanTouchUser -User $User)) { Add-Action -Id 'REREGISTER' -Rung 3 -Title 'Package re-registration' -Status Skipped -User $u -Detail 'must run in the user session' | Out-Null; return }

    if ($need.Count -gt 0) {
        if (-not $script:IsElevated) { Add-Action -Id 'REREGISTER' -Rung 3 -Title 'Package re-registration' -Status Skipped -User $u -Detail 'needs an elevated PowerShell in the user session' | Out-Null }
        elseif (-not (Confirm-Choice -Prompt 'Apply rung 3 (re-register the missing in-box account packages; open apps will be closed)?' -Rung 'Reregister')) { Add-Action -Id 'REREGISTER' -Rung 3 -Title 'Package re-registration' -Status Skipped -User $u -Detail 'not approved' | Out-Null }
        else {
            if ($need | Where-Object { $_.Id -eq 'BROKER-PSR-ACL' }) { Repair-BrokerPsrAcl -User $User }
            $map = @{ 'APPX-BROKER' = 'Microsoft.AAD.BrokerPlugin'; 'APPX-CEH' = 'Microsoft.Windows.CloudExperienceHost' }
            foreach ($f in $need) {
                if (-not $map.ContainsKey($f.Id)) { continue }
                $pkg = $map[$f.Id]
                $manifest = Join-Path -Path $env:SystemRoot -ChildPath ("SystemApps\{0}_cw5n1h2txyewy\AppxManifest.xml" -f $pkg)
                if (-not (Test-Path -LiteralPath $manifest)) { Add-Action -Id $f.Id -Rung 3 -Title ("Re-register {0}" -f $pkg) -Status Failed -User $u -Detail ("manifest not found: {0}" -f $manifest) | Out-Null; continue }
                if (-not $PSCmdlet.ShouldProcess($pkg, 'Add-AppxPackage -Register -DisableDevelopmentMode -ForceApplicationShutdown')) { Add-Action -Id $f.Id -Rung 3 -Title ("Re-register {0}" -f $pkg) -Status WhatIf -User $u | Out-Null; continue }
                try {
                    Start-Spinner ("Re-registering {0} from its in-box manifest" -f $pkg)
                    if ($script:IsPS7 -and -not (Get-Module -Name Appx)) { Import-Module -Name Appx -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue }
                    Add-AppxPackage -Register $manifest -DisableDevelopmentMode -ForceApplicationShutdown -ErrorAction Stop
                    $after = @(Get-AppxPackage -Name $pkg -ErrorAction SilentlyContinue)
                    Stop-Spinner
                    Add-Action -Id $f.Id -Rung 3 -Title ("{0} re-registered" -f $pkg) -Status $(if ($after.Count -gt 0) { 'Verified' } else { 'NotVerified' }) -User $u -Detail 'in-box package; nothing removed, no restart needed' | Out-Null
                } catch { Stop-Spinner; Add-Action -Id $f.Id -Rung 3 -Title ("Re-register {0}" -f $pkg) -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
            }
        }
    }

    if ($teamsReset) {
        if (-not (Get-Command -Name Reset-AppxPackage -ErrorAction SilentlyContinue)) { Add-Action -Id 'TEAMS-RESET' -Rung 3 -Title 'New Teams app reset' -Status Skipped -User $u -Detail 'Reset-AppxPackage is not available on this Windows build; use Settings > Apps > Microsoft Teams > Advanced options > Reset' | Out-Null }
        elseif (-not (Confirm-Choice -Prompt 'Reset the new Teams app (same as Settings > Apps > Reset: app data and personalisation are deleted, not quarantined)?' -Rung 'Reregister')) { Add-Action -Id 'TEAMS-RESET' -Rung 3 -Title 'New Teams app reset' -Status Skipped -User $u -Detail 'not approved' | Out-Null }
        elseif ($PSCmdlet.ShouldProcess('MSTeams', 'Reset-AppxPackage (app data deleted, not restorable)')) {
            try {
                Stop-UserApps -User $User -Names @('ms-teams.exe') | Out-Null
                Start-Spinner 'Resetting the new Teams app (Reset-AppxPackage)'
                if ($script:IsPS7 -and -not (Get-Module -Name Appx)) { Import-Module -Name Appx -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue }
                $pkg = Get-AppxPackage -Name MSTeams -ErrorAction Stop | Select-Object -First 1
                Reset-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
                Stop-Spinner
                $still = (@(Get-AppxPackage -Name MSTeams -ErrorAction SilentlyContinue).Count -gt 0)
                $cacheGone = (-not (Test-Path -LiteralPath $UserFacts.Paths.TeamsNew)) -or (@(Get-ChildItem -LiteralPath $UserFacts.Paths.TeamsNew -Force -ErrorAction SilentlyContinue).Count -eq 0)
                $script:RestoreLines.Add('New Teams app data was reset with Reset-AppxPackage (Settings > Apps > Reset equivalent). Not restorable; Teams rebuilds it at the next sign-in.'); Write-RestoreInstructions
                Add-Action -Id 'TEAMS-RESET' -Rung 3 -Title 'New Teams app reset' -Status $(if ($still -and $cacheGone) { 'Verified' } else { 'NotVerified' }) -User $u -Detail 'sign in again on next start' | Out-Null
            } catch { Stop-Spinner; Add-Action -Id 'TEAMS-RESET' -Rung 3 -Title 'New Teams app reset' -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
        } else { Add-Action -Id 'TEAMS-RESET' -Rung 3 -Title 'Reset the new Teams app' -Status WhatIf -User $u | Out-Null }
    }
}

function Repair-BrokerPsrAcl {
    # Microsoft's fix for event 1098 (0xCAA5001C): take ownership of the PSR key if necessary (owner SYSTEM) and re-enable
    # inheritance so the SystemAppData permissions flow down. The key is exported first; the ACL is recorded before and after.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$User)
    $u = $User.Name
    $psr = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\PSR'
    if (-not (Test-RegKey $psr)) { Add-Action -Id 'BROKER-PSR-ACL' -Rung 3 -Title 'Broker PSR key permissions' -Status Skipped -User $u -Detail 'key not found' | Out-Null; return }
    if (-not $PSCmdlet.ShouldProcess($psr, 'Set owner to SYSTEM and re-enable permission inheritance')) { Add-Action -Id 'BROKER-PSR-ACL' -Rung 3 -Title 'Repair broker PSR key permissions' -Status WhatIf -User $u | Out-Null; return }
    try {
        Start-Spinner 'Repairing permissions on the token broker PSR key'
        $exp = Export-RegKeyToQuarantine -RegPath $psr -Name 'Broker-PSR'
        $before = (Get-Acl -LiteralPath $psr).Sddl
        New-Quarantine
        Set-Content -Path (Join-Path $script:Quarantine 'Broker-PSR-acl-before.sddl') -Value $before -Encoding UTF8
        $script:RestoreLines.Add(('{0}  <-  previous ACL (SDDL) of {1}; restore with Set-Acl after Get-Acl | .SetSecurityDescriptorSddlForm' -f (Join-Path $script:Quarantine 'Broker-PSR-acl-before.sddl'), $psr)); Write-RestoreInstructions
        $native = 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\PSR'
        $acl = Get-Acl -LiteralPath $psr
        if ($acl.Owner -notmatch 'SYSTEM$') {
            try { $acl.SetOwner([System.Security.Principal.NTAccount]'NT AUTHORITY\SYSTEM'); Set-Acl -LiteralPath $psr -AclObject $acl -ErrorAction Stop } catch { Write-Log ('owner change through Set-Acl failed, trying the key ACL API: {0}' -f (Get-ErrorText $_)) 'DEBUG' }
        }
        $sub = 'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\PSR'
        $key = $null
        try { $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor [System.Security.AccessControl.RegistryRights]::ReadPermissions) }
        catch {
            # The broken ACL denies even the administrator. Take ownership first (always allowed with TakeOwnership), then reopen.
            Write-Log ('PSR key refused ChangePermissions; taking ownership first: {0}' -f (Get-ErrorText $_)) 'DEBUG'
            $own = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
            try { $osec = $own.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner); $osec.SetOwner([System.Security.Principal.WindowsIdentity]::GetCurrent().User); $own.SetAccessControl($osec) } finally { $own.Dispose() }
            $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        }
        try {
            $sec = $key.GetAccessControl()
            $sec.SetAccessRuleProtection($false, $true)
            $key.SetAccessControl($sec)
        } finally { $key.Dispose() }
        $after = Get-Acl -LiteralPath $psr
        $systemFull = [bool]@($after.Access | Where-Object { $_.IdentityReference.Value -match 'SYSTEM$' -and $_.RegistryRights.ToString() -match 'FullControl' -and $_.AccessControlType -eq 'Allow' }).Count
        $ok = (-not $after.AreAccessRulesProtected) -and $systemFull
        Stop-Spinner
        Add-Action -Id 'BROKER-PSR-ACL' -Rung 3 -Title 'Broker PSR key permissions repaired' -Status $(if ($ok) { 'Verified' } else { 'NotVerified' }) -User $u -Detail ("inheritance {0}; owner {1}; SYSTEM full control {2}. Sign out and in, then check the AAD Operational log for new 1098 events" -f $(if ($after.AreAccessRulesProtected) { 'still disabled' } else { 'enabled' }), $after.Owner, $(if ($systemFull) { 'yes' } else { 'no' })) -Restore $(if ($exp) { "reg import `"$exp`" (values) and the saved SDDL (permissions)" } else { 'saved SDDL' }) | Out-Null
    } catch { Stop-Spinner; Add-Action -Id 'BROKER-PSR-ACL' -Rung 3 -Title 'Broker PSR key permissions' -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
}

# ----- Rung 4: Microsoft tools (Full mode only) --------------------------------------------------
function Invoke-WebView2Install {
    # Machine-level (Full mode, elevated): install the Evergreen runtime when neither the machine nor the user has it.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if ($Mode -ne 'Full') { return }
    if (-not [bool]($script:Findings | Where-Object { $_.Id -eq 'WEBVIEW2' })) { return }
    if (-not $script:IsElevated) { Add-Action -Id 'WEBVIEW2' -Rung 4 -Title 'WebView2 Runtime install' -Status Skipped -Detail 'needs elevation' | Out-Null; return }
    if (-not (Confirm-Choice -Prompt 'Apply rung 4a (download and silently install the Microsoft Edge WebView2 Runtime)?' -Rung 'Tool')) { Add-Action -Id 'WEBVIEW2' -Rung 4 -Title 'WebView2 Runtime install' -Status Skipped -Detail 'not approved' | Out-Null; return }
    $dl = Join-Path -Path $script:RunDir -ChildPath 'downloads'; New-Item -Path $dl -ItemType Directory -Force | Out-Null
    $setup = Join-Path -Path $dl -ChildPath 'MicrosoftEdgeWebview2Setup.exe'
    if (-not $PSCmdlet.ShouldProcess('Microsoft Edge WebView2 Runtime', 'Download the Evergreen bootstrapper and install silently')) { Add-Action -Id 'WEBVIEW2' -Rung 4 -Title 'Install WebView2 Runtime' -Status WhatIf | Out-Null; return }
    try {
        # Bootstrapper link from the WebView2 download page ("Get the Link"); the signature check below is what makes running it safe.
        Start-Spinner 'Downloading the WebView2 Runtime bootstrapper from Microsoft'
        Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $setup -UseBasicParsing -ErrorAction Stop
        Set-SpinnerText 'Checking the Authenticode signature'
        $sig = Get-AuthenticodeSignature -FilePath $setup
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') { throw 'downloaded installer is not signed by Microsoft Corporation; not run' }
        Set-SpinnerText 'Installing the WebView2 Runtime silently'
        $p = Start-Process -FilePath $setup -ArgumentList '/silent /install' -Wait -PassThru -ErrorAction Stop
        Stop-Spinner
        $pv = Get-RegValue $(if ($script:Is64BitOS) { 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' } else { 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' }) 'pv'
        Add-Action -Id 'WEBVIEW2' -Rung 4 -Title 'WebView2 Runtime installed' -Status $(if ($pv -and $pv -ne '0.0.0.0') { 'Verified' } else { 'NotVerified' }) -Detail ("installer exit {0}; pv {1}" -f $p.ExitCode, $pv) | Out-Null
    } catch { Stop-Spinner; Add-Action -Id 'WEBVIEW2' -Rung 4 -Title 'WebView2 Runtime install' -Status Failed -Detail ((Get-ErrorText $_) + '. Manual: learn.microsoft.com/microsoft-edge/webview2/concepts/distribution') | Out-Null }
}

function Invoke-MicrosoftTools {
    # User-level (Full mode, elevated, in the user's session): Reset Office Activation through the command line version of Get Help.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$User, [Parameter(Mandatory)]$UserFacts)
    if ($Mode -ne 'Full') { return }
    $u = $User.Name
    $needOffice = [bool]@($script:Findings | Where-Object { $_.Id -eq 'OFFICE-LICENSE' -and $_.User -eq $u }).Count -or [bool]@($script:DecodedCodes | Where-Object { (-not $_.Family) -and $_.Key -eq '8007000D' }).Count
    if (-not $needOffice) { return }
    if (-not (Test-CanTouchUser -User $User)) { Add-Action -Id 'OFFICE-RESET' -Rung 4 -Title 'Reset Office Activation' -Status Skipped -User $u -Detail 'must run in the user session' | Out-Null; return }
    if (-not $script:IsElevated) { Add-Action -Id 'OFFICE-RESET' -Rung 4 -Title 'Reset Office Activation' -Status Skipped -User $u -Detail 'needs elevation' | Out-Null; return }
    if (-not (Confirm-Choice -Prompt 'Apply rung 4b (download the command line version of Get Help and run Reset Office Activation; every Office identity on this device signs out)?' -Rung 'Tool')) { Add-Action -Id 'OFFICE-RESET' -Rung 4 -Title 'Reset Office Activation' -Status Skipped -User $u -Detail 'not approved' | Out-Null; return }
    $dl = Join-Path -Path $script:RunDir -ChildPath 'downloads'; New-Item -Path $dl -ItemType Directory -Force | Out-Null
    # Builds of GetHelpCmd expire 90 days after creation, so it is always downloaded fresh from the location Microsoft's own sample scripts use.
    $zip = Join-Path -Path $dl -ChildPath 'GetHelpCmd.zip'; $dir = Join-Path -Path $dl -ChildPath 'GetHelpCmd'
    if (-not $PSCmdlet.ShouldProcess('GetHelpCmd.exe -S ResetOfficeActivation -AcceptEula -CloseOffice', 'Download the current build and run the documented reset')) { Add-Action -Id 'OFFICE-RESET' -Rung 4 -Title 'Reset Office Activation with GetHelpCmd' -Status WhatIf -User $u | Out-Null; return }
    try {
        Start-Spinner 'Downloading the command line version of Get Help from Microsoft'
        Invoke-WebRequest -Uri 'https://aka.ms/SaRA_EnterpriseVersionFiles' -OutFile $zip -UseBasicParsing -ErrorAction Stop
        Set-SpinnerText 'Extracting and checking the signature'
        Expand-Archive -Path $zip -DestinationPath $dir -Force -ErrorAction Stop
        $exe = Get-ChildItem -Path $dir -Recurse -Filter 'GetHelpCmd.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $exe) { $exe = Get-ChildItem -Path $dir -Recurse -Filter 'SaRAcmd.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
        if (-not $exe) { throw 'GetHelpCmd.exe not found in the downloaded package' }
        $sig = Get-AuthenticodeSignature -FilePath $exe.FullName
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') { throw 'downloaded tool is not signed by Microsoft Corporation; not run' }
        Set-SpinnerText 'Running Reset Office Activation (this takes a few minutes; Office apps are closed by the tool)'
        $r = Invoke-Native -File $exe.FullName -Arguments @('-S', 'ResetOfficeActivation', '-AcceptEula', '-CloseOffice') -TimeoutSec 900
        Stop-Spinner
        # Result: the documented two-digit code leads the output; the process exit code carries the same value on current builds.
        $code = ''
        if ($r.ExitCode -in @(1, 71, 72, 73, 74, 75, 76, 78, 79, 80)) { $code = ('{0:D2}' -f $r.ExitCode) }
        if (-not $code) { $m = [regex]::Match($r.Output, '(?m)^\s*(\d{2})\s*[:\-]'); if ($m.Success) { $code = $m.Groups[1].Value } }
        if (-not $code) { $code = 'none' }
        $meaning = switch ($code) { '80' { 'success; start an Office app and sign in to activate' } '01' { 'requires -CloseOffice' } '71' { 'tool problem; run the Office Activation scenario in the full Get Help app' } '72' { 'requires an elevated prompt' } '73' { 'OLicenseCleanup failed' } '74' { 'dsregcmd failed' } '75' { 'Windows older than 1803' } '76' { 'SignOutOfWamAccounts failed' } '78' { 'WorkplaceJoined but Windows older than 1809' } '79' { 'WPJCleanup failed' } default { 'unknown result; see run.log' } }
        Write-Log ("GetHelpCmd output: {0}" -f (($r.Output -split "`r?`n" | Select-Object -First 12) -join ' | ')) 'DEBUG'
        Add-Action -Id 'OFFICE-RESET' -Rung 4 -Title 'Reset Office Activation (GetHelpCmd)' -Status $(if ($code -eq '80') { 'Verified' } else { 'NotVerified' }) -User $u -Detail ("result {0}: {1}" -f $code, $meaning) | Out-Null
    } catch { Stop-Spinner; Add-Action -Id 'OFFICE-RESET' -Rung 4 -Title 'Reset Office Activation (GetHelpCmd)' -Status Failed -User $u -Detail (Get-ErrorText $_) | Out-Null }
}

# ----- SYSTEM: run the per-user part inside each user's session ----------------------------------
function Invoke-InUserSession {
    # Creates a one-shot scheduled task that runs this script as the target user (interactive token), waits for its
    # result.json, then removes the task. This is the supported pattern for per-user state from SYSTEM; HKU\.DEFAULT is never touched.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$User)
    $taskName = 'M365SignInRepair-' + $User.Sid.Substring([math]::Max(0, $User.Sid.Length - 8))
    $childDir = Join-Path -Path $OutputRoot -ChildPath ($script:RunId + '-' + $User.Sid.Substring([math]::Max(0, $User.Sid.Length - 6)))
    $childJson = Join-Path -Path $childDir -ChildPath 'result.json'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NonInteractive', '-WindowStyle', 'Hidden', '-File', ('"{0}"' -f $PSCommandPath), '-Mode', $Mode, '-NonInteractive', '-Quiet', '-NoOpenReport', '-OutputRoot', ('"{0}"' -f $OutputRoot), '-ChildOfRun', $script:RunId)
    if ($Apps) { $argList += @('-Apps', ($Apps -join ',')) }
    if ($Approve) { $argList += @('-Approve', ($Approve -join ',')) }
    if ($ErrorCode) { $argList += @('-ErrorCode', ($ErrorCode -join ',')) }
    if ($SkipNetwork) { $argList += '-SkipNetwork' }
    if ($CaseNumber) { $argList += @('-CaseNumber', ('"{0}"' -f $CaseNumber)) }
    $pwsh = if ($script:IsPS7) { (Get-Process -Id $PID).Path } else { "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
    if (-not $PSCmdlet.ShouldProcess($User.Name, ("Run the per-user repair in the user's session through a temporary scheduled task ({0})" -f $taskName))) { Add-Action -Id 'USER-SESSION' -Rung 1 -Title 'Per-user run' -Status WhatIf -User $User.Name | Out-Null; return }
    try {
        $action = New-ScheduledTaskAction -Execute $pwsh -Argument ($argList -join ' ')
        $principal = $null
        try { $principal = New-ScheduledTaskPrincipal -UserId $User.Sid -LogonType Interactive -RunLevel Highest -ErrorAction Stop } catch { $principal = New-ScheduledTaskPrincipal -UserId $User.Name -LogonType Interactive -RunLevel Highest -ErrorAction Stop }
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -Hidden
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Start-Spinner ("Repairing inside {0}'s session through a temporary scheduled task" -f $User.Name)
        $deadline = (Get-Date).AddMinutes(30); $started = Get-Date; $st = 'Running'
        do {
            Start-Sleep -Seconds 5
            $st = (Get-ScheduledTask -TaskName $taskName -ErrorAction Stop).State
            $elapsed = ((Get-Date) - $started).TotalSeconds
        } while (-not (Test-Path -LiteralPath $childJson) -and -not ($st -ne 'Running' -and $elapsed -gt 60) -and (Get-Date) -lt $deadline)
        $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $childJson) {
            Start-Sleep -Seconds 2
            $res = Get-Content -LiteralPath $childJson -Raw | ConvertFrom-Json
            # The child owns this user's findings; drop the parent's read-only copies to avoid duplicates.
            $keep = @($script:Findings | Where-Object { $_.User -ne $User.Name }); $script:Findings.Clear(); foreach ($k in $keep) { $script:Findings.Add($k) }
            foreach ($f in @($res.Findings)) { $script:Findings.Add([pscustomobject]$f) }
            foreach ($a in @($res.Actions)) { $script:Actions.Add([pscustomobject]$a) }
            $childExit = [int]$res.ExitCode
            Add-Action -Id 'USER-SESSION' -Rung 1 -Title ("Per-user run completed in {0}'s session" -f $User.Name) -Status $(if ($childExit -eq 0) { 'Verified' } else { 'NotVerified' }) -User $User.Name -Detail ("exit {0}; report {1}" -f $childExit, $childDir) | Out-Null
            if ($childExit -gt $script:ExitCode) { $script:ExitCode = $childExit }
        } else { Add-Action -Id 'USER-SESSION' -Rung 1 -Title ("Per-user run for {0}" -f $User.Name) -Status Failed -User $User.Name -Detail ("task state {0}, last result {1}; no result.json in {2}" -f $st, $(if ($info) { $info.LastTaskResult } else { 'n/a' }), $childDir) | Out-Null }
    } catch { Add-Action -Id 'USER-SESSION' -Rung 1 -Title ("Per-user run for {0}" -f $User.Name) -Status Failed -User $User.Name -Detail (Get-ErrorText $_) | Out-Null }
    finally { Stop-Spinner; try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch { } }
}

# ---------------------------------------------------------------------------------------------
# PHASE 6  Reports: result.json (machine readable), report.html (human), CASE-NOTES.txt (paste into the case)
# ---------------------------------------------------------------------------------------------
function ConvertTo-HtmlText { param([string]$Text) return [System.Net.WebUtility]::HtmlEncode([string]$Text) }

function Write-Reports {
    $end = Get-Date
    $sevOrder = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $findings = @($script:Findings | Sort-Object -Property @{ Expression = { $sevOrder[$_.Severity] } }, Area)
    $actions = @($script:Actions)
    $high = @($findings | Where-Object { $_.Severity -eq 'High' }).Count
    $medium = @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $verified = @($actions | Where-Object { $_.Status -eq 'Verified' }).Count
    $notVerified = @($actions | Where-Object { $_.Status -in @('NotVerified', 'Failed') }).Count
    $decoded = @($script:DecodedCodes)

    # Exit code contract
    #   0  healthy, or every planned repair applied and verified
    #   1  a repairable issue exists and nothing (or not everything approved) was done: Intune detection state
    #   2  something was changed but could not be verified, or failed
    #   3  the run stopped early (Ctrl+C or an unexpected error); the report is still complete up to that point
    $repairableLeft = @($findings | Where-Object { $_.Severity -in @('High', 'Medium') -and $_.Rung -ge 1 }).Count
    $unverified = @($actions | Where-Object { $_.Status -in @('Applied', 'NotVerified', 'Failed') }).Count
    $skippedForApproval = @($actions | Where-Object { $_.Status -eq 'Skipped' -and $_.Detail -match 'not approved|needs elevation|needs -Mode Full|needs an elevated|must run in the user session|run the tool inside' }).Count
    if ($script:Stopped) { $script:ExitCode = 3 }
    elseif ($unverified -gt 0) { $script:ExitCode = [math]::Max($script:ExitCode, 2) }
    elseif ($repairableLeft -gt 0 -and ($verified -eq 0 -or $skippedForApproval -gt 0)) { $script:ExitCode = [math]::Max($script:ExitCode, 1) }
    $notVerified = $unverified

    $facts = [ordered]@{}
    foreach ($k in $script:Facts.Keys) { if ($k -in @('Dsreg.Raw', 'Time.Status', 'Dsreg')) { continue }; $facts[$k] = $script:Facts[$k] }
    $result = [ordered]@{
        Tool = 'M365 Sign-In Repair'; Version = $script:Version; RunId = $script:RunId; Mode = $Mode; CaseNumber = $CaseNumber
        Started = $script:Started.ToString('s'); Ended = $end.ToString('s'); ExitCode = $script:ExitCode
        Computer = $env:COMPUTERNAME; RunAs = $script:Identity.Name; Elevated = $script:IsElevated; System = $script:IsSystem
        Users = @($script:Users | ForEach-Object { @{ Sid = $_.Sid; Name = $_.Name } })
        Codes = @($decoded | ForEach-Object { @{ Code = $_.Code; Meaning = $_.Meaning; Owner = $_.Owner; Rung = $_.Rung; Source = $_.Source; Documented = (-not $_.Family) } })
        Facts = $facts; Findings = @($findings); Actions = @($actions)
    }
    $json = Join-Path -Path $script:RunDir -ChildPath 'result.json'
    $result | ConvertTo-Json -Depth 6 | Set-Content -Path $json -Encoding UTF8
    if ($script:Facts.Contains('Dsreg.Raw')) { Set-Content -Path (Join-Path -Path $script:RunDir -ChildPath 'dsregcmd-status.txt') -Value $script:Facts['Dsreg.Raw'] -Encoding UTF8 }

    # Case notes
    $notes = [System.Collections.Generic.List[string]]::new()
    $notes.Add(("M365 Sign-In Repair v{0}  {1}  {2}" -f $script:Version, $end.ToString('yyyy-MM-dd HH:mm'), $(if ($CaseNumber) { "case $CaseNumber" } else { '' })))
    $notes.Add(("Device: {0}  {1} {2}  join: {3}  tenant: {4}" -f $env:COMPUTERNAME, $script:Facts['OS'], $script:Facts['Build'], $script:Facts['JoinType'], $script:Facts['TenantName']))
    $notes.Add(("Users: {0}   Mode: {1}   Result: exit {2}" -f (($script:Users | ForEach-Object { $_.Name }) -join ', '), $Mode, $script:ExitCode))
    if ($decoded.Count -gt 0) { $notes.Add('Codes:'); foreach ($c in $decoded) { $notes.Add(("  {0}: {1} [{2}{3}]" -f $c.Code, $c.Meaning, $c.Owner, $(if ($c.Family) { ', not individually documented' } else { '' }))) } }
    $notes.Add(("Findings: {0} high, {1} medium, {2} total" -f $high, $medium, $findings.Count))
    foreach ($f in ($findings | Where-Object { $_.Severity -in @('High', 'Medium') })) { $notes.Add(("  [{0}] {1}: {2}{3}" -f $f.Severity, $f.Area, $f.Title, $(if ($f.Evidence) { " ($($f.Evidence))" } else { '' }))) }
    if ($actions.Count -gt 0) { $notes.Add('Actions:'); foreach ($a in $actions) { $notes.Add(("  {0}: {1}{2}" -f $a.Status, $a.Title, $(if ($a.Detail) { " ($($a.Detail))" } else { '' }))) } }
    $next = @()
    if ($script:Facts.Contains('RebootRecommended') -and $script:Facts['RebootRecommended']) { $next += 'Restart the computer (token broker account cache was cleared).' }
    if ($script:Facts.Contains('PendingReboot') -and $script:Facts['PendingReboot']) { $next += 'A reboot was already pending; restart before re-testing.' }
    foreach ($f in ($findings | Where-Object { $_.Rung -eq 0 -and $_.Severity -in @('High', 'Medium') })) { $next += ("{0}: {1}" -f $f.Title, $f.Fix) }
    if ($next.Count -gt 0) { $notes.Add('Next steps (outside the tool):'); foreach ($n in ($next | Select-Object -First 8)) { $notes.Add('  ' + $n) } }
    $notes.Add(("Report: {0}" -f $script:RunDir))
    Set-Content -Path (Join-Path -Path $script:RunDir -ChildPath 'CASE-NOTES.txt') -Value $notes -Encoding UTF8

    # HTML
    $sevColor = @{ High = '#c0392b'; Medium = '#d68910'; Low = '#2874a6'; Info = '#6c757d' }
    $stColor = @{ Verified = '#1e8449'; Applied = '#1e8449'; NotVerified = '#d68910'; Failed = '#c0392b'; Skipped = '#6c757d'; WhatIf = '#6c757d'; Planned = '#2874a6' }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>M365 Sign-In Repair report</title>')
    [void]$sb.AppendLine('<style>body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f4f6f8;color:#1f2933}header{background:#1b1f3a;color:#fff;padding:28px 40px}header h1{margin:0;font-size:22px;font-weight:600}header p{margin:6px 0 0;color:#b9c2d0}main{padding:24px 40px;max-width:1200px}.cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}.card{background:#fff;border-radius:8px;padding:16px 20px;min-width:150px;box-shadow:0 1px 3px rgba(0,0,0,.08)}.card b{display:block;font-size:26px}.card span{color:#6c757d;font-size:13px}table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:28px}th{background:#e9edf2;text-align:left;padding:10px 12px;font-size:13px}td{padding:10px 12px;border-top:1px solid #edf0f3;font-size:14px;vertical-align:top}.tag{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:12px}h2{font-size:17px;margin:28px 0 10px}code{background:#eef1f4;padding:1px 5px;border-radius:4px;font-size:13px}footer{padding:20px 40px;color:#6c757d;font-size:13px}dl{display:grid;grid-template-columns:260px 1fr;gap:4px 16px;background:#fff;padding:16px 20px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}dt{color:#6c757d}dd{margin:0;word-break:break-all}</style></head><body>')
    [void]$sb.AppendLine(('<header><h1>M365 Sign-In Repair</h1><p>{0} &middot; {1} &middot; mode {2}{3} &middot; exit code {4}</p></header><main>' -f (ConvertTo-HtmlText $env:COMPUTERNAME), $end.ToString('yyyy-MM-dd HH:mm'), (ConvertTo-HtmlText $Mode), $(if ($CaseNumber) { ' &middot; case ' + (ConvertTo-HtmlText $CaseNumber) } else { '' }), $script:ExitCode))
    [void]$sb.AppendLine(('<div class="cards"><div class="card"><b>{0}</b><span>high findings</span></div><div class="card"><b>{1}</b><span>medium findings</span></div><div class="card"><b>{2}</b><span>actions verified</span></div><div class="card"><b>{3}</b><span>not verified or failed</span></div><div class="card"><b>{4}</b><span>users inspected</span></div></div>' -f $high, $medium, $verified, $notVerified, $script:Users.Count))
    if ($decoded.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Error codes</h2><table><tr><th>Code</th><th>Meaning</th><th>Owner</th><th>Rung</th><th>Source</th></tr>')
        foreach ($c in $decoded) { [void]$sb.AppendLine(('<tr><td><code>{0}</code></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (ConvertTo-HtmlText $c.Code), (ConvertTo-HtmlText $c.Meaning), (ConvertTo-HtmlText $c.Owner), $c.Rung, (ConvertTo-HtmlText $c.Source))) }
        [void]$sb.AppendLine('</table>')
    }
    [void]$sb.AppendLine('<h2>Findings</h2><table><tr><th>Severity</th><th>Area</th><th>User</th><th>Finding</th><th>Evidence</th><th>Rung</th><th>What fixes it</th><th>Source</th></tr>')
    if ($findings.Count -eq 0) { [void]$sb.AppendLine('<tr><td colspan="8">No problems found.</td></tr>') }
    foreach ($f in $findings) { [void]$sb.AppendLine(('<tr><td><span class="tag" style="background:{0}">{1}</span></td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>' -f $sevColor[$f.Severity], $f.Severity, (ConvertTo-HtmlText $f.Area), (ConvertTo-HtmlText $f.User), (ConvertTo-HtmlText $f.Title), (ConvertTo-HtmlText $f.Evidence), $f.Rung, (ConvertTo-HtmlText $f.Fix), (ConvertTo-HtmlText $f.Source))) }
    [void]$sb.AppendLine('</table>')
    [void]$sb.AppendLine('<h2>Actions</h2><table><tr><th>Status</th><th>Rung</th><th>User</th><th>Action</th><th>Detail</th><th>Restore</th></tr>')
    if ($actions.Count -eq 0) { [void]$sb.AppendLine('<tr><td colspan="6">No changes were made.</td></tr>') }
    foreach ($a in $actions) { [void]$sb.AppendLine(('<tr><td><span class="tag" style="background:{0}">{1}</span></td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f $stColor[$a.Status], $a.Status, $a.Rung, (ConvertTo-HtmlText $a.User), (ConvertTo-HtmlText $a.Title), (ConvertTo-HtmlText $a.Detail), (ConvertTo-HtmlText $a.Restore))) }
    [void]$sb.AppendLine('</table><h2>Device facts</h2><dl>')
    foreach ($k in $facts.Keys) { $v = $facts[$k]; if ($v -is [array]) { $v = $v -join ', ' }; [void]$sb.AppendLine(('<dt>{0}</dt><dd>{1}</dd>' -f (ConvertTo-HtmlText $k), (ConvertTo-HtmlText ([string]$v)))) }
    [void]$sb.AppendLine('</dl>')
    [void]$sb.AppendLine(('<h2>Files</h2><p>Run folder: <code>{0}</code><br>result.json, CASE-NOTES.txt, run.log, dsregcmd-status.txt{1}</p>' -f (ConvertTo-HtmlText $script:RunDir), $(if (Test-Path -LiteralPath $script:Quarantine) { ', quarantine\ and RESTORE-INSTRUCTIONS.txt' } else { '' })))
    [void]$sb.AppendLine(('</main><footer>M365 Sign-In Repair v{0} &middot; Arwaz Khan, Microsoft Support Engineer &middot; every repair traces to a Microsoft article listed in docs/sources.md</footer></body></html>' -f $script:Version))
    $html = Join-Path -Path $script:RunDir -ChildPath 'report.html'
    Set-Content -Path $html -Value $sb.ToString() -Encoding UTF8
    return $html
}

function Show-Summary {
    param([string]$HtmlPath)
    $findings = @($script:Findings); $actions = @($script:Actions)
    $lines = @()
    $lines += ("{0} finding(s): {1} high, {2} medium, {3} low, {4} info" -f $findings.Count, @($findings | Where-Object Severity -eq 'High').Count, @($findings | Where-Object Severity -eq 'Medium').Count, @($findings | Where-Object Severity -eq 'Low').Count, @($findings | Where-Object Severity -eq 'Info').Count)
    foreach ($f in ($findings | Where-Object { $_.Severity -in @('High', 'Medium') } | Select-Object -First 12)) { $lines += ("  {0} {1}: {2}" -f (Get-Tinted $script:Glyph.Warn $(if ($f.Severity -eq 'High') { 'Red' } else { 'Yellow' })), $f.Area, $f.Title) }
    if ($actions.Count -gt 0) {
        $lines += ''
        $lines += ("{0} action(s): {1} verified, {2} applied, {3} not verified, {4} failed, {5} skipped" -f $actions.Count, @($actions | Where-Object Status -eq 'Verified').Count, @($actions | Where-Object Status -eq 'Applied').Count, @($actions | Where-Object Status -eq 'NotVerified').Count, @($actions | Where-Object Status -eq 'Failed').Count, @($actions | Where-Object Status -in @('Skipped', 'WhatIf')).Count)
        foreach ($a in ($actions | Where-Object { $_.Status -in @('Verified', 'Applied', 'NotVerified', 'Failed') } | Select-Object -First 12)) { $lines += ("  {0} {1}" -f (Get-Tinted $(if ($a.Status -in @('Verified', 'Applied')) { $script:Glyph.Ok } else { $script:Glyph.Fail }) $(if ($a.Status -in @('Verified', 'Applied')) { 'Mint' } else { 'Red' })), $a.Title) }
    }
    if ($script:Facts.Contains('RebootRecommended') -and $script:Facts['RebootRecommended']) { $lines += ''; $lines += (Get-Tinted 'Restart the computer to complete the token broker reset.' 'Orange') }
    $lines += ''
    $lines += ("Report  {0}" -f (Get-Tinted $HtmlPath 'Cyan'))
    $reportOnly = @($findings | Where-Object { $_.Rung -eq 0 -and $_.Severity -in @('High', 'Medium') })
    $exitText = switch ($script:ExitCode) {
        0 { if ($actions.Count -gt 0) { 'every approved repair verified' } elseif ($reportOnly.Count -gt 0) { 'nothing this tool may change; the findings above belong to the owners named in the report' } else { 'healthy' } }
        1 { 'repairable issue found, nothing changed' } 2 { 'repair applied but not verified' } 3 { 'stopped early' } default { '' } }
    $lines += ("Exit    {0}  ({1})" -f $script:ExitCode, $exitText)
    if ($script:DecodedCodes.Count -eq 0 -and $reportOnly.Count -gt 0 -and $actions.Count -eq 0) { $lines += ''; $lines += (Get-Tinted 'Tip: pass the code from the sign-in dialog with -ErrorCode; the documented repairs for the broker are keyed to it.' 'Yellow') }
    $color = switch ($script:ExitCode) { 0 { 'Mint' } 1 { 'Yellow' } 2 { 'Orange' } default { 'Red' } }
    Write-Box -Title 'Summary' -Lines $lines -Color $color -Reveal
}

# ---------------------------------------------------------------------------------------------
# Orchestration. The finally block always writes the report and restore guidance, even after Ctrl+C or a crash.
# ---------------------------------------------------------------------------------------------
function Invoke-Main {
    $script:DecodedCodes = @()
    foreach ($c in $ErrorCode) { foreach ($piece in ($c -split '[,\s]+')) { if ($piece) { $script:DecodedCodes += (Resolve-ErrorCode -Code $piece) } } }

    if ($DecodeOnly) {
        if ($script:DecodedCodes.Count -eq 0) { Write-Ui 'Nothing to decode: pass -ErrorCode.'; $script:MainCompleted = $true; return }
        $lines = @()
        foreach ($d in $script:DecodedCodes) { $lines += ("{0}  {1}" -f (Get-Tinted $d.Code 'White'), $d.Meaning); $lines += ("    owner {0}  rung {1}  source {2}{3}" -f $d.Owner, $d.Rung, $d.Source, $(if ($d.Family) { '  (family routing, not individually documented)' } else { '' })) }
        Write-Box -Title 'Error codes' -Lines $lines -Color 'Violet'
        $script:MainCompleted = $true
        return
    }

    Show-Intro
    if (-not $Mode) {
        if (-not (Show-StartMenu)) { Write-Log 'Nothing done.' 'INFO'; $script:MainCompleted = $true; return }
        $script:DecodedCodes = @()
        foreach ($c in $ErrorCode) { foreach ($piece in ($c -split '[,\s]+')) { if ($piece) { $script:DecodedCodes += (Resolve-ErrorCode -Code $piece) } } }
        if ($DecodeOnly) {
            if ($script:DecodedCodes.Count -eq 0) { Write-Ui '  Nothing to decode.'; $script:MainCompleted = $true; return }
            $lines = @()
            foreach ($d in $script:DecodedCodes) { $lines += ("{0}  {1}" -f (Get-Tinted $d.Code 'White'), $d.Meaning); $lines += ("    owner {0}  rung {1}  source {2}{3}" -f $d.Owner, $d.Rung, $d.Source, $(if ($d.Family) { '  (family routing, not individually documented)' } else { '' })) }
            Write-Box -Title 'Error codes' -Lines $lines -Color 'Violet'
            $script:MainCompleted = $true
            return
        }
        Write-Ui ''
        Write-Ui ("  {0}" -f (Get-Tinted ("Mode {0}  |  apps {1}{2}" -f $Mode, ($Apps -join ', '), $(if ($ErrorCode.Count -gt 0) { '  |  codes ' + ($ErrorCode -join ', ') } else { '' })) 'Gray'))
    }
    if ($script:DecodedCodes.Count -gt 0) {
        $lines = @(); foreach ($d in $script:DecodedCodes) { $lines += ("{0}  {1}  [{2}, rung {3}]" -f (Get-Tinted $d.Code 'White'), $d.Meaning, $d.Owner, $d.Rung) }
        Write-Box -Title 'Codes you reported' -Lines $lines -Color 'Violet'
        if ($script:DecodedCodes | Where-Object { $_.Owner -eq 'Tenant' }) { Write-Log 'At least one code is a server-side response (tenant policy, licence or account). The device is inspected anyway, but that code is fixed by an administrator, not by this tool.' 'WARN' }
    }

    Write-Banner -Text 'Device, platform, TLS, time' -Phase 1
    Invoke-WithSpinner -Text 'Reading device, services, TLS posture, root trust, policies and time' -Action { Get-DeviceFacts } | Out-Null
    Write-Log ("{0}  {1}  {2}  ({3})" -f $script:Facts['OS'], $script:Facts['Build'], $(if ($script:Facts.Contains('Office.Version') -and $script:Facts['Office.Version']) { "Office $($script:Facts['Office.Version'])" } else { 'Office not installed' }), (Get-PhaseElapsed)) 'OK'

    Write-Banner -Text 'Device registration and sign-in events' -Phase 2
    Invoke-WithSpinner -Text 'dsregcmd /status and the AAD and User Device Registration event logs' -Action { Get-RegistrationFacts } | Out-Null
    Write-Log ("{0}{1}  ({2})" -f $(if ($script:Facts.Contains('JoinType')) { $script:Facts['JoinType'] } else { 'join state unknown' }), $(if ($script:Facts.Contains('PRT')) { "  PRT $($script:Facts['PRT'])" } else { '' }), (Get-PhaseElapsed)) 'OK'

    Write-Banner -Text 'Network path to Microsoft 365' -Phase 3
    Invoke-WithSpinner -Text 'Proxy, DNS, endpoints and TLS interception' -Action { Get-NetworkFacts } | Out-Null
    if ($SkipNetwork) { Write-Log 'Network checks skipped' 'INFO' }
    else { Write-Log ("{0} endpoint(s) reachable, {1} failed; TLS issuer: {2}  ({3})" -f $script:Facts['Endpoints.OK'], @($script:Facts['Endpoints.Failed']).Count, $(if ($script:Facts.Contains('TLS.Issuer')) { $script:Facts['TLS.Issuer'] } else { 'not probed' }), (Get-PhaseElapsed)) 'OK' }

    Write-Banner -Text 'Users and their sign-in state' -Phase 4
    $script:Users = @(Get-TargetUsers)
    $script:UserFacts = @{}
    $ui = 0
    foreach ($usr in $script:Users) {
        $ui++
        $label = if ($script:Users.Count -gt 1) { (Get-Tinted 'Reading users ' 'Gray') + (Get-MiniBar -Done ($ui - 1) -Total $script:Users.Count) + (Get-Tinted (" {0}/{1}  {2}" -f $ui, $script:Users.Count, $usr.Name) 'Gray') } else { ("Reading {0}" -f $usr.Name) }
        $uf = Invoke-WithSpinner -Text $label -Action { Get-UserFacts -User $usr }
        $script:UserFacts[$usr.Sid] = $uf
        $bits = @()
        if ($uf.Contains('Appx.BrokerPlugin')) { $bits += ("broker {0}" -f $(if ($uf['Appx.BrokerPlugin'] -eq $true) { 'ok' } elseif ($uf['Appx.BrokerPlugin'] -eq 'unknown') { 'unknown' } else { 'MISSING' })) }
        if ($uf.Contains('Office.Identities')) { $bits += ("{0} Office identit{1}" -f $uf['Office.Identities'], $(if ($uf['Office.Identities'] -eq 1) { 'y' } else { 'ies' })) }
        if ($uf.Contains('OneDrive.Business1') -and $uf['OneDrive.Business1']) { $bits += ("OneDrive {0}" -f $uf['OneDrive.Business1']) }
        if ($uf.Contains('Teams.New')) { $bits += ("Teams {0}" -f $(if ($uf['Teams.New']) { 'new' } elseif ($uf['Teams.Classic']) { 'classic' } else { 'none' })) }
        if ($uf.Processes.Count -gt 0) { $bits += ("running: {0}" -f (($uf.Processes | Select-Object -Unique) -join ', ')) }
        Write-Log ("{0}: {1}" -f $usr.Name, ($bits -join '; ')) 'OK'
    }

    # Plan
    $repairable = @($script:Findings | Where-Object { $_.Rung -ge 1 })
    $reportOnly = @($script:Findings | Where-Object { $_.Rung -eq 0 -and $_.Severity -in @('High', 'Medium') })
    Write-Banner -Text 'Plan' -Phase 5
    $plan = @()
    if ($repairable.Count -eq 0 -and $reportOnly.Count -eq 0) { $plan += (Get-Tinted 'Nothing to repair: no sign-in problem was found on this device.' 'Mint') }
    foreach ($r in @(1, 2, 3, 4)) {
        $items = @($repairable | Where-Object { $_.Rung -eq $r })
        if ($items.Count -eq 0) { continue }
        $name = switch ($r) { 1 { 'Rung 1  nudge' } 2 { 'Rung 2  reset caches (quarantined)' } 3 { 'Rung 3  re-register in-box packages' } 4 { 'Rung 4  Microsoft tools' } }
        $plan += (Get-Tinted $name 'White')
        foreach ($i in $items) { $plan += ("    {0} {1}{2}" -f $script:Glyph.Arrow, $i.Title, $(if ($i.User) { " [$($i.User)]" } else { '' })) }
    }
    if ($reportOnly.Count -gt 0) {
        $plan += (Get-Tinted 'Report only (organisation controls or manual steps; the tool never changes these)' 'Gray')
        foreach ($i in ($reportOnly | Select-Object -First 10)) { $plan += ("    {0} {1}: {2}" -f $script:Glyph.Dot, $i.Title, $i.Fix) }
    }
    if ($Mode -eq 'Diagnose' -and $repairable.Count -gt 0) { $plan += ''; $plan += (Get-Tinted 'Diagnose mode: nothing is changed. Run again with -Mode Repair to apply the rungs above.' 'Yellow') }
    if ($repairable.Count -eq 0 -and $reportOnly.Count -gt 0 -and $script:DecodedCodes.Count -eq 0) { $plan += ''; $plan += (Get-Tinted 'No rung applies without an error code. Pass the code shown in the sign-in dialog with -ErrorCode to unlock the documented broker repairs.' 'Yellow') }
    Write-Box -Title 'Plan' -Lines $plan -Color 'Cyan'

    if ($Mode -ne 'Diagnose' -and ($repairable.Count -gt 0 -or $script:DecodedCodes.Count -gt 0)) {
        if (-not $WhatIfPreference) { New-Quarantine }
        Write-RestoreInstructions
        $machineUser = [pscustomobject]@{ Sid = $script:CurrentSid; Name = $script:Identity.Name; IsCurrent = $false }
        $selfUsers = @($script:Users | Where-Object { Test-CanTouchUser -User $_ })
        # Machine-level rungs (services, clock, DNS, WebView2) run once in this process when it is elevated and no per-user
        # pass will cover them; a child running as a standard user could not.
        if ($script:IsElevated -and $selfUsers.Count -eq 0) { Invoke-Nudges -User $machineUser; Invoke-WebView2Install }
        foreach ($usr in $script:Users) {
            $uf = $script:UserFacts[$usr.Sid]
            if (-not (Test-CanTouchUser -User $usr)) {
                if ($script:IsElevated) { Invoke-InUserSession -User $usr } else { Add-Action -Id 'USER-SESSION' -Rung 1 -Title ("Per-user repair for {0}" -f $usr.Name) -Status Skipped -User $usr.Name -Detail 'run the tool inside that user session, or elevated with -TargetUserSid' | Out-Null }
                continue
            }
            Invoke-Nudges -User $usr
            Invoke-CacheReset -User $usr -UserFacts $uf
            Invoke-Reregister -User $usr -UserFacts $uf
            Invoke-WebView2Install
            Invoke-MicrosoftTools -User $usr -UserFacts $uf
        }
        Write-RestoreInstructions
    }
    $script:MainCompleted = $true
}

$htmlPath = ''
$script:MainCompleted = $false
try {
    Invoke-Main
} catch {
    if ($_.Exception -is [System.Management.Automation.PipelineStoppedException] -or $_.FullyQualifiedErrorId -match 'PipelineStopped') { $script:Stopped = $true }
    else { Write-Log ("Stopped: {0}" -f (Get-ErrorText $_)) 'FAIL'; Write-Log ($_.ScriptStackTrace) 'DEBUG'; $script:Stopped = $true }
} finally {
    if (-not $script:MainCompleted -and -not $DecodeOnly) { $script:Stopped = $true }
    if ($script:Stopped) { Remove-Spinner }
    try {
        if (-not $DecodeOnly -and -not $script:Quit) {
            if ($script:RestoreLines.Count -gt 0) { Write-RestoreInstructions }
            Write-Banner -Text 'Report' -Phase 6
            if (-not $script:Stopped) { Start-Spinner 'Writing report.html, result.json and CASE-NOTES.txt' }
            $htmlPath = Write-Reports
            Stop-Spinner
            Show-Summary -HtmlPath $htmlPath
            if ($script:Interactive -and -not $NoOpenReport -and $htmlPath -and (Test-Path -LiteralPath $htmlPath)) { try { Start-Process -FilePath $htmlPath -ErrorAction Stop } catch { } }
            Show-Outro
        }
    } catch { Stop-Spinner; Write-Host ("Report could not be written: {0}" -f (Get-ErrorText $_)) -ForegroundColor Red; if ($script:ExitCode -lt 2) { $script:ExitCode = 2 } }
    finally { Remove-Spinner }
}
exit $script:ExitCode
