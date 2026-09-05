# Troubleshooting the tool

## "Running scripts is disabled on this system"

The execution policy blocks unsigned scripts. Run it for this process only:

```powershell
powershell -ExecutionPolicy Bypass -File .\Repair-M365SignIn.ps1
```

## The plan shows the right findings but every action says "must run in the user session"

You are elevated as one account while the affected user is another, or you are running as SYSTEM without `-TargetUserSid` or `-AllUsers`. Per-user caches, Credential Manager and package registration can only be touched from inside that user's session. Either run the tool as that user (elevation optional), or run it elevated with `-TargetUserSid <their SID>`; the tool then launches itself in their session through a temporary scheduled task. The SID is in the report under Users, or from `whoami /user` in their session.

## "Quarantine is on C: but the item is on D:"

The user's profile is on a different volume from the run folder. Point the run folder at the same volume: `-OutputRoot D:\M365SignInRepair`. The tool refuses cross-volume moves on purpose, because copy-then-delete is the failure mode it exists to avoid.

## "Quarantine folder is inside a OneDrive synced folder"

`-OutputRoot` points at a synced location. Choose a local one; token caches must never be uploaded.

## Store package inventory unavailable

`Get-AppxPackage` failed, so the broker registration check was skipped and reported as Info. On PowerShell 7 this needs the Windows PowerShell compatibility layer; run the tool under Windows PowerShell 5.1 instead, or make sure the AppX Deployment Service (AppXSVC) is not disabled.

## PRT refresh is NotVerified

`dsregcmd /refreshprt` was issued but the timestamp did not move within the check window. Lock and unlock the device (Microsoft's documented refresh), then run `dsregcmd /status` and read `AzureAdPrtUpdateTime`. If it still does not move, the Server Error Description in the report names the cause (for example AADSTS50155 device disabled, or a network failure to `login.microsoftonline.com`).

## Clock resync is NotVerified

On a domain member the tool only checks that `Last Successful Sync Time` changed; if the domain controller is unreachable it cannot. On a standalone or Entra-joined device UDP 123 to `time.windows.com` must be open.

## Endpoints show as unreachable but the browser works

The browser follows the WinINet proxy; the tool's probes follow the system stack as well, so a difference usually means the PAC or proxy setting differs between the two, or the proxy requires authentication the probe cannot supply. The report shows both proxy values. This is a report-only finding; hand the failing hostnames and endpoint set numbers to the network owner.

## TLS interception reported but the security team says there is none

The issuer of the certificate served for `login.microsoftonline.com` was not a Microsoft, DigiCert, Entrust or Baltimore authority. Antivirus products with HTTPS scanning do this locally. The report shows the exact issuer string.

## The GetHelpCmd step failed to download

The command line version of Get Help is downloaded fresh from Microsoft each run because each build expires ninety days after creation. If the device cannot reach the download location, run the scenario manually from any machine that can: extract the package and run `GetHelpCmd.exe -S ResetOfficeActivation -AcceptEula -CloseOffice` from an elevated prompt. Result 80 is success.

## "Unexpected token" errors full of characters like â•­ or â–ˆ

The file was read in the wrong encoding. The scripts are UTF-8 with a byte-order mark so that both Windows PowerShell 5.1 and PowerShell 7 decode the box-drawing symbols correctly. If an editor or a copy-paste stripped the mark, Windows PowerShell 5.1 falls back to the ANSI code page and the parser fails on the first symbol. Download the file again rather than copying its text, or run it with PowerShell 7 (`pwsh -File .\Repair-M365SignIn.ps1`), which reads UTF-8 by default.

## Where are the files

Interactive runs open `report.html` at the end. The run folder path is printed in the summary box and in `CASE-NOTES.txt`. Default locations: `%LOCALAPPDATA%\M365SignInRepair\<run id>` for a normal run, `%ProgramData%\M365SignInRepair\<run id>` when elevated. Child runs launched in other users' sessions use the same run id with the last six characters of the user's SID appended.

## Undoing a repair

Open `RESTORE-INSTRUCTIONS.txt` in the run folder. Every moved folder is listed with its original path; close the owning app and move it back. Registry exports are restored with `reg import "<file>"`. Credential Manager entries and the new Teams app data cannot be restored and are recreated by the apps at the next sign-in; the instructions say so for each run.
