# How it works

## One idea

Sign-in on Windows is a stack, and the error the user sees is the top of it. Office, Outlook, OneDrive and new Teams all obtain tokens through the same Web Account Manager broker, which depends on the device's registration with Entra ID and its Primary Refresh Token, which depends on the clock, DNS, TLS and the proxy, which depend on policies someone set. A broken layer low in the stack produces dozens of different codes at the top.

So the tool reads the whole stack before it does anything, and when it repairs, it starts at the bottom and with the least destructive step.

## The six phases

1. **Device and platform.** Registry and service reads. TLS posture (Schannel, .NET, WinHTTP, cipher policy), root trust, WebView2, pending reboot, disk, policies, clock offset against `time.windows.com` (only when not domain joined; domain members take time from the domain hierarchy).
2. **Device registration.** `dsregcmd /status` parsed into a dictionary. The PRT is judged only on Entra joined and hybrid devices; Microsoft says to ignore the SSO section on Entra registered (workplace joined) devices, so the tool does. The join type comes from the documented AzureAdJoined / EnterpriseJoined / DomainJoined matrix. SSO State and User State are only trusted when the script runs as the user it is inspecting, because those sections describe the account running dsregcmd. Event logs for the last 24 hours: AAD Operational (1098 broker failure, 1081 and 1088 server errors, 1084 network sub-error) and User Device Registration Admin (304, 305, 307, 220).
3. **Network.** Both proxies, PAC reachability, DNS answers with sinkhole detection, a HEAD request to each identity endpoint through the system stack (any HTTP status counts as reachable; only transport failures count against), and a raw TLS handshake to read the leaf issuer without trusting it. A corporate CA issuing for `login.microsoftonline.com` means interception, which Microsoft asks organisations to bypass for identity traffic.
4. **Users.** Which users to inspect (see below), then everything per user from that user's own hive and profile path.
5. **Plan and repair.** The plan lists every repairable finding by rung and every report-only finding with its owner. In Repair or Full mode each rung asks for approval, applies, verifies.
6. **Report.** `result.json`, `report.html`, `CASE-NOTES.txt`, `run.log`, `dsregcmd-status.txt`, and the quarantine with `RESTORE-INSTRUCTIONS.txt`. Written in a `finally` block so an interrupted run still produces them.

## Which users

- Not elevated: the current user.
- Elevated, no target given: the current account, with a warning when the console user is somebody else (an administrator's elevated prompt often runs as a different account than the person with the problem). Use `-TargetUserSid` for that person.
- Elevated with `-TargetUserSid` or `-AllUsers`: those users. Entra ID cloud users have SIDs that start `S-1-12-1`; domain and local users start `S-1-5-21`. Both are real users and both are inspected.
- SYSTEM: the owner of `explorer.exe`, or every interactive owner on a multi-session host.

Per-user repairs (caches, Credential Manager, Appx registration) only run when the tool is executing as that user. When it is elevated and the target is somebody else, it re-launches itself in that user's session through a temporary scheduled task with the interactive logon type, waits for the child's `result.json`, merges it, and removes the task. It never writes to `HKEY_USERS\<sid>` or `.DEFAULT`.

## Findings and rungs

A finding has a severity (High, Medium, Low, Info), an area, evidence, the rung that could fix it, the fix text, and the Microsoft source. Rung 0 means report only. Only High and Medium findings open a rung; Info and Low rows describe state and never trigger a change on their own.

| Rung | Trigger | Actions | Verification |
|---|---|---|---|
| 1 Nudge | PRT missing or older than four hours; stale DNS cache; a stopped service that should run; clock off by more than a minute | `dsregcmd /refreshprt`; `Clear-DnsClientCache`; `Start-Service`; `w32tm /resync /rediscover` | PRT timestamp moved in the last ten minutes; names resolve to public addresses; service Running; offset under a minute or sync time changed |
| 2 Reset | High or Medium finding in the broker, Office, Outlook, OneDrive or Teams area, or a documented client-side code | Export identity registry keys, move OneAuth, IdentityCache, Office licence folders, broker account blobs, Teams caches and the OneDrive pre-sign-in file to quarantine; remove Office, OneDrive and Teams entries from Credential Manager (list saved first); clear OneDrive's OneAuth failure marker (key exported first); `OneDrive.exe /reset` then relaunch at the user's integrity level | Key gone; folder empty; entries gone from `cmdkey /list`; OneDrive process back |
| 3 Re-register | `Get-AppxPackage` returns nothing for `Microsoft.AAD.BrokerPlugin` or `Microsoft.Windows.CloudExperienceHost` for that user; or the broker's PSR registry key has broken permissions (Microsoft's documented cause of event 1098, 0xCAA5001C) | `Add-AppxPackage -Register <SystemApps manifest> -DisableDevelopmentMode -ForceApplicationShutdown`; for the PSR key, re-enable permission inheritance (taking ownership first if the key refuses), after exporting the key and saving its ACL | `Get-AppxPackage` returns the package; inheritance enabled and SYSTEM has full control |
| 4 Tools | WebView2 missing in both registry views; Office licence not in the Licensed state | Download the WebView2 bootstrapper or the command line version of Get Help, check the Authenticode signature is Microsoft Corporation, run `/silent /install` or `-S ResetOfficeActivation -AcceptEula -CloseOffice` | `pv` value present; Get Help result 80 |

The rung 2 scope is derived, not fixed. Office identity caches go together because Microsoft's reset procedure clears all of them as one operation. OneDrive and Teams are separate decisions driven by their own findings and codes. The new Teams app reset (`Reset-AppxPackage`, the Settings > Apps > Reset equivalent) is only offered for the documented Teams login-loop codes and has its own approval because it is not restorable.

## Apps are closed only when needed

Before rung 2 moves anything, the tool lists which of the user's own Office, Teams, OneDrive processes are running and includes that list in the plan. Closing goes through `ShouldProcess`, tries `CloseMainWindow` first, then stops what is left. If any process survives, nothing is moved for that rung.

## Quarantine

The run folder lives under `%LOCALAPPDATA%\M365SignInRepair` (or `%ProgramData%` when elevated). Moves are same-volume renames; a cross-volume quarantine is refused rather than falling back to copy-and-delete. The quarantine path is checked against the OneDrive environment variables, the OneDrive account `UserFolder` values and the folder name, and refused if it would be synced. When elevated, the quarantine folder's inheritance is removed so exported registry keys and credential lists are readable only by SYSTEM, Administrators and the current user. `RESTORE-INSTRUCTIONS.txt` is rewritten after every move.

## Error codes

Seventy codes are decoded with meaning, owner, rung and source. Input can be `0x8004de40`, `8004DE40`, `CAA50021`, `AADSTS50076` or the signed decimal Windows sometimes prints (`-2147024809`). Codes that Microsoft does not document individually are marked as family-routed: they contribute to the report and the plan text but never open a rung by themselves. Server-side AADSTS codes are always report only.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Healthy, or every planned repair applied and verified |
| 1 | A repairable issue exists and nothing (or not everything approved) was done. This is the Intune detection state |
| 2 | Something was changed but could not be verified, or a step failed |
| 3 | The run stopped early (Ctrl+C or an unexpected error). The report is complete up to that point |

## Compatibility

Windows PowerShell 5.1 and PowerShell 7 on Windows 10 and 11. On PowerShell 7 the Appx module is loaded through Windows PowerShell compatibility. Strict mode is on throughout; every optional property is guarded. The console layer degrades to plain text when there is no console, when output is redirected, or when `NO_COLOR` is set, so RMM logs stay clean.
