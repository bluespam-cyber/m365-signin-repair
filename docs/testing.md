# Testing

## Offline test

`scripts\Test-RepairM365SignIn.ps1` exercises the whole tool without touching the real machine. It writes a shadow module that replaces every Windows dependency the tool calls (`Get-CimInstance`, services, event logs, DNS, web requests, Appx cmdlets, processes, scheduled tasks) and a wrapper that swaps the tool's native-process function for a fake `dsregcmd`, `w32tm`, `netsh`, `cmdkey` and `reg`. The tool's registry hive is redirected to `HKCU:\Software\M365SignInRepairTest`, and `LOCALAPPDATA` and `APPDATA` to a folder under `%TEMP%`, so the identity caches it moves are fakes created by the test.

Five scenarios, thirty checks:

1. Diagnose on a healthy state: no High findings, exit 0, no actions.
2. Diagnose on a broken state (missing broker package, stale PRT, OneAuth failure marker, pre-sign-in file, cached identity, credential): the expected findings, the code decoded to rung 3, exit 1, nothing moved.
3. Repair with `-WhatIf`: only WhatIf and Skipped actions, nothing moved.
4. Repair approved for rungs 1 to 3: PRT refresh verified, every cache moved to quarantine, registry keys exported and removed, credential removed and verified, restore instructions, case notes and report written, no failed actions.
5. Decode only: three codes decoded, the server-side one marked as tenant-owned.

```powershell
.\scripts\Test-RepairM365SignIn.ps1
```

Runs in about a minute on Windows PowerShell 5.1 or PowerShell 7. No elevation needed. The lab folder path is printed at the end; the test removes its registry key and leaves the lab folder for inspection.

## Continuous integration

`.github/workflows/test.yml` runs the offline test on `windows-latest` under both engines on every push and pull request.

## Live verification

The offline test proves the logic; it cannot prove that Windows behaves as documented. Before relying on the tool in a new environment, run `-Mode Diagnose` on a healthy device and a known-broken one and read the plan. Then run `-Mode Repair -WhatIf` on the broken one and confirm the printed changes are the ones you expect.
