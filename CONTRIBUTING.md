# Contributing

Thank you for looking at this. The rules are short and they exist because the tool changes sign-in state on other people's computers.

## Every repair needs a Microsoft source

A new check or fix must point to a Microsoft article that documents it, added to `docs/sources.md` and named in the `-Source` argument of the finding. Community posts can inform a read-only check, marked as such, but never a change.

## Least destructive first, verified after

New actions go on the lowest rung that can fix the problem, behind `ShouldProcess`, behind the rung's approval, and end with a check that proves the change landed. An action that cannot be verified must record `NotVerified`, never `Applied` alone.

## Nothing is deleted

Removals move into the quarantine through `Move-ToQuarantine`. Registry keys are exported first. Anything that cannot be restored (a Store app reset, a credential) must say so in the restore instructions.

## Per-user work runs as the user

Do not read or write `HKEY_USERS\<sid>` or another profile's AppData to repair it. Use the existing pattern: the tool re-launches itself in that user's session.

## Test before you open a pull request

```powershell
.\scripts\Test-RepairM365SignIn.ps1
```

All thirty checks must pass on Windows PowerShell 5.1 and PowerShell 7. Extend the shadow module when your change calls a Windows dependency the test does not fake yet.

## Style

Plain sentences. No emoji. Comments only where a reader would otherwise wonder why. `Set-StrictMode -Version Latest` stays on; guard every optional property.
