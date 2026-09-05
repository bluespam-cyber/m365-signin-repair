# Sources

Every check and repair in Repair-M365SignIn.ps1 traces to one of the Microsoft articles below. The research behind the tool covered 126 documented checks and fixes across five areas; codes and paths that Microsoft does not document individually are marked as family-routed in the decoder and never trigger a change.

## Identity broker, device registration, Windows Hello

- [Authentication automatically fails in Microsoft 365 services](https://learn.microsoft.com/en-us/troubleshoot/microsoft-365/admin/authentication/automatic-authentication-fails)
- [Configure device proxy and internet connection settings (WinHTTP)](https://learn.microsoft.com/en-us/purview/device-onboarding-configure-proxy)
- [Diagnostic logging for troubleshooting Workplace Join issues (CAPI2)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/diagnostic-logging-troubleshoot-workplace-join-issues)
- [Error AADSTS500011: Resource Principal Not Found](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/error-code-aadsts500011-resource-principal-not-found)
- [Errors associated with Web Account Manager (WAM)](https://learn.microsoft.com/en-us/entra/msal/dotnet/advanced/exceptions/wam-errors)
- [Event 1098 Error 0xCAA5001C Token broker operation failed](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/event-1098-error-0xcaa5001c)
- [Microsoft Entra authentication & authorization error codes (AADSTS)](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- [Microsoft Entra devices FAQ (BlockAADWorkplaceJoin)](https://learn.microsoft.com/en-us/entra/identity/devices/faq)
- [PIN reset (Windows Hello for Business)](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/pin-reset)
- [Troubleshoot devices by using the dsregcmd command](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd)
- [Troubleshoot Microsoft Entra hybrid joined devices](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-hybrid-join-windows-current)
- [Troubleshoot primary refresh token issues on Windows devices](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-primary-refresh-token)
- [Troubleshoot Windows device access for school or work (Intune)](https://learn.microsoft.com/en-us/intune/user-help/troubleshooting/troubleshoot-device-access-windows)
- [Use Remediations to Detect and Fix Support Issues](https://learn.microsoft.com/en-us/intune/device-management/tools/deploy-remediations)
- [Using MSAL.NET with Web Account Manager (WAM)](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/desktop-mobile/wam)
- [Windows Hello errors during PIN creation](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-errors-during-pin-creation)
- [Windows Hello for Business known deployment issues](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-deployment-issues)

## Office and Outlook activation and sign-in

- [Add-AppxProvisionedPackage (DISM)](https://learn.microsoft.com/en-us/powershell/module/dism/add-appxprovisionedpackage)
- [Can't sign in or activate Outlook and Microsoft 365 applications (NIC/IPv4 checksum)](https://learn.microsoft.com/en-us/troubleshoot/outlook/connectivity/outlook-cannot-signin-activate)
- [Check the license and activation status for Microsoft 365 Apps (vnextdiag.ps1)](https://learn.microsoft.com/en-us/microsoft-365-apps/licensing-activation/vnextdiag)
- [Enterprise version of Microsoft Support and Recovery Assistant (download)](https://www.microsoft.com/en-us/download/details.aspx?id=103391)
- [Modern Authentication configuration requirements (EnableADAL/Version)](https://learn.microsoft.com/en-us/troubleshoot/exchange/administration/modern-authentication-configuration)
- [Office error code 0x8004FC12 when activating Office](https://support.microsoft.com/en-us/microsoft-365-activation-licensing/office-error-code-0x8004fc12-when-activating-office)
- [Outlook 2016 implementation of Autodiscover (Exclude* control values)](https://support.microsoft.com/en-us/outlook/outlook-2016-implementation-of-autodiscover)
- [Outlook prompts for password when Modern Authentication is enabled (KB 3126599)](https://learn.microsoft.com/en-us/troubleshoot/outlook/authentication/outlook-prompt-password-modern-authentication-enabled)
- [Overview of shared computer activation for Microsoft 365 Apps](https://learn.microsoft.com/en-us/microsoft-365-apps/licensing-activation/overview-shared-computer-activation)
- [Reset activation state for Microsoft 365 Apps for enterprise](https://learn.microsoft.com/en-us/troubleshoot/microsoft-365-apps/activation/reset-activation-state)
- [Tools to manage volume activation of Office (ospp.vbs)](https://learn.microsoft.com/en-us/office/volume-license-activation/tools-to-manage-volume-activation-of-office)
- [Unlicensed Product and activation errors in Office](https://support.microsoft.com/en-us/microsoft-365-activation-licensing/office-install/unlicensed-product-and-activation-errors-in-office)

## OneDrive

- [Error Code 0x8004de40 or 0x8004de88 when signing in to OneDrive](https://learn.microsoft.com/en-us/troubleshoot/sharepoint/sync/error-0x8004de40-in-onedrive)
- [Install the sync app per-machine (Windows)](https://learn.microsoft.com/en-us/sharepoint/per-machine-installation)
- [IT Admins: Use OneDrive policies to control sync settings (Group Policy)](https://learn.microsoft.com/en-us/sharepoint/use-group-policy)
- [Reinstall OneDrive](https://support.microsoft.com/en-us/onedrive/reinstall-onedrive)
- [Reset OneDrive (Microsoft Support)](https://support.microsoft.com/en-us/onedrive/reset-onedrive)
- [Silently configure user accounts](https://learn.microsoft.com/en-us/sharepoint/use-silent-account-configuration)
- [What do the OneDrive error codes mean?](https://support.microsoft.com/en-us/onedrive/what-do-the-onedrive-error-codes-mean)

## Teams

- [Bulk deploy the Microsoft Teams client (teamsbootstrapper, WebView2, CloudType)](https://learn.microsoft.com/en-us/microsoftteams/teams-client-bulk-install)
- [Clear the Teams client cache](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-administration/clear-teams-cache)
- [Collect Teams client diagnostic logs](https://learn.microsoft.com/en-us/microsoftteams/log-files)
- [Resolve sign-in errors in Teams](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-sign-in/resolve-sign-in-errors)
- [Resolve Teams Meeting add-in issues in classic Outlook](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/meetings/resolve-teams-meeting-add-in-issues)

## Network, TLS, time, certificates

- [Accounts: Block Microsoft accounts](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-block-microsoft-accounts)
- [Azure Certificate Authority details](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-certificate-authority-details)
- [Changes to the managed TLS feature](https://learn.microsoft.com/en-us/azure/security/fundamentals/managed-tls-changes)
- [Configure trusted roots and disallowed certificates in Windows](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates)
- [Disabling TLS 1.0 and 1.1 for Microsoft 365](https://learn.microsoft.com/en-us/purview/tls-1.0-and-1.1-deprecation-for-office-365)
- [Distribute the WebView2 Runtime (runtime storage needs)](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution)
- [How to enable TLS 1.2 on clients (Configuration Manager)](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/security/enable-tls-1-2-client)
- [KB3140245: Update to enable TLS 1.1/1.2 as default secure protocols in WinHTTP](https://support.microsoft.com/en-us/topic/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-winhttp-in-windows-c4bd73d2-31d7-761e-0178-11268bb10392)
- [Managing Microsoft 365 endpoints](https://learn.microsoft.com/en-us/microsoft-365/enterprise/managing-office-365-endpoints)
- [Maximum tolerance for computer clock synchronization](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-tolerance-for-computer-clock-synchronization)
- [Microsoft 365 IP Address and URL web service](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service)
- [Microsoft 365 network connectivity principles](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-network-connectivity-principles)
- [Microsoft 365 URLs and IP address ranges](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges)
- [Network Location Awareness Service Provider (NLA)](https://learn.microsoft.com/en-us/windows/win32/winsock/network-location-awareness-service-provider-nla--2)
- [Prepare for TLS 1.2 in Office 365 (KB4057306)](https://learn.microsoft.com/en-us/purview/prepare-tls-1.2-in-office-365)
- [Transport Layer Security (TLS) best practices with .NET Framework](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls)
- [Transport Layer Security (TLS) registry settings](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)
- [Windows 10 end of support and Microsoft 365 Apps](https://learn.microsoft.com/en-us/microsoft-365-apps/end-of-support/windows-10-support)
- [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/Windows-Time-Service-Tools-and-Settings)

## Tooling, logs, Intune

- [certutil (Windows commands reference)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [Command line version of Get Help (formerly SaRA)](https://learn.microsoft.com/en-us/troubleshoot/microsoft-365/admin/miscellaneous/get-help-command-line-overview)
- [How to enable global and advanced logging for Microsoft Outlook](https://support.microsoft.com/en-us/outlook/how-to-enable-global-and-advanced-logging-for-microsoft-outlook)
- [Microsoft 365 troubleshooters (Get Help)](https://support.microsoft.com/en-us/support/get-help/microsoft-365-troubleshooters)
- [Scenario: Reset Office Activation (command‑line Get Help)](https://learn.microsoft.com/en-us/troubleshoot/microsoft-365/admin/miscellaneous/get-help-reset-office-activation)

## Community (Microsoft Q&A and Tech Community, marked moderate or low confidence in the tool)

- ["You're missing out! Ask your admin to enable Microsoft Teams"](https://learn.microsoft.com/en-us/answers/questions/4439739/)
- [Error Code: CAA50021 (Microsoft Q&A)](https://learn.microsoft.com/en-us/answers/questions/992099/error-code-caa50021)
- [Error OOBE 80180018 (Microsoft Q&A)](https://learn.microsoft.com/en-us/answers/questions/5638429/error-oobe-80180018)
- [How do I troubleshoot activation error 0xC004F074?](https://learn.microsoft.com/en-us/answers/questions/5623228/how-do-i-troubleshoot-activation-error-0xc004f074)
- [How to repair Office 365 for business through command line (C2R repair switches)](https://learn.microsoft.com/en-us/answers/questions/4966654/how-to-repair-office-365-for-business-through-comm)
- [How to reset Outlook (new)](https://learn.microsoft.com/en-us/answers/questions/4614333/how-to-reset-outlook-new)
- [Microsoft Account Sign-In Assistant (wlidsvc)](https://learn.microsoft.com/en-us/answers/questions/5597296/microsoft-account-sign-in-assistant-service-wlidsv)
- [Microsoft OneDrive: Logs / info for IT administrators](https://learn.microsoft.com/en-us/answers/questions/2100978/)
- [Office keeps asking for password (Microsoft Q&A)](https://learn.microsoft.com/en-us/answers/questions/4986303/office-keeps-asking-for-password)
- [Outlook 2016/2021 keeps asking for password (E1): ExcludeExplicitO365Endpoint](https://learn.microsoft.com/en-us/answers/questions/1188423/outlook-2016-2021-pro-keeps-asking-for-password-e1)
- [Permanently remove cached Microsoft account (Credential Manager)](https://learn.microsoft.com/en-us/answers/questions/5826755/permanently-remove-cached-microsoft-account-its-pr)
- [Recurring Office365 auth prompts in RDS: DisableAADWAM](https://learn.microsoft.com/en-us/answers/questions/5819084/recurring-office365-authentication-prompts-in-rds)
- [WamDefaultSet : ERROR (0x80070520) (Microsoft Q&A)](https://learn.microsoft.com/en-us/answers/questions/2279186/wamdefaultset-error-0x80070520-when-signing-into-m)
- [Windows Cloud Files Filter Driver (CldFlt) getting disabled](https://learn.microsoft.com/en-us/answers/questions/5890390/)

## Corrections made during research

- The Support and Recovery Assistant command line (SaRAcmd.exe) is deprecated; the current tool is the command line version of Get Help (GetHelpCmd.exe). There is no OfficeSignInScenario and no -Script or -Silent switch in the current scenario table.
- AADSTS70008 means the refresh token expired through inactivity, not clock skew. The clock-skew code is AADSTS500133.
- 0x80090325 is SEC_E_UNTRUSTED_ROOT (certificate trust), not a time error.
- ospp.vbs is for volume licences only; subscription Microsoft 365 Apps are inspected with vnextdiag.ps1.
- SignInOptions accepts 0 to 3; there is no value 4.
- The Outlook value AlwaysPromptForCredentials under Outlook\Security is not documented by Microsoft; the setting lives in the account profile. The tool does not write it.
- Root certificate thumbprints were verified against the Azure Certificate Authority details page: DigiCert Global Root G2 is DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 and DigiCert Global Root CA is A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436.
