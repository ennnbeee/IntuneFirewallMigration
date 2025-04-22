# 🔥🧱🪄 IntuneFirewallMigration

IntuneFirewallMigration is an updated version of the no longer available [Microsoft tool](https://learn.microsoft.com/en-us/mem/intune/protect/endpoint-security-firewall-rule-tool) which was removed in June 2024:

![Firewall Migration Tool](/img/mstool.png)

This version is a streamlined version of the previous tool with the following changes:

- **Uses Settings Catalog firewall rule policies natively**
- Removed the reliance on the old Microsoft GitHub repository.
- Changed to the `Microsoft.Graph.Authentication` PowerShell module.
- Changed to `Invoke-MgGraphRequest` for calls to Graph.
- Disabled and removed all telemetry functions and calls.
- Fixed issues when checking for profile name matching when there are no existing firewall rule policies.
- Resolved issues with module `Microsoft.Graph` version 2.26.1 module on PowerShell 5.

## ⚠ Public Preview Notice

IntuneFirewallMigration is currently in Public Preview, meaning that although it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create an issue.

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 5 and 7 on Windows
> - `Microsoft.Graph.Authentication` the script will detect and install if required.
> - `ImportExcel` the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account.

## 🔄 Updates

- **v0.2**
  - Creates Setting Catalog policies as standard
  - Allows for creation of legacy Endpoint Security policies using the `legacyProfile` switch
- v0.1
  - Initial release

## 🔑 Permissions

The PowerShell script requires the below Graph API permissions, you can create an Entra ID App Registration with the following Graph API Application permissions:

- `DeviceManagementConfiguration.ReadWrite.All`
- `DeviceManagementManagedDevices.ReadWrite.All`

The script can then be authenticated by passing in the App Registration details:

```PowerShell
$tenantId = '437e8ffb-3030-469a-99da-e5b527908001'
$appId = '375793fc-0132-4938-bc80-a907e5cba4d0'
$appSecret = 'supersecretstuff'

.\IntuneFirewallMigration.ps1 -profileName TestMigration -tenantId $tenantId -appId $appId -appSecret $appSecret
```

## ⏯ Usage

Clone or download this repository to the Windows machine where you want to capture Firewall Rules, then execute the following commands from within the extracted or cloned folder:

### 🧪 Testing

Creates **Settings Catalog** Firewall rule profiles with the name prefix `TestMigration` using only the first **20** **enabled** **Group Policy** applied firewall rules:

```powershell
.\IntuneFirewallMigration.ps1 -profileName TestMigration -mode Test
```

### 🧱 General Usage

Creates **Settings Catalog** Firewall rule profiles with the name prefix `TestMigration` with **100** rules per profile, using all **enabled** **Group Policy** applied firewall rules:

```powershell
.\IntuneFirewallMigration.ps1 -profileName TestMigration
```

### 🏠 Local Rules

Creates **Settings Catalog** Firewall rule profiles with the name prefix `TestMigration` with **70** rules per profile, using all **enabled** **Group Policy and Locally** applied firewall rules:

```powershell
.\IntuneFirewallMigration.ps1 -profileName TestMigration -includeLocalRules -splitRules 70
```

### 📐 Disabled Rules

Creates **Settings Catalog** Firewall rule profiles with the name prefix `TestMigration` with **50** rules per profile, using all **enabled and disabled** **Group Policy** applied firewall rules:

```powershell
.\IntuneFirewallMigration.ps1 -profileName TestMigration -includeDisabledRules -splitRules 50
```

### ⚙ Endpoint Security Profiles

Creates **Endpoint Security** Firewall rule profiles with the name prefix `TestMigration` with **100** rules per profile, using all **enabled** **Group Policy** applied firewall rules:

```powershell
.\IntuneFirewallMigration.ps1 -profileName TestMigration -legacyProfile
```

## 🚑 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/ennnbeee/IntuneFirewallMigration/issues) page
2. Open a new issue if needed

Thank you for your support.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Created by [Nick Benton](https://github.com/ennnbeee) of [odds+endpoints](https://www.oddsandendpoints.co.uk/)
