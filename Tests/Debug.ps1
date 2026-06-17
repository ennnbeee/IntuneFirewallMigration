# variables
$profileName = 'TestProfile'
$mode = 'test'
$EnabledOnly = $true
$policyStoreSource = 'All'
$splitRules = 100
$legacyProfile = $false
$firewallProfile = 'all'
$ruleDirection = 'both'

# check for admin rights
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity

if (!$principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host -ForegroundColor Red 'Error:  Must run elevated: run as administrator'
    Write-Host 'No commands completed'
    return
}

# check for PowerShell 5
if ($PSVersionTable.PSVersion.Major -gt 5) {
    Write-Host "Warning: Running PowerShell version $($PSVersionTable.PSVersion). This debug script needs to be launched in PowerShell 5" -ForegroundColor Yellow
    exit
}

# modules
Import-Module '.\IntuneFirewallMigration.psm1' -Force
Import-Module '.\IntuneFirewallMigration\Private\Strings.ps1' -Force


#Export-NetFirewallRule -ProfileName $profileName -EnabledOnly:$EnabledOnly -PolicyStoreSource:$policyStoreSource -Mode $mode -splitRules $splitRules -legacyProfile:$legacyProfile -firewallProfile:$firewallProfile -ruleDirection:$ruleDirection

# gets rules
$rules = Get-FirewallData -Enabled:$EnabledOnly -Mode:$Mode -PolicyStoreSource:$PolicyStoreSource
# converts to intune rules
$rulesIntune = $rules | ConvertTo-IntuneFirewallRule -doNotSplitConflictingAttributes:$doNotSplitConflictingAttributes
# rule direction
$rulesIntuneDirection = $rulesIntune | Select-IntuneFirewallDirection -ruleDirection:$ruleDirection
# firewall profile
$rulesIntuneProfile = $rulesIntuneDirection | Select-IntuneFirewallRule -firewallProfile:$firewallProfile

# authenticate to graph
$requiredScope = 'DeviceManagementConfiguration.ReadWrite.All'
Connect-MgGraph -Scopes $requiredScope -NoWelcome -ErrorAction Stop

# send rules to intune
$rulesIntuneProfile | Send-IntuneFirewallRulesPolicy -migratedProfileName:$ProfileName -splitRules:$splitRules -legacyProfile:$legacyProfile -firewallProfile:$firewallProfile -ruleDirection:$ruleDirection