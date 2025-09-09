$testRule = '_localaddressrange'
$profileName = 'TestProfile'
$mode = 'full'
$EnabledOnly = $true
$policyStoreSource = 'All'
$splitRules = 100
$legacyProfile = $false
$firewallProfile = 'domain'
$ruleDirection = 'inbound'


Export-NetFirewallRule -ProfileName $profileName -EnabledOnly:$EnabledOnly -PolicyStoreSource:$policyStoreSource -Mode $mode -splitRules $splitRules -legacyProfile:$legacyProfile -firewallProfile:$firewallProfile -ruleDirection:$ruleDirection


$rules = Get-FirewallData -Enabled:$EnabledOnly -Mode:$Mode -PolicyStoreSource:$PolicyStoreSource
$rulesFiltered = $rules | Where-Object { $_.DisplayName -eq $testRule }

$rulesDirection = $rulesFiltered | Select-IntuneFirewallDirection -ruleDirection:$ruleDirection
$rulesProfile = $rulesDirection |Select-IntuneFirewallRule -firewallProfile:$firewallProfile
$rulesIntune = $rulesProfile | ConvertTo-IntuneFirewallRule -doNotSplitConflictingAttributes:$doNotSplitConflictingAttributes
$rulesIntune | ConvertTo-IntuneSCFirewallRule
$rulesIntune | Send-IntuneFirewallRulesPolicy -migratedProfileName:$ProfileName -splitRules:$splitRules -legacyProfile:$legacyProfile -firewallProfile:$firewallProfile -ruleDirection:$ruleDirection