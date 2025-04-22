. "$PSScriptRoot\ConvertTo-IntuneFirewallRule.ps1"
. "$PSScriptRoot\Get-FirewallData.ps1"
. "$PSScriptRoot\..\Private\Strings.ps1"

function Export-NetFirewallRule {
    <#
    .SYNOPSIS
    Exports network firewall rules found on this host into Intune firewall rules.

    .DESCRIPTION
    Export-NetFirewallRule will export all network firewall rules found on the host and convert them into an
    intermediate IntuneFirewallRule object

    .EXAMPLE
    Export-NetFirewallRule
    Export-NetFirewallRule -PolicyStoreSource GroupPolicy
    Export-NetFirewallRule -PolicyStoreSource All
    Export-NetFirewallRule -splitConflictingAttributes

    .NOTES
    Export-NetFirewallRule is a wrapper for the cmdlet call to Get-NetFirewallRule piped to ConvertTo-IntuneFirewallRule.

    If -splitConflictingAttributes is toggled, then firewall rules with multiple attributes of filePath, serviceName,
    or packageFamilyName will automatically be processed and split instead of prompting users to split the firewall rule

    .LINK
    https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=win10-ps#description

    .OUTPUTS
    IntuneFirewallRule[]

    A stream of exported firewall rules represented via the intermediate IntuneFirewallRule class
    #>
    [CmdletBinding()]
    Param(
        #Defines the profile Name for the set of rules to be imported
        [Parameter(Mandatory = $true)]
        [String]
        $ProfileName,
        # Defines the policy store source to pull net firewall rules from.
        [ValidateSet('GroupPolicy', 'All')]
        [string] $PolicyStoreSource = 'GroupPolicy',
        # If this switch is toggled, only the firewall rules that are currently enabled are imported
        [boolean]
        $EnabledOnly = $True,
        # This determines if we are running a test version or a full importation. The default value is full. The test version imports only 20 rules
        [ValidateSet('Full', 'Test')]
        [String]
        $Mode = 'Full',

        [Parameter(HelpMessage = 'The number of rules per profiles to be exported.')]
        [ValidateRange(10, 100)]
        [int]$splitRules = 100,

        [Parameter(HelpMessage = 'When set, the script will use the legacy Endpoint Security profile format.')]
        [ValidateNotNullOrEmpty()]
        [switch]$legacyProfile,

        # If this flag is toggled, then firewall rules with multiple attributes of filePath, serviceName,
        # or packageFamilyName will not automatically be processed and split and the users will be prompted users to split
        [switch] $doNotsplitConflictingAttributes

    )

    # The default behaviour for Get-NetFirewallRule is to retrieve all WDFWAS firewall rules
    return $(Get-FirewallData -Enabled:$EnabledOnly -Mode:$Mode -PolicyStoreSource:$PolicyStoreSource | `
            ConvertTo-IntuneFirewallRule -doNotsplitConflictingAttributes:$doNotsplitConflictingAttributes | `
            Send-IntuneFirewallRulesPolicy -migratedProfileName:$ProfileName -splitRules:$splitRules -legacyProfile:$legacyProfile
    )

}