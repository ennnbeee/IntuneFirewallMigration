. "$PSScriptRoot\IntuneFirewallRule.ps1"
. "$PSScriptRoot\ExportTo-ExcelFile.ps1"
. "$PSScriptRoot\..\Private\ConvertTo-IntuneFirewallRule-Helper.ps1"
. "$PSScriptRoot\..\Private\Process-IntuneFirewallRules.ps1"
. "$PSScriptRoot\..\Private\Use-HelperFunctions.ps1"
. "$PSScriptRoot\..\Private\Strings.ps1"

function ConvertTo-IntuneFirewallRule {
    <#
    .SYNOPSIS
    Converts firewall rules to IntuneFirewallRule objects.

    .DESCRIPTION
    ConvertTo-IntuneFirewallRule takes a firewall rule object retrieved from Get-NetFirewallRule and converts it into an IntuneFirewallRule

    .EXAMPLE
    Get-NetFirewallRule | ConvertTo-IntuneFirewallRule
    Get-NetFirewallRule -PolicyStore RSOP | ConvertTo-IntuneFirewallRule -splitConflictingAttributes
    Get-NetFirewallRule -PolicyStore PersistentStore -PolicyStoreSourceType Local | ConvertTo-IntuneFirewallRule -splitConflictingAttributes

    .PARAMETER incomingFirewallRules a stream of firewall rules to be processed and converted

    .NOTES
    If -splitConflictingAttributes is toggled, then firewall rules with multiple attributes of filePath, serviceName,
    or packageFamilyName will automatically be processed and split instead of prompting users to split the firewall rule

    .LINK
    https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=win10-ps#description

    .INPUTS
    Microsoft.Management.Infrastructure.CimInstance#root\StandardCimv2\MSFT_NetFirewallRule[]

    A stream of network firewall rules retrieved from the NetSecurity module

    .OUTPUTS
    IntuneFirewallRule[]

    A stream of exported firewall rules represented via the intermediate IntuneFirewallRule class
    #>

    [CmdletBinding()]
    Param(
        # For testing purposes, we do not require that the object is strongly typed;
        # however, it will fail in general other cases if it is not a firewall rule object
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $incomingFirewallRules,
        # If this flag is toggled, then firewall rules with multiple attributes of filePath, serviceName,
        # or packageFamilyName will automatically be processed and split instead of prompting users to split
        [switch] $doNotSplitConflictingAttributes

    )

    Begin {
        $firewallRules = @()
        $rulesFailedToConvert = @()

    }

    Process {
        # Get-NetFirewallRule returns firewall rule objects pretty quickly,
        # so we can wait to pool the firewall rule objects into an array
        # to display the progress bars
        $firewallRules += $_
    }

    End {
        $intuneFirewallRuleObjects = @()
        $choice = ''
        $remainingFirewallRules = $firewallRules.Count

        ForEach ($firewallRule in $firewallRules) {
            Try {
                # remainingFirewallRules is decremented after displaying operation status
                $remainingFirewallRules = Show-OperationProgress `
                    -remainingObjects $remainingFirewallRules `
                    -totalObjects $firewallRules.Count `
                    -activityMessage $Strings.ConvertToIntuneFirewallRuleProgressMessage

                # Processing firewall rule objects for endpoint security
                $intuneFirewallRuleObject = New-IntuneFirewallRule
                # All of the attributes needed for firewall can be found, but they are typically scattered
                # by multiple cmdlet filters. Look in the link provided for more information
                $intuneFirewallRuleObject.displayName = Get-FirewallDisplayName $firewallRule
                $intuneFirewallRuleObject.description = $firewallRule.description
                $intuneFirewallRuleObject.packageFamilyName = Get-FirewallPackageFamilyName $firewallRule
                $intuneFirewallRuleObject.filePath = Get-FirewallFilePath $firewallRule
                $intuneFirewallRuleObject.serviceName = Get-FirewallServiceName $firewallRule
                $intuneFirewallRuleObject.protocol = Get-FirewallProtocol $firewallRule
                $intuneFirewallRuleObject.localPortRanges = Get-FirewallLocalPortRange $firewallRule
                $intuneFirewallRuleObject.remotePortRanges = Get-FirewallRemotePortRange $firewallRule
                $intuneFirewallRuleObject.actualLocalAddressRanges = Get-FirewallLocalAddressRange $firewallRule
                $intuneFirewallRuleObject.actualRemoteAddressRanges = Get-FirewallRemoteAddressRange $firewallRule
                $intuneFirewallRuleObject.profileTypes = Get-FirewallProfileType $firewallRule.Profiles
                $intuneFirewallRuleObject.action = Get-FirewallAction $firewallRule.Action
                $intuneFirewallRuleObject.trafficDirection = Get-FirewallDirection $firewallRule.Direction
                $intuneFirewallRuleObject.interfaceTypes = Get-FirewallInterfaceType $firewallRule
                $intuneFirewallRuleObject.localUserAuthorizations = Get-FirewallLocalUserAuthorization $firewallRule
                $intuneFirewallRuleObject.useAnyLocalAddressRange = Get-useAnyLocalAddressRangeOption $firewallRule
                $intuneFirewallRuleObject.useAnyRemoteAddressRange = Get-useAnyRemoteAddressRangeOption $firewallRule

                # Check to see if a firewall rule needs to be split, and prompts the user if they want to split
                If (Test-IntuneFirewallRuleSplit -firewallObject $intuneFirewallRuleObject) {

                    $splitFirewallRuleChoice = Get-SplitIntuneFirewallRuleChoice `
                        -splitConflictingAttributes $doNotSplitConflictingAttributes `
                        -firewallObject $intuneFirewallRuleObject
                    $splittedFirewallRuleObjects = Split-IntuneFirewallRule -firewallObject $intuneFirewallRuleObject
                    Switch ($splitFirewallRuleChoice) {
                        $Strings.Yes { $intuneFirewallRuleObjects += $splittedFirewallRuleObjects }
                        $Strings.No { Throw $Strings.ConvertToIntuneFirewallRuleNoSplit }
                        $Strings.YesToAll {
                            $intuneFirewallRuleObjects += $splittedFirewallRuleObjects
                            # Allows future splitting operations to continue without user prompt
                            $doNotSplitConflictingAttributes = $false
                        }
                        $Strings.Continue { continue }
                    }
                }
                Else {
                    $intuneFirewallRuleObjects += $intuneFirewallRuleObject
                }
            }
            Catch {

                # Add items that failed to be formatted to a collection of objects to be exported to an excel file
                $newExcelObject = New-Object -TypeName ExcelFormat
                $newExcelObject.displayName = $firewallRule.DisplayName
                $newExcelObject.description = $firewallRule.Description
                $newExcelObject.trafficDirection = $firewallRule.Direction
                $newExcelObject.action = $firewallRule.Action
                $newExcelObject.errorMessage = $errorMessage
                $rulesFailedToConvert += $newExcelObject

            }
        }
        # Create an excel file with information about the items that where incompatible with Intune format
        Export-ExcelFile -fileName 'RuleError' -failedToConvert $rulesFailedToConvert
        Set-SummaryDetail -numberOfFirewallRules $firewallRules.Count -ConvertedRulesNumber ($firewallRules.Count - $rulesFailedToConvert.Count )
        return $intuneFirewallRuleObjects
    }
}