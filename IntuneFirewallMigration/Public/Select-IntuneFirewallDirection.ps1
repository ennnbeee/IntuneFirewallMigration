function Select-IntuneFirewallDirection {
    <#
    .SYNOPSIS


    .DESCRIPTION
    This function updates incoming firewall rules based on their direction

    .EXAMPLE
    Select-IntuneFirewallDirection -incomingRules $rules -ruleDirection Inbound

    .PARAMETER incomingRules
    The incoming firewall rules to be updated.

    .PARAMETER ruleDirection
    The firewall rule direction to filter the rules by. Valid values are 'Inbound', 'Outbound', and 'All'.

    .NOTES

    .LINK

    .INPUTS

    .OUTPUTS

    #>

    [CmdletBinding()]
    param(

        [Parameter(ValueFromPipeline = $true)]
        $incomingRules,

        [Parameter(HelpMessage = 'The direction of the firewall rules to be exported. The default value is both.')]
        [ValidateSet('inbound', 'outbound', 'both')]
        [String]$ruleDirection

    )

    begin {
        $fwRules = @()
        $inboundRules = @()
        $outboundRules = @()

        $incomingRules = $rules
    }

    process {

        if ($incomingRules) {
            $fwRules += $incomingRules
        }
        else {
            $fwRules += $_
        }

    }

    end {

        if ($ruleDirection -ne 'both') {
            foreach ($fwRule in $fwRules) {

                if ($fwRule.Direction -eq 'Inbound') {
                    $inboundRules += $fwRule
                }
                if ($fwRule.Direction -eq 'Outbound') {
                    $outboundRules += $fwRule
                }
            }
            if ($ruleDirection -eq 'inbound') {
                $updatedFWRules = $inboundRules
            }
            else {
                $updatedFWRules = $outboundRules
            }
        }
        else {
            $updatedFWRules += $fwRules
        }

        return $updatedFWRules
    }
}