function Select-IntuneFirewallRule {
    <#
    .SYNOPSIS


    .DESCRIPTION
    This function updates incoming firewall rules based on the specified firewall profile.

    .EXAMPLE
    Select-IntuneFirewallRule -incomingRules $rules -firewallProfile domain

    .PARAMETER incomingRules
    The incoming firewall rules to be updated.

    .PARAMETER firewallProfile
    The firewall profile to filter the rules by. Valid values are 'all', 'domain', 'private', and 'public'.

    .NOTES

    .LINK

    .INPUTS

    .OUTPUTS

    #>

    [CmdletBinding()]
    param(

        [Parameter(ValueFromPipeline = $true)]
        $incomingRules,

        [Parameter()]
        [ValidateSet('all', 'domain', 'private', 'public')]
        $firewallProfile

    )

    begin {
        $fwRules = @()
        $updatedFWRules = @()
        $domainFWRules = @()
        $privateFWRules = @()
        $publicFWRules = @()
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

        if ($firewallProfile) {
            switch ($firewallProfile) {
                'domain' {
                    foreach ($fwRule in $fwRules) {
                        if ($fwRule.Profile -eq 'Domain' -or $fwRule.Profile -eq 'Any') {
                            $fwRule.Profile = 'Domain'
                            $domainFWRules += $fwRule
                        }
                    }
                    $updatedFWRules += $domainFWRules
                }
                'private' {
                    foreach ($fwRule in $fwRules) {
                        if ($fwRule.Profile -eq 'Private' -or $fwRule.Profile -eq 'Any') {
                            $fwRule.Profile = 'Private'
                            $privateFWRules += $fwRule
                        }
                    }
                    $updatedFWRules += $privateFWRules
                }
                'public' {
                    foreach ($fwRule in $fwRules) {
                        if ($fwRule.Profile -eq 'Public' -or $fwRule.Profile -eq 'Any') {
                            $fwRule.Profile = 'Public'
                            $publicFWRules += $fwRule
                        }
                    }
                    $updatedFWRules += $publicFWRules
                }
                'all' {
                    $updatedFWRules += $fwRules
                }
            }
        }
        else {
            $updatedFWRules += $fwRules
        }

        return $updatedFWRules
    }
}