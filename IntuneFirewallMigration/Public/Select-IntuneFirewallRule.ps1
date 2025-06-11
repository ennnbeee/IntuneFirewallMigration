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
    Param(

        [Parameter(ValueFromPipeline = $true)]
        $incomingRules,

        [Parameter()]
        [ValidateSet('all', 'domain', 'private', 'public', 'notConfigured')]
        $firewallProfile

    )

    Begin {
        $fwRules = @()
        $updatedFWRules = @()
        $domainFWRules = @()
        $privateFWRules = @()
        $publicFWRules = @()
        $notConfiguredFWRules = @()

    }

    Process {

        if ($incomingRules) {
            $fwRules += $incomingRules
        }
        else {
            $fwRules += $_
        }

    }

    End {

        foreach ($fwRule in $fwRules) {

            if ($fwRule.profileTypes -contains 'domain') {
                $domainFWRules += [PSCustomObject]@{
                    'displayName'               = $fwRule.displayName
                    'description'               = $fwRule.description
                    'packageFamilyName'         = $fwRule.packageFamilyName
                    'filePath'                  = $fwRule.filePath
                    'serviceName'               = $fwRule.serviceName
                    'protocol'                  = $fwRule.protocol
                    'localPortRanges'           = $fwRule.localPortRanges
                    'remotePortRanges'          = $fwRule.remotePortRanges
                    'actualLocalAddressRanges'  = $fwRule.actualLocalAddressRanges
                    'actualRemoteAddressRanges' = $fwRule.actualRemoteAddressRanges
                    'profileTypes'              = @('domain')
                    'action'                    = $fwRule.action
                    'trafficDirection'          = $fwRule.trafficDirection
                    'interfaceTypes'            = $fwRule.interfaceTypes
                    'localUserAuthorizations'   = $fwRule.localUserAuthorizations
                    'useAnyRemoteAddressRange'  = $fwRule.useAnyRemoteAddressRange
                    'useAnyLocalAddressRange'  = $fwRule.useAnyLocalAddressRange
                }
            }
            if ($fwRule.profileTypes -contains 'private') {
                $privateFWRules += [PSCustomObject]@{
                    'displayName'               = $fwRule.displayName
                    'description'               = $fwRule.description
                    'packageFamilyName'         = $fwRule.packageFamilyName
                    'filePath'                  = $fwRule.filePath
                    'serviceName'               = $fwRule.serviceName
                    'protocol'                  = $fwRule.protocol
                    'localPortRanges'           = $fwRule.localPortRanges
                    'remotePortRanges'          = $fwRule.remotePortRanges
                    'actualLocalAddressRanges'  = $fwRule.actualLocalAddressRanges
                    'actualRemoteAddressRanges' = $fwRule.actualRemoteAddressRanges
                    'profileTypes'              = @('private')
                    'action'                    = $fwRule.action
                    'trafficDirection'          = $fwRule.trafficDirection
                    'interfaceTypes'            = $fwRule.interfaceTypes
                    'localUserAuthorizations'   = $fwRule.localUserAuthorizations
                    'useAnyRemoteAddressRange'  = $fwRule.useAnyRemoteAddressRange
                    'useAnyLocalAddressRange'  = $fwRule.useAnyLocalAddressRange
                }
            }
            if ($fwRule.profileTypes -contains 'public') {
                $publicFWRules += [PSCustomObject]@{
                    'displayName'               = $fwRule.displayName
                    'description'               = $fwRule.description
                    'packageFamilyName'         = $fwRule.packageFamilyName
                    'filePath'                  = $fwRule.filePath
                    'serviceName'               = $fwRule.serviceName
                    'protocol'                  = $fwRule.protocol
                    'localPortRanges'           = $fwRule.localPortRanges
                    'remotePortRanges'          = $fwRule.remotePortRanges
                    'actualLocalAddressRanges'  = $fwRule.actualLocalAddressRanges
                    'actualRemoteAddressRanges' = $fwRule.actualRemoteAddressRanges
                    'profileTypes'              = @('public')
                    'action'                    = $fwRule.action
                    'trafficDirection'          = $fwRule.trafficDirection
                    'interfaceTypes'            = $fwRule.interfaceTypes
                    'localUserAuthorizations'   = $fwRule.localUserAuthorizations
                    'useAnyRemoteAddressRange'  = $fwRule.useAnyRemoteAddressRange
                    'useAnyLocalAddressRange'  = $fwRule.useAnyLocalAddressRange
                }
            }
            if ($fwRule.profileTypes -eq 'notConfigured') {
                $notConfiguredFWRules += [PSCustomObject]@{
                    'displayName'               = $fwRule.displayName
                    'description'               = $fwRule.description
                    'packageFamilyName'         = $fwRule.packageFamilyName
                    'filePath'                  = $fwRule.filePath
                    'serviceName'               = $fwRule.serviceName
                    'protocol'                  = $fwRule.protocol
                    'localPortRanges'           = $fwRule.localPortRanges
                    'remotePortRanges'          = $fwRule.remotePortRanges
                    'actualLocalAddressRanges'  = $fwRule.actualLocalAddressRanges
                    'actualRemoteAddressRanges' = $fwRule.actualRemoteAddressRanges
                    'profileTypes'              = $fwRule.profileTypes
                    'action'                    = $fwRule.action
                    'trafficDirection'          = $fwRule.trafficDirection
                    'interfaceTypes'            = $fwRule.interfaceTypes
                    'localUserAuthorizations'   = $fwRule.localUserAuthorizations
                    'useAnyRemoteAddressRange'  = $fwRule.useAnyRemoteAddressRange
                    'useAnyLocalAddressRange'  = $fwRule.useAnyLocalAddressRange
                }
            }

        }

        if ($firewallProfile) {
            switch ($firewallProfile) {
                'domain' {
                    $updatedFWRules += $domainFWRules
                }
                'private' {
                    $updatedFWRules += $privateFWRules
                }
                'public' {
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