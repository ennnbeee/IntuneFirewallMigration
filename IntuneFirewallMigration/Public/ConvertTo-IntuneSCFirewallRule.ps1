function ConvertTo-IntuneSCFirewallRule {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .EXAMPLE

    .PARAMETER incomingProfile a Intune Endpoint Security policy object to be processed and converted to Settings Catalog JSON

    .NOTES

    .LINK

    .INPUTS

    .OUTPUTS

    #>

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $incomingProfile

    )

    Begin {
        $scJSONAllRules = @()

    }

    Process {
        try {
            $jsonProfile = $_ | Out-String | ConvertFrom-Json
        }
        catch {
            Write-Error 'Failed to convert incoming profile to JSON. Please check the input.'
            return
        }
        $scPolicyName = $jsonProfile.displayName
        $scPolicyDescription = $jsonProfile.description
        $fwRules = Get-Unique -InputObject ($jsonProfile.settingsDelta.valueJson | ConvertFrom-Json)
        $JSONPolicyStart = @"
        {
            "description": "$scPolicyDescription",
            "name": "$scPolicyName",
            "platforms": "windows10",
            "technologies@odata.type": "#microsoft.graph.deviceManagementConfigurationTechnologies",
            "technologies": "mdm,microsoftSense",
            "templateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicyTemplateReference",
                "templateId": "19c8aa67-f286-4861-9aa0-f23541d31680_1",
                "templateFamily@odata.type": "#microsoft.graph.deviceManagementConfigurationTemplateFamily",
                "templateFamily": "endpointSecurityFirewall",
                "templateDisplayName": "Microsoft Defender Firewall Rules",
                "templateDisplayVersion": "Version 1"
            },
            "settings": [
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                    "settingInstance": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}",
                        "settingInstanceTemplateReference": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                            "settingInstanceTemplateId": "76c7a8be-67d2-44bf-81a5-38c94926b1a1"
                        },
                        "groupSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationGroupSettingValue)",
                        "groupSettingCollectionValue": [

"@

        $JSONPolicyEnd = @'
                        ]
                    }
                }
            ]
        }
'@

        # Capturing existing rules with duplicate names, as Settings Catalog will not allow duplicates
        $duplicateRules = $fwRules | Group-Object -Property displayName | Where-Object { $_.count -gt 1 }
    }

    End {
        foreach ($fwRule in $fwRules) {

            # Blank Out variables as not all rules have each variable
            Clear-Variable JSONRule*
            Clear-Variable -Name ('ruleName', 'ruleDescription', 'ruleDirection', 'ruleAction', 'ruleFWProfiles', 'rulePackageFamilyName', 'ruleFilePath', 'ruleService', 'ruleProtocol', 'ruleLocalPorts', 'ruleRemotePorts', 'ruleInterfaces', 'ruleUseAnyLocalAddresses', 'ruleLocalAddresses', 'ruleUseAnyRemoteAddresses', 'ruleRemoteAddresses') -ErrorAction Ignore

            # Capturing the Rule Data
            $ruleName = ($fwRule.displayName)
            if ($duplicateRules.Group -contains $fwRule) {
                $ruleName = $ruleName + '-' + ($duplicateRules.Group | Where-Object { $_.displayName -eq $fwRule.displayName }).indexof($fwRule)
            }

            $ruleName = $ruleName.Replace('\', '\\')
            $ruleDescription = $fwRule.description
            $ruleDirection = $fwRule.trafficDirection
            $ruleAction = $fwRule.action
            $ruleFWProfiles = $fwRule.profileTypes
            $rulePackageFamilyName = $fwRule.packageFamilyName
            $ruleFilePath = ($fwRule.filePath).Replace('\', '\\')
            $ruleService = $fwRule.serviceName
            $ruleProtocol = $fwRule.protocol
            $ruleLocalPorts = $fwRule.localPortRanges
            $ruleRemotePorts = $fwRule.remotePortRanges
            $ruleInterfaces = $fwRule.interfaceTypes
            $ruleAuthUsers = $fwRule.localUserAuthorizations
            $ruleUseAnyLocalAddresses = $fwRule.useAnyLocalAddressRange
            $ruleLocalAddresses = $fwRule.actualLocalAddressRanges
            $ruleUseAnyRemoteAddresses = $fwRule.useAnyRemoteAddressRange
            $ruleRemoteAddresses = $fwRule.actualRemoteAddressRanges

            # Setting the Start of each rule
            $JSONRuleStart = @'
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingValue",
        "settingValueTemplateReference": null,
        "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
        "children": [
'@

            # JSON data is different for first rule in the policy
            if ($fwRule -eq $fwRules[0]) {
                # Rule Name
                $JSONRuleName = @"
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_name",
        "settingInstanceTemplateReference": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
            "settingInstanceTemplateId": "116a696a-3270-493e-9938-c336cf05ea98"
        },
        "simpleSettingValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
            "value": "$ruleName",
            "settingValueTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingValueTemplateReference",
                "settingValueTemplateId": "12994a33-6185-4c3d-a0e8-69316f6293ea",
                "useTemplateDefault": false
            }
        }
    },

"@

                # Rule State (Enabled)
                $JSONRuleState = @'
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_enabled",
        "settingInstanceTemplateReference": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
            "settingInstanceTemplateId": "4e150e1a-6a10-49b2-a20c-911bf44ea767"
        },
        "choiceSettingValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
            "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_enabled_1",
            "settingValueTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingValueTemplateReference",
                "settingValueTemplateId": "7562f243-f281-4f6f-b7e6-ecdb76dc1f1b",
                "useTemplateDefault": false
            },
            "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
            "children": []
        }
    },

'@

                # Rule Direction
                $JSONRuleDirection = @"
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction",
        "settingInstanceTemplateReference": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
            "settingInstanceTemplateId": "2114ad3d-157c-47d3-b646-60fcf50949c7"
        },
        "choiceSettingValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
            "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction_$ruleDirection",
            "settingValueTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingValueTemplateReference",
                "settingValueTemplateId": "8b45e13b-952d-4164-bbac-37f4e97b7985",
                "useTemplateDefault": false
            },
            "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
            "children": []
        }
    },

"@
                # Protocol
                if ($null -ne $ruleProtocol) {
                    $JSONRuleProtocol = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_protocol",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "b8f45398-674f-40c3-ab18-e002aa8e589b"
                },
            "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                "value": "$ruleProtocol",
                "settingValueTemplateReference": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingValueTemplateReference",
                    "settingValueTemplateId": "27d0d86c-d87d-473b-a41c-eef503d8baec",
                    "useTemplateDefault": false
                }
            }
        },

"@
                }

                # Local Address Ranges
                if ($ruleUseAnyLocalAddresses -eq $false) {
                    $JSONRuleLocalAddressRangeStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_localaddressranges",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "8b5de251-c683-4440-91d6-3b679b0aa5aa"
            },
            "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
            "simpleSettingCollectionValue": [

'@
                    $JSONLocalAddresses = @()
                    foreach ($ruleLocalAddress in $ruleLocalAddresses) {
                        # Last address in the set
                        if (($ruleLocalAddress -eq $ruleLocalAddresses[-1]) -or ($ruleLocalAddresses.count -eq '1')) {
                            $JSONRuleLocalAddress = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleLocalAddress"
                }

"@
                        }
                        else {
                            $JSONRuleLocalAddress = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleLocalAddress"
                },

"@
                        }
                        $JSONLocalAddresses += $JSONRuleLocalAddress
                    }
                    $JSONRuleLocalAddressRangeEnd = @'

            ]
        },

'@
                    $JSONRuleLocalAddressRange = $JSONRuleLocalAddressRangeStart + $JSONLocalAddresses + $JSONRuleLocalAddressRangeEnd
                }

                # Interface Type
                if ($ruleInterfaces -ne 'notConfigured') {
                    $JSONRuleInterface = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_interfacetypes",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "406b5410-e52e-4df3-933f-1ee6e550a5c8"
            },
            "choiceSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationChoiceSettingValue)",
            "choiceSettingCollectionValue": [
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_interfacetypes_all",
                    "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
                    "children": []
                }
            ]
        },

'@
                }

                # Package Family Name
                If (!([string]::IsNullOrEmpty($rulePackageFamilyName))) {
                    $JSONRulePackageFamily = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_app_packagefamilyname",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "1a91448b-b04e-4cb0-a80c-10ec64addfda"
            },
            "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                "value": "$rulePackageFamilyName",
                "settingValueTemplateReference": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingValueTemplateReference",
                    "settingValueTemplateId": "a9b123c6-1c6f-4de3-8840-34f91dfb9422",
                    "useTemplateDefault": false
                }
            }
        },

"@
                }

                # App File Path
                if (!([string]::IsNullOrEmpty($ruleFilePath))) {
                    $JSONRuleFilePath = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_app_filepath",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "dd825fa0-961b-4fcc-a6b3-4d2dc0419d4e"
            },
            "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                "value": "$ruleFilePath",
                "settingValueTemplateReference": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingValueTemplateReference",
                    "settingValueTemplateId": "8c94fefa-67e5-40b5-8d97-6fca4f0c1e98",
                    "useTemplateDefault": false
                }
            }
        },

"@
                }

                # Authorized Users
                if (!([string]::IsNullOrEmpty($ruleAuthUsers))) {
                    $JSONRuleAuthUsersStart = @'
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_localuserauthorizedlist",
                "settingInstanceTemplateReference": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                    "settingInstanceTemplateId": "b11c8e7d-babc-4899-a4b4-04683b898faa"
                },
                "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
                "simpleSettingCollectionValue": [

'@
                    $JSONAuthUsers = @()
                    foreach ($ruleAuthUser in $ruleAuthUsers) {
                        # Last address in the set
                        if (($ruleAuthUser -eq $ruleAuthUsers[-1]) -or ($ruleAuthUsers.count -eq '1')) {
                            $JSONRuleAuthUser = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleAuthUser"
                }

"@
                        }
                        else {
                            $JSONRuleAuthUser = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleAuthUser"
                },

"@
                        }
                        $JSONAuthUsers += $JSONRuleAuthUser
                    }
                    $JSONRuleAuthUsersEnd = @'

            ]
        },
'@
                    $JSONRuleAuthUsers = $JSONRuleAuthUsersStart + $JSONAuthUsers + $JSONRuleAuthUsersEnd
                }
                # Remote Ports
                if (!([string]::IsNullOrEmpty($ruleRemotePorts))) {
                    $JSONRuleRemotePortsStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_remoteportranges",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "de5d058e-ab1d-4772-81f5-32b6a35b4587"
            },
            "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
            "simpleSettingCollectionValue": [

'@
                    $JSONRemotePorts = @()
                    foreach ($ruleRemotePort in $ruleRemotePorts) {
                        # Last address in the set
                        if (($ruleRemotePort -eq $ruleRemotePorts[-1]) -or ($ruleRemotePorts.count -eq '1')) {
                            $JSONRuleRemotePort = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleRemotePort"
                }

"@
                        }
                        else {
                            $JSONRuleRemotePort = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleRemotePort"
                },

"@
                        }
                        $JSONRemotePorts += $JSONRuleRemotePort
                    }
                    $JSONRuleRemotePortsEnd = @'

            ]
        },

'@
                    $JSONRuleRemotePorts = $JSONRuleRemotePortsStart + $JSONRemotePorts + $JSONRuleRemotePortsEnd
                }

                # Firewall Profile
                if ($ruleFWProfiles -ne 'notConfigured') {
                    $JSONRuleFWProfileStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "7dc9b243-cdd2-4359-b5f5-0c48edb8fd34"
            },
            "choiceSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationChoiceSettingValue)",
            "choiceSettingCollectionValue": [

'@

                    $JSONRuleFWProfileTypes = @()
                    foreach ($ruleFWProfile in $ruleFWProfiles) {
                        Switch ($ruleFWProfile) {
                            'domain' { $ruleFWProfileNo = '1' }
                            'private' { $ruleFWProfileNo = '2' }
                            'public' { $ruleFWProfileNo = '4' }
                        }

                        if (($ruleFWProfile -eq $ruleFWProfiles[-1]) -or ($ruleFWProfiles.count -eq '1')) {
                            $JSONRuleFWProfileType = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_$ruleFWProfileNo",
                    "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
                    "children": []
                }

"@
                        }
                        else {
                            $JSONRuleFWProfileType = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_$ruleFWProfileNo",
                    "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
                    "children": []
                },

"@
                        }

                        $JSONRuleFWProfileTypes += $JSONRuleFWProfileType
                    }

                    $JSONRuleFWProfileEnd = @'
            ]
        },

'@

                    $JSONRuleFWProfile = $JSONRuleFWProfileStart + $JSONRuleFWProfileTypes + $JSONRuleFWProfileEnd
                }

                # Service Name
                if (!([string]::IsNullOrEmpty($ruleService))) {
                    $JSONRuleService = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_app_servicename",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "1bd709fe-1cd4-4cc4-9a6f-4cb7f104da66"
            },
            "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                "value": "$ruleService",
                "settingValueTemplateReference": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingValueTemplateReference",
                    "settingValueTemplateId": "c77294ec-795e-43dc-9af6-775b3b2f911d",
                    "useTemplateDefault": false
                }
            }
        },

"@
                }

                # Local Ports
                if ((!([string]::IsNullOrEmpty($ruleLocalPorts)))) {
                    $JSONRuleLocalPortsStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_localportranges",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "b57dc83e-5bf3-439a-b923-4c3e49ac9e2d"
            },
            "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
            "simpleSettingCollectionValue": [

'@
                    $JSONLocalPorts = @()
                    foreach ($ruleLocalPort in $ruleLocalPorts) {
                        # Last address in the set
                        if (($ruleLocalPort -eq $ruleLocalPorts[-1]) -or ($ruleLocalPorts.count -eq '1')) {
                            $JSONRuleLocalPort = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleLocalPort"
                }

"@
                        }
                        else {
                            $JSONRuleLocalPort = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleLocalPort"
                },

"@
                        }
                        $JSONLocalPorts += $JSONRuleLocalPort
                    }
                    $JSONRuleLocalPortsEnd = @'

            ]
        },

'@
                    $JSONRuleLocalPorts = $JSONRuleLocalPortsStart + $JSONLocalPorts + $JSONRuleLocalPortsEnd
                }

                # Remote Address Ranges
                if ($ruleUseAnyRemoteAddresses -eq $false) {
                    $JSONRuleRemoteAddressRangeStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_remoteaddressranges",
            "settingInstanceTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
                "settingInstanceTemplateId": "bf9855fc-f2c0-4241-94cf-94cf823f1c1c"
            },
            "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
            "simpleSettingCollectionValue": [

'@
                    $JSONRemoteAddresses = @()
                    foreach ($ruleRemoteAddress in $ruleRemoteAddresses) {
                        # Last address in the set
                        if (($ruleRemoteAddress -eq $ruleRemoteAddresses[-1]) -or ($ruleRemoteAddresses.count -eq '1')) {
                            $JSONRuleRemoteAddress = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleRemoteAddress"
                }

"@
                        }
                        else {
                            $JSONRuleRemoteAddress = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleRemoteAddress"
                },

"@
                        }
                        $JSONRemoteAddresses += $JSONRuleRemoteAddress
                    }
                    $JSONRuleRemoteAddressRangeEnd = @'

            ]
        },

'@
                    $JSONRuleRemoteAddressRange = $JSONRuleRemoteAddressRangeStart + $JSONRemoteAddresses + $JSONRuleRemoteAddressRangeEnd
                }

                # Rule Action
                Switch ($ruleAction) {
                    'allowed' { $ruleActionType = '1' }
                    'blocked' { $ruleActionType = '0' }
                }
                $JSONRuleAction = @"
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_action_type",
        "settingInstanceTemplateReference": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
            "settingInstanceTemplateId": "0565cfd1-21c2-4965-b87f-6bde2b8d2cbd"
        },
        "choiceSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_action_type_$ruleActionType",
                "settingValueTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingValueTemplateReference",
                "settingValueTemplateId": "419773d8-bffe-4d6f-a91f-286871963f5c",
                "useTemplateDefault": false
        },
        "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
        "children": []
        }
    },

"@

                # Rule Description
                $JSONRuleDescription = @"
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_description",
        "settingInstanceTemplateReference": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference",
            "settingInstanceTemplateId": "6c85987f-3adb-4f8d-93e1-4f23e238121b"
        },
        "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                "value": "$ruleDescription",
                "settingValueTemplateReference": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingValueTemplateReference",
                "settingValueTemplateId": "18ab9c3a-b6be-4995-9438-289c34eee294",
                "useTemplateDefault": false
            }
        }
    }

"@

                #Rule ending
                if ($fwRule -eq $fwRules[-1]) {
                    $JSONRuleEnd = @'
            ]
        }

'@
                }
                else {
                    $JSONRuleEnd = @'
            ]
        },

'@
                }

                # Build the first Rule and add it to array
                $JSONRule = $JSONRuleStart + $JSONRuleName + $JSONRuleState + $JSONRuleDirection + $JSONRuleProtocol + $JSONRuleLocalAddressRange + $JSONRuleInterface + $JSONRulePackageFamily + $JSONRuleFilePath + $JSONRuleAuthUsers + $JSONRuleRemotePorts + $JSONRuleFWProfile + $JSONRuleService + $JSONRuleLocalPorts + $JSONRuleRemoteAddressRange + $JSONRuleAction + $JSONRuleDescription + $JSONRuleEnd
                $scJSONAllRules += $JSONRule
            }
            # JSON data is different for each subsequent rule in the policy
            else {
                # Rule Name
                $JSONRuleName = @"
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_name",
        "settingInstanceTemplateReference": null,
        "simpleSettingValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
            "settingValueTemplateReference": null,
            "value": "$ruleName"
        }
    },

"@

                # Rule State (Enabled)
                $JSONRuleState = @'
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_enabled",
        "settingInstanceTemplateReference": null,
        "choiceSettingValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
            "settingValueTemplateReference": null,
            "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_enabled_1",
            "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
            "children": []
        }
    },

'@

                # Rule Direction
                $JSONRuleDirection = @"
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction",
        "settingInstanceTemplateReference": null,
        "choiceSettingValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
            "settingValueTemplateReference": null,
            "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction_$ruleDirection",
            "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
            "children": []
        }
    },

"@

                # Protocol
                if ($null -ne $ruleProtocol) {
                    $JSONRuleProtocol = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_protocol",
            "settingInstanceTemplateReference": null,
            "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                "settingValueTemplateReference": null,
                "value": "$ruleProtocol"
            }
        },

"@
                }

                # Local Address Ranges
                if ($ruleUseAnyLocalAddresses -eq $false) {
                    $JSONRuleLocalAddressRangeStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_localaddressranges",
            "settingInstanceTemplateReference": null,
            "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
            "simpleSettingCollectionValue": [

'@
                    $JSONLocalAddresses = @()
                    foreach ($ruleLocalAddress in $ruleLocalAddresses) {
                        # Last address in the set
                        if (($ruleLocalAddress -eq $ruleLocalAddresses[-1]) -or ($ruleLocalAddresses.count -eq '1')) {
                            $JSONRuleLocalAddress = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleLocalAddress"
                }

"@
                        }
                        else {
                            $JSONRuleLocalAddress = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleLocalAddress"
                },

"@
                        }
                        $JSONLocalAddresses += $JSONRuleLocalAddress
                    }
                    $JSONRuleLocalAddressRangeEnd = @'

            ]
        },
'@
                    $JSONRuleLocalAddressRange = $JSONRuleLocalAddressRangeStart + $JSONLocalAddresses + $JSONRuleLocalAddressRangeEnd
                }

                # Interface Type
                if ($ruleInterfaces -ne 'notConfigured') {
                    $JSONRuleInterface = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_interfacetypes",
            "settingInstanceTemplateReference": null,
            "choiceSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationChoiceSettingValue)",
            "choiceSettingCollectionValue": [
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_interfacetypes_all",
                    "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
                    "children": []
                }
            ]
        },

'@
                }

                # Package Family Name
                If (!([string]::IsNullOrEmpty($rulePackageFamilyName))) {
                    $JSONRulePackageFamily = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_app_packagefamilyname",
            "settingInstanceTemplateReference": null,
            "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                "settingValueTemplateReference": null,
                "value": "$rulePackageFamilyName"
            }
        },

"@
                }

                # App File Path
                if (!([string]::IsNullOrEmpty($ruleFilePath))) {
                    $JSONRuleFilePath = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_app_filepath",
            "settingInstanceTemplateReference": null,
            "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                "settingValueTemplateReference": null,
                "value": "$ruleFilePath"
            }
        },

"@
                }

                # Authorized Users
                if (!([string]::IsNullOrEmpty($ruleAuthUsers))) {
                    $JSONRuleAuthUsersStart = @'
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_localuserauthorizedlist",
                "settingInstanceTemplateReference": null,
                "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
                "simpleSettingCollectionValue": [

'@
                    $JSONAuthUsers = @()
                    foreach ($ruleAuthUser in $ruleAuthUsers) {
                        # Last address in the set
                        if (($ruleAuthUser -eq $ruleAuthUsers[-1]) -or ($ruleAuthUsers.count -eq '1')) {
                            $JSONRuleAuthUser = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleAuthUser"
                }

"@
                        }
                        else {
                            $JSONRuleAuthUser = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleAuthUser"
                },

"@
                        }
                        $JSONAuthUsers += $JSONRuleAuthUser
                    }
                    $JSONRuleAuthUsersEnd = @'

            ]
        },
'@
                    $JSONRuleAuthUsers = $JSONRuleAuthUsersStart + $JSONAuthUsers + $JSONRuleAuthUsersEnd
                }

                # Remote Ports
                if (!([string]::IsNullOrEmpty($ruleRemotePorts))) {
                    $JSONRuleRemotePortsStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_remoteportranges",
            "settingInstanceTemplateReference": null,
            "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
            "simpleSettingCollectionValue": [

'@
                    $JSONRemotePorts = @()
                    foreach ($ruleRemotePort in $ruleRemotePorts) {
                        # Last address in the set
                        if (($ruleRemotePort -eq $ruleRemotePorts[-1]) -or ($ruleRemotePorts.count -eq '1')) {
                            $JSONRuleRemotePort = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleRemotePort"
                }

"@
                        }
                        else {
                            $JSONRuleRemotePort = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleRemotePort"
                },

"@
                        }
                        $JSONRemotePorts += $JSONRuleRemotePort
                    }
                    $JSONRuleRemotePortsEnd = @'

            ]
        },
'@
                    $JSONRuleRemotePorts = $JSONRuleRemotePortsStart + $JSONRemotePorts + $JSONRuleRemotePortsEnd
                }


                # Firewall Profile
                if ($ruleFWProfiles -ne 'notConfigured') {
                    $JSONRuleFWProfileStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles",
            "settingInstanceTemplateReference": null,
            "choiceSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationChoiceSettingValue)",
            "choiceSettingCollectionValue": [

'@

                    $JSONRuleFWProfileTypes = @()
                    foreach ($ruleFWProfile in $ruleFWProfiles) {
                        Switch ($ruleFWProfile) {
                            'domain' { $ruleFWProfileNo = '1' }
                            'private' { $ruleFWProfileNo = '2' }
                            'public' { $ruleFWProfileNo = '4' }
                        }

                        if (($ruleFWProfile -eq $ruleFWProfiles[-1]) -or ($ruleFWProfiles.count -eq '1')) {
                            $JSONRuleFWProfileType = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_$ruleFWProfileNo",
                    "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
                    "children": []
                }

"@
                        }
                        else {
                            $JSONRuleFWProfileType = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_$ruleFWProfileNo",
                    "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
                    "children": []
                },

"@
                        }

                        $JSONRuleFWProfileTypes += $JSONRuleFWProfileType
                    }

                    $JSONRuleFWProfileEnd = @'
            ]
        },

'@

                    $JSONRuleFWProfile = $JSONRuleFWProfileStart + $JSONRuleFWProfileTypes + $JSONRuleFWProfileEnd
                }

                # Service Name
                if (!([string]::IsNullOrEmpty($ruleService))) {
                    $JSONRuleService = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_app_servicename",
            "settingInstanceTemplateReference": null,
            "simpleSettingValue": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                "settingValueTemplateReference": null,
                "value": "$ruleService"
            }
        },

"@
                }

                # Local Ports
                if ((!([string]::IsNullOrEmpty($ruleLocalPorts)))) {
                    $JSONRuleLocalPortsStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_localportranges",
            "settingInstanceTemplateReference": null,
            "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
            "simpleSettingCollectionValue": [

'@
                    $JSONLocalPorts = @()
                    foreach ($ruleLocalPort in $ruleLocalPorts) {
                        # Last address in the set
                        if (($ruleLocalPort -eq $ruleLocalPorts[-1]) -or ($ruleLocalPorts.count -eq '1')) {
                            $JSONRuleLocalPort = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleLocalPort"
                }

"@
                        }
                        else {
                            $JSONRuleLocalPort = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleLocalPort"
                },

"@
                        }
                        $JSONLocalPorts += $JSONRuleLocalPort
                    }
                    $JSONRuleLocalPortsEnd = @'
            ]
        },

'@
                    $JSONRuleLocalPorts = $JSONRuleLocalPortsStart + $JSONLocalPorts + $JSONRuleLocalPortsEnd
                }

                # Remote Address Ranges
                if ($ruleUseAnyRemoteAddresses -eq $false) {
                    $JSONRuleRemoteAddressRangeStart = @'
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
            "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_remoteaddressranges",
            "settingInstanceTemplateReference": null,
            "simpleSettingCollectionValue@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSimpleSettingValue)",
            "simpleSettingCollectionValue": [

'@
                    $JSONRemoteAddresses = @()
                    foreach ($ruleRemoteAddress in $ruleRemoteAddresses) {
                        # Last address in the set
                        if (($ruleRemoteAddress -eq $ruleRemoteAddresses[-1]) -or ($ruleRemoteAddresses.count -eq '1')) {
                            $JSONRuleRemoteAddress = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleRemoteAddress"
                }

"@
                        }
                        else {
                            $JSONRuleRemoteAddress = @"
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$ruleRemoteAddress"
                },

"@
                        }
                        $JSONRemoteAddresses += $JSONRuleRemoteAddress
                    }
                    $JSONRuleRemoteAddressRangeEnd = @'
            ]
        },

'@
                    $JSONRuleRemoteAddressRange = $JSONRuleRemoteAddressRangeStart + $JSONRemoteAddresses + $JSONRuleRemoteAddressRangeEnd
                }

                # Rule Action
                Switch ($ruleAction) {
                    'allowed' { $ruleActionType = '1' }
                    'blocked' { $ruleActionType = '0' }
                }
                $JSONRuleAction = @"
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_action_type",
        "settingInstanceTemplateReference": null,
        "choiceSettingValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
            "settingValueTemplateReference": null,
            "value": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_action_type_$ruleActionType",
            "children@odata.type": "#Collection(microsoft.graph.deviceManagementConfigurationSettingInstance)",
            "children": []
        }
    },

"@

                # Rule Description
                $JSONRuleDescription = @"
    {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
        "settingDefinitionId": "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_description",
        "settingInstanceTemplateReference": null,
        "simpleSettingValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
            "settingValueTemplateReference": null,
            "value": "$ruleDescription"
        }
    }

"@

                #Rule ending
                if ($fwRule -eq $fwRules[-1]) {
                    $JSONRuleEnd = @'
            ]
        }

'@
                }
                else {
                    $JSONRuleEnd = @'
            ]
        },

'@
                }

                # Build the subsequent Rule and add to array
                $JSONRule = $JSONRuleStart + $JSONRuleName + $JSONRuleState + $JSONRuleDirection + $JSONRuleProtocol + $JSONRuleLocalAddressRange + $JSONRuleInterface + $JSONRulePackageFamily + $JSONRuleFilePath + $JSONRuleAuthUsers + $JSONRuleRemotePorts + $JSONRuleFWProfile + $JSONRuleService + $JSONRuleLocalPorts + $JSONRuleRemoteAddressRange + $JSONRuleAction + $JSONRuleDescription + $JSONRuleEnd
                $scJSONAllRules += $JSONRule
            }
        }

        try {
            $JSONPolicy = $JSONPolicyStart + $scJSONAllRules + $JSONPolicyEnd
            Test-JSONData -JSON $JSONPolicy
            $scPolicyJSON = $JSONPolicy | Out-String | ConvertFrom-Json | ConvertTo-Json -Depth 100
            return $scPolicyJSON
        }
        catch {

        }

    }

}