. "$PSScriptRoot\IntuneFirewallRule.ps1"
. "$PSScriptRoot\..\Private\Use-HelperFunctions.ps1"
. "$PSScriptRoot\..\Private\Strings.ps1"
. "$PSScriptRoot\ConvertTo-IntuneSCFirewallRule.ps1"

# Sends Intune Firewall objects out to the Intune Powershell SDK
# and returns the response to the API call

function Send-IntuneFirewallRulesPolicy {
    <#
    .SYNOPSIS
    Send firewall rule objects out to Intune

    .DESCRIPTION
    Sends IntuneFirewallRule objects out to the Intune Powershell SDK and returns the response to the API call

    .EXAMPLE
    Get-NetFirewallRule | ConvertTo-IntuneFirewallRule | Send-IntuneFirewallRulesPolicy
    Send-IntuneFirewallRulesPolicy -firewallObjects $randomObjects
    Get-NetFirewallRule -PolicyStore RSOP | ConvertTo-IntuneFirewallRule -splitConflictingAttributes | Send-IntuneFirewallRulesPolicy -migratedProfileName "someCustomName"
    Get-NetFirewallRule -PolicyStore PersistentStore -PolicyStoreSourceType Local | ConvertTo-IntuneFirewallRule | Send-IntuneFirewallRulesPolicy -migratedProfileName "someCustomName"

    .PARAMETER firewallObjects the collection of firewall objects to be sent to be processed
    .PARAMETER migratedProfileName an optional argument that represents the prefix for the name of newly created firewall rule profiles

    .NOTES
    While Send-IntuneFirewallRulesPolicy primarily accepts IntuneFirewallRule objects, any object piped into the cmdlet that can be
    called with the ConvertTo-Json cmdlet and represented as a JSON string can be sent to Intune, with the Graph
    performing the validation on the the JSON payload.

    Any attributes that have null or empty string values are filtered out from being sent to Graph. This is because
    the Graph can insert default values when no set values have been placed in the payload.

    Users should authenticate themselves through the SDK first by running Connect-MSGraph, which will then allow
    them to use this cmdlet.

    .LINK
    https://docs.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windowsfirewallrule?view=graph-rest-beta
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(ValueFromPipeline = $true)]
        $firewallObjects,

        [Parameter(Mandatory = $false)]
        [String]
        $migratedProfileName = $Strings.SendIntuneFirewallRulesPolicyProfileNameDefault,

        [Parameter(HelpMessage = 'The number of rules per profiles to be exported.')]
        [ValidateRange(10, 100)]
        [int]$splitRules = 100,

        [Parameter()]
        [ValidateSet('all', 'domain', 'private', 'public')]
        $firewallProfile,

        [Parameter()]
        [ValidateSet('inbound', 'outbound', 'both')]
        [String]$ruleDirection,

        [Parameter(HelpMessage = 'When set, the script will use the legacy Endpoint Security profile format.')]
        [ValidateNotNullOrEmpty()]
        [switch]$legacyProfile
    )

    begin { $firewallArr = @() }

    # We apply a filter that strips objects of their null attributes so that Graph can
    # apply default values in the absence of set values
    process {
        $object = $_
        $allProperties = $_.PsObject.Properties.Name
        #$allProperties = ($object | Get-Member).Name
        $nonNullProperties = $allProperties.Where( { $null -ne $object.$_ -and $object.$_ -ne '' })
        $firewallArr += $object | Select-Object $nonNullProperties
    }

    end {
        # Split the incoming firewall objects into separate profiles
        $profiles = @()
        $currentProfile = @()
        $sentSuccessfully = @()
        $failedToSend = @()
        foreach ($firewall in $firewallArr) {
            if ($currentProfile.Count -ge $splitRules) {
                # Arrays may be "unrolled", so we need to enforce no unrolling
                $profiles += , $currentProfile
                $currentProfile = @()
            }
            $currentProfile += $firewall

        }
        if ($currentProfile.Count -gt 0 ) {
            # Arrays may be "unrolled", so we need to enforce no unrolling
            $profiles += , $currentProfile
        }

        $profileNumber = 0
        $remainingProfiles = $profiles.Count

        $dateFormatted = Get-Date -Format 'yyyy-MM-dd-HH-mm'
        $responsePath = './logs/http_response ' + $dateFormatted + '.txt'
        $payloadPath = './logs/http_payload ' + $dateFormatted + '.txt'
        if (-not(Test-Path './logs')) {
            $item = New-Item './logs' -ItemType Directory
        }

        foreach ($fwPolicy in $profiles) {
            # remainingProfiles is decremented after displaying operation status
            $remainingProfiles = Show-OperationProgress `
                -remainingObjects $remainingProfiles `
                -totalObjects $profiles.Count `
                -activityMessage $Strings.SendIntuneFirewallRulesPolicyProgressStatus
            #---------------------------------------------------------------------------------
            $textHeader = ''
            $NewIntuneObject = ''
            $profileAsString = '['
            foreach ($rules in $fwPolicy) {
                if ($fwPolicy.IndexOf($rules) -eq $fwPolicy.Length - 1) {
                    $profileAsString += (ConvertTo-IntuneFirewallRuleString $rules) + ']'
                }
                else {
                    $profileAsString += (ConvertTo-IntuneFirewallRuleString $rules) + ','
                }
            }
            $profileJson = $profileAsString | ConvertTo-Json
            #$profileJson | Out-File "./logs/$migratedProfileName-$firewallProfile-$profileNumber.json"
            if ($legacyProfile) {
                $textHeader = 'Endpoint Security Payload'
                $uri = 'https://graph.microsoft.com/beta/deviceManagement/templates/4356d05c-a4ab-4a07-9ece-739f7c792910/createInstance'


                $NewIntuneObject = "{
                                        `"description`" : `"Migrated firewall profile created on $dateFormatted`",
                                        `"displayName`" : `"$migratedProfileName-$firewallProfile-$ruleDirection-$profileNumber`",
                                        `"roleScopeTagIds`" :[],
                                        `"settingsDelta`" : [{
                                                            `"@odata.type`": `"#microsoft.graph.deviceManagementCollectionSettingInstance`",
                                                            `"definitionId`" : `"deviceConfiguration--windows10EndpointProtectionConfiguration_firewallRules`",
                                                            `"valueJson`" : $profileJson
                                                        }]
                                        }"
            }
            else {
                $textHeader = 'Settings Catalog Payload'
                $uri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'

                $JSONPolicyStart = @"
                {
                    "description": "Migrated firewall profile created on $dateFormatted",
                    "name": "$migratedProfileName-$firewallProfile-$ruleDirection-$profileNumber",
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

                $scJSONAllRules = $profileJson | ConvertTo-IntuneSCFirewallRule
                $NewIntuneObject = $JSONPolicyStart + $scJSONAllRules + $JSONPolicyEnd
                Test-JSONData -JSON $NewIntuneObject
                #$NewIntuneObject | Out-File "./logs/$migratedProfileName-$firewallProfile-$profileNumber.json"
            }

            if ($PSCmdlet.ShouldProcess($NewIntuneObject, $Strings.SendIntuneFirewallRulesPolicyShouldSendData)) {
                try {
                    $successResponse = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $NewIntuneObject
                    $successMessage = "`r`n$migratedProfileName-$profileNumber has been successfully imported to Intune`r`n"

                    Write-Verbose $successResponse
                    Write-Verbose $NewIntuneObject
                    Add-Content $responsePath "`r `n $dateFormatted `r `n $successMessage `r `n $successResponse"

                    $profileNumber++
                    $sentSuccessfully += Get-ExcelFormatObject -intuneFirewallObjects $fwPolicy

                }
                catch {
                    # Intune Graph errors are points that can detect payload mistakes
                    $errorMessage = $_.ToString()
                    #$errorType = $_.Exception.GetType().ToString()
                    $failedToSend += Get-ExcelFormatObject -intuneFirewallObjects $fwPolicy -errorMessage $errorMessage

                    Add-Content $responsePath "`r `n $dateFormatted `r `n $errorMessage"
                }
            }
            Add-Content $payloadPath "`r `n$dateFormatted `r `n$textHeader `r `n$NewIntuneObject"
        }

        Export-ExcelFile -fileName 'Imported_to_Intune' -succeededToSend $sentSuccessfully
        Export-ExcelFile -fileName 'Failed_to_Import_to_Intune' -failedToSend $failedToSend
        Set-SummaryDetail -numberOfSplittedRules $firewallArr.Count -ProfileName $migratedProfileName -successCount $sentSuccessfully.Count
        Get-SummaryDetail
    }
}