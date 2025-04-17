. "$PSScriptRoot\IntuneFirewallRule.ps1"
. "$PSScriptRoot\..\Private\Use-HelperFunctions.ps1"
. "$PSScriptRoot\..\Private\Strings.ps1"


# Sends Intune Firewall objects out to the Intune Powershell SDK
# and returns the response to the API call

Function Send-IntuneFirewallRulesPolicy {
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
    Param(
        [Parameter(ValueFromPipeline = $true)]
        $firewallObjects,

        [Parameter(Mandatory = $false)]
        [String]
        $migratedProfileName = $Strings.SendIntuneFirewallRulesPolicyProfileNameDefault,

        [Parameter(HelpMessage = 'The number of rules per profiles to be exported.')]
        [ValidateRange(10, 100)]
        [int]$splitRules = 100
    )

    Begin { $firewallArr = @() }

    # We apply a filter that strips objects of their null attributes so that Graph can
    # apply default values in the absence of set values
    Process {

        $object = $_
        $allProperties = $_.PsObject.Properties.Name
        #$allProperties = ($object | Get-Member).Name
        $nonNullProperties = $allProperties.Where( { $null -ne $object.$_ -and $object.$_ -ne '' })
        $firewallArr += $object | Select-Object $nonNullProperties
    }

    End {
        # Split the incoming firewall objects into separate profiles
        $profiles = @()
        $currentProfile = @()
        $sentSuccessfully = @()
        $failedToSend = @()
        ForEach ($firewall in $firewallArr) {
            If ($currentProfile.Count -ge $splitRules) {
                # Arrays may be "unrolled", so we need to enforce no unrolling
                $profiles += , $currentProfile
                $currentProfile = @()
            }
            $currentProfile += $firewall

        }
        If ($currentProfile.Count -gt 0 ) {
            # Arrays may be "unrolled", so we need to enforce no unrolling
            $profiles += , $currentProfile
        }

        $profileNumber = 0
        $remainingProfiles = $profiles.Count

        $date = Get-Date
        $dateformatted = Get-Date -Format 'yyyy_MM_dd_HH_mm'
        $responsePath = './logs/http_response ' + $dateformatted + '.txt'
        $payloadPath = './logs/http_payload ' + $dateformatted + '.txt'
        if (-not(Test-Path './logs')) {
            $item = New-Item './logs' -ItemType Directory
        }

        ForEach ($profile in $profiles) {
            # remainingProfiles is decremented after displaying operation status
            $remainingProfiles = Show-OperationProgress `
                -remainingObjects $remainingProfiles `
                -totalObjects $profiles.Count `
                -activityMessage $Strings.SendIntuneFirewallRulesPolicyProgressStatus
            #---------------------------------------------------------------------------------
            $textHeader = ''
            $NewIntuneObject = ''
            $esNewIntuneObject = ''
            $textHeader = 'Settings Catalog Payload'
            $profileAsString = '['
            ForEach ($rules in $profile) {
                if ($profile.IndexOf($rules) -eq $profile.Length - 1) {
                    $profileAsString += (ConvertTo-IntuneFirewallRuleString $rules) + ']'
                }
                else {
                    $profileAsString += (ConvertTo-IntuneFirewallRuleString $rules) + ','
                }
            }
            $profileJson = $profileAsString | ConvertTo-Json
            $esNewIntuneObject = "{
                                    `"description`" : `"Migrated firewall profile created on $date`",
                                    `"displayName`" : `"$migratedProfileName-$profileNumber`",
                                    `"roleScopeTagIds`" :[],
                                    `"settingsDelta`" : [{
                                                        `"@odata.type`": `"#microsoft.graph.deviceManagementCollectionSettingInstance`",
                                                        `"definitionId`" : `"deviceConfiguration--windows10EndpointProtectionConfiguration_firewallRules`",
                                                        `"valueJson`" : $profileJson
                                                    }]
                                    }"

            $NewIntuneObject = $esNewIntuneObject | ConvertTo-IntuneSCFirewallRule

            If ($PSCmdlet.ShouldProcess($NewIntuneObject, $Strings.SendIntuneFirewallRulesPolicyShouldSendData)) {
                Try {

                    #$successResponse = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/templates/4356d05c-a4ab-4a07-9ece-739f7c792910/createInstance' -Body $NewIntuneObject
                    $successResponse = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -Body $NewIntuneObject
                    $successMessage = "`r`n$migratedProfileName-$profileNumber has been successfully imported to Intune (Settings Catalog)`r`n"

                    Write-Verbose $successResponse
                    Write-Verbose $NewIntuneObject
                    Add-Content $responsePath "`r `n $date `r `n $successMessage `r `n $successResponse"

                    $profileNumber++
                    $sentSuccessfully += Get-ExcelFormatObject -intuneFirewallObjects $profile

                }
                Catch {
                    # Intune Graph errors are points that can detect payload mistakes
                    $errorMessage = $_.ToString()
                    #$errorType = $_.Exception.GetType().ToString()
                    $failedToSend += Get-ExcelFormatObject -intuneFirewallObjects $profile -errorMessage $errorMessage

                    Add-Content $responsePath "`r `n $date `r `n $errorMessage"
                }
            }
            Add-Content $payloadPath "`r `n$date `r `n$textHeader `r `n$NewIntuneObject"
        }


        Export-ExcelFile -fileName 'Imported_to_Intune' -succeededToSend $sentSuccessfully
        Export-ExcelFile -fileName 'Failed_to_Import_to_Intune' -failedToSend $failedToSend
        Set-SummaryDetail -numberOfSplittedRules $firewallArr.Count -ProfileName $migratedProfileName -successCount $sentSuccessfully.Count
        Get-SummaryDetail
    }
}