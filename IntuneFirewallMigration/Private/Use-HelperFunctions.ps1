. "$PSScriptRoot\Strings.ps1"
# This file represents several utility functions that do not belong to exporting, or importing alone.

function Show-OperationProgress {
    <#
    .SYNOPSIS
    Displays a progress bar regarding how much work has been completed.

    .DESCRIPTION
    Show-OperationProgress does two things: It will display the progress of the work that has already been done, and also return a number
    stating how many objects are left to process

    .EXAMPLE
    Show-OperationProgress -remainingObjects 14 -totalObjects 28 -activityMessage "foo"

    .PARAMETER remainingObjects an int representing how many objects are left to process
    .PARAMETER totalObjects an int representing how many objects need to be processed in total
    .PARAMETER activityMessage a string representing what activity is currently being done

    .NOTES
    Show-OperationProgress writes the progress to a bar on the host console.

    .LINK
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/write-progress?view=powershell-6

    .OUTPUTS
    Int32

    The remaining amount of objects that need to be processed after this operation.
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [int]
        $remainingObjects,
        [Parameter(Mandatory = $true)]
        [int]
        $totalObjects,
        [Parameter(Mandatory = $true)]
        [string]
        $activityMessage
    )

    # The function should never be called with 0 or less objects because there needs to be objects to process
    If ($totalObjects -le 0) {
        Throw $Strings.ShowOperationProgressException
    }

    $completedObjects = $totalObjects - $remainingObjects
    # Write-Progress will normally take an int value, but it is possible to send this value as a truncated float
    $percentComplete = [Math]::Round($completedObjects / $totalObjects * 100, 2)
    Write-Progress -Activity $activityMessage `
        -Status $($Strings.OperationStatus -f $completedObjects, $totalObjects, $percentComplete) `
        -PercentComplete $percentComplete
    # Since this represents a single operation, we decrement the remaining objects to work once.
    return $remainingObjects - 1
}
function Get-UserPrompt {
    <#
    .SYNOPSIS
    Wrapper function for getting user prompt data.

    .DESCRIPTION
    Get-UserPrompt is a wrapper function that wraps around $host.ui.PromptForChoice, as Pester does not currently support the mocking of such methods.

    .EXAMPLE
    Get-UserPrompt -promptTitle "title" -promptMessage "description" -promptOptions $promptOptions -defaultOption 0

    .PARAMETER promptTitle The title of the prompt
    .PARAMETER promptMessage The message of the prompt
    .PARAMETER promptOptions a set of choices that users have the option of picking from
    .PARAMETER defaultOption an integer representing the index of the option to be selected by default

    .OUTPUTS
    Int32

    The index of the option provided from the given set of choices
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $promptTitle,

        [Parameter(Mandatory = $true)]
        [string]
        $promptMessage,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Host.ChoiceDescription[]]
        $promptOptions,

        [Parameter(Mandatory = $true)]
        [int]
        $defaultOption
    )
    return $host.ui.PromptForChoice($promptTitle, $promptMessage, $promptOptions, $defaultOption)
}
Function Test-JSONData() {

    param (
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $TestJSON | Out-Null
        $validJson = $true
    }
    catch {
        $validJson = $false
        Write-Error $_.Exception.Message
        break
    }
    if (!$validJson) {
        Write-Error $_.Exception.Message
        break
    }
}
Function Connect-ToGraph {

    <#
    .SYNOPSIS
    Authenticates to the Graph API via the Microsoft.Graph.Authentication module.

    .DESCRIPTION
    The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.

    .PARAMETER Tenant
    Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.

    .PARAMETER AppId
    Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.

    .PARAMETER AppSecret
    Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

    .PARAMETER Scopes
    Specifies the user scopes for interactive authentication.

    .EXAMPLE
    Connect-ToGraph -tenantId $tenantId -appId $app -appSecret $secret

    -#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$tenantId,
        [Parameter(Mandatory = $false)] [string]$appId,
        [Parameter(Mandatory = $false)] [string]$appSecret,
        [Parameter(Mandatory = $false)] [string[]]$scopes
    )

    Process {
        #Import-Module Microsoft.Graph.Authentication
        $version = (Get-Module microsoft.graph.authentication | Select-Object -ExpandProperty Version).major

        if ($AppId -ne '') {
            $body = @{
                grant_type    = 'client_credentials';
                client_id     = $appId;
                client_secret = $appSecret;
                scope         = 'https://graph.microsoft.com/.default';
            }

            $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body
            $accessToken = $response.access_token

            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
                $accessTokenFinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
                $accessTokenFinal = $accessToken
            }
            $graph = Connect-MgGraph -AccessToken $accessTokenFinal
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        }
        else {
            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -Scopes $scopes -TenantId $tenantId
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}