[CmdletBinding()]

param(

    [Parameter(Mandatory = $true, HelpMessage = 'The name of the profile to be created')]
    [String]$profileName,

    [Parameter(HelpMessage = 'This determines if we are running a test version or a full importation. The default value is full. The test version imports only 20 rules')]
    [ValidateSet('Full', 'Test')]
    [String]$mode = 'Full',

    [Parameter(HelpMessage = 'The number of rules per profiles to be exported. The default value is 100 rules per profile')]
    [ValidateRange(10, 100)]
    [int]$splitRules = 100,

    [Parameter(HelpMessage = 'The rules from a specific firewall profile to be imported. The default value is all profiles.')]
    [ValidateSet('all', 'domain', 'private', 'public')]
    [String]$firewallProfile = 'all',

    [Parameter(HelpMessage = 'The direction of the firewall rules to be exported. The default value is both.')]
    [ValidateSet('inbound', 'outbound', 'both')]
    [String]$ruleDirection = 'both',

    [Parameter(HelpMessage = 'Include Disabled Firewall Rules in the export')]
    [ValidateNotNullOrEmpty()]
    [switch]$includeDisabledRules,

    [Parameter(HelpMessage = 'Include Local Firewall Rules in the export')]
    [ValidateNotNullOrEmpty()]
    [switch]$includeLocalRules,

    [Parameter(HelpMessage = 'When set, the script will use the legacy Endpoint Security profile format.')]
    [ValidateNotNullOrEmpty()]
    [switch]$legacyProfile,

    [Parameter(HelpMessage = 'Provide the Id of the Entra ID tenant to connect to')]
    [ValidateLength(36, 36)]
    [String]$tenantId,

    [Parameter(HelpMessage = 'Provide the Id of the Entra App registration to be used for authentication')]
    [ValidateLength(36, 36)]
    [String]$appId,

    [Parameter(HelpMessage = 'Provide the App secret to allow for authentication to graph')]
    [ValidateNotNullOrEmpty()]
    [String]$appSecret

)

#region preflight
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity

if (!$principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host -ForegroundColor Red 'Error:  Must run elevated: run as administrator'
    Write-Host 'No commands completed'
    return
}

## check for running from correct folder location
Import-Module '.\IntuneFirewallMigration.psm1' -Force
Import-Module '.\IntuneFirewallMigration\Private\Strings.ps1' -Force
#endregion preflight

#region authentication
if (Get-MgContext) {
    Write-Host 'Disconnecting from existing Graph session.' -ForegroundColor Cyan
    Disconnect-MgGraph
}

##scopes required for the script
$requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All')
[String[]]$scopes = $requiredScopes -join ', '


## authentication
try {
    if (!$tenantId) {
        Write-Host 'Connecting using interactive authentication' -ForegroundColor Yellow
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    }
    else {
        if ((!$appId -and !$appSecret) -or ($appId -and !$appSecret) -or (!$appId -and $appSecret)) {
            Write-Host 'Missing App Details, connecting using user authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -Scopes $scopes -ErrorAction Stop
        }
        else {
            Write-Host 'Connecting using App authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -appId $appId -appSecret $appSecret -ErrorAction Stop
        }
    }
    $context = Get-MgContext
    Write-Host ''
    Write-Host "Successfully connected to Microsoft Graph Tenant ID $($context.TenantId)." -ForegroundColor Green
}
catch {
    Write-Error $_.Exception.Message
    exit
}

$currentScopes = $context.Scopes
## Validate required permissions
$missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
if ($missingScopes.Count -gt 0) {
    Write-Host 'WARNING: The following scope permissions are missing:' -ForegroundColor Red
    $missingScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ''
    Write-Host 'Please ensure these permissions are granted to the app registration for full functionality.' -ForegroundColor Yellow
    exit
}
Write-Host ''
Write-Host 'All required scope permissions are present.' -ForegroundColor Green
#endregion authentication

#region script
try {
    if ($legacyProfile) {
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/intents?$filter=templateId%20eq%20%274b219836-f2b1-46c6-954d-4cd2f4128676%27%20or%20templateId%20eq%20%274356d05c-a4ab-4a07-9ece-739f7c792910%27%20or%20templateId%20eq%20%275340aa10-47a8-4e67-893f-690984e4d5da%27'
    }
    else {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=technologies has 'MicrosoftSense'"
    }
    $graphResults = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    $results = @()
    $results += $graphResults.value
    $pages = $graphResults.'@odata.nextLink'
    while ($null -ne $pages) {
        $additional = Invoke-MgGraphRequest -Uri $pages -Method Get -OutputType PSObject
        if ($pages) {
            $pages = $additional.'@odata.nextLink'
        }
        $results += $additional.value
    }
    $profiles = $results | Where-Object { $_.templateReference.templateDisplayName -eq 'Windows Firewall Rules' }
    $profileNameExist = $true
    while ($profileNameExist) {
        if (![string]::IsNullOrEmpty($profiles)) {
            foreach ($display in $profiles) {
                if ($legacyProfile) {
                    $name = $display.displayName.Split('-')
                }
                else {
                    $name = $display.name.Split('-')
                }
                $profileNameExist = $false
                if ($name[0] -eq $profileName) {
                    $profileNameExist = $true
                    $profileName = Read-Host -Prompt $Strings.ProfileExists
                    while (-not($profileName)) {
                        $profileName = Read-Host -Prompt $Strings.ProfileCannotBeBlank
                    }
                    break
                }
            }
        }
        else {
            $profileNameExist = $false
        }
    }

    $EnabledOnly = $true
    if ($includeDisabledRules) {
        $EnabledOnly = $false
    }
    switch ($includeLocalRules) {
        $true { $policyStoreSource = 'All' }
        $false { $policyStoreSource = 'GroupPolicy' }
    }

    Export-NetFirewallRule -ProfileName $profileName -EnabledOnly:$EnabledOnly -PolicyStoreSource:$policyStoreSource -Mode $mode -splitRules $splitRules -legacyProfile:$legacyProfile -firewallProfile:$firewallProfile -ruleDirection:$ruleDirection
}
catch {
    $errorMessage = $_.ToString()
    Write-Host -ForegroundColor Red $errorMessage
    Write-Host 'No commands completed'
}
#endregion script