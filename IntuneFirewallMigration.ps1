[CmdletBinding()]

param(

    [Parameter(Mandatory = $true)]
    [String]$profileName,

    [Parameter(HelpMessage = 'Provide the Id of the Entra ID tenant to connect to')]
    [ValidateLength(36, 36)]
    [String]$tenantId,

    [Parameter(HelpMessage = 'Provide the Id of the Entra App registration to be used for authentication')]
    [ValidateLength(36, 36)]
    [String]$appId,

    [Parameter(HelpMessage = 'Provide the App secret to allow for authentication to graph')]
    [ValidateNotNullOrEmpty()]
    [String]$appSecret,

    [Parameter(HelpMessage = 'Include Disabled Firewall Rules in the export')]
    [ValidateNotNullOrEmpty()]
    [switch]$includeDisabledRules,

    [Parameter(HelpMessage = 'Include Local Firewall Rules in the export')]
    [ValidateNotNullOrEmpty()]
    [switch]$includeLocalRules
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
Import-Module '.\IntuneFirewallMigration.psm1'
. '.\IntuneFirewallMigration\Private\Strings.ps1'
#endregion preflight

#region authentication
if (Get-MgContext) {
    Write-Host 'Disconnecting from existing Graph session.' -ForegroundColor Cyan
    Disconnect-MgGraph
}

##scopes required for the script
$requiredScopes = @('DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All')
[String[]]$scopes = $requiredScopes -join ', '


##authentication
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
    Exit
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

    $json = Invoke-MgGraphRequest -Method GET -Uri $Strings.GraphFirewallRulesEndpoint
    $profiles = $json.value
    $profileNameExist = $true
    while (-not($profileName)) {
        $profileName = Read-Host -Prompt $Strings.ProfileCannotBeBlank
    }
    while ($profileNameExist) {
        if (![string]::IsNullOrEmpty($profiles)) {
            foreach ($display in $profiles) {
                $name = $display.displayName.Split('-')
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

    if ($includeLocalRules) {
        Export-NetFirewallRule -ProfileName $profileName -CheckProfileName $false -EnabledOnly:$EnabledOnly -PolicyStoreSource 'All'
    }
    else {
        Export-NetFirewallRule -ProfileName $profileName -CheckProfileName $false -EnabledOnly:$EnabledOnly
    }

}
catch {
    $errorMessage = $_.ToString()
    Write-Host -ForegroundColor Red $errorMessage
    Write-Host 'No commands completed'
}
#endregion script