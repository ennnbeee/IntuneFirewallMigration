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
$requiredScopes = @('DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All')
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

#region variables
$profileName = '0.3-20250430-0800'
$mode = 'Test'
$legacyProfile = $false
$PolicyStoreSource = 'All'
#endregion variables

$rules = Get-FirewallData -Enabled:$EnabledOnly -Mode:$Mode -PolicyStoreSource:$PolicyStoreSource
$convertedRules = $rules | ConvertTo-IntuneFirewallRule

[ValidateSet('domain', 'private', 'public')]
[String[]]$fwProfiles = 'private,domain'

$selectedFWFules = @()

foreach ($fwProfile in $fwProfiles) {
    $selectedFWFules += $convertedRules | Where-Object -Property profileTypes -Contains $fwProfiles
}

$convertedRules | Where-Object -Property profileTypes -Contains $fwProfile


$convertedRules | Send-IntuneFirewallRulesPolicy -migratedProfileName:$ProfileName