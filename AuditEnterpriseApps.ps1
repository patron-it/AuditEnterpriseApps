<#
.SYNOPSIS
  Script to create a report on Enterprise Application and Application Registration in Entra ID tenant. 
.DESCRIPTION
  Connect to Entra ID tenant, fetch required informations and prepare a HTML output.
.INPUTS
  None
.OUTPUTS
  Log file stored in current folder named by audited Entra ID tenant and datetime.
.NOTES
  Version:        1.0
  Author:         Martin Haller (PATRON-IT s.r.o.)
  Creation Date:  2024-06-21
  Purpose/Change: Initial script development
.EXAMPLE
  Just run the script
#>
#Requires -modules Microsoft.Graph

####################
# Connection
####################
# Login to MS Graph
Connect-MgGraph -Scopes Directory.Read.All, CrossTenantInformation.ReadBasic.All -NoWelcome

####################
# Definitions
####################
# Parameters
$hideDisabledApps = $true
$fetchSignInLogs = $true

######
$dangerousScopes = @(
    'AdministrativeUnit.ReadWrite.All'
    'Application.ReadWrite.All', 
    'AppRoleAssignment.ReadWrite.All',
    'DelegatedAdminRelationship.ReadWrite.All',
    'Domain.ReadWrite.All',
    'Directory.AccessAsUser.All',
    'EntitlementManagement.ReadWrite.All',
    'Exchange.Manage', 
    'Exchange.ManageAsApp',
    'Organization.ReadWrite.All',
    'Policy.ReadWrite.Authorization',
    'Policy.ReadWrite.PermissionGrant',
    'PrivilegedAccess.ReadWrite.AzureAD',
    'PrivilegedAccess.ReadWrite.AzureADGroup',
    'PrivilegedAccess.ReadWrite.AzureResources',
    'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup',
    'RoleAssignmentSchedule.ReadWrite.Directory',
    'RoleEligibilitySchedule.ReadWrite.Directory',
    'RoleManagement.ReadWrite.Directory',
    'RoleManagementPolicy.ReadWrite.AzureADGroup',
    'RoleManagementPolicy.ReadWrite.Directory'
    'UserAuthenticationMethod.ReadWrite.All',
    'user_impersonation')
$safeDelegatedScopes = @('User.Read', 'Contacts.Read', 'openid', 'profile', 'email', 'People.Read', 'offline_access', 'Calendars.Read')
$safeDelegatedApps = @(
    'f8d98a96-0999-43f5-8af3-69971c7bb423' # iOS accounts
    '4e9b8b9a-1001-4017-8dd1-6e8f25e19d13' # Adobe Reader
    '8acd33ea-7197-4a96-bc33-d7cc7101262f' # Samsung email
    '0004c632-673b-4105-9bb6-f3bbd2a927fe' # PowerApps and Flow
)

####################
# Helper functions
####################
function Get-SigninLogs {
    param (
        $app
    )
    
    $interactiveLog = (Get-MgBetaAuditLogSignIn -Filter "(signInEventTypes/any(t: t eq 'interactiveUser')) and AppId eq '$($app.AppId)'" -Top 1).CreatedDateTime
    $nonInteractiveLog = (Get-MgBetaAuditLogSignIn -Filter "(signInEventTypes/any(t: t eq 'nonInteractiveUser')) and AppId eq '$($app.AppId)'" -Top 1).CreatedDateTime
    $servicePrincipalLog = (Get-MgBetaAuditLogSignIn -Filter "(signInEventTypes/any(t: t eq 'servicePrincipal')) and AppId eq '$($app.AppId)'" -Top 1).CreatedDateTime
    #Get-MgAuditLogSignIn -Filter "(signInEventTypes/any(t: t ne 'interactiveUser')) and AppId eq '$($app.AppId)'" -Top 1
    $result += [PSCustomObject]@{
        Interactive = $interactiveLog
        NonInteractive = $nonInteractiveLog
        ServicePrincipal = $servicePrincipalLog
    }
    return $result
}

function Render-AppHeader ($app) {
    $output = "<h3 class='app'><span class='name'>$($app.App.DisplayName)</span> <span class='id'>($($app.App.AppId))</span></h3>"
    $output += "<ul class='app-header'>"
    if($null -eq $app.App.AppOwnerOrganizationId) {
        $output += "<li>Home tenant: </li>"
    }
    else {
        $ownerTenant = $tenants[$app.App.AppOwnerOrganizationId]        
        if($ownerTenant.tenantId -eq $homeTenantId) {$class="domestic"}
        else {$class="foreign"}
        $output += "<li>Home tenant: <span class='$class'>$($ownerTenant.displayName) ($($ownerTenant.tenantId), $($ownerTenant.defaultDomainName))</span></li>"
    }
    $output += "<li>Enabled: $($app.App.AccountEnabled)</li>"
    $output += "<li>Service principal type: $($app.App.ServicePrincipalType)</li>"
    if($null -eq $app.AppSignIn) {
        $output += "<li>Sign-in logs not fetched</li>"
    } 
    else {
        $output += "<li>Last interactive sign-in: $($app.AppSignIn.Interactive)</li>"
        $output += "<li>Last non-interactive sign-in: $($app.AppSignIn.NonInteractive)</li>"
        $output += "<li>Last service principal sign-in: $($app.AppSignIn.ServicePrincipal)</li>"
        if( $null -eq $app.AppSignIn.Interactive -and
            $null -eq $app.AppSignIn.NonInteractive -and
            $null -eq $app.AppSignIn.ServicePrincipal) {
            $output += "<li class='warn'>Application hasn't been used last $signInLogsRetention days or more (based on sign-in logs)</li>"
        }
    }
    $output += "</ul>"
    return $output
}

function Render-AppCreds ($credentials, $type) {
    $output = ""
    if($null -ne $credentials) {
        $output += "<h4 class='creds'>$type</h4>"
        $output += "<ul>"        
        foreach($credential in $credentials) {
            $output += "<li>"
            if($credential.EndDateTime -lt (Get-Date)) { 
                $output += "<span class='warn'>(expired) </span>"
            }
            $output += "$($credential.DisplayName) ($($credential.StartDateTime.ToString('yyyy-MM-dd')) - $($credential.EndDateTime.ToString('yyyy-MM-dd')))</li>"
        }
        $output += "</ul>"        
    }

    return $output
}

function Render-AppPermissions ($app) {
    $output = "<h4 class='permissions'>Application permissions</h4>"
    $output += "<ul>"
    foreach ($perm in $app.AppPriv) {
        $resource = $allApps | Where-Object {$_.id -eq $perm.ResourceId}
        $role = $resource.AppRoles | Where-Object {$_.id -eq $perm.AppRoleId}
        
        if($role.Value -in $dangerousScopes) { $class = "dangerous" }
        else {$class = ""}
            
        $output += "<li class='$class'>$($resource.DisplayName), $($role.Value) ($($role.DisplayName))</li>"
    }
    $output += "</ul>"
    return $output
}

function Render-Owner ($owners, $type) {
    $output = ""
    if($owners) {
        $output += "<h4>$type</h4>"
        $output += "<ul>"
        foreach($owner in $owners) {
            $output += "<li> $($owner.DisplayName) ($($owner.UserPrincipalName))</li>"
        }
        $output += "</ul>"
    }
    
    return $output
}

function Resolve-SigninLogs ($apps) {
    $appsCount = $apps.count
    $step = 5
    for ($i = 0; $i -lt $appsCount; $i=$i+$step) {
        Write-Progress -Activity "Fetching signing logs" -Status "$i out of $appsCount completed" -PercentComplete (($i / $appsCount) * 100)
        $apps[$i..($i+$step)] | Foreach-Object -ThrottleLimit 5 -Parallel {
            try {
                $interactiveLog = (Get-MgBetaAuditLogSignIn -Filter "(signInEventTypes/any(t: t eq 'interactiveUser')) and AppId eq '$($_.App.AppId)'" -Top 1).CreatedDateTime
                $nonInteractiveLog = (Get-MgBetaAuditLogSignIn -Filter "(signInEventTypes/any(t: t eq 'nonInteractiveUser')) and AppId eq '$($_.App.AppId)'" -Top 1).CreatedDateTime
                $servicePrincipalLog = (Get-MgBetaAuditLogSignIn -Filter "(signInEventTypes/any(t: t eq 'servicePrincipal')) and AppId eq '$($_.App.AppId)'" -Top 1).CreatedDateTime
                $logs += [PSCustomObject]@{
                    Interactive = $interactiveLog
                    NonInteractive = $nonInteractiveLog
                    ServicePrincipal = $servicePrincipalLog
                }                
                $_.AppSignIn = $logs
            }
            catch {}
        }
    }
    Write-Progress -Activity "Fetching signing logs" -Completed
}

# Just a help function to receive reg owner as native Entra ID object
function Get-MgAplicationOwnerAsNative($applicationId) {
    $objects = @(Get-MgApplicationOwner -ApplicationId $applicationId)
    $result = New-Object System.Collections.Generic.List[System.Object]
    foreach($object in $objects) {
        $type = "Microsoft.Graph.PowerShell.Models."+($object.AdditionalProperties['@odata.type'] -replace '\.|#','')
        $result.Add($object -as $type)
    }
    return $result
}

# Just a help function to receive owner as native Entra ID object
function Get-MgServicePrincipalOwnerAsNative($servicePrincipalId) {
    $objects = @(Get-MgServicePrincipalOwner -ServicePrincipalId $servicePrincipalId)
    $result = New-Object System.Collections.Generic.List[System.Object]
    foreach($object in $objects) {
        $type = "Microsoft.Graph.PowerShell.Models."+($object.AdditionalProperties['@odata.type'] -replace '\.|#','')
        $result.Add($object -as $type)
    }
    return $result
}


####################
# Read out information
####################

#################
# Fetch information
# 
$homeTenant = Get-MgOrganization
$homeTenantId = $homeTenant.Id

# Entra ID level
$skus = (Get-MgSubscribedSku).ServicePlans
if(($skus | Where-Object { $_.ServicePlanName -Like 'AAD_PREMIUM_P2' -and $_.ProvisioningStatus -eq 'Success'}).count) {$EntraLevel = "P2"; $signInLogsRetention = 30}
elseif(($skus | Where-Object { $_.ServicePlanName -Like 'AAD_PREMIUM' -and $_.ProvisioningStatus -eq 'Success'}).count) {$EntraLevel = "P1"; $signInLogsRetention = 30}
else {$EntraLevel = "Free";  $signInLogsRetention = 7}

# Roles
Write-Host "Reading out Entra Roles"
$roles = Get-MgDirectoryRole -All

# Users
Write-Host "Reading out users"
$users = Get-MgUser -All

# Enterprise apps
Write-Host "Reading out Service Principals"
$allApps = Get-MgServicePrincipal -All

# App registrations
Write-Host "Reading out Applications"
$appRegistrations = Get-MgApplication -All

# Tenant IDs
$tenants = @{}
$tenantIds = $allApps.AppOwnerOrganizationId | Select-Object -Unique
foreach($tenantId in $tenantIds) {
    $ResolveUri = ("https://graph.microsoft.com/beta/tenantRelationships/findTenantInformationByDomainName(domainName='{0}')" -f $tenantId)
    $tenants[$tenantId] = Invoke-MgGraphRequest -Method Get -Uri $ResolveUri | Select-Object tenantId, displayName, defaultDomainName, federationBrandName
}

# Filter out MS Apps
# Those with AppOwnerOrg f8cdef31-a31e-4b4a-93e4-5f571e91255a (MS) and 72f988bf-86f1-41af-91ab-2d7cd011db47
$apps = $allApps | Where-Object {$_.AppOwnerOrganizationId -ne 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' `
    -and $_.AppOwnerOrganizationId -ne '72f988bf-86f1-41af-91ab-2d7cd011db47'}

# Filter out disabled apps
if($hideDisabledApps) {
    $apps = $apps | Where-Object {$_.AccountEnabled -eq $true}    
}

# Create grouping object
$i = 0
$appObjs = @()
foreach ($app in $apps) {
    $i++
    $progressPercent = [Math]::Round($i / $apps.count * 100)
    Write-Progress -Activity "App info enrichment" -Status "$progressPercent%" -PercentComplete $progressPercent

    $appPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $app.id -All
    $appDelegatePermissions = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $app.id -All

    $appObj = [PSCustomObject]@{
        App = $app
        AppPriv = $appPermissions
        AppDelegatedPriv = $appDelegatePermissions
        AppSignIn = $null
        AppOwner = $null
        AppRoles = $null
        AppRegistration = $null
        AppRegistrationOwner = $null
    }

    $appObj.AppOwner = Get-MgServicePrincipalOwnerAsNative $app.id

    $memberOf = Get-MgServicePrincipalMemberOf -ServicePrincipalId $app.id
    $appObj.AppRoles = $roles | Where-Object {$_.Id -in $memberOf.Id}

    if($app.AppOwnerOrganizationId -eq $homeTenantId) {
        $appObj.AppRegistration = $appRegistrations | Where-Object {$_.AppId -eq $app.AppId}
        $appObj.AppRegistrationOwner = Get-MgAplicationOwnerAsNative $appObj.AppRegistration.Id
    }

    $appObjs += $appObj
}

##################
# Statistics
Write-Host "Apps total: $($allApps.count)"
Write-Host "Non MS apps: $($apps.count)"
Write-Host "Own apps: $($appRegistrations.count)"

if($fetchSignInLogs) {
    $appsToFetchLogs = $appObjs | Where-Object {$_.AppRoles -or $_.AppPriv}
    Write-Host "Fetching sing-in logs for Applications with Application Permissions or Roles (Count: $($appsToFetchLogs.count))"
    Resolve-SigninLogs $appsToFetchLogs
}

$appsWithDelegatedPriv = $appObjs | Where-Object {$_.AppDelegatedPriv -and $_.App.AppId -notin $safeDelegatedApps}

$appsWithUnsafeDelegatedPriv = $appsWithDelegatedPriv | ForEach-Object {
    $uniqueScopes = $_.AppDelegatedPriv.scope -split " " | Select-Object -Unique | Where-Object { $_ -ne "" }
    # Only return apps with other than safe permissions
    if(($uniqueScopes | Where-Object {$_ -notin $safeDelegatedScopes}).Count) {
        $_
    }
}

if($fetchSignInLogs) {
    Write-Host "Fetching sing-in logs for Applications with unsafe Delegate Permissions (Count: $($appsWithUnsafeDelegatedPriv.count))"
    Resolve-SigninLogs $appsWithUnsafeDelegatedPriv
}

####################
# Parsing and evaluating data
####################
Write-Host "Generating report"
$outputfile = "./Report-$($homeTenant.DisplayName)-$((get-date).ToString('yyyy-MM-dd-HH-mm-ss')).html"

@"
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>$($homeTenant.DisplayName) $((get-date).ToString('yyyy-MM-dd-HH-mm-ss'))</title>
        <meta charset="UTF-8" />        
        <style>
        body {background-color: #181818; color: #BFBFBF; font: 11pt/1.25 Monaco, monospace; padding: 10px 20px}
        ul {margin: 0;}
        ul.app-header {list-style: none; padding: 0;}
        h1, h2 {text-align: center;}
        h3.app {margin-bottom: 0;}
        h3.app .name {color: #246ADC}
        h3.app .id {font-size: 0.8em;}
        h4 {margin: 0; color: #23A1BD}
        .debug { color: #FFFAFA; }
        .info, .safe  { color: #63CA00; }
        .warn, .foreign, .unclassified { color: #DAA520; }
        .error, .dangerous { color: #F08080; }
        </style>        
    </head>
    <body>
        <h1>Report of applications used in Entra ID: $($homeTenant.DisplayName) ($((get-date).ToString('yyyy-MM-dd HH:mm')))</h1>
"@ | Out-File $outputfile

######
# Apps With Roles

'<h2>Applications with roles</h2>' | Out-File $outputfile -Append   
$appsWithRoles = $appObjs | Where-Object {$_.AppRoles}
if($appsWithRoles) {
    foreach($app in $appsWithRoles) {
        Render-AppHeader $app | Out-File $outputfile -Append
        "<h4>Roles</h4>" | Out-File $outputfile -Append
        "<ul>" | Out-File $outputfile -Append
        foreach ($role in $app.AppRoles) {
            "<li> $($role.DisplayName) ($($role.Description))</li>" | Out-File $outputfile -Append
        }
        "</ul>" | Out-File $outputfile -Append
    }
}

######
# Apps with App Permissions
$appsWithAppPrivs = $appObjs | Where-Object {$_.AppPriv}
'<h2>Applications with Application Permissions</h2>' | Out-File $outputfile -Append

if($appsWithAppPrivs) {
    foreach($app in $appsWithAppPrivs) {
        Render-AppHeader $app | Out-File $outputfile -Append
        Render-AppPermissions $app | Out-File $outputfile -Append

        Render-Owner $app.AppOwner "Service principal owners:" | Out-File $outputfile -Append
        Render-Owner $app.AppRegistrationOwner "Application owners:" | Out-File $outputfile -Append

        Render-AppCreds $app.App.PasswordCredentials "Password credentials (Service Principal)"  | Out-File $outputfile -Append
        Render-AppCreds $app.App.KeyCredentials "Certificate credentials (Service Principal)" | Out-File $outputfile -Append
        if($app.AppRegistration) {
            Render-AppCreds $app.AppRegistration.PasswordCredentials "Password credentials (Application)"  | Out-File $outputfile -Append
            Render-AppCreds $app.AppRegistration.KeyCredentials "Certificate credentials (Application)"  | Out-File $outputfile -Append
        }
    }    
}


######
# Apps with Unsafe Delegated permissions
'<h2>Applications with unsafe Delegated Permissions</h2>' | Out-File $outputfile -Append
if($appsWithUnsafeDelegatedPriv) {
    foreach($app in $appsWithUnsafeDelegatedPriv) {
        Render-AppHeader $app  | Out-File $outputfile -Append
        Render-Owner $app.AppOwner "Service principal owners:"  | Out-File $outputfile -Append
        Render-Owner $app.AppRegistrationOwner "Application owners:"  | Out-File $outputfile -Append

        $delegatedPermissions = $app.AppDelegatedPriv
        "<h4 class='permissions'>Delegated permissions</h4>"  | Out-File $outputfile -Append
        "<ul>" | Out-File $outputfile -Append
        foreach ($perm in $delegatedPermissions) {
            $resource = $allApps | Where-Object {$_.id -eq $perm.ResourceId}

            # Depends if the app is consented by admin for all users or by single user
            if($perm.ConsentType -eq 'Principal') {
                $consentUser = $users | Where-object {$_.id -eq $perm.PrincipalId}
                "<li> $($resource.DisplayName), $($consentUser.DisplayName) ($($consentUser.UserPrincipalName))"  | Out-File $outputfile -Append    
            }
            else {
                "<li> $($resource.DisplayName), $($perm.ConsentType)"  | Out-File $outputfile -Append    
            }

            $scopes = $perm.scope -split " " | Where-Object { $_ -ne "" }
            "<ul>" | Out-File $outputfile -Append
            foreach($scope in $scopes) {
                if($scope -in $safeDelegatedScopes) { $class = "safe"}
                elseif($scope -in $dangerousScopes) { $class = "dangerous" }
                else {$class = "unclassified"}
                "<li class='$class'>$scope</li>" | Out-File $outputfile -Append
            }
            "</ul></li>" | Out-File $outputfile -Append
        }
        "</ul> "| Out-File $outputfile -Append
    }
}
"</body></html>" | Out-File $outputfile -Append

Write-Host "Report generated and saved to $outputfile"
