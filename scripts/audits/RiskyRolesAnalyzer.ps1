# ---------------------------------------------------------------------------------------------
# SUPERSEDED. This script has been rebuilt. The rebuilt version is still a single file you
# download and run, and it fixes what this one gets wrong: custom roles are rated correctly on
# Az.Resources 10, PIM activations are told apart from permanent assignments, the score is
# documented, and every finding carries the command that fixes it.
#
#     Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/simon-vedder/risky-roles-analyzer/main/dist/Invoke-RiskyRolesAudit.ps1' -OutFile 'Invoke-RiskyRolesAudit.ps1'
#
#     https://simonvedder.com/tools/risky-roles-analyzer/
#
# This file stays as it was published in May 2026, together with the post it belongs to:
# https://simonvedder.com/the-privileged-role-exposures-defender-misses/
# It gets no further changes, and on Az.Resources 10 it reports every custom role as harmless.
# ---------------------------------------------------------------------------------------------

<#
.SYNOPSIS
    RiskyRolesAnalyzer — audits privileged Azure RBAC and Entra ID role assignments
    across a tenant and produces an interactive HTML report.

.DESCRIPTION
    A focused snapshot tool for finding privileged role exposure that mainstream
    posture-management tools commonly miss:

    - Custom Azure RBAC and Entra directory roles whose actions confer privilege
      escalation paths (e.g. Microsoft.Authorization/roleAssignments/write,
      microsoft.directory/users/password/update, Microsoft.Authorization/denyAssignments/delete)
    - Indirect privilege through nested groups (members are recursively expanded
      and shown together with the group they inherit through)
    - App Registrations that hold privileged roles but have expired or no
      credentials — a classic dormant-persistence pattern
    - App Registrations marked as deactivated in the portal (isDisabled = true,
      only exposed on Microsoft Graph /beta)
    - Disabled users who still hold permanent privileged assignments
    - Service Principal sign-in disabled vs Microsoft-blocked vs no-credential
      states, distinguished separately
    - Active vs PIM-eligible Entra assignments, scored separately
    - Cleanup commands generated per finding for direct or via-group removal

    Output: a single self-contained HTML file with filters, sorting, severity
    rating, and CSV export.

.PARAMETER OutputPath
    Path of the HTML report. Default: .\PrivilegedRoleAudit_<timestamp>.html

.PARAMETER AdditionalAzureRoles
    Optional list of extra Azure RBAC role names to treat as privileged.

.PARAMETER AdditionalEntraRoles
    Optional list of extra Entra directory role display names to treat as privileged.

.PARAMETER SkipPim
    If set, only active Entra role assignments are queried (PIM eligible skipped).

.PARAMETER AutoInstallModules
    If set, missing PowerShell modules are installed without prompting.

.PARAMETER RequestWriteScopes
    If set, requests RoleManagement.ReadWrite.Directory in addition to the
    read-only scopes. Required only if you want to run the cleanup commands
    suggested by the report from the same session. Without this switch, the
    audit runs read-only — safer default. To run cleanups later, you can also
    re-connect manually:
        Disconnect-MgGraph
        Connect-MgGraph -Scopes 'RoleManagement.ReadWrite.Directory','Directory.Read.All'

.NOTES
    Author : Simon Vedder
    Site   : https://simonvedder.com
    License: MIT

    Required modules: Az.Accounts, Az.Resources, Microsoft.Graph.Authentication

    Required permissions:
        Azure:  Reader on every subscription you want to audit (Mgmt Group level works too)
        Graph:  RoleManagement.Read.Directory, Directory.Read.All, Group.Read.All,
                Application.Read.All

    Superseded by the rebuilt Invoke-RiskyRolesAudit.ps1. This file is kept as published and
    unchanged.

.LINK
    https://simonvedder.com/tools/risky-roles-analyzer/

.LINK
    https://github.com/simon-vedder/risky-roles-analyzer
#>

[CmdletBinding()]
param(
  [string] $OutputPath,
  [string[]] $AdditionalAzureRoles = @(),
  [string[]] $AdditionalEntraRoles = @(),
  [switch] $SkipPim,
  [switch] $AutoInstallModules,
  [switch] $RequestWriteScopes
)

$ErrorActionPreference = 'Stop'

if (-not $OutputPath) {
  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $OutputPath = Join-Path (Get-Location) "PrivilegedRoleAudit_$stamp.html"
}

# ---------------------------------------------------------------------------
# Default privileged role definitions
# ---------------------------------------------------------------------------

$DefaultPrivilegedAzureRoles = @(
  'Owner',
  'Contributor',
  'User Access Administrator',
  'Role Based Access Control Administrator',
  'Access Review Operator Service Role',
  'Reservation Purchaser',
  'Key Vault Administrator',
  'Storage Account Key Operator Service Role',
  # BloodHound "Dangerous Managed Roles"
  'Security Admin',
  'Resource Policy Contributor',
  # BloodHound "Transitive Managed Identity Access"
  'Virtual Machine Contributor',
  'Website Contributor',
  'Managed Identity Operator'
)

# Risky permissions that mark a custom role as privileged.
# Matches both exact and wildcard prefix (e.g. "Microsoft.Authorization/*" matches
# "Microsoft.Authorization/roleAssignments/write").
$RiskyAzureActions = @(
  'Microsoft.Authorization/roleAssignments/write',
  'Microsoft.Authorization/roleAssignments/delete',
  'Microsoft.Authorization/denyAssignments/delete',
  'Microsoft.Authorization/roleDefinitions/write',
  'Microsoft.Authorization/roleDefinitions/delete',
  'Microsoft.Authorization/elevateAccess/action',
  'Microsoft.Authorization/policyAssignments/write',
  'Microsoft.Authorization/policyDefinitions/write',
  'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action',
  'Microsoft.Compute/virtualMachines/runCommand/action',
  'Microsoft.Compute/virtualMachines/extensions/write',
  'Microsoft.KeyVault/vaults/accessPolicies/write',
  'Microsoft.Web/sites/publish/Action',
  'Microsoft.Web/sites/config/list/action'
)

$RiskyEntraActions = @(
  'microsoft.directory/users/create',
  'microsoft.directory/users/inviteGuest',
  'microsoft.directory/users/password/update',
  'microsoft.directory/users/authenticationMethods/update',
  'microsoft.directory/servicePrincipals/create',
  'microsoft.directory/servicePrincipals/credentials/update',
  'microsoft.directory/applications/create',
  'microsoft.directory/applications/credentials/update',
  'microsoft.directory/applications/owners/update',
  'microsoft.directory/groups/members/update',
  'microsoft.directory/roleAssignments/allProperties/allTasks',
  'microsoft.directory/roleDefinitions/allProperties/allTasks'
)

$DefaultPrivilegedEntraRoles = @(
  'Global Administrator',
  'Privileged Role Administrator',
  'Privileged Authentication Administrator',
  'User Administrator',
  'Application Administrator',
  'Cloud Application Administrator',
  'Authentication Administrator',
  'Conditional Access Administrator',
  'Security Administrator',
  'Exchange Administrator',
  'SharePoint Administrator',
  'Intune Administrator',
  'Helpdesk Administrator',
  'Hybrid Identity Administrator',
  'Domain Name Administrator',
  'External Identity Provider Administrator',
  'Partner Tier1 Support',
  'Partner Tier2 Support',
  'Directory Writers',
  'Groups Administrator'
)

$privAzureRoles = ($DefaultPrivilegedAzureRoles + $AdditionalAzureRoles) | Sort-Object -Unique
$privEntraRoles = ($DefaultPrivilegedEntraRoles + $AdditionalEntraRoles) | Sort-Object -Unique

Write-Host "Privileged Role Audit" -ForegroundColor Cyan
Write-Host "  Azure RBAC roles tracked: $($privAzureRoles.Count)"
Write-Host "  Entra roles tracked:      $($privEntraRoles.Count)"
Write-Host ""

# ---------------------------------------------------------------------------
# Module checks + auto-install
# ---------------------------------------------------------------------------

$requiredModules = @(
  'Az.Accounts',
  'Az.Resources',
  'Microsoft.Graph.Authentication'
)

function Install-MissingModule {
  param([string] $Name)

  Write-Host "  Installing $Name..." -ForegroundColor Yellow

  # Make sure PSGallery exists and is trusted (otherwise -Confirm prompts pop up)
  try {
    $gallery = Get-PSRepository -Name PSGallery -ErrorAction Stop
    if ($gallery.InstallationPolicy -ne 'Trusted') {
      Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
      Write-Host "    PSGallery marked as trusted" -ForegroundColor Gray
    }
  }
  catch {
    Write-Warning "    Could not configure PSGallery: $_"
  }

  # Make sure NuGet provider is available (PowerShell 5.1 needs this on first install)
  if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    try {
      Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 `
        -Scope CurrentUser -Force | Out-Null
    }
    catch {
      Write-Warning "    Could not install NuGet provider: $_"
    }
  }

  Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
  Write-Host "    OK" -ForegroundColor Green
}

$missing = @()
foreach ($m in $requiredModules) {
  if (-not (Get-Module -ListAvailable -Name $m)) {
    $missing += $m
  }
}

if ($missing.Count -gt 0) {
  Write-Host ""
  Write-Host "Missing PowerShell modules:" -ForegroundColor Yellow
  $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
  Write-Host ""

  $doInstall = $false
  if ($AutoInstallModules) {
    $doInstall = $true
    Write-Host "AutoInstallModules switch is set, installing now..." -ForegroundColor Cyan
  }
  else {
    $reply = Read-Host "Install these modules now into the current user scope? [Y/n]"
    if ([string]::IsNullOrWhiteSpace($reply) -or $reply -match '^(y|yes)$') {
      $doInstall = $true
    }
  }

  if (-not $doInstall) {
    throw "Cannot continue without required modules. Install them manually with: " +
    "Install-Module $($missing -join ', ') -Scope CurrentUser"
  }

  foreach ($m in $missing) {
    try {
      Install-MissingModule -Name $m
    }
    catch {
      throw "Failed to install $m : $_"
    }
  }
  Write-Host ""
}

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------

Write-Host "Connecting to Azure..." -ForegroundColor Cyan
$azContext = Get-AzContext -ErrorAction SilentlyContinue
if (-not $azContext) {
  Connect-AzAccount | Out-Null
  $azContext = Get-AzContext
}
Write-Host "  Az context: $($azContext.Account) in tenant $($azContext.Tenant.Id)" -ForegroundColor Gray

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
$graphScopes = @(
  'RoleManagement.Read.Directory',
  'Directory.Read.All',
  'Group.Read.All',
  'Application.Read.All'
)
if ($RequestWriteScopes) {
  $graphScopes += 'RoleManagement.ReadWrite.Directory'
  Write-Host "  RequestWriteScopes set — will also request RoleManagement.ReadWrite.Directory" -ForegroundColor Yellow
}
$mgContext = Get-MgContext -ErrorAction SilentlyContinue
if (-not $mgContext -or ($graphScopes | Where-Object { $_ -notin $mgContext.Scopes })) {
  Connect-MgGraph -Scopes $graphScopes -NoWelcome
}

$tenantId = (Get-MgContext).TenantId
$currentScopes = (Get-MgContext).Scopes
Write-Host "Tenant: $tenantId" -ForegroundColor Green

if ($azContext -and $azContext.Tenant.Id -and $azContext.Tenant.Id -ne $tenantId) {
  Write-Warning "Az and Graph are in different tenants!"
  Write-Warning "  Az:    $($azContext.Tenant.Id)"
  Write-Warning "  Graph: $tenantId"
  Write-Warning "Reconnect Az with: Connect-AzAccount -TenantId $tenantId"
}

# Inform about cleanup-command capability
$hasWriteScope = $currentScopes -contains 'RoleManagement.ReadWrite.Directory' -or
$currentScopes -contains 'RoleManagement.ReadWrite.All'
if (-not $hasWriteScope) {
  Write-Host ""
  Write-Host "Note: Current Graph session is READ-ONLY." -ForegroundColor DarkGray
  Write-Host "      Cleanup commands suggested in the report will require a write-scoped" -ForegroundColor DarkGray
  Write-Host "      session before they can run. To enable, either:" -ForegroundColor DarkGray
  Write-Host "        a) re-run this script with: -RequestWriteScopes" -ForegroundColor DarkGray
  Write-Host "        b) or before running cleanups manually:" -ForegroundColor DarkGray
  Write-Host "             Disconnect-MgGraph; Connect-MgGraph -Scopes 'RoleManagement.ReadWrite.Directory','Directory.Read.All'" -ForegroundColor DarkGray
}
Write-Host ""

# ---------------------------------------------------------------------------
# Caches
# ---------------------------------------------------------------------------

$principalCache = @{}   # objectId -> resolved principal
$groupMemberCache = @{}   # groupId  -> flat list of leaf principals
$appByAppId = @{}   # appId    -> application registration object
$appCredInfoByAppId = @{}  # appId    -> @{ HasValidCred=bool; CredCount=int; ExpiredCount=int }

function Resolve-Principal {
  param([string] $ObjectId)

  if (-not $ObjectId) { return $null }
  if ($principalCache.ContainsKey($ObjectId)) { return $principalCache[$ObjectId] }

  $result = [PSCustomObject]@{
    ObjectId       = $ObjectId
    Type           = 'Unknown'
    DisplayName    = '(unresolved)'
    UPN            = $null
    AppId          = $null
    SpType         = $null
    IsEnabled      = $null
    ActivityStatus = 'Unknown'   # Active | Disabled | NoValidCredential | BlockedByMicrosoft | Unknown
    ActivityReason = $null
  }

  try {
    $obj = Invoke-MgGraphRequest -Method GET `
      -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$ObjectId" -ErrorAction Stop
    $odata = $obj.'@odata.type'

    switch -Wildcard ($odata) {
      '*.user' {
        $result.Type = 'User'
        $result.DisplayName = $obj.displayName
        $result.UPN = $obj.userPrincipalName

        # /directoryObjects doesn't always return accountEnabled for users.
        # Make an explicit call to /users/{id} to get the real status.
        $userEnabled = $null
        try {
          $userDetail = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/$ObjectId`?`$select=accountEnabled,displayName,userPrincipalName" `
            -ErrorAction Stop
          if ($userDetail.ContainsKey('accountEnabled')) {
            $userEnabled = $userDetail['accountEnabled']
          }
          Write-Verbose ("User detail [{0}]: accountEnabled={1}" -f $obj.displayName, $userEnabled)
        }
        catch {
          Write-Verbose "Could not fetch user detail for $ObjectId : $_"
        }
        $result.IsEnabled = $userEnabled

        if ($userEnabled -eq $false) {
          $result.ActivityStatus = 'Disabled'
          $result.ActivityReason = 'Account disabled'
        }
        elseif ($userEnabled -eq $true) {
          $result.ActivityStatus = 'Active'
        }
        # else: leave as Unknown
      }
      '*.group' {
        $result.Type = 'Group'
        $result.DisplayName = $obj.displayName
        $result.ActivityStatus = 'Active'   # Groups don't sign in
      }
      '*.servicePrincipal' {
        $result.DisplayName = $obj.displayName
        $result.AppId = $obj.appId
        $result.SpType = $obj.servicePrincipalType

        # /directoryObjects doesn't reliably return accountEnabled for SPs.
        # Always make an explicit call to /servicePrincipals/{id} to get
        # the real activation state.
        $disabledByMs = $null
        $spAccountEnabled = $null
        try {
          $spDetail = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ObjectId`?`$select=disabledByMicrosoftStatus,accountEnabled,displayName,appId" `
            -ErrorAction Stop
          if ($spDetail.ContainsKey('disabledByMicrosoftStatus') -and $spDetail['disabledByMicrosoftStatus']) {
            $disabledByMs = $spDetail['disabledByMicrosoftStatus']
          }
          if ($spDetail.ContainsKey('accountEnabled')) {
            $spAccountEnabled = $spDetail['accountEnabled']
          }
          Write-Verbose ("SP detail [{0}]: accountEnabled={1}, disabledByMs={2}" -f `
              $obj.displayName, $spAccountEnabled, $disabledByMs)
        }
        catch {
          Write-Verbose "Could not fetch SP detail for $ObjectId : $_"
        }
        $result.IsEnabled = $spAccountEnabled

        if ($obj.servicePrincipalType -eq 'ManagedIdentity') {
          $result.Type = 'ManagedIdentity'
        }
        elseif ($appByAppId.ContainsKey($obj.appId)) {
          $result.Type = 'AppRegistration'
        }
        else {
          $result.Type = 'EnterpriseApp'
        }

        # Status precedence: SP disabled > MS-blocked > no valid cred > active
        if ($spAccountEnabled -eq $false) {
          $result.ActivityStatus = 'Disabled'
          $result.ActivityReason = 'Service principal sign-in disabled'
        }
        elseif ($disabledByMs) {
          $result.ActivityStatus = 'BlockedByMicrosoft'
          $result.ActivityReason = "Blocked by Microsoft: $disabledByMs"
        }
        elseif ($result.Type -eq 'ManagedIdentity') {
          $result.ActivityStatus = 'Active'
        }
        elseif ($result.Type -eq 'AppRegistration') {
          $info = $appCredInfoByAppId[$obj.appId]
          if (-not $info) {
            $result.ActivityStatus = 'Unknown'
            $result.ActivityReason = 'Could not load credential info'
          }
          elseif ($info.IsDisabled) {
            $result.ActivityStatus = 'Disabled'
            $result.ActivityReason = 'App registration deactivated'
          }
          elseif ($info.CredCount -eq 0) {
            $result.ActivityStatus = 'NoValidCredential'
            $result.ActivityReason = 'No password or certificate credentials'
          }
          elseif (-not $info.HasValidCred) {
            $result.ActivityStatus = 'NoValidCredential'
            $result.ActivityReason = "All $($info.CredCount) credentials expired"
          }
          else {
            $result.ActivityStatus = 'Active'
          }
        }
        else {
          $result.ActivityStatus = 'Active'
        }
      }
      default {
        $result.Type = 'Other'
        $result.DisplayName = $obj.displayName
      }
    }
  }
  catch {
    Write-Verbose "Could not resolve $ObjectId : $_"
  }

  $principalCache[$ObjectId] = $result
  return $result
}

function Get-GroupMembersRecursive {
  param(
    [string] $GroupId,
    [System.Collections.Generic.HashSet[string]] $Seen
  )

  if (-not $Seen) { $Seen = [System.Collections.Generic.HashSet[string]]::new() }
  if ($groupMemberCache.ContainsKey($GroupId)) { return $groupMemberCache[$GroupId] }
  if (-not $Seen.Add($GroupId)) { return @() }   # cycle protection

  $leaves = New-Object System.Collections.Generic.List[object]
  try {
    $url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$top=999"
    do {
      $resp = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop
      foreach ($member in $resp.value) {
        $type = $member.'@odata.type'
        if ($type -like '*.group') {
          $nested = Get-GroupMembersRecursive -GroupId $member.id -Seen $Seen
          foreach ($n in $nested) { $leaves.Add($n) }
        }
        else {
          $resolved = Resolve-Principal -ObjectId $member.id
          if ($resolved) { $leaves.Add($resolved) }
        }
      }
      $url = $resp.'@odata.nextLink'
    } while ($url)
  }
  catch {
    Write-Verbose "Could not list members of group $GroupId : $_"
  }

  $groupMemberCache[$GroupId] = $leaves
  return $leaves
}

# ---------------------------------------------------------------------------
# Pre-fetch app registrations including credentials for activity check
# ---------------------------------------------------------------------------

Write-Host "Loading App Registrations..." -ForegroundColor Cyan
$now = Get-Date
$totalCredsSeen = 0
$totalAppsWithExpiredOnly = 0
$totalAppsDeactivated = 0

# First pass: v1.0 — properties available in stable
$url = 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999'
do {
  $resp = Invoke-MgGraphRequest -Method GET -Uri $url
  foreach ($app in $resp.value) {
    $hasValidCred = $false
    $credCount = 0
    $expiredCount = 0

    $allCreds = @()
    if ($app['passwordCredentials']) { $allCreds += @($app['passwordCredentials']) }
    if ($app['keyCredentials']) { $allCreds += @($app['keyCredentials']) }

    foreach ($cred in $allCreds) {
      if (-not $cred) { continue }
      $credCount++
      $start = $null; $end = $null
      try { if ($cred['startDateTime']) { $start = [datetime]$cred['startDateTime'] } } catch {}
      try { if ($cred['endDateTime']) { $end = [datetime]$cred['endDateTime'] } } catch {}
      $isValid = $true
      if ($start -and $start -gt $now) { $isValid = $false }
      if ($end -and $end -lt $now) { $isValid = $false; $expiredCount++ }
      if ($isValid) { $hasValidCred = $true }
    }

    $totalCredsSeen += $credCount
    if ($credCount -gt 0 -and -not $hasValidCred) { $totalAppsWithExpiredOnly++ }

    $appByAppId[$app['appId']] = $app
    $appCredInfoByAppId[$app['appId']] = @{
      HasValidCred = $hasValidCred
      CredCount    = $credCount
      ExpiredCount = $expiredCount
      IsDisabled   = $false   # populated by /beta call below
    }
  }
  $url = $resp.'@odata.nextLink'
} while ($url)

# Second pass: /beta — the 'isDisabled' property (= the App Registration "Deactivated"
# toggle in the Azure Portal) is only exposed on the beta endpoint as of this writing.
try {
  $url = 'https://graph.microsoft.com/beta/applications?$select=appId,isDisabled&$top=999'
  do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop
    foreach ($app in $resp.value) {
      $aid = $app['appId']
      if ($aid -and $appCredInfoByAppId.ContainsKey($aid)) {
        if ($app['isDisabled'] -eq $true) {
          $appCredInfoByAppId[$aid]['IsDisabled'] = $true
          $totalAppsDeactivated++
        }
      }
    }
    $url = $resp.'@odata.nextLink'
  } while ($url)
}
catch {
  Write-Warning "Could not load isDisabled from /beta endpoint: $_"
  Write-Warning "App-Registration 'Deactivated' status may not be detected."
}

Write-Host "  $($appByAppId.Count) App Registrations cached"
Write-Host "  $totalCredsSeen total credentials seen"
Write-Host "  $totalAppsWithExpiredOnly apps with only expired credentials" -ForegroundColor $(if ($totalAppsWithExpiredOnly -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host "  $totalAppsDeactivated app registrations deactivated`n" -ForegroundColor $(if ($totalAppsDeactivated -gt 0) { 'Red' } else { 'Gray' })

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
  param(
    [string] $RoleScope,
    [string] $RoleName,
    [string] $Scope,
    [string] $ScopeName,
    [string] $AssignmentType,
    [PSCustomObject] $Principal,
    [string] $ViaGroup = $null,
    [string] $ViaGroupId = $null,
    [bool]   $IsCustomRole = $false,
    [string[]] $RiskyActions = @()
  )

  # Determine scope level
  $scopeInfo = if ($RoleScope -eq 'Azure') {
    Get-ScopeInfo -Scope $Scope
  }
  else {
    if ($Scope -eq '/') { @{ Level = 'Tenant'; Detail = 'Tenant-wide' } }
    else { @{ Level = 'AdminUnit'; Detail = $Scope } }
  }

  # Score
  $riskScore = Get-RiskScore -RoleScope $RoleScope -RoleName $RoleName `
    -ScopeLevel $scopeInfo.Level -PrincipalType $Principal.Type `
    -AssignmentType $AssignmentType -IsCustomRole $IsCustomRole `
    -RiskyActions $RiskyActions -ActivityStatus $Principal.ActivityStatus

  # Cleanup
  $cleanup = Get-CleanupCommand -RoleScope $RoleScope -RoleName $RoleName -Scope $Scope `
    -PrincipalId $Principal.ObjectId -PrincipalType $Principal.Type `
    -AssignmentType $AssignmentType `
    -ViaGroupId $ViaGroupId -ViaGroupName $ViaGroup

  $findings.Add([PSCustomObject]@{
      RoleScope      = $RoleScope
      RoleName       = $RoleName
      IsCustomRole   = $IsCustomRole
      RiskyActions   = ($RiskyActions -join '; ')
      Scope          = $Scope
      ScopeName      = $ScopeName
      ScopeLevel     = $scopeInfo.Level
      ScopeDetail    = $scopeInfo.Detail
      AssignmentType = $AssignmentType
      PrincipalType  = $Principal.Type
      PrincipalName  = $Principal.DisplayName
      PrincipalId    = $Principal.ObjectId
      UPN            = $Principal.UPN
      AppId          = $Principal.AppId
      AccountEnabled = $Principal.IsEnabled
      ActivityStatus = $Principal.ActivityStatus
      ActivityReason = $Principal.ActivityReason
      ViaGroup       = $ViaGroup
      ViaGroupId     = $ViaGroupId
      RiskScore      = $riskScore
      CleanupPrimary = $cleanup.Primary
      CleanupAlt     = $cleanup.Alt
    })
}

# Wildcard-aware action matching.
# A role definition action like 'Microsoft.Authorization/*' matches risky
# action 'Microsoft.Authorization/roleAssignments/write'.
function Test-ActionMatch {
  param([string] $Pattern, [string] $Action)
  if ([string]::IsNullOrEmpty($Pattern) -or [string]::IsNullOrEmpty($Action)) { return $false }
  if ($Pattern -eq '*') { return $true }
  if ($Pattern -eq $Action) { return $true }
  if ($Pattern -like '*`**') {
    # Convert wildcard pattern to regex
    $regex = '^' + [regex]::Escape($Pattern).Replace('\*', '.*') + '$'
    return $Action -match $regex
  }
  return $false
}

# Returns the list of risky actions a role grants, after applying NotActions.
function Get-RiskyActionsForRole {
  param(
    [string[]] $Actions = @(),
    [string[]] $NotActions = @(),
    [string[]] $DataActions = @(),
    [string[]] $NotDataActions = @(),
    [string[]] $RiskyList
  )

  $hits = New-Object System.Collections.Generic.List[string]
  foreach ($risky in $RiskyList) {
    # Granted by Actions or DataActions?
    $granted = $false
    foreach ($p in $Actions) { if (Test-ActionMatch -Pattern $p -Action $risky) { $granted = $true; break } }
    if (-not $granted) {
      foreach ($p in $DataActions) { if (Test-ActionMatch -Pattern $p -Action $risky) { $granted = $true; break } }
    }
    if (-not $granted) { continue }

    # Removed by NotActions / NotDataActions?
    $blocked = $false
    foreach ($p in $NotActions) { if (Test-ActionMatch -Pattern $p -Action $risky) { $blocked = $true; break } }
    if (-not $blocked) {
      foreach ($p in $NotDataActions) { if (Test-ActionMatch -Pattern $p -Action $risky) { $blocked = $true; break } }
    }
    if (-not $blocked) { $hits.Add($risky) }
  }
  return $hits
}

# Parse an Azure RBAC scope string into a hierarchy level and pretty name.
# Examples:
#   /                                                                  -> Root
#   /providers/Microsoft.Management/managementGroups/{id}              -> ManagementGroup
#   /subscriptions/{guid}                                              -> Subscription
#   /subscriptions/{guid}/resourceGroups/{name}                        -> ResourceGroup
#   /subscriptions/{guid}/resourceGroups/{name}/providers/.../{name}   -> Resource
function Get-ScopeInfo {
  param([string] $Scope)

  if ([string]::IsNullOrWhiteSpace($Scope) -or $Scope -eq '/') {
    return @{ Level = 'Root'; Detail = 'Tenant root' }
  }
  if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/(.+)$') {
    return @{ Level = 'ManagementGroup'; Detail = "MG: $($Matches[1])" }
  }
  if ($Scope -match '^/subscriptions/[0-9a-fA-F\-]+/resourceGroups/[^/]+/providers/.+$') {
    $resName = ($Scope -split '/')[-1]
    return @{ Level = 'Resource'; Detail = "Resource: $resName" }
  }
  if ($Scope -match '^/subscriptions/[0-9a-fA-F\-]+/resourceGroups/([^/]+)$') {
    return @{ Level = 'ResourceGroup'; Detail = "RG: $($Matches[1])" }
  }
  if ($Scope -match '^/subscriptions/[0-9a-fA-F\-]+$') {
    return @{ Level = 'Subscription'; Detail = 'Subscription' }
  }
  return @{ Level = 'Other'; Detail = $Scope }
}

# Compute a 0.0-10.0 risk score (CVSS-style).
# Considers role type, scope breadth, principal type, custom-with-risky-actions,
# permanent vs eligible, and inactive principals.
function Get-RiskScore {
  param(
    [string] $RoleScope,         # Azure / Entra
    [string] $RoleName,
    [string] $ScopeLevel,        # Root / ManagementGroup / Subscription / ResourceGroup / Resource / Other
    [string] $PrincipalType,
    [string] $AssignmentType,    # Permanent / Eligible
    [bool]   $IsCustomRole,
    [string[]] $RiskyActions,
    [string] $ActivityStatus
  )

  # Base score per role
  $base = 3.0
  $criticalRoles = @(
    'Owner', 'User Access Administrator', 'Role Based Access Control Administrator',
    'Global Administrator', 'Privileged Role Administrator',
    'Privileged Authentication Administrator'
  )
  $highRoles = @(
    'Contributor', 'Security Admin', 'Security Administrator',
    'Application Administrator', 'Cloud Application Administrator',
    'Authentication Administrator', 'User Administrator',
    'Key Vault Administrator', 'Resource Policy Contributor'
  )
  $mediumRoles = @(
    'Virtual Machine Contributor', 'Website Contributor', 'Managed Identity Operator',
    'Conditional Access Administrator', 'Exchange Administrator',
    'SharePoint Administrator', 'Intune Administrator',
    'Helpdesk Administrator', 'Hybrid Identity Administrator',
    'Domain Name Administrator', 'External Identity Provider Administrator',
    'Groups Administrator', 'Directory Writers',
    'Partner Tier1 Support', 'Partner Tier2 Support',
    'Storage Account Key Operator Service Role',
    'Access Review Operator Service Role', 'Reservation Purchaser'
  )

  if ($RoleName -in $criticalRoles) { $base = 9.0 }
  elseif ($RoleName -in $highRoles) { $base = 7.0 }
  elseif ($RoleName -in $mediumRoles) { $base = 5.5 }

  # Custom role with risky actions: rated by what it can actually do
  if ($IsCustomRole) {
    $base = 6.0   # baseline for any privileged custom role
    if ($RiskyActions) {
      $criticalActions = @(
        'Microsoft.Authorization/roleAssignments/write',
        'Microsoft.Authorization/roleDefinitions/write',
        'Microsoft.Authorization/elevateAccess/action',
        'Microsoft.Authorization/denyAssignments/delete',
        'microsoft.directory/roleAssignments/allProperties/allTasks',
        'microsoft.directory/roleDefinitions/allProperties/allTasks',
        'microsoft.directory/users/password/update',
        'microsoft.directory/applications/credentials/update',
        'microsoft.directory/servicePrincipals/credentials/update'
      )
      foreach ($a in $RiskyActions) {
        if ($a -in $criticalActions) { $base = [Math]::Max($base, 9.0) }
      }
      # multiple risky actions stack
      if ($RiskyActions.Count -ge 3) { $base += 0.5 }
    }
  }

  # Scope multiplier
  $scopeMod = switch ($ScopeLevel) {
    'Root' { 1.0 }
    'ManagementGroup' { 0.95 }
    'Subscription' { 0.85 }
    'ResourceGroup' { 0.65 }
    'Resource' { 0.45 }
    default { 0.85 }
  }

  $score = $base * $scopeMod

  # Modifiers
  if ($AssignmentType -eq 'Eligible') { $score -= 1.5 }   # PIM = better
  if ($PrincipalType -in 'EnterpriseApp', 'AppRegistration', 'ManagedIdentity') {
    $score += 0.5   # apps/MIs are quieter persistence vectors
  }
  if ($ActivityStatus -eq 'Disabled') { $score -= 2.0 }   # can't sign in -> lower live risk
  if ($ActivityStatus -eq 'NoValidCredential') { $score -= 1.0 }   # someone could add a new secret though
  if ($ActivityStatus -eq 'BlockedByMicrosoft') { $score -= 2.5 }

  # Clamp to 0.0 - 10.0 with one decimal
  if ($score -lt 0) { $score = 0 }
  if ($score -gt 10) { $score = 10 }
  return [Math]::Round($score, 1)
}

# Generate a remediation command suggestion for a finding.
# Returns @{ Primary = '...'; Alt = '...' } where Alt may be null.
function Get-CleanupCommand {
  param(
    [string] $RoleScope,        # Azure / Entra
    [string] $RoleName,
    [string] $Scope,
    [string] $PrincipalId,
    [string] $PrincipalType,
    [string] $AssignmentType,
    [string] $ViaGroupId,
    [string] $ViaGroupName
  )

  $primary = $null
  $alt = $null

  if ($ViaGroupId) {
    # Group-member finding: give both options
    $primary = "Remove-AzADGroupMember -GroupObjectId '$ViaGroupId' -MemberObjectId '$PrincipalId'"
    if ($RoleScope -eq 'Azure') {
      $alt = "Remove-AzRoleAssignment -ObjectId '$ViaGroupId' -RoleDefinitionName '$RoleName' -Scope '$Scope'  # removes role for ENTIRE group"
    }
    else {
      $alt = "# To remove the role from the entire group, use the Entra portal or:`n# Remove via roleManagement/directory/roleAssignments DELETE for the group's assignment"
    }
  }
  else {
    if ($RoleScope -eq 'Azure') {
      $primary = "Remove-AzRoleAssignment -ObjectId '$PrincipalId' -RoleDefinitionName '$RoleName' -Scope '$Scope'"
    }
    else {
      # Entra: different command for permanent vs eligible
      if ($AssignmentType -eq 'Eligible') {
        $primary = "# Remove PIM eligibility for principal '$PrincipalId' on role '$RoleName' via Entra portal -> PIM -> Eligible assignments"
      }
      else {
        $primary = "# Find and delete the role assignment:`nGet-MgRoleManagementDirectoryRoleAssignment -Filter `"principalId eq '$PrincipalId'`" |`n  Where-Object { `$_.RoleDefinitionId -eq (Get-MgRoleManagementDirectoryRoleDefinition -Filter `"displayName eq '$RoleName'`").Id } |`n  ForEach-Object { Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId `$_.Id }"
      }
    }
  }

  return @{ Primary = $primary; Alt = $alt }
}

# ---------------------------------------------------------------------------
# Azure RBAC enumeration
# ---------------------------------------------------------------------------

Write-Host "Enumerating Azure RBAC..." -ForegroundColor Cyan

# Get all subscriptions accessible by the current account (don't filter by tenant
# initially — some setups expose subs via guest contexts that the tenant filter drops).
$allSubs = Get-AzSubscription -ErrorAction SilentlyContinue
$subs = $allSubs | Where-Object { $_.State -eq 'Enabled' -and $_.TenantId -eq $tenantId }

Write-Host "  Subscriptions visible to your account: $($allSubs.Count)"
Write-Host "  Enabled in target tenant ($tenantId): $($subs.Count)"

if ($subs.Count -eq 0) {
  Write-Warning "  No subscriptions matched the target tenant. Things to check:"
  Write-Warning "    - Run 'Get-AzSubscription' manually to see what your account can see"
  Write-Warning "    - Make sure your Az login is for the correct tenant: Connect-AzAccount -TenantId $tenantId"
  Write-Warning "    - The tenantId being used was taken from your Graph session"
}

# Cache: roleDefinitionId -> @{ Risky=[strings]; IsCustom=$true } so we only
# evaluate each definition once even if it appears in many subscriptions.
$roleRiskCache = @{}

$i = 0
foreach ($sub in $subs) {
  $i++
  Write-Host "  [$i/$($subs.Count)] $($sub.Name)" -ForegroundColor Gray
  Set-AzContext -SubscriptionId $sub.Id -TenantId $tenantId | Out-Null

  # 1) Scan custom role definitions in this sub for risky actions
  $riskyCustomRoleNames = New-Object System.Collections.Generic.HashSet[string]
  try {
    $defs = Get-AzRoleDefinition -ErrorAction Stop | Where-Object { $_.IsCustom }
    foreach ($def in $defs) {
      if (-not $roleRiskCache.ContainsKey($def.Id)) {
        $hits = Get-RiskyActionsForRole `
          -Actions       $def.Actions `
          -NotActions    $def.NotActions `
          -DataActions   $def.DataActions `
          -NotDataActions $def.NotDataActions `
          -RiskyList     $RiskyAzureActions
        $roleRiskCache[$def.Id] = @{
          Risky    = @($hits)
          IsCustom = $true
          Name     = $def.Name
        }
      }
      if ($roleRiskCache[$def.Id].Risky.Count -gt 0) {
        [void]$riskyCustomRoleNames.Add($def.Name)
      }
    }
  }
  catch {
    Write-Warning "    Could not list role definitions on $($sub.Name): $_"
  }

  if ($riskyCustomRoleNames.Count -gt 0) {
    Write-Host "    Risky custom roles in this sub: $($riskyCustomRoleNames.Count)" -ForegroundColor Yellow
  }

  # 2) Get all assignments and filter by either built-in priv or risky custom role
  try {
    $allAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction Stop
    Write-Host "    Total assignments in scope: $($allAssignments.Count)" -ForegroundColor DarkGray
    $assignments = $allAssignments | Where-Object {
      ($_.RoleDefinitionName -in $privAzureRoles) -or
      ($riskyCustomRoleNames.Contains($_.RoleDefinitionName))
    }
    Write-Host "    Privileged assignments matched: $($assignments.Count)" -ForegroundColor DarkGray
  }
  catch {
    Write-Warning "    Could not list assignments on $($sub.Name): $_"
    continue
  }

  foreach ($a in $assignments) {
    $principal = Resolve-Principal -ObjectId $a.ObjectId
    if (-not $principal) { continue }

    # Decide if custom and look up the risky-action list for this role
    $isCustom = $false
    $risky = @()
    if ($riskyCustomRoleNames.Contains($a.RoleDefinitionName)) {
      $isCustom = $true
      # find the cache entry that matches this name (Id is the key)
      $defIdGuess = ($roleRiskCache.GetEnumerator() |
        Where-Object { $_.Value.Name -eq $a.RoleDefinitionName } |
        Select-Object -First 1).Key
      if ($defIdGuess) { $risky = $roleRiskCache[$defIdGuess].Risky }
    }

    $commonArgs = @{
      RoleScope      = 'Azure'
      RoleName       = $a.RoleDefinitionName
      Scope          = $a.Scope
      ScopeName      = $sub.Name
      AssignmentType = 'Permanent'
      IsCustomRole   = $isCustom
      RiskyActions   = $risky
    }

    if ($principal.Type -eq 'Group') {
      Add-Finding @commonArgs -Principal $principal

      $members = Get-GroupMembersRecursive -GroupId $principal.ObjectId
      foreach ($m in $members) {
        Add-Finding @commonArgs -Principal $m `
          -ViaGroup $principal.DisplayName -ViaGroupId $principal.ObjectId
      }
    }
    else {
      Add-Finding @commonArgs -Principal $principal
    }
  }
}

# ---------------------------------------------------------------------------
# Entra ID role assignments
# ---------------------------------------------------------------------------

Write-Host "`nEnumerating Entra ID role assignments..." -ForegroundColor Cyan

# Fetch full role definitions including rolePermissions so we can scan custom roles
$roleDefs = Invoke-MgGraphRequest -Method GET `
  -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'

# Build maps:
#   $privRoleDefMap   id -> displayName  (built-in priv roles + custom roles with risky actions)
#   $customRoleRisk   id -> array of risky actions found in this custom role
$privRoleDefMap = @{}
$customRoleRisk = @{}
$customRoleSet = New-Object System.Collections.Generic.HashSet[string]

foreach ($rd in $roleDefs.value) {
  $isBuiltIn = if ($null -ne $rd.isBuiltIn) { $rd.isBuiltIn } else { $true }

  if ($isBuiltIn) {
    if ($rd.displayName -in $privEntraRoles) {
      $privRoleDefMap[$rd.id] = $rd.displayName
    }
  }
  else {
    # Aggregate allowedResourceActions across all rolePermissions blocks
    $allowed = New-Object System.Collections.Generic.List[string]
    foreach ($rp in @($rd.rolePermissions)) {
      foreach ($act in @($rp.allowedResourceActions)) { $allowed.Add($act) }
    }

    $hits = Get-RiskyActionsForRole -Actions $allowed -RiskyList $RiskyEntraActions
    if ($hits.Count -gt 0) {
      $privRoleDefMap[$rd.id] = $rd.displayName
      $customRoleRisk[$rd.id] = @($hits)
      [void]$customRoleSet.Add($rd.id)
    }
  }
}

$builtInPrivCount = ($privRoleDefMap.Keys | Where-Object { -not $customRoleSet.Contains($_) }).Count
Write-Host "  Built-in privileged roles matched: $builtInPrivCount"
Write-Host "  Custom directory roles with risky actions: $($customRoleSet.Count)"

function Get-EntraAssignments {
  param([string] $Endpoint, [string] $TypeLabel)

  $results = New-Object System.Collections.Generic.List[object]
  $url = "https://graph.microsoft.com/v1.0/roleManagement/directory/$Endpoint"
  do {
    try {
      $resp = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop
    }
    catch {
      Write-Warning "  Could not query $Endpoint : $_"
      return $results
    }
    foreach ($a in $resp.value) {
      if ($privRoleDefMap.ContainsKey($a.roleDefinitionId)) {
        $results.Add([PSCustomObject]@{
            PrincipalId      = $a.principalId
            RoleId           = $a.roleDefinitionId
            RoleName         = $privRoleDefMap[$a.roleDefinitionId]
            DirectoryScopeId = $a.directoryScopeId
            Type             = $TypeLabel
          })
      }
    }
    $url = $resp.'@odata.nextLink'
  } while ($url)
  return $results
}

$entraActive = Get-EntraAssignments -Endpoint 'roleAssignments' -TypeLabel 'Permanent'
Write-Host "  $($entraActive.Count) permanent assignments on privileged roles"

$entraEligible = @()
if (-not $SkipPim) {
  $entraEligible = Get-EntraAssignments -Endpoint 'roleEligibilitySchedules' -TypeLabel 'Eligible'
  Write-Host "  $($entraEligible.Count) PIM eligible assignments on privileged roles"
}

foreach ($a in @($entraActive) + @($entraEligible)) {
  $principal = Resolve-Principal -ObjectId $a.PrincipalId
  if (-not $principal) { continue }

  $scopeDisplay = if ($a.DirectoryScopeId -eq '/') { 'Tenant-wide' } else { $a.DirectoryScopeId }
  $isCustom = $customRoleSet.Contains($a.RoleId)
  $risky = if ($isCustom) { $customRoleRisk[$a.RoleId] } else { @() }

  $commonArgs = @{
    RoleScope      = 'Entra'
    RoleName       = $a.RoleName
    Scope          = $a.DirectoryScopeId
    ScopeName      = $scopeDisplay
    AssignmentType = $a.Type
    IsCustomRole   = $isCustom
    RiskyActions   = $risky
  }

  if ($principal.Type -eq 'Group') {
    Add-Finding @commonArgs -Principal $principal

    $members = Get-GroupMembersRecursive -GroupId $principal.ObjectId
    foreach ($m in $members) {
      Add-Finding @commonArgs -Principal $m `
        -ViaGroup $principal.DisplayName -ViaGroupId $principal.ObjectId
    }
  }
  else {
    Add-Finding @commonArgs -Principal $principal
  }
}

Write-Host "`nTotal findings: $($findings.Count)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

$totalFindings = $findings.Count
$uniqueUsers = ($findings | Where-Object { $_.PrincipalType -eq 'User' } |
  Select-Object -ExpandProperty PrincipalId -Unique).Count
$uniqueApps = ($findings | Where-Object { $_.PrincipalType -in 'EnterpriseApp', 'AppRegistration' } |
  Select-Object -ExpandProperty PrincipalId -Unique).Count
$uniqueMI = ($findings | Where-Object { $_.PrincipalType -eq 'ManagedIdentity' } |
  Select-Object -ExpandProperty PrincipalId -Unique).Count
$uniqueGroups = ($findings | Where-Object { $_.PrincipalType -eq 'Group' } |
  Select-Object -ExpandProperty PrincipalId -Unique).Count
$permanentCount = ($findings | Where-Object AssignmentType -eq 'Permanent').Count
$eligibleCount = ($findings | Where-Object AssignmentType -eq 'Eligible').Count
$customCount = ($findings | Where-Object IsCustomRole -eq $true).Count
$inactiveCount = ($findings | Where-Object { $_.ActivityStatus -in 'Disabled', 'NoValidCredential', 'BlockedByMicrosoft' }).Count
$criticalCount = ($findings | Where-Object { $_.RiskScore -ge 9.0 }).Count
$highCount = ($findings | Where-Object { $_.RiskScore -ge 7.0 -and $_.RiskScore -lt 9.0 }).Count

# ---------------------------------------------------------------------------
# Build HTML report
# ---------------------------------------------------------------------------

Write-Host "`nBuilding HTML report..." -ForegroundColor Cyan

$dataJson = $findings | ConvertTo-Json -Depth 4 -Compress
if (-not $dataJson) { $dataJson = '[]' }
# A single object isn't wrapped in [] by ConvertTo-Json
if ($dataJson -notmatch '^\s*\[') { $dataJson = "[$dataJson]" }
$dataJson = $dataJson -replace '</', '<\/'

$generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

# HTML head + body — double-quoted here-string so PS interpolates the stats
$head = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RiskyRolesAnalyzer Report</title>
<style>
  :root {
    --bg: #0f172a;
    --panel: #1e293b;
    --panel2: #273449;
    --border: #334155;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --ok: #22c55e;
    --warn: #f59e0b;
    --err: #ef4444;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.5;
  }
  header {
    padding: 24px 32px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  }
  h1 {
    margin: 0 0 4px 0;
    font-size: 22px;
    font-weight: 600;
    letter-spacing: -0.2px;
  }
  .subtitle { color: var(--muted); font-size: 13px; }
  .summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    padding: 20px 32px;
    border-bottom: 1px solid var(--border);
  }
  .stat {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
  }
  .stat-label { font-size: 11px; text-transform: uppercase; color: var(--muted); letter-spacing: 0.5px; }
  .stat-value { font-size: 22px; font-weight: 600; margin-top: 4px; }
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    padding: 16px 32px;
    border-bottom: 1px solid var(--border);
    background: var(--panel);
  }
  .controls input, .controls select, .controls button {
    background: var(--panel2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 7px 11px;
    font-size: 13px;
    font-family: inherit;
  }
  .controls input { min-width: 240px; }
  .controls input:focus, .controls select:focus { outline: none; border-color: var(--accent); }
  .controls button {
    cursor: pointer;
    background: var(--accent);
    color: #0f172a;
    border-color: var(--accent);
    font-weight: 600;
  }
  .controls button:hover { background: #0ea5e9; }
  .toggle-btn {
    background: var(--panel2) !important;
    color: var(--text) !important;
    border: 1px solid var(--border) !important;
    font-weight: 500 !important;
  }
  .toggle-btn:hover {
    background: var(--panel) !important;
  }
  .toggle-btn[data-active="true"] {
    background: var(--accent) !important;
    color: #0f172a !important;
    border-color: var(--accent) !important;
    font-weight: 600 !important;
  }
  .accept-cell {
    text-align: center;
  }
  .accept-cb {
    width: 18px;
    height: 18px;
    cursor: pointer;
    accent-color: var(--ok);
  }
  tr.accepted {
    opacity: 0.45;
  }
  tr.accepted td {
    text-decoration: line-through;
    text-decoration-color: rgba(148,163,184,0.4);
  }
  tr.accepted td:last-child {
    text-decoration: none;   /* don't strike through the checkbox itself */
  }
  .controls .count { margin-left: auto; color: var(--muted); align-self: center; font-size: 12px; }
  .table-wrap { padding: 0 32px 32px 32px; overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  thead th {
    text-align: left;
    padding: 10px 12px;
    background: var(--panel);
    border-bottom: 2px solid var(--border);
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    color: var(--muted);
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
  }
  thead th:hover { color: var(--text); }
  thead th.sorted-asc::after  { content: ' \25B2'; color: var(--accent); }
  thead th.sorted-desc::after { content: ' \25BC'; color: var(--accent); }
  tbody td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:hover { background: rgba(56,189,248,0.04); }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    border: 1px solid transparent;
    white-space: nowrap;
  }
  .badge-User            { background: rgba(96,165,250,0.15);  color: #93c5fd; border-color: rgba(96,165,250,0.4); }
  .badge-Group           { background: rgba(167,139,250,0.15); color: #c4b5fd; border-color: rgba(167,139,250,0.4); }
  .badge-EnterpriseApp   { background: rgba(244,114,182,0.15); color: #f9a8d4; border-color: rgba(244,114,182,0.4); }
  .badge-AppRegistration { background: rgba(244,114,182,0.15); color: #f9a8d4; border-color: rgba(244,114,182,0.4); }
  .badge-ManagedIdentity { background: rgba(251,146,60,0.15);  color: #fdba74; border-color: rgba(251,146,60,0.4); }
  .badge-Other           { background: rgba(148,163,184,0.15); color: #cbd5e1; border-color: rgba(148,163,184,0.4); }
  .badge-Unknown         { background: rgba(148,163,184,0.15); color: #cbd5e1; border-color: rgba(148,163,184,0.4); }
  .badge-Permanent       { background: rgba(34,197,94,0.15);   color: #86efac; border-color: rgba(34,197,94,0.4); }
  .badge-Eligible        { background: rgba(245,158,11,0.15);  color: #fcd34d; border-color: rgba(245,158,11,0.4); }
  .badge-Azure           { background: rgba(56,189,248,0.15);  color: #7dd3fc; border-color: rgba(56,189,248,0.4); }
  .badge-Entra           { background: rgba(129,140,248,0.15); color: #a5b4fc; border-color: rgba(129,140,248,0.4); }
  .badge-status-Active             { background: rgba(34,197,94,0.15); color: #86efac; border-color: rgba(34,197,94,0.4); }
  .badge-status-Disabled           { background: rgba(239,68,68,0.18); color: #fca5a5; border-color: rgba(239,68,68,0.4); }
  .badge-status-NoValidCredential  { background: rgba(245,158,11,0.18); color: #fcd34d; border-color: rgba(245,158,11,0.4); }
  .badge-status-BlockedByMicrosoft { background: rgba(239,68,68,0.25); color: #fecaca; border-color: rgba(239,68,68,0.6); }
  .badge-status-Unknown            { background: rgba(148,163,184,0.15); color: #cbd5e1; border-color: rgba(148,163,184,0.4); }
  .status-reason { font-size: 11px; color: var(--muted); margin-top: 3px; }
  .mono { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 12px; color: var(--muted); }
  .identity-upn { font-size: 11px; margin-top: 2px; color: #cbd5e1; }
  .identity-id  { font-size: 10px; margin-top: 1px; color: var(--muted); opacity: 0.7; }
  .via { font-size: 11px; color: var(--warn); margin-top: 3px; }
  .empty { padding: 60px; text-align: center; color: var(--muted); }
  .report-footer {
    text-align: center;
    padding: 20px 32px 28px 32px;
    color: var(--muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 8px;
  }
  .report-footer a {
    color: var(--accent);
    text-decoration: none;
  }
  .report-footer a:hover { text-decoration: underline; }
  .report-footer strong { color: var(--text); font-weight: 600; }
  .disabled-flag { color: var(--err); font-weight: 600; font-size: 11px; margin-left: 6px; }
  .custom-flag {
    display: inline-block;
    margin-left: 6px;
    padding: 1px 6px;
    border-radius: 4px;
    background: rgba(239,68,68,0.18);
    color: #fca5a5;
    border: 1px solid rgba(239,68,68,0.4);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.4px;
    vertical-align: middle;
  }
  .actions-cell { max-width: 380px; }
  .action-pill {
    display: inline-block;
    padding: 2px 6px;
    margin: 1px 2px;
    border-radius: 4px;
    background: rgba(245,158,11,0.12);
    border: 1px solid rgba(245,158,11,0.3);
    color: #fcd34d;
    font-family: 'SF Mono', Menlo, Consolas, monospace;
    font-size: 10px;
    word-break: break-all;
  }
  .score {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 10px;
    letter-spacing: 0.5px;
    text-align: center;
    white-space: nowrap;
  }
  .score-critical { background: rgba(239,68,68,0.2);  color: #fca5a5; border: 1px solid rgba(239,68,68,0.5); }
  .score-high     { background: rgba(245,158,11,0.18); color: #fcd34d; border: 1px solid rgba(245,158,11,0.45); }
  .score-medium   { background: rgba(56,189,248,0.15); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.4); }
  .score-low      { background: rgba(34,197,94,0.15);  color: #86efac; border: 1px solid rgba(34,197,94,0.4); }
  .score-info     { background: rgba(148,163,184,0.15); color: #cbd5e1; border: 1px solid rgba(148,163,184,0.4); }
  .scope-Root,
  .scope-Tenant,
  .scope-ManagementGroup { color: #fca5a5; font-weight: 600; }
  .scope-Subscription   { color: #fcd34d; font-weight: 600; }
  .scope-ResourceGroup  { color: #7dd3fc; }
  .scope-Resource       { color: #86efac; }
  .scope-AdminUnit      { color: #c4b5fd; }
  .scope-detail { font-size: 11px; color: var(--muted); margin-top: 2px; }
  .cleanup-btn {
    background: var(--panel2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 11px;
    font-family: inherit;
  }
  .cleanup-btn:hover { background: var(--accent); color: #0f172a; border-color: var(--accent); }
  .cleanup-btn.copied { background: var(--ok); color: #0f172a; border-color: var(--ok); }
  .cleanup-popup {
    position: fixed;
    z-index: 1000;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    max-width: 600px;
    display: none;
  }
  .cleanup-popup pre {
    background: #0a0f1c;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px;
    margin: 6px 0;
    font-size: 11px;
    overflow-x: auto;
    color: #e2e8f0;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .cleanup-popup h4 { margin: 0 0 8px 0; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.4px; }
  .cleanup-popup .close { float: right; cursor: pointer; color: var(--muted); padding: 0 4px; }
  .cleanup-popup .close:hover { color: var(--text); }
  .cleanup-popup code {
    background: rgba(56,189,248,0.12);
    color: #7dd3fc;
    padding: 1px 5px;
    border-radius: 3px;
    font-family: 'SF Mono', Menlo, Consolas, monospace;
    font-size: 11px;
  }
  .prereq-box {
    background: rgba(245,158,11,0.06);
    border: 1px solid rgba(245,158,11,0.25);
    border-radius: 6px;
    padding: 10px 12px;
    margin-bottom: 14px;
    font-size: 12px;
    color: #e2e8f0;
  }
  .prereq-title {
    font-size: 10px;
    color: #fcd34d;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 700;
    margin-bottom: 6px;
  }
</style>
</head>
<body>
<header>
  <h1>Privileged Role Audit</h1>
  <div class="subtitle">RiskyRolesAnalyzer &nbsp;&middot;&nbsp; Tenant: $tenantId &nbsp;&middot;&nbsp; Generated: $generated</div>
</header>
<section class="summary">
  <div class="stat"><div class="stat-label">Total Findings</div><div class="stat-value">$totalFindings</div></div>
  <div class="stat"><div class="stat-label">Critical</div><div class="stat-value" style="color:#fca5a5">$criticalCount</div></div>
  <div class="stat"><div class="stat-label">High</div><div class="stat-value" style="color:#fcd34d">$highCount</div></div>
  <div class="stat"><div class="stat-label">Permanent</div><div class="stat-value" style="color:var(--ok)">$permanentCount</div></div>
  <div class="stat"><div class="stat-label">Eligible (PIM)</div><div class="stat-value" style="color:var(--warn)">$eligibleCount</div></div>
  <div class="stat"><div class="stat-label">Unique Users</div><div class="stat-value">$uniqueUsers</div></div>
  <div class="stat"><div class="stat-label">Unique Apps</div><div class="stat-value">$uniqueApps</div></div>
  <div class="stat"><div class="stat-label">Managed Identities</div><div class="stat-value">$uniqueMI</div></div>
  <div class="stat"><div class="stat-label">Groups Assigned</div><div class="stat-value">$uniqueGroups</div></div>
  <div class="stat"><div class="stat-label">Custom Roles</div><div class="stat-value" style="color:var(--err)">$customCount</div></div>
  <div class="stat"><div class="stat-label">Inactive Principals</div><div class="stat-value" style="color:var(--err)">$inactiveCount</div></div>
</section>
<section class="controls">
  <input type="text" id="search" placeholder="Search anything (name, role, scope, UPN, AppId)...">
  <select id="filterScope">
    <option value="">All sources</option>
    <option value="Azure">Azure RBAC</option>
    <option value="Entra">Entra ID</option>
  </select>
  <select id="filterAssignment">
    <option value="">All assignment types</option>
    <option value="Permanent">Permanent</option>
    <option value="Eligible">Eligible (PIM)</option>
  </select>
  <select id="filterPrincipal">
    <option value="">All principal types</option>
    <option value="User">Users</option>
    <option value="Group">Groups</option>
    <option value="EnterpriseApp">Enterprise Apps</option>
    <option value="AppRegistration">App Registrations</option>
    <option value="ManagedIdentity">Managed Identities</option>
  </select>
  <select id="filterRole">
    <option value="">All roles</option>
  </select>
  <select id="filterVia">
    <option value="">Direct &amp; via group</option>
    <option value="direct">Direct only</option>
    <option value="group">Via group only</option>
  </select>
  <select id="filterCustom">
    <option value="">Built-in &amp; custom</option>
    <option value="custom">Custom only</option>
    <option value="builtin">Built-in only</option>
  </select>
  <select id="filterStatus">
    <option value="">All activity statuses</option>
    <option value="Active">Active only</option>
    <option value="inactive">Inactive only (disabled / no creds / blocked)</option>
    <option value="Disabled">Disabled</option>
    <option value="NoValidCredential">No valid credential</option>
    <option value="BlockedByMicrosoft">Blocked by Microsoft</option>
  </select>
  <select id="filterMinScore">
    <option value="">Any severity</option>
    <option value="9">Critical only</option>
    <option value="7">High &amp; above</option>
    <option value="5">Medium &amp; above</option>
    <option value="3">Low &amp; above</option>
  </select>
  <button id="toggleAccepted" class="toggle-btn" data-active="false">Show accepted</button>
  <button id="exportCsv">Export CSV</button>
  <span class="count" id="count"></span>
</section>
<section class="table-wrap">
  <table id="data">
    <thead>
      <tr>
        <th data-key="RiskScore">Severity</th>
        <th data-key="RoleScope">Source</th>
        <th data-key="RoleName">Role</th>
        <th data-key="AssignmentType">Type</th>
        <th data-key="PrincipalType">Principal</th>
        <th data-key="PrincipalName">Identity</th>
        <th data-key="ActivityStatus">Status</th>
        <th data-key="ScopeLevel">Scope</th>
        <th data-key="ViaGroup">Via</th>
        <th data-key="RiskyActions">Risky Actions</th>
        <th>Cleanup</th>
        <th>Accept</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>
  <div class="empty" id="empty" style="display:none">No matching findings</div>
</section>
<footer class="report-footer">
  Generated by <strong>RiskyRolesAnalyzer</strong> &nbsp;&middot;&nbsp;
  by <a href="https://simonvedder.com" target="_blank" rel="noopener">Simon Vedder</a>
</footer>
<div id="cleanupPopup" class="cleanup-popup">
  <span class="close" onclick="document.getElementById('cleanupPopup').style.display='none'">&times;</span>
  <h4>Cleanup Command</h4>
  <div id="cleanupBody"></div>
</div>
"@

# JS — single-quoted here-string: PS does NOT interpolate, JS template literals stay intact
$js = @'
<script>
const DATA = __DATA_PLACEHOLDER__;

const tbody = document.querySelector('#data tbody');
const search = document.getElementById('search');
const fScope = document.getElementById('filterScope');
const fAssign = document.getElementById('filterAssignment');
const fPrincipal = document.getElementById('filterPrincipal');
const fRole = document.getElementById('filterRole');
const fVia = document.getElementById('filterVia');
const fCustom = document.getElementById('filterCustom');
const fStatus = document.getElementById('filterStatus');
const fMinScore = document.getElementById('filterMinScore');
const toggleAccepted = document.getElementById('toggleAccepted');
const countEl = document.getElementById('count');

// In-memory set of accepted finding signatures (session-only).
// Lost on page reload by design — keeps the report self-contained.
const accepted = new Set();

// Stable signature so checkbox state survives sorts/filters.
function findingKey(r) {
  return `${r.RoleScope}|${r.RoleName}|${r.Scope}|${r.PrincipalId}|${r.AssignmentType}|${r.ViaGroupId || ''}`;
}
const emptyEl = document.getElementById('empty');

const roles = [...new Set(DATA.map(r => r.RoleName))].sort();
roles.forEach(r => {
  const o = document.createElement('option');
  o.value = r; o.textContent = r;
  fRole.appendChild(o);
});

let sortKey = 'RiskScore';
let sortDir = 'desc';
let filtered = DATA.slice();

function applyFilters() {
  const q = search.value.trim().toLowerCase();
  const sc = fScope.value;
  const as = fAssign.value;
  const pr = fPrincipal.value;
  const ro = fRole.value;
  const vi = fVia.value;
  const cu = fCustom.value;
  const st = fStatus.value;
  const ms = parseFloat(fMinScore.value);
  const showAccepted = toggleAccepted.dataset.active === 'true';

  filtered = DATA.filter(r => {
    const isAccepted = accepted.has(findingKey(r));
    if (!showAccepted && isAccepted) return false;
    if (sc && r.RoleScope !== sc) return false;
    if (as && r.AssignmentType !== as) return false;
    if (pr && r.PrincipalType !== pr) return false;
    if (ro && r.RoleName !== ro) return false;
    if (vi === 'direct' && r.ViaGroup) return false;
    if (vi === 'group' && !r.ViaGroup) return false;
    if (cu === 'custom' && !r.IsCustomRole) return false;
    if (cu === 'builtin' && r.IsCustomRole) return false;
    if (st === 'inactive') {
      if (!['Disabled','NoValidCredential','BlockedByMicrosoft'].includes(r.ActivityStatus)) return false;
    } else if (st && r.ActivityStatus !== st) {
      return false;
    }
    if (!isNaN(ms) && (r.RiskScore ?? 0) < ms) return false;
    if (q) {
      const hay = [r.RoleName, r.PrincipalName, r.UPN, r.AppId, r.ScopeName,
                   r.ViaGroup, r.PrincipalId, r.RiskyActions, r.ActivityReason,
                   r.ScopeDetail, r.ScopeLevel]
        .filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  applySort();
}

function applySort() {
  filtered.sort((a, b) => {
    let va = a[sortKey];
    let vb = b[sortKey];
    // Numeric sort for RiskScore
    if (sortKey === 'RiskScore') {
      va = parseFloat(va) || 0;
      vb = parseFloat(vb) || 0;
    } else {
      va = (va ?? '').toString().toLowerCase();
      vb = (vb ?? '').toString().toLowerCase();
    }
    if (va < vb) return sortDir === 'asc' ? -1 : 1;
    if (va > vb) return sortDir === 'asc' ?  1 : -1;
    return 0;
  });
  document.querySelectorAll('th').forEach(th => {
    th.classList.remove('sorted-asc', 'sorted-desc');
    if (th.dataset.key === sortKey) th.classList.add('sorted-' + sortDir);
  });
  render();
}

function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function render() {
  const acceptedTotal = accepted.size;
  const countSuffix = acceptedTotal > 0 ? ` (${acceptedTotal} accepted)` : '';
  countEl.textContent = `${filtered.length} of ${DATA.length} findings${countSuffix}`;
  if (filtered.length === 0) {
    tbody.innerHTML = '';
    emptyEl.style.display = 'block';
    return;
  }
  emptyEl.style.display = 'none';

  const rows = filtered.map((r, idx) => {
    const upnOrApp = r.UPN || r.AppId || '';
    const customFlag = r.IsCustomRole ? '<span class="custom-flag">CUSTOM</span>' : '';
    const via = r.ViaGroup
      ? `<div class="via">via group: ${esc(r.ViaGroup)}</div>`
      : `<span class="mono">direct</span>`;
    let actionsHtml = '';
    if (r.RiskyActions) {
      actionsHtml = r.RiskyActions.split(';')
        .map(a => a.trim()).filter(Boolean)
        .map(a => `<span class="action-pill">${esc(a)}</span>`).join('');
    }
    const statusClass = `badge badge-status-${esc(r.ActivityStatus || 'Unknown')}`;
    const statusLabel = (r.ActivityStatus || 'Unknown').replace(/([A-Z])/g, ' $1').trim();
    const reason = r.ActivityReason
      ? `<div class="status-reason">${esc(r.ActivityReason)}</div>` : '';

    // Score pill — labels instead of numbers
    const score = r.RiskScore ?? 0;
    let scoreCls = 'score-info', scoreLabel = 'INFO';
    if (score >= 9)      { scoreCls = 'score-critical'; scoreLabel = 'CRITICAL'; }
    else if (score >= 7) { scoreCls = 'score-high';     scoreLabel = 'HIGH'; }
    else if (score >= 5) { scoreCls = 'score-medium';   scoreLabel = 'MEDIUM'; }
    else if (score >= 3) { scoreCls = 'score-low';      scoreLabel = 'LOW'; }
    const scoreHtml = `<span class="score ${scoreCls}">${scoreLabel}</span>`;

    // Scope display
    const scopeLevel = r.ScopeLevel || 'Other';
    const scopeHtml = `<span class="scope-${esc(scopeLevel)}">${esc(scopeLevel)}</span>` +
                      `<div class="scope-detail">${esc(r.ScopeName || r.ScopeDetail || '')}</div>`;

    // Cleanup button (data stored as index, popup reads from DATA at click time)
    const cleanupHtml = (r.CleanupPrimary || r.CleanupAlt)
      ? `<button class="cleanup-btn" data-idx="${idx}">Show</button>`
      : '<span class="mono">-</span>';

    return `
      <tr${accepted.has(findingKey(r)) ? ' class="accepted"' : ''}>
        <td>${scoreHtml}</td>
        <td><span class="badge badge-${esc(r.RoleScope)}">${esc(r.RoleScope)}</span></td>
        <td>${esc(r.RoleName)}${customFlag}</td>
        <td><span class="badge badge-${esc(r.AssignmentType)}">${esc(r.AssignmentType)}</span></td>
        <td><span class="badge badge-${esc(r.PrincipalType)}">${esc(r.PrincipalType)}</span></td>
        <td>
          <div>${esc(r.PrincipalName)}</div>
          ${upnOrApp ? `<div class="mono identity-upn">${esc(upnOrApp)}</div>` : ''}
          <div class="mono identity-id">${esc(r.PrincipalId)}</div>
        </td>
        <td><span class="${statusClass}">${esc(statusLabel)}</span>${reason}</td>
        <td>${scopeHtml}</td>
        <td>${via}</td>
        <td class="actions-cell">${actionsHtml}</td>
        <td>${cleanupHtml}</td>
        <td class="accept-cell">
          <input type="checkbox" class="accept-cb" data-idx="${idx}" title="Mark as accepted / reviewed"${accepted.has(findingKey(r)) ? ' checked' : ''}>
        </td>
      </tr>`;
  }).join('');
  tbody.innerHTML = rows;

  // Wire cleanup buttons
  tbody.querySelectorAll('.cleanup-btn').forEach(btn => {
    btn.addEventListener('click', (ev) => showCleanup(parseInt(btn.dataset.idx, 10), ev));
  });

  // Wire accept checkboxes
  tbody.querySelectorAll('.accept-cb').forEach(cb => {
    cb.addEventListener('change', (ev) => {
      ev.stopPropagation();
      const r = filtered[parseInt(cb.dataset.idx, 10)];
      if (!r) return;
      const key = findingKey(r);
      if (cb.checked) accepted.add(key);
      else            accepted.delete(key);
      // re-apply filters so the row is hidden if "Show accepted" is off
      applyFilters();
    });
  });
}

function showCleanup(idx, ev) {
  const r = filtered[idx];
  if (!r) return;
  const popup = document.getElementById('cleanupPopup');
  const body = document.getElementById('cleanupBody');

  // Detect prerequisites based on what kind of cleanup this is.
  // Entra Graph commands need RoleManagement.ReadWrite.Directory.
  // Azure RBAC commands need an active Az session (probably already logged in).
  const isEntra = r.RoleScope === 'Entra';
  const usesGraph = isEntra ||
                    (r.CleanupPrimary || '').includes('Get-Mg') ||
                    (r.CleanupAlt || '').includes('Get-Mg');
  const usesAz = (r.CleanupPrimary || '').includes('Remove-Az') ||
                 (r.CleanupAlt || '').includes('Remove-Az') ||
                 (r.CleanupPrimary || '').includes('Remove-AzADGroupMember');

  let html = '';

  // Prerequisites box at the top
  let prereqs = [];
  if (usesGraph) {
    prereqs.push(
      `<div><strong>Graph (write):</strong> the running session needs ` +
      `<code>RoleManagement.ReadWrite.Directory</code>. ` +
      `Reconnect if needed:</div>` +
      `<pre id="prereqGraph">Disconnect-MgGraph; Connect-MgGraph -Scopes 'RoleManagement.ReadWrite.Directory','Directory.Read.All'</pre>` +
      `<button class="cleanup-btn" data-copy-from="prereqGraph">Copy</button>`
    );
  }
  if (usesAz) {
    prereqs.push(
      `<div><strong>Azure:</strong> ensure you are logged in to the right tenant ` +
      `(<code>Connect-AzAccount -TenantId &lt;id&gt;</code>) and have rights to modify the assignment.</div>`
    );
  }
  if (prereqs.length > 0) {
    html += `<div class="prereq-box"><div class="prereq-title">Prerequisites</div>${prereqs.join('<div style="height:8px"></div>')}</div>`;
  }

  if (r.ViaGroup) {
    html += `<div style="margin-bottom:8px;font-size:12px;color:var(--muted);">` +
            `Principal "<strong>${esc(r.PrincipalName)}</strong>" inherits this role via group ` +
            `"<strong>${esc(r.ViaGroup)}</strong>". Choose the right scope:</div>`;
  }
  if (r.CleanupPrimary) {
    html += `<div style="margin-top:8px;font-size:11px;color:var(--muted);">` +
            (r.ViaGroup ? 'Option A — remove only this principal from the group:' : 'Run this command:') +
            `</div>`;
    html += `<pre id="cleanupPrimaryText">${esc(r.CleanupPrimary)}</pre>`;
    html += `<button class="cleanup-btn" data-copy-from="cleanupPrimaryText">Copy</button>`;
  }
  if (r.CleanupAlt) {
    html += `<div style="margin-top:14px;font-size:11px;color:var(--muted);">Option B — remove the role from the entire group (affects all members):</div>`;
    html += `<pre id="cleanupAltText">${esc(r.CleanupAlt)}</pre>`;
    html += `<button class="cleanup-btn" data-copy-from="cleanupAltText">Copy</button>`;
  }
  body.innerHTML = html;

  // Wire copy buttons inside the popup
  body.querySelectorAll('.cleanup-btn[data-copy-from]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const sourceId = btn.dataset.copyFrom;
      const sourceEl = document.getElementById(sourceId);
      if (!sourceEl) return;
      const text = sourceEl.textContent;
      navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
      }).catch(err => {
        console.error('Clipboard write failed:', err);
        btn.textContent = 'Failed';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      });
    });
  });

  // Position near the click
  const x = Math.min(ev.clientX, window.innerWidth - 620);
  const y = Math.min(ev.clientY, window.innerHeight - 280);
  popup.style.left = x + 'px';
  popup.style.top = y + 'px';
  popup.style.display = 'block';
}

// Click outside the popup to close
document.addEventListener('click', (ev) => {
  const popup = document.getElementById('cleanupPopup');
  if (popup.style.display === 'block' && !popup.contains(ev.target) && !ev.target.classList.contains('cleanup-btn')) {
    popup.style.display = 'none';
  }
});

document.querySelectorAll('th').forEach(th => {
  th.addEventListener('click', () => {
    const k = th.dataset.key;
    if (sortKey === k) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else { sortKey = k; sortDir = 'asc'; }
    applySort();
  });
});

[search, fScope, fAssign, fPrincipal, fRole, fVia, fCustom, fStatus, fMinScore].forEach(el =>
  el.addEventListener('input', applyFilters));

toggleAccepted.addEventListener('click', () => {
  const isActive = toggleAccepted.dataset.active === 'true';
  toggleAccepted.dataset.active = (!isActive).toString();
  toggleAccepted.textContent = isActive ? 'Show accepted' : 'Hide accepted';
  applyFilters();
});

document.getElementById('exportCsv').addEventListener('click', () => {
  const cols = ['RiskScore','RoleScope','RoleName','IsCustomRole','RiskyActions','AssignmentType',
                'PrincipalType','PrincipalName','PrincipalId','UPN','AppId','AccountEnabled',
                'ActivityStatus','ActivityReason',
                'ScopeLevel','ScopeDetail','ScopeName','Scope','ViaGroup','ViaGroupId',
                'CleanupPrimary','CleanupAlt'];
  const escCsv = v => v == null ? '' : `"${String(v).replace(/"/g,'""')}"`;
  const lines = [cols.join(',')];
  filtered.forEach(r => lines.push(cols.map(c => escCsv(r[c])).join(',')));
  const blob = new Blob([lines.join('\n')], {type: 'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'privileged-role-audit.csv'; a.click();
  URL.revokeObjectURL(url);
});

applyFilters();
</script>
</body>
</html>
'@

$js = $js.Replace('__DATA_PLACEHOLDER__', $dataJson)
$html = $head + $js
Set-Content -Path $OutputPath -Value $html -Encoding UTF8

Write-Host "`nReport written: $OutputPath" -ForegroundColor Green
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Findings:        $totalFindings"
Write-Host "  Critical (>=9):  $criticalCount" -ForegroundColor Red
Write-Host "  High (7.0-8.9):  $highCount" -ForegroundColor Yellow
Write-Host "  Permanent:       $permanentCount" -ForegroundColor Green
Write-Host "  Eligible (PIM):  $eligibleCount" -ForegroundColor Yellow
Write-Host "  Unique users:    $uniqueUsers"
Write-Host "  Apps:            $uniqueApps"
Write-Host "  Managed IDs:     $uniqueMI"
Write-Host "  Groups assigned: $uniqueGroups"
Write-Host "  Custom roles:    $customCount" -ForegroundColor Red
Write-Host "  Inactive:        $inactiveCount" -ForegroundColor Red

if ($IsWindows -or $env:OS -eq 'Windows_NT') {
  Start-Process $OutputPath
}