<#
.SYNOPSIS
    AppLifecycleAnalyzer — audits all Entra ID App Registrations and produces an
    interactive HTML report focused on inactivity, credential expiry, and cleanup.

.DESCRIPTION
    Connects to Microsoft Graph and enumerates every App Registration in the tenant
    along with its secrets, certificates, federated credentials, last sign-in
    activity (combined from two Graph sources for accuracy), and the application's
    isDisabled state from /beta.

    Generates a single self-contained HTML report (RiskyRolesAnalyzer style) with:
      - Filters: Activity status, Expiry status, Credential type, free-text search
      - Sortable columns
      - Cleanup commands per finding:
            * Delete individual expired secrets / certs (keyId-targeted)
            * Bulk-delete all expired credentials of an app
            * Delete the entire app registration
      - Detail modal listing every credential with its own per-row cleanup command
      - CSV export of the currently filtered rows

.PARAMETER OutputPath
    Path of the HTML report. Default: .\AppLifecycleAnalysis_<timestamp>.html

.PARAMETER TenantId
    Optional tenant ID. If omitted, you sign in interactively to your home tenant.

.PARAMETER InactiveDays
    Days without a sign-in before flagging an app as "Inactive". Default: 90.

.PARAMETER ExpiryWarningDays
    Days before credential expiry to flag as "Expiring soon". Default: 30.

.PARAMETER AutoInstallModules
    If set, missing PowerShell modules are installed without prompting.

.PARAMETER RequestWriteScopes
    If set, requests Application.ReadWrite.All in addition to read-only scopes.
    Required only if you want to run the cleanup commands directly from the same
    session. Without this switch, the audit runs read-only — safer default.
    To enable cleanup later, you can also re-connect manually:
        Disconnect-MgGraph
        Connect-MgGraph -Scopes 'Application.ReadWrite.All','Directory.Read.All'

.NOTES
    Author : Simon Vedder
    Site   : https://simonvedder.com
    License: MIT

    Required modules: Microsoft.Graph.Authentication, Microsoft.Graph.Applications

    Required Graph permissions (delegated, read-only by default):
        - Application.Read.All
        - AuditLog.Read.All        (signInActivity needs Entra ID P1 or P2)
        - Directory.Read.All

.EXAMPLE
    .\Get-AppLifecycleAnalysis.ps1

.EXAMPLE
    .\Get-AppLifecycleAnalysis.ps1 -InactiveDays 60 -RequestWriteScopes
#>

[CmdletBinding()]
param(
  [string] $OutputPath,
  [string] $TenantId,
  [int]    $InactiveDays = 90,
  [int]    $ExpiryWarningDays = 30,
  [switch] $AutoInstallModules,
  [switch] $RequestWriteScopes
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Module checks + auto-install
# ---------------------------------------------------------------------------

$requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')

function Install-MissingModule {
  param([string] $Name)
  Write-Host "  Installing $Name..." -ForegroundColor Yellow
  try {
    $gallery = Get-PSRepository -Name PSGallery -ErrorAction Stop
    if ($gallery.InstallationPolicy -ne 'Trusted') {
      Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    }
  }
  catch { Write-Warning "    Could not configure PSGallery: $_" }
  if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    try {
      Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
    }
    catch { Write-Warning "    Could not install NuGet provider: $_" }
  }
  Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
  Write-Host "    OK" -ForegroundColor Green
}

$missing = @()
foreach ($m in $requiredModules) {
  if (-not (Get-Module -ListAvailable -Name $m)) { $missing += $m }
}

if ($missing.Count -gt 0) {
  Write-Host "Missing PowerShell modules:" -ForegroundColor Yellow
  $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
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
    try { Install-MissingModule -Name $m } catch { throw "Failed to install $m : $_" }
  }
  Write-Host ""
}

foreach ($m in $requiredModules) { Import-Module $m -ErrorAction Stop }

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------

$graphScopes = @('Application.Read.All', 'AuditLog.Read.All', 'Directory.Read.All')
if ($RequestWriteScopes) {
  $graphScopes += 'Application.ReadWrite.All'
  Write-Host "RequestWriteScopes set — also requesting Application.ReadWrite.All" -ForegroundColor Yellow
}

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
$mgContext = Get-MgContext -ErrorAction SilentlyContinue
$needsConnect = -not $mgContext -or ($graphScopes | Where-Object { $_ -notin $mgContext.Scopes })

if ($needsConnect) {
  if ($TenantId) {
    Connect-MgGraph -Scopes $graphScopes -TenantId $TenantId -NoWelcome
  }
  else {
    Connect-MgGraph -Scopes $graphScopes -NoWelcome
  }
}

$ctx = Get-MgContext
if (-not $ctx) { throw "Failed to connect to Microsoft Graph." }

$currentScopes = $ctx.Scopes
$hasWriteScope = $currentScopes -contains 'Application.ReadWrite.All'
Write-Host "Tenant: $($ctx.TenantId)" -ForegroundColor Green
Write-Host "Account: $($ctx.Account)" -ForegroundColor Gray

if (-not $hasWriteScope) {
  Write-Host ""
  Write-Host "Note: Current Graph session is READ-ONLY." -ForegroundColor DarkGray
  Write-Host "      Cleanup commands suggested in the report will require a write-scoped" -ForegroundColor DarkGray
  Write-Host "      session before they can run. To enable, either:" -ForegroundColor DarkGray
  Write-Host "        a) re-run this script with: -RequestWriteScopes" -ForegroundColor DarkGray
  Write-Host "        b) or before running cleanups manually:" -ForegroundColor DarkGray
  Write-Host "             Disconnect-MgGraph; Connect-MgGraph -Scopes 'Application.ReadWrite.All','Directory.Read.All'" -ForegroundColor DarkGray
}
Write-Host ""

# ---------------------------------------------------------------------------
# Fetch app registrations + service principals
# ---------------------------------------------------------------------------

Write-Host "Retrieving app registrations..." -ForegroundColor Cyan
$apps = Get-MgApplication -All -Property `
  Id, AppId, DisplayName, CreatedDateTime, SignInAudience, `
  PasswordCredentials, KeyCredentials, Notes, PublisherDomain
Write-Host "  Found $($apps.Count) app registrations" -ForegroundColor Gray

# isDisabled is the "App Registration deactivated" toggle from the Azure portal.
# It's only exposed on the /beta endpoint as of this writing.
Write-Host "Retrieving isDisabled status from /beta..." -ForegroundColor Cyan
$isDisabledByAppId = @{}
$disabledCount = 0
try {
  $url = 'https://graph.microsoft.com/beta/applications?$select=appId,isDisabled&$top=999'
  do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop
    foreach ($a in $resp.value) {
      if (-not $a.appId) { continue }
      $isDisabledByAppId[$a.appId] = [bool]$a.isDisabled
      if ($a.isDisabled) { $disabledCount++ }
    }
    $url = $resp.'@odata.nextLink'
  } while ($url)
  Write-Host "  $disabledCount of $($apps.Count) apps are deactivated (isDisabled = true)" `
    -ForegroundColor $(if ($disabledCount -gt 0) { 'Yellow' } else { 'Gray' })
}
catch {
  Write-Warning "  Could not fetch isDisabled from /beta: $($_.Exception.Message)"
  Write-Warning "  'Deactivated' status will be unknown for all apps."
}

Write-Host "Retrieving service principals..." -ForegroundColor Cyan
# Note: signInActivity is NOT a property on servicePrincipal — it only exists on user.
# We get sign-in activity from a separate endpoint below.
$sps = Get-MgServicePrincipal -All -Property `
  Id, AppId, DisplayName, AccountEnabled, ServicePrincipalType `
  -ErrorAction SilentlyContinue

$spByAppId = @{}
foreach ($sp in $sps) { if ($sp.AppId) { $spByAppId[$sp.AppId] = $sp } }
Write-Host "  Found $($sps.Count) service principals" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Retrieve service principal sign-in activity
# ---------------------------------------------------------------------------
# Primary path: /beta/reports/servicePrincipalSignInActivities — one call returns
# the latest sign-in per AppId across all four authentication flows. Requires
# AuditLog.Read.All + Entra ID P1/P2.
#
# Fallback: if the primary endpoint is not available (e.g. tenant without P1),
# we query /v1.0/auditLogs/signIns for SP sign-ins over the last 30 days and
# aggregate the latest one per appId. Slower but works on more tenants.
#
# Known caveat: even on the right endpoint, MS-side replication can lag by
# several hours, so a sign-in visible in the portal in the last hour may not
# appear here yet.

Write-Host "Retrieving service principal sign-in activity..." -ForegroundColor Cyan
$spSignInByAppId = @{}
$signInSourceUsed = 'none'

# Source 1: per-AppId sign-in activity report (covers years of history but lags
# behind the actual sign-in by minutes-to-hours, sometimes longer).
$source1Count = 0
try {
  $url = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=999'
  do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop
    foreach ($entry in $resp.value) {
      if (-not $entry.appId) { continue }
      $candidates = @(
        $entry.lastSignInActivity.lastSignInDateTime,
        $entry.applicationAuthenticationClientSignInActivity.lastSignInDateTime,
        $entry.applicationAuthenticationResourceSignInActivity.lastSignInDateTime,
        $entry.delegatedClientSignInActivity.lastSignInDateTime,
        $entry.delegatedResourceSignInActivity.lastSignInDateTime
      ) | Where-Object { $_ } | ForEach-Object { [datetime]$_ } | Sort-Object -Descending
      if ($candidates.Count -gt 0) {
        $spSignInByAppId[$entry.appId] = $candidates[0]
        $source1Count++
      }
    }
    $url = $resp.'@odata.nextLink'
  } while ($url)
  $signInSourceUsed = 'reports + auditLogs (combined)'
  Write-Host "  Report: $source1Count apps with historical sign-in records" -ForegroundColor Gray
}
catch {
  Write-Warning "  Primary sign-in activity report unavailable: $($_.Exception.Message)"
}

# Source 2: auditLogs/signIns for the last 7 days. The report can lag, but the
# audit log is fresh — so this catches recent sign-ins that the report doesn't
# know about yet. We always keep the LATEST timestamp from either source.
$source2Count = 0
$source2Updates = 0
try {
  $since = (Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
  $filter = "createdDateTime ge $since and signInEventTypes/any(t:t eq 'servicePrincipal')"
  $url = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($filter))&`$top=1000"
  $scanned = 0
  do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop
    foreach ($e in $resp.value) {
      if (-not $e.appId) { continue }
      $when = [datetime]$e.createdDateTime
      $existing = $spSignInByAppId[$e.appId]
      if (-not $existing) {
        $spSignInByAppId[$e.appId] = $when
        $source2Count++
      }
      elseif ($existing -lt $when) {
        $spSignInByAppId[$e.appId] = $when
        $source2Updates++
      }
      $scanned++
    }
    $url = $resp.'@odata.nextLink'
  } while ($url -and $scanned -lt 50000)
  Write-Host "  AuditLogs (7d): $source2Count new apps, $source2Updates updates to fresher timestamp" -ForegroundColor Gray

  if ($source1Count -eq 0 -and ($source2Count -gt 0 -or $source2Updates -gt 0)) {
    $signInSourceUsed = 'auditLogs/signIns (last 7 days)'
  }
}
catch {
  Write-Warning "  AuditLogs/signIns scan failed: $($_.Exception.Message)"
  if ($source1Count -eq 0) {
    Write-Warning "  Both sign-in sources failed — Last sign-in column will be empty."
    Write-Warning "  Verify: tenant has Entra ID P1/P2 and the signed-in account has AuditLog.Read.All."
    $signInSourceUsed = 'unavailable'
  }
  else {
    $signInSourceUsed = 'reports only (auditLogs failed)'
  }
}

Write-Host "  Total apps with sign-in info: $($spSignInByAppId.Count)" -ForegroundColor Gray

Write-Host "Retrieving federated identity credentials..." -ForegroundColor Cyan
$fedCredsByApp = @{}
$progress = 0
foreach ($app in $apps) {
  $progress++
  if ($progress % 25 -eq 0) {
    Write-Progress -Activity "Federated credentials" -Status "$progress / $($apps.Count)" `
      -PercentComplete (($progress / $apps.Count) * 100)
  }
  try {
    $fc = Get-MgApplicationFederatedIdentityCredential -ApplicationId $app.Id -ErrorAction Stop
    if ($fc) { $fedCredsByApp[$app.Id] = $fc }
  }
  catch { }
}
Write-Progress -Activity "Federated credentials" -Completed

# ---------------------------------------------------------------------------
# Build records
# ---------------------------------------------------------------------------

$now = Get-Date
$records = foreach ($app in $apps) {
  $sp = $spByAppId[$app.AppId]
  $secrets = $app.PasswordCredentials
  $certs = $app.KeyCredentials
  $feds = $fedCredsByApp[$app.Id]

  $secretCount = ($secrets | Measure-Object).Count
  $certCount = ($certs   | Measure-Object).Count
  $fedCount = ($feds    | Measure-Object).Count

  $allCredEnds = @()
  if ($secrets) { $allCredEnds += $secrets | ForEach-Object { $_.EndDateTime } }
  if ($certs) { $allCredEnds += $certs   | ForEach-Object { $_.EndDateTime } }
  $allCredEnds = $allCredEnds | Where-Object { $_ } | Sort-Object

  $expiredSecretCount = 0
  $expiredCertCount = 0
  if ($secrets) { $expiredSecretCount = ($secrets | Where-Object { $_.EndDateTime -and $_.EndDateTime -lt $now }).Count }
  if ($certs) { $expiredCertCount = ($certs   | Where-Object { $_.EndDateTime -and $_.EndDateTime -lt $now }).Count }
  $expiredCredCount = $expiredSecretCount + $expiredCertCount

  $nextExpiry = $null
  $daysToExpiry = $null
  # Default: nothing configured at all
  $expiryStatus = 'No credentials'
  if ($allCredEnds.Count -gt 0) {
    $nextExpiry = $allCredEnds[0]
    $daysToExpiry = [int]($nextExpiry - $now).TotalDays
    if ($daysToExpiry -lt 0) { $expiryStatus = 'Expired' }
    elseif ($daysToExpiry -le $ExpiryWarningDays) { $expiryStatus = 'Expiring soon' }
    else { $expiryStatus = 'Valid' }
  }
  elseif ($fedCount -gt 0) {
    # App has federated credentials but no secrets/certs — nothing to expire
    $expiryStatus = 'No expiry'
  }

  $lastSignIn = $null
  if ($spSignInByAppId.ContainsKey($app.AppId)) {
    $lastSignIn = $spSignInByAppId[$app.AppId]
  }

  $isDisabled = $false
  if ($isDisabledByAppId.ContainsKey($app.AppId)) {
    $isDisabled = $isDisabledByAppId[$app.AppId]
  }

  $daysSinceSignIn = $null
  $activityStatus = 'Unknown'
  # Disabled is the strongest signal — overrides sign-in/no-sign-in info
  if ($isDisabled) {
    $activityStatus = 'Disabled'
  }
  elseif ($lastSignIn) {
    $daysSinceSignIn = [int]($now - $lastSignIn).TotalDays
    $activityStatus = if ($daysSinceSignIn -gt $InactiveDays) { 'Inactive' } else { 'Active' }
  }
  elseif ($sp) {
    $activityStatus = 'No sign-ins recorded'
  }
  else {
    $activityStatus = 'No service principal'
  }

  $credDetails = @()
  foreach ($s in $secrets) {
    $isExp = $s.EndDateTime -and $s.EndDateTime -lt $now
    $credDetails += [pscustomobject]@{
      Type      = 'Secret'
      Name      = $s.DisplayName
      StartDate = $s.StartDateTime
      EndDate   = $s.EndDateTime
      Hint      = $s.Hint
      KeyId     = $s.KeyId
      Expired   = [bool]$isExp
    }
  }
  foreach ($c in $certs) {
    $isExp = $c.EndDateTime -and $c.EndDateTime -lt $now
    $credDetails += [pscustomobject]@{
      Type      = 'Certificate'
      Name      = $c.DisplayName
      StartDate = $c.StartDateTime
      EndDate   = $c.EndDateTime
      Hint      = $c.CustomKeyIdentifier
      KeyId     = $c.KeyId
      Expired   = [bool]$isExp
    }
  }
  foreach ($f in $feds) {
    $credDetails += [pscustomobject]@{
      Type      = 'Federated'
      Name      = $f.Name
      StartDate = $null
      EndDate   = $null
      Hint      = "$($f.Issuer) | $($f.Subject)"
      KeyId     = $f.Id
      Expired   = $false
    }
  }

  [pscustomobject]@{
    DisplayName        = $app.DisplayName
    AppId              = $app.AppId
    ObjectId           = $app.Id
    CreatedDateTime    = $app.CreatedDateTime
    SignInAudience     = $app.SignInAudience
    PublisherDomain    = $app.PublisherDomain
    Notes              = $app.Notes
    SecretCount        = $secretCount
    CertCount          = $certCount
    FedCount           = $fedCount
    ExpiredSecretCount = $expiredSecretCount
    ExpiredCertCount   = $expiredCertCount
    ExpiredCredCount   = $expiredCredCount
    NextExpiry         = $nextExpiry
    DaysToExpiry       = $daysToExpiry
    ExpiryStatus       = $expiryStatus
    LastSignIn         = $lastSignIn
    DaysSinceSignIn    = $daysSinceSignIn
    ActivityStatus     = $activityStatus
    IsDisabled         = $isDisabled
    SpAccountEnabled   = if ($sp) { $sp.AccountEnabled } else { $null }
    CredentialDetails  = $credDetails
  }
}

# ---------------------------------------------------------------------------
# JSON payload
# ---------------------------------------------------------------------------

$jsonObjects = $records | ForEach-Object {
  [pscustomobject]@{
    displayName        = $_.DisplayName
    appId              = $_.AppId
    objectId           = $_.ObjectId
    createdDateTime    = if ($_.CreatedDateTime) { $_.CreatedDateTime.ToString('o') } else { $null }
    signInAudience     = $_.SignInAudience
    publisherDomain    = $_.PublisherDomain
    notes              = $_.Notes
    secretCount        = $_.SecretCount
    certCount          = $_.CertCount
    fedCount           = $_.FedCount
    expiredSecretCount = $_.ExpiredSecretCount
    expiredCertCount   = $_.ExpiredCertCount
    expiredCredCount   = $_.ExpiredCredCount
    nextExpiry         = if ($_.NextExpiry) { $_.NextExpiry.ToString('o') } else { $null }
    daysToExpiry       = $_.DaysToExpiry
    expiryStatus       = $_.ExpiryStatus
    lastSignIn         = if ($_.LastSignIn) { $_.LastSignIn.ToString('o') } else { $null }
    daysSinceSignIn    = $_.DaysSinceSignIn
    activityStatus     = $_.ActivityStatus
    isDisabled         = $_.IsDisabled
    spAccountEnabled   = $_.SpAccountEnabled
    credentialDetails  = @($_.CredentialDetails | ForEach-Object {
        [pscustomobject]@{
          type      = $_.Type
          name      = $_.Name
          startDate = if ($_.StartDate) { $_.StartDate.ToString('o') } else { $null }
          endDate   = if ($_.EndDate) { $_.EndDate.ToString('o') }   else { $null }
          hint      = $_.Hint
          keyId     = $_.KeyId
          expired   = $_.Expired
        }
      })
  }
}
$dataJson = ($jsonObjects | ConvertTo-Json -Depth 6 -Compress) -replace '</', '<\/'
if (-not $dataJson) { $dataJson = '[]' }
if ($dataJson -notmatch '^\s*\[') { $dataJson = "[$dataJson]" }

# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

$totalApps = $records.Count
$expiredCount = ($records | Where-Object { $_.ExpiryStatus -eq 'Expired' }).Count
$expiringCount = ($records | Where-Object { $_.ExpiryStatus -eq 'Expiring soon' }).Count
$inactiveCount = ($records | Where-Object { $_.ActivityStatus -eq 'Inactive' }).Count
$disabledStat = ($records | Where-Object { $_.IsDisabled }).Count
$noSignInCount = ($records | Where-Object { $_.ActivityStatus -eq 'No sign-ins recorded' }).Count
$noCredsCount = ($records | Where-Object { $_.ExpiryStatus -eq 'No credentials' }).Count
$expiredCredsTotal = ($records | Measure-Object -Property ExpiredCredCount -Sum).Sum
if (-not $expiredCredsTotal) { $expiredCredsTotal = 0 }

$generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

if (-not $OutputPath) {
  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $OutputPath = Join-Path (Get-Location) "AppLifecycleAnalysis_$stamp.html"
}

# ---------------------------------------------------------------------------
# HTML head + body — double-quoted, PS interpolates the stats
# ---------------------------------------------------------------------------

$head = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AppLifecycleAnalyzer Report</title>
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
  tbody tr { cursor: pointer; }
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
  .badge-Valid          { background: rgba(34,197,94,0.15);  color: #86efac; border-color: rgba(34,197,94,0.4); }
  .badge-Expiring       { background: rgba(245,158,11,0.18); color: #fcd34d; border-color: rgba(245,158,11,0.45); }
  .badge-Expired        { background: rgba(239,68,68,0.18);  color: #fca5a5; border-color: rgba(239,68,68,0.45); }
  .badge-NoCreds        { background: rgba(148,163,184,0.15); color: #cbd5e1; border-color: rgba(148,163,184,0.4); }
  .badge-NoExpiry       { background: rgba(56,189,248,0.15); color: #7dd3fc; border-color: rgba(56,189,248,0.4); }
  .badge-Active         { background: rgba(34,197,94,0.15);  color: #86efac; border-color: rgba(34,197,94,0.4); }
  .badge-Inactive       { background: rgba(245,158,11,0.18); color: #fcd34d; border-color: rgba(245,158,11,0.45); }
  .badge-Disabled       { background: rgba(239,68,68,0.18);  color: #fca5a5; border-color: rgba(239,68,68,0.45); }
  .badge-NoSignIn       { background: rgba(148,163,184,0.15); color: #cbd5e1; border-color: rgba(148,163,184,0.4); }
  .badge-Unknown        { background: rgba(148,163,184,0.15); color: #cbd5e1; border-color: rgba(148,163,184,0.4); }
  .mono { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 12px; color: var(--muted); }
  .empty { padding: 60px; text-align: center; color: var(--muted); }
  .report-footer {
    text-align: center;
    padding: 20px 32px 28px 32px;
    color: var(--muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 8px;
  }
  .report-footer a { color: var(--accent); text-decoration: none; }
  .report-footer a:hover { text-decoration: underline; }
  .report-footer strong { color: var(--text); font-weight: 600; }
  .days { font-size: 11px; color: var(--muted); margin-top: 2px; }
  .days.warn { color: #fcd34d; }
  .days.err  { color: #fca5a5; }
  .creds-summary { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 12px; }
  .creds-summary .seg { display: inline-block; margin-right: 6px; }
  .creds-summary .ok  { color: #86efac; }
  .creds-summary .exp { color: #fca5a5; }
  .name-cell-main  { font-weight: 500; }
  .name-cell-appid { font-size: 11px; margin-top: 2px; font-family: 'SF Mono', Menlo, Consolas, monospace; color: #cbd5e1; }
  .name-cell-objid { font-size: 10px; margin-top: 1px; font-family: 'SF Mono', Menlo, Consolas, monospace; color: var(--muted); opacity: 0.7; }
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
  .cleanup-btn.danger:hover { background: var(--err); color: #fff; border-color: var(--err); }

  /* Modal (App detail) */
  .modal-bg {
    position: fixed; inset: 0;
    background: rgba(0,0,0,.65);
    display: none;
    align-items: center; justify-content: center;
    z-index: 100;
  }
  .modal-bg.open { display: flex; }
  .modal {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    width: min(900px, 94vw);
    max-height: 88vh;
    overflow: auto;
    padding: 24px;
  }
  .modal h2 { margin: 0 0 4px 0; font-size: 18px; }
  .modal .sub { color: var(--muted); font-size: 12px; margin-bottom: 16px; font-family: 'SF Mono', Menlo, Consolas, monospace; }
  .modal dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0 0 18px 0; font-size: 13px; }
  .modal dt { color: var(--muted); }
  .modal dd { margin: 0; }
  .modal h3 { font-size: 13px; margin: 16px 0 8px 0; text-transform: uppercase; color: var(--muted); letter-spacing: 0.4px; }
  .modal table { font-size: 12px; margin-top: 4px; }
  .modal th, .modal td { padding: 7px 10px; }
  .modal tbody tr { cursor: default; }
  .modal tbody tr:hover { background: transparent; }
  .modal tbody tr.expired td { background: rgba(239,68,68,0.06); }
  .close { float: right; cursor: pointer; color: var(--muted); font-size: 22px; line-height: 1; }
  .close:hover { color: var(--text); }
  .cred-actions { display: flex; gap: 6px; flex-wrap: wrap; }

  /* Cleanup popup (table-row level) */
  .cleanup-popup {
    position: fixed;
    z-index: 1000;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    width: min(620px, calc(100vw - 40px));
    max-height: calc(100vh - 40px);
    overflow-y: auto;
    overscroll-behavior: contain;
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
  .danger-box {
    background: rgba(239,68,68,0.08);
    border: 1px solid rgba(239,68,68,0.3);
    border-radius: 6px;
    padding: 10px 12px;
    margin: 10px 0;
    font-size: 12px;
  }
  .danger-title {
    font-size: 10px;
    color: #fca5a5;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 700;
    margin-bottom: 4px;
  }
</style>
</head>
<body>
<header>
  <h1>App Registration Lifecycle</h1>
  <div class="subtitle">AppLifecycleAnalyzer &nbsp;&middot;&nbsp; Tenant: $($ctx.TenantId) &nbsp;&middot;&nbsp; Generated: $generated &nbsp;&middot;&nbsp; Inactive threshold: $InactiveDays days &nbsp;&middot;&nbsp; Expiry warning: $ExpiryWarningDays days &nbsp;&middot;&nbsp; Sign-in source: $signInSourceUsed</div>
</header>
<section class="summary">
  <div class="stat"><div class="stat-label">Total Apps</div><div class="stat-value">$totalApps</div></div>
  <div class="stat"><div class="stat-label">Expired Credentials</div><div class="stat-value" style="color:#fca5a5">$expiredCount</div></div>
  <div class="stat"><div class="stat-label">Expiring &le; $ExpiryWarningDays days</div><div class="stat-value" style="color:#fcd34d">$expiringCount</div></div>
  <div class="stat"><div class="stat-label">Inactive &gt; $InactiveDays days</div><div class="stat-value" style="color:#fcd34d">$inactiveCount</div></div>
  <div class="stat"><div class="stat-label">Deactivated</div><div class="stat-value" style="color:#fca5a5">$disabledStat</div></div>
  <div class="stat"><div class="stat-label">No Sign-ins Recorded</div><div class="stat-value">$noSignInCount</div></div>
  <div class="stat"><div class="stat-label">No Credentials</div><div class="stat-value">$noCredsCount</div></div>
  <div class="stat"><div class="stat-label">Expired Cred Items (Total)</div><div class="stat-value" style="color:#fca5a5">$expiredCredsTotal</div></div>
</section>
<section class="controls">
  <input type="text" id="search" placeholder="Search anything (name, AppId, ObjectId, publisher, notes)...">
  <select id="filterExpiry">
    <option value="">All expiry states</option>
    <option value="Expired">Expired</option>
    <option value="Expiring soon">Expiring soon</option>
    <option value="Valid">Valid</option>
    <option value="No expiry">No expiry (federated only)</option>
    <option value="No credentials">No credentials</option>
  </select>
  <select id="filterActivity">
    <option value="">All activity states</option>
    <option value="Active">Active</option>
    <option value="Inactive">Inactive</option>
    <option value="Disabled">Deactivated</option>
    <option value="No sign-ins recorded">No sign-ins recorded</option>
    <option value="No service principal">No service principal</option>
    <option value="Unknown">Unknown</option>
  </select>
  <select id="filterCredType">
    <option value="">Any credential type</option>
    <option value="secret">Has secret</option>
    <option value="cert">Has certificate</option>
    <option value="fed">Has federated</option>
    <option value="hasExpired">Has expired credentials</option>
    <option value="none">No credentials</option>
  </select>
  <button id="exportCsv">Export CSV</button>
  <span class="count" id="count"></span>
</section>
<section class="table-wrap">
  <table id="data">
    <thead>
      <tr>
        <th data-key="displayName">App</th>
        <th data-key="expiryStatus">Expiry</th>
        <th data-key="nextExpiry">Next Expiry</th>
        <th data-key="activityStatus">Activity</th>
        <th data-key="lastSignIn">Last Sign-in</th>
        <th data-key="credSummaryKey">Credentials</th>
        <th data-key="createdDateTime">Created</th>
        <th>Cleanup</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>
  <div class="empty" id="empty" style="display:none">No matching app registrations</div>
</section>
<footer class="report-footer">
  Generated by <strong>AppLifecycleAnalyzer</strong> &nbsp;&middot;&nbsp;
  by <a href="https://simonvedder.com" target="_blank" rel="noopener">Simon Vedder</a>
</footer>
<div id="cleanupPopup" class="cleanup-popup">
  <span class="close" onclick="document.getElementById('cleanupPopup').style.display='none'">&times;</span>
  <h4>Cleanup Command</h4>
  <div id="cleanupBody"></div>
</div>
<div id="modalBg" class="modal-bg"><div id="modal" class="modal"></div></div>
"@

# ---------------------------------------------------------------------------
# JS — single-quoted: PS does NOT interpolate, JS template literals stay intact
# ---------------------------------------------------------------------------

$js = @'
<script>
const DATA = __DATA_PLACEHOLDER__;

const tbody = document.querySelector('#data tbody');
const search = document.getElementById('search');
const fExpiry = document.getElementById('filterExpiry');
const fActivity = document.getElementById('filterActivity');
const fCred = document.getElementById('filterCredType');
const countEl = document.getElementById('count');
const emptyEl = document.getElementById('empty');

let sortKey = 'daysToExpiry';
let sortDir = 'asc';
let filtered = DATA.slice();

function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function fmtDate(iso) {
  if (!iso) return '<span class="mono">—</span>';
  return new Date(iso).toISOString().slice(0, 10);
}
function fmtDateTime(iso) {
  return iso ? new Date(iso).toLocaleString() : '—';
}

function expiryBadge(status) {
  const cls = status === 'Valid' ? 'Valid'
            : status === 'Expiring soon' ? 'Expiring'
            : status === 'Expired' ? 'Expired'
            : status === 'No expiry' ? 'NoExpiry'
            : 'NoCreds';
  return `<span class="badge badge-${cls}">${esc(status)}</span>`;
}
function activityBadge(status) {
  let cls = 'Unknown';
  let label = status;
  if (status === 'Active') cls = 'Active';
  else if (status === 'Inactive') cls = 'Inactive';
  else if (status === 'Disabled') { cls = 'Disabled'; label = 'Deactivated'; }
  else if (status === 'No sign-ins recorded') cls = 'NoSignIn';
  return `<span class="badge badge-${cls}">${esc(label)}</span>`;
}

function credSummary(r) {
  const parts = [];
  if (r.secretCount > 0) {
    const exp = r.expiredSecretCount > 0 ? ` <span class="exp">(${r.expiredSecretCount} exp)</span>` : '';
    parts.push(`<span class="seg ok">S:${r.secretCount}</span>${exp}`);
  }
  if (r.certCount > 0) {
    const exp = r.expiredCertCount > 0 ? ` <span class="exp">(${r.expiredCertCount} exp)</span>` : '';
    parts.push(`<span class="seg ok">C:${r.certCount}</span>${exp}`);
  }
  if (r.fedCount > 0) parts.push(`<span class="seg ok">F:${r.fedCount}</span>`);
  if (parts.length === 0) return '<span class="mono">—</span>';
  return `<div class="creds-summary">${parts.join(' ')}</div>`;
}

function applyFilters() {
  const q = search.value.trim().toLowerCase();
  const fe = fExpiry.value;
  const fa = fActivity.value;
  const fc = fCred.value;

  filtered = DATA.filter(r => {
    if (q) {
      const hay = [r.displayName, r.appId, r.objectId, r.publisherDomain, r.notes]
        .filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (fe && r.expiryStatus !== fe) return false;
    if (fa && r.activityStatus !== fa) return false;
    if (fc === 'secret' && r.secretCount === 0) return false;
    if (fc === 'cert'   && r.certCount   === 0) return false;
    if (fc === 'fed'    && r.fedCount    === 0) return false;
    if (fc === 'hasExpired' && r.expiredCredCount === 0) return false;
    if (fc === 'none'   && (r.secretCount + r.certCount + r.fedCount) > 0) return false;
    return true;
  });
  applySort();
}

function applySort() {
  // Synthetic key for sortable cred summary
  filtered.forEach(r => {
    r.credSummaryKey = (r.secretCount + r.certCount + r.fedCount) * 1000 - r.expiredCredCount;
  });
  filtered.sort((a, b) => {
    let va = a[sortKey];
    let vb = b[sortKey];
    if (sortKey === 'daysToExpiry' || sortKey === 'daysSinceSignIn' || sortKey === 'credSummaryKey') {
      va = (va == null) ? (sortDir === 'asc' ? Infinity : -Infinity) : va;
      vb = (vb == null) ? (sortDir === 'asc' ? Infinity : -Infinity) : vb;
    } else if (sortKey === 'nextExpiry' || sortKey === 'lastSignIn' || sortKey === 'createdDateTime') {
      va = va ? new Date(va).getTime() : (sortDir === 'asc' ? Infinity : -Infinity);
      vb = vb ? new Date(vb).getTime() : (sortDir === 'asc' ? Infinity : -Infinity);
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

function render() {
  countEl.textContent = `${filtered.length} of ${DATA.length} apps`;
  if (filtered.length === 0) {
    tbody.innerHTML = '';
    emptyEl.style.display = 'block';
    return;
  }
  emptyEl.style.display = 'none';

  const rows = filtered.map((r, i) => {
    // Days inline (after dates)
    let expiryDays = '';
    if (r.daysToExpiry != null) {
      const cls = r.daysToExpiry < 0 ? 'days err' : (r.daysToExpiry <= 30 ? 'days warn' : 'days');
      const sign = r.daysToExpiry < 0 ? `${r.daysToExpiry} d` : `in ${r.daysToExpiry} d`;
      expiryDays = `<div class="${cls}">${sign}</div>`;
    }
    let signInDays = '';
    if (r.daysSinceSignIn != null) {
      const cls = r.daysSinceSignIn > 90 ? 'days warn' : 'days';
      signInDays = `<div class="${cls}">${r.daysSinceSignIn} d ago</div>`;
    }
    return `
      <tr data-idx="${i}">
        <td>
          <div class="name-cell-main">${esc(r.displayName || '(no name)')}</div>
          <div class="name-cell-appid">${esc(r.appId)}</div>
          <div class="name-cell-objid">${esc(r.objectId)}</div>
        </td>
        <td>${expiryBadge(r.expiryStatus)}</td>
        <td>${fmtDate(r.nextExpiry)}${expiryDays}</td>
        <td>${activityBadge(r.activityStatus)}</td>
        <td>${fmtDate(r.lastSignIn)}${signInDays}</td>
        <td>${credSummary(r)}</td>
        <td>${fmtDate(r.createdDateTime)}</td>
        <td><button class="cleanup-btn" data-idx="${i}" data-act="cleanup">Cleanup</button></td>
      </tr>`;
  }).join('');

  tbody.innerHTML = rows;

  // Wire row click → modal (but ignore button clicks)
  tbody.querySelectorAll('tr').forEach(tr => {
    tr.addEventListener('click', (ev) => {
      if (ev.target.closest('button')) return;
      openModal(filtered[parseInt(tr.dataset.idx, 10)]);
    });
  });

  // Wire cleanup buttons
  tbody.querySelectorAll('.cleanup-btn').forEach(btn => {
    btn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      showCleanup(filtered[parseInt(btn.dataset.idx, 10)], ev);
    });
  });
}

// ----- Cleanup commands ---------------------------------------------------

function cmdRemoveAppRegistration(r) {
  return `# Permanently delete this entire app registration\n` +
         `Remove-MgApplication -ApplicationId '${r.objectId}'`;
}

function cmdRemoveSingleSecret(r, keyId) {
  return `# Remove a single secret (keyId-targeted)\n` +
         `Remove-MgApplicationPassword -ApplicationId '${r.objectId}' -KeyId '${keyId}'`;
}

function cmdRemoveSingleCert(r, keyId) {
  return `# Remove a single certificate by patching keyCredentials\n` +
         `$app = Get-MgApplication -ApplicationId '${r.objectId}'\n` +
         `$keep = $app.KeyCredentials | Where-Object { $_.KeyId -ne '${keyId}' }\n` +
         `Update-MgApplication -ApplicationId '${r.objectId}' -KeyCredentials $keep`;
}

function cmdRemoveAllExpiredSecrets(r) {
  if (r.expiredSecretCount === 0) return null;
  return `# Remove ALL expired secrets from this app\n` +
         `$app = Get-MgApplication -ApplicationId '${r.objectId}'\n` +
         `$expired = $app.PasswordCredentials | Where-Object { $_.EndDateTime -lt (Get-Date) }\n` +
         `foreach ($p in $expired) {\n` +
         `  Remove-MgApplicationPassword -ApplicationId '${r.objectId}' -KeyId $p.KeyId\n` +
         `}`;
}

function cmdRemoveAllExpiredCerts(r) {
  if (r.expiredCertCount === 0) return null;
  return `# Remove ALL expired certificates by replacing keyCredentials with valid ones only\n` +
         `$app = Get-MgApplication -ApplicationId '${r.objectId}'\n` +
         `$valid = $app.KeyCredentials | Where-Object { -not $_.EndDateTime -or $_.EndDateTime -ge (Get-Date) }\n` +
         `Update-MgApplication -ApplicationId '${r.objectId}' -KeyCredentials $valid`;
}

let popupCounter = 0;

function positionCleanupPopup(popup, ev) {
  const margin = 20;
  const gap = 10;

  popup.style.visibility = 'hidden';
  popup.style.display = 'block';

  const rect = popup.getBoundingClientRect();
  const target = ev.currentTarget ? ev.currentTarget.getBoundingClientRect() : null;
  const anchorLeft = target ? target.left : ev.clientX;
  const anchorTop = target ? target.top : ev.clientY;
  const anchorBottom = target ? target.bottom : ev.clientY;

  const left = Math.min(
    Math.max(margin, anchorLeft),
    Math.max(margin, window.innerWidth - rect.width - margin)
  );

  let top;
  const spaceBelow = window.innerHeight - anchorBottom - margin;
  const spaceAbove = anchorTop - margin;

  if (spaceBelow >= rect.height || spaceBelow >= spaceAbove) {
    top = Math.min(anchorBottom + gap, window.innerHeight - rect.height - margin);
  } else {
    top = Math.max(margin, anchorTop - rect.height - gap);
  }

  popup.style.left = left + 'px';
  popup.style.top = Math.max(margin, top) + 'px';
  popup.style.visibility = 'visible';
}

function showCleanup(r, ev) {
  const popup = document.getElementById('cleanupPopup');
  const body = document.getElementById('cleanupBody');
  popupCounter++;
  const ns = `pop${popupCounter}`;

  let html = '';

  // Prerequisites box
  html += `<div class="prereq-box">` +
          `<div class="prereq-title">Prerequisites</div>` +
          `<div>The running session needs <code>Application.ReadWrite.All</code>. Reconnect if needed:</div>` +
          `<pre id="${ns}-prereq">Disconnect-MgGraph; Connect-MgGraph -Scopes 'Application.ReadWrite.All','Directory.Read.All'</pre>` +
          `<button class="cleanup-btn" data-copy-from="${ns}-prereq">Copy</button>` +
          `</div>`;

  html += `<div style="margin-bottom:8px;font-size:12px;color:var(--muted);">` +
          `App: <strong>${esc(r.displayName || '(no name)')}</strong> ` +
          `(<code>${esc(r.appId)}</code>)</div>`;

  // Option 1: bulk remove expired secrets
  const cmdSec = cmdRemoveAllExpiredSecrets(r);
  if (cmdSec) {
    html += `<div style="margin-top:14px;font-size:11px;color:var(--muted);">Option A — remove all ${r.expiredSecretCount} expired secret(s):</div>`;
    html += `<pre id="${ns}-sec">${esc(cmdSec)}</pre>`;
    html += `<button class="cleanup-btn" data-copy-from="${ns}-sec">Copy</button>`;
  }

  // Option 2: bulk remove expired certs
  const cmdCert = cmdRemoveAllExpiredCerts(r);
  if (cmdCert) {
    html += `<div style="margin-top:14px;font-size:11px;color:var(--muted);">Option B — remove all ${r.expiredCertCount} expired certificate(s):</div>`;
    html += `<pre id="${ns}-cert">${esc(cmdCert)}</pre>`;
    html += `<button class="cleanup-btn" data-copy-from="${ns}-cert">Copy</button>`;
  }

  if (!cmdSec && !cmdCert) {
    html += `<div style="margin-top:10px;font-size:12px;color:var(--muted);">` +
            `No expired secrets or certificates on this app — only the full-delete option below applies.</div>`;
  }

  // Option 3: delete entire app registration
  html += `<div class="danger-box">` +
          `<div class="danger-title">Danger zone</div>` +
          `<div style="margin-bottom:6px;">Delete the entire app registration. This breaks any consumer of <code>${esc(r.appId)}</code>.</div>` +
          `<pre id="${ns}-app">${esc(cmdRemoveAppRegistration(r))}</pre>` +
          `<button class="cleanup-btn danger" data-copy-from="${ns}-app">Copy delete command</button>` +
          `</div>`;

  // Detail link
  html += `<div style="margin-top:12px;font-size:11px;color:var(--muted);">` +
          `Tip: Click the row itself to see every credential individually with per-keyId cleanup commands.</div>`;

  body.innerHTML = html;

  // Wire copy buttons
  body.querySelectorAll('.cleanup-btn[data-copy-from]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const sourceEl = document.getElementById(btn.dataset.copyFrom);
      if (!sourceEl) return;
      navigator.clipboard.writeText(sourceEl.textContent).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1500);
      }).catch(() => {
        btn.textContent = 'Failed';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      });
    });
  });

  positionCleanupPopup(popup, ev);
}

// ----- Modal --------------------------------------------------------------

function openModal(r) {
  if (!r) return;
  let credRows = '';
  if (r.credentialDetails && r.credentialDetails.length > 0) {
    credRows = r.credentialDetails.map((c, ci) => {
      const expClass = c.expired ? 'expired' : '';
      let actionBtn = '';
      if (c.type === 'Secret' && c.expired) {
        actionBtn = `<button class="cleanup-btn danger" data-cred-action="secret" data-keyid="${esc(c.keyId)}" data-objid="${esc(r.objectId)}">Remove</button>`;
      } else if (c.type === 'Certificate' && c.expired) {
        actionBtn = `<button class="cleanup-btn danger" data-cred-action="cert" data-keyid="${esc(c.keyId)}" data-objid="${esc(r.objectId)}">Remove</button>`;
      } else {
        actionBtn = '<span class="mono">—</span>';
      }
      return `
        <tr class="${expClass}">
          <td>${esc(c.type)}</td>
          <td>${esc(c.name || '—')}</td>
          <td>${fmtDate(c.startDate)}</td>
          <td>${fmtDate(c.endDate)}</td>
          <td class="mono">${esc(c.hint || '')}</td>
          <td class="mono" style="font-size:10px">${esc(c.keyId || '')}</td>
          <td class="cred-actions">${actionBtn}</td>
        </tr>`;
    }).join('');
  }

  const credTable = credRows
    ? `<table>
         <thead><tr>
           <th>Type</th><th>Name</th><th>Start</th><th>End</th>
           <th>Hint / Issuer</th><th>Key ID</th><th>Action</th>
         </tr></thead>
         <tbody>${credRows}</tbody>
       </table>`
    : '<p class="mono">No credentials configured.</p>';

  document.getElementById('modal').innerHTML = `
    <span class="close" onclick="closeModal()">×</span>
    <h2>${esc(r.displayName || '(no name)')}</h2>
    <div class="sub">${esc(r.appId)}</div>
    <dl>
      <dt>Object ID</dt><dd class="mono">${esc(r.objectId)}</dd>
      <dt>Publisher</dt><dd>${esc(r.publisherDomain || '—')}</dd>
      <dt>Audience</dt><dd>${esc(r.signInAudience || '—')}</dd>
      <dt>Created</dt><dd>${fmtDateTime(r.createdDateTime)}</dd>
      <dt>Last sign-in</dt><dd>${fmtDateTime(r.lastSignIn)}</dd>
      <dt>SP enabled</dt><dd>${r.spAccountEnabled == null ? '—' : r.spAccountEnabled}</dd>
      <dt>Deactivated</dt><dd>${r.isDisabled ? '<span style="color:#fca5a5;font-weight:600">yes</span>' : 'no'}</dd>
      <dt>Notes</dt><dd>${esc(r.notes || '—')}</dd>
    </dl>
    <h3>Credentials</h3>
    ${credTable}
  `;

  // Wire per-credential remove buttons -> show command popup at click position
  document.querySelectorAll('#modal [data-cred-action]').forEach(btn => {
    btn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      const act = btn.dataset.credAction;
      const keyId = btn.dataset.keyid;
      const objId = btn.dataset.objid;
      const cmd = act === 'secret'
        ? `# Remove this single expired secret\nRemove-MgApplicationPassword -ApplicationId '${objId}' -KeyId '${keyId}'`
        : `# Remove this single expired certificate\n$app = Get-MgApplication -ApplicationId '${objId}'\n$keep = $app.KeyCredentials | Where-Object { $_.KeyId -ne '${keyId}' }\nUpdate-MgApplication -ApplicationId '${objId}' -KeyCredentials $keep`;
      const popup = document.getElementById('cleanupPopup');
      const body = document.getElementById('cleanupBody');
      popupCounter++;
      const id = `popcred${popupCounter}`;
      body.innerHTML = `
        <div class="prereq-box">
          <div class="prereq-title">Prerequisites</div>
          <div>Needs <code>Application.ReadWrite.All</code>.</div>
        </div>
        <div style="margin-top:6px;font-size:11px;color:var(--muted);">${act === 'secret' ? 'Removes the secret with the given KeyId:' : 'Removes the certificate with the given KeyId:'}</div>
        <pre id="${id}">${esc(cmd)}</pre>
        <button class="cleanup-btn" data-copy-from="${id}">Copy</button>
      `;
      body.querySelectorAll('.cleanup-btn[data-copy-from]').forEach(b => {
        b.addEventListener('click', (e) => {
          e.stopPropagation();
          navigator.clipboard.writeText(document.getElementById(b.dataset.copyFrom).textContent).then(() => {
            b.textContent = 'Copied';
            b.classList.add('copied');
            setTimeout(() => { b.textContent = 'Copy'; b.classList.remove('copied'); }, 1500);
          });
        });
      });
      positionCleanupPopup(popup, ev);
    });
  });

  document.getElementById('modalBg').classList.add('open');
}

function closeModal() {
  document.getElementById('modalBg').classList.remove('open');
}
document.getElementById('modalBg').addEventListener('click', (ev) => {
  if (ev.target.id === 'modalBg') closeModal();
});
document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeModal(); });

// Click outside cleanup popup to close
document.addEventListener('click', (ev) => {
  const popup = document.getElementById('cleanupPopup');
  if (popup.style.display === 'block' &&
      !popup.contains(ev.target) &&
      !ev.target.classList.contains('cleanup-btn') &&
      !ev.target.closest('.cleanup-btn')) {
    popup.style.display = 'none';
  }
});

// Sorting
document.querySelectorAll('th[data-key]').forEach(th => {
  th.addEventListener('click', () => {
    const k = th.dataset.key;
    if (sortKey === k) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else { sortKey = k; sortDir = 'asc'; }
    applySort();
  });
});

[search, fExpiry, fActivity, fCred].forEach(el => el.addEventListener('input', applyFilters));

// CSV export
document.getElementById('exportCsv').addEventListener('click', () => {
  const cols = ['displayName','appId','objectId','expiryStatus','nextExpiry','daysToExpiry',
                'activityStatus','isDisabled','lastSignIn','daysSinceSignIn','secretCount','certCount',
                'fedCount','expiredSecretCount','expiredCertCount','createdDateTime',
                'signInAudience','publisherDomain'];
  const escCsv = v => v == null ? '' : `"${String(v).replace(/"/g,'""')}"`;
  const lines = [cols.join(',')];
  filtered.forEach(r => lines.push(cols.map(c => escCsv(r[c])).join(',')));
  const blob = new Blob([lines.join('\n')], {type: 'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'app-lifecycle-analysis.csv'; a.click();
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
Write-Host "  Total apps:        $totalApps"
Write-Host "  Expired creds:     $expiredCount"     -ForegroundColor $(if ($expiredCount) { 'Red' }    else { 'Gray' })
Write-Host "  Expiring soon:     $expiringCount"    -ForegroundColor $(if ($expiringCount) { 'Yellow' } else { 'Gray' })
Write-Host "  Inactive (>$InactiveDays d): $inactiveCount" -ForegroundColor $(if ($inactiveCount) { 'Yellow' } else { 'Gray' })
Write-Host "  Deactivated:       $disabledStat" -ForegroundColor $(if ($disabledStat) { 'Red' } else { 'Gray' })
Write-Host "  No sign-ins:       $noSignInCount"
Write-Host "  No credentials:    $noCredsCount"
Write-Host "  Expired items:     $expiredCredsTotal" -ForegroundColor $(if ($expiredCredsTotal) { 'Red' } else { 'Gray' })

if ($IsWindows -or $env:OS -eq 'Windows_NT') { Start-Process $OutputPath }
