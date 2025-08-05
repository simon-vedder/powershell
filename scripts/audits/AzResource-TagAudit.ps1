<#
.TITLE
    AzResource-TagAudit

.SYNOPSIS
    Find all Azure resources that are missing required tags across all subscriptions.

.DESCRIPTION
    This PowerShell script will scan every resource within your tenant to identify resources
    that are missing specific required tags. It provides an option to remediate by adding
    empty tags (without values) to non-compliant resources.
    
.TAGS
    PowerShell, Diagnostic, Compliance, Tags

.MINROLE
    Reader (for audit only)
    Contributor (for remediation)

.PERMISSIONS
    Microsoft.Resources/subscriptions/read
    Microsoft.Resources/resources/read
    Microsoft.Resources/tags/write (for remediation)

.AUTHOR
    Simon Vedder (info@simonvedder.com)

.VERSION
    1.0

.CHANGELOG
    1.0 - Initial release

.LASTUPDATE
    2025-08-05

.NOTES
    Configure the required tag names in the $RequiredTags array and set $EnableRemediation before running.
    Remediation adds empty tags that can be filled with appropriate values later.
    Output will also be exported as a CSV file in the same directory as the script. If not needed, uncomment the lines 232-234

.USAGE
  - Run locally or use it in your runbook while changing Connect-AzAccount to use a non-interactive authentication
  - Configure $RequiredTags array and $EnableRemediation boolean before running
  - Empty tags created by remediation can be filled with appropriate values later
  
#>

# ==================== CONFIGURATION ====================
# Define required tags that should be present on all resources (only tag names, no values)
$RequiredTags = @(
    "Environment",
    "Owner", 
    "CostCenter",
    "Project"
)

# Set to $true to enable remediation (adding missing tags), $false to only audit
$EnableRemediation = $false

# ==================== SCRIPT EXECUTION ====================

$nonCompliantResources = @()
$compliantResources = @()
$remediatedResources = @()

Write-Host "AzResource-TagAudit" -ForegroundColor Yellow
Write-Host "by Simon Vedder"
Write-Host "- Tag Compliance Check -"
Write-Host "------------------------"
Write-Host (Get-Date)
Write-Host ""

# Display configuration
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "Required Tags: $($RequiredTags -join ', ')"
Write-Host "Remediation Enabled: $EnableRemediation"
Write-Host ""

#LOGIN
Write-Host "Connecting to Azure..."
$result = Connect-AzAccount | Out-Null

# Get all Subscriptions
try {
    Write-Host "Retrieving Azure Subscriptions..."
    $subscriptions = Get-AzSubscription -ErrorAction Stop
    Write-Host "Found $($subscriptions.Count) subscription(s)" -ForegroundColor Green
}
catch {
    Write-Error "Error retrieving subscriptions: $($_.Exception.Message)"
    exit 1
}

# Run code in each subscription
foreach($sub in $subscriptions)
{
    # Change the subscription context
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    Write-Host ""
    Write-Host "Processing Subscription: $($sub.Name)" -ForegroundColor Cyan
    Write-Host "Subscription ID: $($sub.Id)"
    
    # Get all resources within the subscription
    try {
        Write-Host "Retrieving all resources in subscription..."
        $resources = Get-AzResource -ErrorAction Stop
        Write-Host "Found $($resources.Count) resource(s)" -ForegroundColor Green
    }
    catch {
        Write-Error "Error retrieving resources: $($_.Exception.Message)"
        continue
    }

    if (-not $resources -or $resources.Count -eq 0) {
        Write-Warning "No resources found in subscription '$($sub.Name)'"
        continue
    }

    # Check each resource for required tags
    Write-Host "Checking tag compliance..."
    
    foreach ($resource in $resources) {
        $missingTags = @()
        $isCompliant = $true
        
        # Check each required tag
        foreach ($requiredTag in $RequiredTags) {
            # Check if the tag exists on the resource
            if (-not $resource.Tags -or -not $resource.Tags.ContainsKey($requiredTag)) {
                $missingTags += $requiredTag
                $isCompliant = $false
            }
        }
        
        if (-not $isCompliant) {
            Write-Host "Non-compliant resource found: $($resource.Name)" -ForegroundColor Red
            
            $resourceInfo = [PSCustomObject]@{
                ResourceName = $resource.Name
                ResourceType = $resource.ResourceType
                ResourceGroup = $resource.ResourceGroupName
                Subscription = $sub.Name
                SubscriptionId = $sub.Id
                Location = $resource.Location
                MissingTags = ($missingTags -join ', ')
                ResourceId = $resource.ResourceId
            }
            
            $nonCompliantResources += $resourceInfo
            
            # Perform remediation if enabled
            if ($EnableRemediation) {
                try {
                    Write-Host "  Attempting remediation..." -ForegroundColor Yellow
                    
                    # Get current tags
                    $currentTags = if ($resource.Tags) { $resource.Tags } else { @{} }
                    
                    # Add missing tags with empty values
                    foreach ($missingTag in $missingTags) {
                        $currentTags[$missingTag] = ""
                        Write-Host "    Adding empty tag: $missingTag" -ForegroundColor Yellow
                    }
                    
                    # Update the resource with new tags
                    Set-AzResource -ResourceId $resource.ResourceId -Tag $currentTags -Force | Out-Null
                    
                    Write-Host "  Remediation successful" -ForegroundColor Green
                    $remediatedResources += $resourceInfo
                }
                catch {
                    Write-Warning "  Failed to remediate resource '$($resource.Name)': $($_.Exception.Message)"
                }
            }
        }
        else {
            $compliantResourceInfo = [PSCustomObject]@{
                ResourceName = $resource.Name
                ResourceType = $resource.ResourceType
                ResourceGroup = $resource.ResourceGroupName
                Subscription = $sub.Name
                SubscriptionId = $sub.Id
                Location = $resource.Location
            }
            
            $compliantResources += $compliantResourceInfo
        }
    }
    
    Write-Host "Subscription '$($sub.Name)' processing complete"
}

# ==================== RESULTS OUTPUT ====================
Write-Host ""
Write-Host "======================== RESULTS ========================" -ForegroundColor Yellow
Write-Host ""

# Summary
Write-Host "SUMMARY:" -ForegroundColor Yellow
Write-Host "Total Subscriptions Processed: $($subscriptions.Count)"
Write-Host "Total Compliant Resources: $($compliantResources.Count)" -ForegroundColor Green
Write-Host "Total Non-Compliant Resources: $($nonCompliantResources.Count)" -ForegroundColor Red

if ($EnableRemediation) {
    Write-Host "Total Remediated Resources: $($remediatedResources.Count)" -ForegroundColor Green
}

Write-Host ""

# Display non-compliant resources
if ($nonCompliantResources.Count -gt 0) {
    Write-Host "NON-COMPLIANT RESOURCES:" -ForegroundColor Red
    $nonCompliantResources | Format-Table -Property ResourceName, ResourceType, ResourceGroup, Subscription, MissingTags -AutoSize
    
    # Export to CSV for further analysis
    $csvPath = "NonCompliantResources_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $nonCompliantResources | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Non-compliant resources exported to: $csvPath" -ForegroundColor Yellow
}
else {
    Write-Host "All resources are compliant with tag requirements!" -ForegroundColor Green
}

# Display remediation results if applicable
if ($EnableRemediation -and $remediatedResources.Count -gt 0) {
    Write-Host ""
    Write-Host "REMEDIATED RESOURCES:" -ForegroundColor Green
    $remediatedResources | Format-Table -Property ResourceName, ResourceType, ResourceGroup, Subscription, MissingTags -AutoSize
    
    # Export remediated resources to CSV
    $remediationCsvPath = "RemediatedResources_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $remediatedResources | Export-Csv -Path $remediationCsvPath -NoTypeInformation
    Write-Host "Remediated resources exported to: $remediationCsvPath" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Script execution completed at $(Get-Date)" -ForegroundColor Yellow