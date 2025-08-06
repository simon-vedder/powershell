<#
.TITLE
    AzVM-OSInventory

.SYNOPSIS
    Inventory of all Azure VMs across all subscriptions with their OS types and support status.

.DESCRIPTION
    This PowerShell script collects information about all virtual machines (VMs) in all accessible Azure subscriptions,
    including the operating system type and version. It also checks whether the OS is considered out of support based on a custom list.

.TAGS
    PowerShell, Inventory, Azure, VirtualMachines, Compliance

.MINROLE
    Reader

.PERMISSIONS
    Microsoft.Compute/virtualMachines/read

.AUTHOR
    Simon Vedder (info@simonvedder.com)

.VERSION
    1.0

.CHANGELOG
    1.0 - Initial release
    1.1 - Changed support for OS ARN instead of simple patterns to be more accurate

.LASTUPDATE
    2025-08-06

.NOTES
    You can update the $UnsupportedOSPatterns array to match your organization’s support policies
    to reflect unsupported OS images (URN without version).
    Output is also exported as CSV in the script directory.

.USAGE
    Run locally or use in Automation Account with Managed Identity.
#>

# ==================== CONFIGURATION ====================

param (
    [Parameter(Mandatory = $false)]
    [bool]$exportCSV = $false
)
# List of OS ARNS considered out of support
# Find ARN on: https://az-vm-image.info/?cmd=--all
$UnsupportedOSPatterns = @(
    "MicrosoftWindowsDesktop:Windows-10:win10-22h2-pro-g2",
    "MicrosoftWindowsServer:WindowsServer:2012-r2-datacenter-gen2",
    "Canonical:UbuntuServer:16.04-LTS",
    "Canonical:UbuntuServer:18.04-LTS",
    "OpenLogic:CentOS:6.5",
    "OpenLogic:CentOS:7.5"
)

# ==================== SCRIPT EXECUTION ====================

$vmInventory = @()

#Title
Write-Host "AzVM-OSInventory" -ForegroundColor Yellow
Write-Host "by Simon Vedder"
Write-Host "- VM OS Overview & Support Status -"
Write-Host "------------------------------------"
Write-Host (Get-Date)
Write-Host ""

#Configuration Output
Write-Host "Configuration: " -ForegroundColor Yellow

$formattedList = $UnsupportedOSPatterns | ForEach-Object { "   • $_" } | Out-String
Write-Host " - Defined unsupported OS:`n$formattedList"
Write-Host ""

# Login
Write-Host "Connecting to Azure..."
Connect-AzAccount | Out-Null

# Get all subscriptions
try {
    Write-Host "Retrieving Azure Subscriptions..."
    $subscriptions = Get-AzSubscription -ErrorAction Stop
    Write-Host "Found $($subscriptions.Count) subscription(s)" -ForegroundColor Green
}
catch {
    Write-Error "Error retrieving subscriptions: $($_.Exception.Message)"
    exit 1
}

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    Write-Host ""
    Write-Host "Processing Subscription: $($sub.Name)" -ForegroundColor Cyan
    Write-Host "Subscription ID: $($sub.Id)"

    try {
        Write-Host "Retrieving VMs..."
        $vms = Get-AzVM -Status -ErrorAction Stop
        Write-Host "Found $($vms.Count) VM(s)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to retrieve VMs in subscription '$($sub.Name)': $($_.Exception.Message)"
        continue
    }

    foreach ($vm in $vms) {
        $imageRef = $vm.StorageProfile.ImageReference

        $outOfSupport = $false
        if (-not $imageRef) {
            Write-Warning "VM '$($vm.Name)' has no ImageReference - skipping."
            continue
        }

        $urnNoVersion = "$($imageRef.Publisher):$($imageRef.Offer):$($imageRef.Sku)"
        $outOfSupport = $UnsupportedOSPatterns -contains $urnNoVersion

        $vmInfo = [PSCustomObject]@{
            VMName          = $vm.Name
            ResourceGroup   = $vm.ResourceGroupName
            Location        = $vm.Location
            Subscription    = $sub.Name
            SubscriptionId  = $sub.Id
            OSType          = $vm.StorageProfile.OsDisk.OsType
            OSPublisher     = $vm.StorageProfile.ImageReference.Publisher
            OSOffer         = $vm.StorageProfile.ImageReference.Offer
            OSSku           = $vm.StorageProfile.ImageReference.Sku
            OSVersion       = $vm.StorageProfile.ImageReference.Version
            OutOfSupport    = $outOfSupport
            PowerState      = ($vm.Statuses | Where-Object { $_.Code -like 'PowerState/*' }).DisplayStatus
        }

        $vmInventory += $vmInfo

        $statusColor = if ($outOfSupport) { 'Red' } else { 'Green' }
        Write-Host "VM: $($vm.Name) - $($urnNoVersion) - OutOfSupport: $outOfSupport" -ForegroundColor $statusColor
    }

    Write-Host "Subscription '$($sub.Name)' processing complete"
}

# ==================== OUTPUT ====================

Write-Host ""
Write-Host "======================== RESULTS ========================" -ForegroundColor Yellow
Write-Host "Total VMs found: $($vmInventory.Count)"

$vmInventory | Format-Table -Property VMName, OSPublisher, OSOffer, OSSku, OSVersion, OSType, Subscription, ResourceGroup, OutOfSupport -AutoSize

# Export CSV
if($exportCSV) {
    $csvPath = "AzVM_OSInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $vmInventory | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Inventory exported to: $csvPath" -ForegroundColor Yellow
}


Write-Host ""
Write-Host "Script execution completed at $(Get-Date)" -ForegroundColor Yellow