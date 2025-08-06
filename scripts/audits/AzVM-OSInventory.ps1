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

.LASTUPDATE
    2025-08-05

.NOTES
    You can update the $UnsupportedOSPatterns array to match your organization’s support policies.
    Output is also exported as CSV in the script directory.

.USAGE
    Run locally or use in Automation Account with Managed Identity.
#>

# ==================== CONFIGURATION ====================
# List of OS descriptions or patterns considered out of support
# Full List: https://az-vm-image.info/?cmd=--all
$UnsupportedOSPatterns = @(
    "Windows-10",
    "Windows Server 2012",
    "Windows Server 2008",
    "Ubuntu 16",
    "Ubuntu 18",
    "CentOS 6",
    "CentOS 7"
)
$exportCSV=$false

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
Write-Host " - Defined unsupported OS: $($UnsupportedOSPatterns -join ', ')"
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
        $osName =   $vm.StorageProfile.ImageReference.Publisher + " " + `
                    $vm.StorageProfile.ImageReference.Offer + " " + `
                    $vm.StorageProfile.ImageReference.Sku

        $outOfSupport = $false
        foreach ($pattern in $UnsupportedOSPatterns) {
            if ($osName -like "*$pattern*") {
                $outOfSupport = $true
                break
            }
        }

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
        Write-Host "VM: $($vm.Name) - $($osName) - OutOfSupport: $outOfSupport" -ForegroundColor $statusColor
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