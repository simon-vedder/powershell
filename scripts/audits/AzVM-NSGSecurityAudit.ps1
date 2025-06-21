<#
.TITLE
    AzVM-NSGSecurityAudit

.SYNOPSIS
    Find all Virtual Machines which are not protected by an NSG.

.DESCRIPTION
    This PowerShell script will find every Virtual Machine within your tenant to find resources without an assigned Network Security Group.
    It will not review if the rules within the NSG are secure.
    
.TAGS
    PowerShell, Diagnostic, Security

.MINROLE
    Reader

.PERMISSIONS
    Microsoft.Resources/subscriptions/read
    Microsoft.Network/networkSecurityGroups/read
    Microsoft.Compute/virtualMachines/read

.AUTHOR
    Simon Vedder

.VERSION
    1.0

.CHANGELOG
    1.0 - Initial release

.LASTUPDATE
    2025-06-21

.NOTES

.USAGE
  - Run locally or use it in your runbook while changing Connect-AzAccount to use a non-interactive authentication
  
#>

$unprotectedVMs = @()
$protectedVMs = @() #optional

Write-Host "AzVM-NSGSecurityAudit"
Write-Host "- by Simon Vedder -"
Write-Host "---------------------"
Write-Host (Get-Date)

#LOGIN
Connect-AzAccount | Out-Null

# Get all Subscriptions
try {
    Write-Host "Retrieve Azure Subscriptions"
    $subscriptions = Get-AzSubscription -ErrorAction Stop
    Write-Host "Subscriptions successfully retrieved" -ForegroundColor Green
}
catch {
    Write-Error "Error: $($_.Exception.Message)"
}

# Run code in each subscription
foreach($sub in $subscriptions)
{
    # Change the subscription
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    Write-Host ""
    Write-Host "SubscriptionName: $($sub.Name)"
    
    # Get all NSGs within the subscription
    try {
        Write-Host "1. Get all NSGs"
        $NSGs = Get-AzNetworkSecurityGroup -ErrorAction Stop
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
    }
    if (-not $NSGs) {
        Write-Warning "No Azure Network Security Groups found in the current context."
        return
    }
    else {
        Write-Host "NetworkSecurityGroups successfully retrieved" -ForegroundColor Green
    }
    # Set variables with NSG Ids that are assigned to NICs and Subnets
    $protectedNICs = $NSGs.NetworkInterfaces.Id
    $protectedSubnets = $NSGs.Subnets.Id


    # Get all VMs within the Subscription
    try {
        Write-Host "2. Get all VMs"
        $VMs = Get-AzVM
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
    }
    if (-not $VMs) {
        Write-Warning "No Azure Virtual Machines found in the current context."
        return
    }
    else {
        Write-Host "VirtualMachines successfully retrieved" -ForegroundColor Green
    }

    

    #Begin the check
    Write-Host "- Start protection check: "
    foreach ($VM in $VMs)
    {
        # Set variables with the VMs NIC and SubnetId
        $NIC = Get-AzNetworkInterface -Name ($VM.NetworkProfile.NetworkInterfaces[0].Id.Split('/')[-1]) -ResourceGroupName $VM.ResourceGroupName
        $subnetId = $NIC.IpConfigurations[0].Subnet.Id

        # Check if the the protected NICs and protectedSubnets contain the VMs resources (NIC & Subnet)
        if ($protectedNICs -notcontains $NIC.Id -and $protectedSubnets -notcontains $subnetId)
        {
            Write-Host "VM found: $($VM.Name)" -ForegroundColor Cyan

            $unprotectedVMs += [PSCustomObject]@{
                UnprotectedVM   = $VM.Name
                ResourceGroup   = $VM.ResourceGroupName
                Subscription    = $sub.Name 
            }
        }
        else {
            $protectedVMs += [PSCustomObject]@{
                ProtectedVM     = $VM.Name
                ResourceGroup   = $VM.ResourceGroupName
                Subscription    = $sub.Name 
            }
        }
    }
}

#Output
if ($unprotectedVMs.Count -gt 0)
{
    Write-Host ""
    Write-Host "--- Overview ---"
    $unprotectedVMs | Format-Table -AutoSize
    $protectedVMs | Format-Table -AutoSize #uncomment if you want to see protected VMS
}
else {
    Write-Host "Every VM is protected by a NSG!" -ForegroundColor Green
}