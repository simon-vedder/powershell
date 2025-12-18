<#
.SYNOPSIS
    Automated Azure VM power management script for scheduled start/stop operations.

.DESCRIPTION
    This PowerShell script provides automated power management for Azure Virtual Machines across multiple subscriptions.
    It supports scheduled start and stop operations with flexible exclusion rules using VM tags and day-of-week filtering.
    The script is designed to run in Azure Automation Runbooks using Managed Identity authentication.

    Important: It is built for getting triggered by an hourly schedule.

.PARAMETER TimeZone
    Sets the default timezone if the VM does not have the timezone specific tag. It defines the time zone these hours refer to.
    Default: "W. Europe Standard Time"

.NOTES
    File Name      : AzVM-PowerManagement.ps1
    Version        : 2.0.0
    Author         : Simon Vedder
    Date           : 06.12.2025
    Prerequisite   : Azure PowerShell modules, Managed Identity with appropriate permissions
    
    Required Permissions:
    - Desktop Virtualization Power On Off Contributor (40c5ff49-9181-41f8-ae61-143b0e78555e)
    
    VM Tag Controls:
    - AutoShutdown              :   "<StartNumber>-<EndNumber>"     - 24h-format e.g. 8-18 (Starts at 8 and ends at 18)
    - AutoShutdown-TimeZone     :   "W. Europe Standard Time"       - TimeZone specifies which time zone these hours apply to (https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-time-zones)
    - AutoShutdown-SkipUntil    :   "yyyy-mm-dd"                    - Skip VM until specified date
    - AutoShutdown-ExcludeOn    :   "yyyy-mm-dd"                    - Exclude VM on specific date only
    - AutoShutdown-ExcludeDays  :   "Monday,Tuesday,Wednesday"      - Exclude VM on specific weekdays

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    Console output with detailed logging of all operations performed.
    Returns summary statistics of processed, actioned, skipped, and error VMs.

.LINK
    https://docs.microsoft.com/en-us/azure/automation/
    https://docs.microsoft.com/en-us/azure/virtual-machines/
    https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-time-zones
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TimeZone = "W. Europe Standard Time"
)

# Function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Level] $Message"
}

# Main Function
try {
    Write-Log "Starting VM Power Management Script - Action: $Action"
    
    # check date and weekday
    $currentDate = Get-Date
    $currentDayOfWeek = $currentDate.DayOfWeek.ToString()
    
    Write-Log "Current Date: $($currentDate.ToString('yyyy-MM-dd')), Day: $currentDayOfWeek"
    
    # Login with managed identity
    Write-Log "Connecting to Azure using Managed Identity..."
    try {
        $null = Connect-AzAccount -Identity -ErrorAction Stop
        Write-Log "Successfully connected to Azure"
    }
    catch {
        Write-Log "Failed to connect to Azure: $($_.Exception.Message)" "ERROR"
        throw
    }
    
    # Get subscription context
    $context = Get-AzContext
    Write-Log "Initially connected to Subscription: $($context.Subscription.Name) ($($context.Subscription.Id))"
    
    $targetSubscriptions = Get-AzSubscription
    Write-Log "Found $($targetSubscriptions.Count) available Subscriptions"
    
    # Statistics
    $processedVMs = 0
    $skippedVMs = 0
    $errorVMs = 0
    $startedVMs = 0
    $stoppedVMs = 0
    
    
    foreach ($subscription in $targetSubscriptions) {
        Write-Log "Processing Subscription: $($subscription.Name) ($($subscription.Id))"
        
        try {
            # Switch subscriptions
            $null = Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop
            Write-Log "Switched to Subscription: $($subscription.Name)"
            
            # Get VMs of this subscription
            $vms = Get-AzVM -ErrorAction Stop | Where-Object { $_.Tags.ContainsKey("AutoShutdown") }

            Write-Log "Found $($vms.Count) VMs in Subscription: $($subscription.Name)"
            
            foreach ($vm in $vms) {
                $processedVMs++
                $vmName = $vm.Name
                $vmResourceGroup = $vm.ResourceGroupName

                # Get VM Tags
                $vmTags = $vm.Tags
                if ($null -eq $vmTags) {
                    $vmTags = @{}
                }
                
                # Set TimeZone VM specific
                $targetTimeZone = if($vmTags["AutoShutdown-TimeZone"]) { 
                    $vmTags["AutoShutdown-TimeZone"] 
                } else { 
                    $TimeZone 
                }

                # Validate TimeZone exists
                try {
                    Set-TimeZone -Name $targetTimeZone -PassThru | Out-Null
                    $currentTimeZone = (Get-TimeZone).StandardName
                }
                catch {
                    Write-Log "Skipping VM: $vmName - Invalid TimeZone '$targetTimeZone'" "WARNING"
                    $skippedVMs++
                    continue
                }
                
                $currentHour = (Get-Date).Hour

                # Set the Action by splitting the tag and compare the values position with the current hour variable
                if (($vmTags["AutoShutdown"] -split "-")[0] -eq $currentHour) {
                    $Action = "Start"
                }
                elseif (($vmTags["AutoShutdown"] -split "-")[1] -eq $currentHour) {
                    $Action = "Stop"
                }
                else {
                    Write-Log "Skipping VM: $vmName skipped due to a different schedule (TimeZone: $currentTimeZone, CurrentHour: $currentHour)" "INFO"
                    $skippedVMs++
                    continue
                }


                Write-Log "Processing VM: $vmName (RG: $vmResourceGroup, Action: $Action, TimeZone: $currentTimeZone, CurrentHour: $currentHour)"
                
                # Check Weekday-based exclusion
                if ($vmTags.ContainsKey("AutoShutdown-ExcludeDays") -and $vmTags["AutoShutdown-ExcludeDays"] -ne "") {
                    $excludedDaysValue = $vmTags["AutoShutdown-ExcludeDays"]
                    $vmExcludedDays = $excludedDaysValue -split ","
                    $vmExcludedDays = $vmExcludedDays | ForEach-Object { $_.Trim() }
                    
                    if ($vmExcludedDays -contains $currentDayOfWeek) {
                        Write-Log "VM $vmName : Skipped due to AutoShutdown-ExcludeDays tag (Today: $currentDayOfWeek)" "WARNING"
                        $skippedVMs++
                        continue
                    }
                }
                
                # Date-based exlusion
                $skipUntilDate = $null
                $excludeDate = $null
                
                # Check Skip-Until Tag (temporary skip until the entered date)
                if ($vmTags.ContainsKey("AutoShutdown-SkipUntil") -and $vmTags["AutoShutdown-SkipUntil"] -ne "") {
                    $skipUntilValue = $vmTags["AutoShutdown-SkipUntil"]
                    try {
                        $skipUntilDate = [DateTime]::ParseExact($skipUntilValue, "yyyy-MM-dd", $null)
                        if ($currentDate.Date -le $skipUntilDate.Date) {
                            Write-Log "VM $vmName : Skipped until $($skipUntilDate.ToString('yyyy-MM-dd'))" "WARNING"
                            $skippedVMs++
                            continue
                        } else {
                            Write-Log "VM $vmName : SkipUntil date ($($skipUntilDate.ToString('yyyy-MM-dd'))) has passed, processing normally"
                        }
                    }
                    catch {
                        Write-Log "VM $vmName : Invalid SkipUntil date format: $skipUntilValue" "WARNING"
                    }
                }
                
                # Check Exclude-On Tag (exclusion at a specific date)
                if ($vmTags.ContainsKey("AutoShutdown-ExcludeOn") -and $vmTags["AutoShutdown-ExcludeOn"] -ne "") {
                    $excludeOnValue = $vmTags["AutoShutdown-ExcludeOn"]
                    try {
                        $excludeDate = [DateTime]::ParseExact($excludeOnValue, "yyyy-MM-dd", $null)
                        if ($currentDate.Date -eq $excludeDate.Date) {
                            Write-Log "VM $vmName : Excluded today due to ExcludeOn tag ($($excludeDate.ToString('yyyy-MM-dd')))" "WARNING"
                            $skippedVMs++
                            continue
                        }
                    }
                    catch {
                        Write-Log "VM $vmName : Invalid ExcludeOn date format: $excludeOnValue" "WARNING"
                    }
                }
                
                # Get VM State
                try {
                    $vmStatus = Get-AzVM -ResourceGroupName $vmResourceGroup -Name $vmName -Status -ErrorAction Stop
                    $powerState = ($vmStatus.Statuses | Where-Object { $_.Code -like "PowerState/*" }).Code
                    
                    Write-Log "VM $vmName : Current state: $powerState"
                    
                    # Action based on the specification and current state 
                    $shouldPerformAction = $false
                    
                    if ($Action -eq "Stop") {
                        if ($powerState -eq "PowerState/running") {
                            $shouldPerformAction = $true
                        } else {
                            Write-Log "VM $vmName : Already stopped or in transition, skipping" "WARNING"
                        }
                    } elseif ($Action -eq "Start") {
                        if ($powerState -eq "PowerState/deallocated" -or $powerState -eq "PowerState/stopped") {
                            $shouldPerformAction = $true
                        } else {
                            Write-Log "VM $vmName : Already running or in transition, skipping" "WARNING"
                        }
                    }
                    
                    if ($shouldPerformAction) {
                        Write-Log "VM $vmName : Performing $Action action..."
                        
                        if ($Action -eq "Stop") {
                            $result = Stop-AzVM -ResourceGroupName $vmResourceGroup -Name $vmName -NoWait -Force -ErrorAction Stop
                            Write-Log "VM $vmName : Successfully stopped/deallocated" "PROGRESS"
                            $stoppedVMs++
                        } elseif ($Action -eq "Start") {
                            $result = Start-AzVM -ResourceGroupName $vmResourceGroup -Name $vmName -NoWait -ErrorAction Stop
                            Write-Log "VM $vmName : Successfully started" "PROGRESS"
                            $startedVMs++
                        }
                        
                    } else {
                        $skippedVMs++
                    }
                }
                catch {
                    Write-Log "VM $vmName : Error during $Action action: $($_.Exception.Message)" "ERROR"
                    $errorVMs++
                }
            }
        }
        catch {
            Write-Log "Error processing Subscription $($subscription.Name): $($_.Exception.Message)" "ERROR"
            $errorVMs++
        }
    }
    
    # Summary
    Write-Log "=== SUMMARY ===" "INFO"
    Write-Log "Total VMs processed: $processedVMs" "INFO"
    Write-Log "VMs started: $startedVMs" "INFO"
    Write-Log "VMs stopped: $stoppedVMs" "INFO"
    Write-Log "VMs skipped: $skippedVMs" "INFO"
    Write-Log "VMs with errors: $errorVMs" "INFO"
    
    Write-Log "Script completed successfully" "INFO"
}
catch {
    Write-Log "Script failed with error: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack Trace: $($_.Exception.StackTrace)" "ERROR"
    throw
}