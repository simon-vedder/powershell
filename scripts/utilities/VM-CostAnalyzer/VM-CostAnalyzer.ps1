<#
.SYNOPSIS
    Azure VM Cost Optimization Analyzer with Live Cost Data

.DESCRIPTION
    This PowerShell script provides comprehensive cost analysis and optimization recommendations for Azure Virtual Machines
    across multiple subscriptions. It analyzes VM usage patterns, retrieves real-time pricing data, and calculates potential
    cost savings through various Azure pricing models including Savings Plans and Reserved Instances.
    
    The script is designed to run interactively or in Azure Automation Runbooks and generates detailed
    reports in both CSV and HTML formats.

    Key Features:
    - Analyzes actual VM usage from Activity Logs (last 30 days)
    - Retrieves real-time pricing from Azure Retail Prices API
    - Calculates costs for 24/7 operation vs. actual usage
    - Evaluates Savings Plans (1-Year and 3-Year) pricing
      Note: Savings Plans are not available for all VM series (e.g., A-series has no Savings Plan discount)
    - Evaluates Reserved Instances (1-Year and 3-Year) pricing via Get-AzReservationQuote
    - Provides VM sizing recommendations based on CPU metrics
    - Generates cost-saving recommendations with percentage savings
    - Exports results to CSV and HTML reports

.NOTES
    File Name      : AzVM-CostOptimizer.ps1
    Version        : 0.0.1
    Author         : Simon Vedder
    Date           : 09.03.2026
    Prerequisite   : PowerShell 7.2+, Azure PowerShell modules (Az.Accounts, Az.Compute, Az.Monitor, Az.Reservations)
                     Managed Identity or interactive login with appropriate permissions
    
    Required Permissions:
    - Reader access to subscriptions
    - Cost Management Reader (optional, for Cost Management API access)
    - Monitoring Reader (for VM metrics access)

    Authentication:
    - The script connects via Connect-AzAccount. For use in Azure Automation Runbooks,
      uncomment the -Identity parameter to use Managed Identity authentication.
    
    Savings Plan Discount Configuration:
    The script uses configurable discount rates for different VM series when API data is unavailable.
    These can be adjusted in the script configuration section:
    - $Script:SavingsPlan1YDiscounts  - 1-Year Savings Plan discounts by VM series
    - $Script:SavingsPlan3YDiscounts  - 3-Year Savings Plan discounts by VM series
    
    Default Discounts (fallback, used when API data is unavailable):
    - A-series:   Not available (0%)
    - Av2-series: 25% (1Y) / 46% (3Y)
    - B-series:   24% (1Y) / 45% (3Y)
    - D-series:   24% (1Y) / 45% (3Y)
    - Other:      25% (1Y) / 45% (3Y)

.INPUTS
    None. This script does not accept pipeline input.
    Configuration is done via script-level variables at the top of the file:
    - $Script:DaysToAnalyze  - Number of days to analyze (default: 30)
    - $Script:DaysInMonth    - Days used for monthly cost projection (default: 30)

.OUTPUTS
    Console output with detailed logging of all operations performed.
    CSV file: VM-Cost-Analysis-<timestamp>.csv
    HTML file: VM-Cost-Analysis-<timestamp>.html
    
    Output includes:
    - VM Name, Subscription, Resource Group, Location
    - VM Size and Power State
    - Usage hours per day
    - Cost calculations (24/7, Actual, 1Y/3Y Savings Plans, 1Y/3Y Reservations)
    - Sizing recommendations with CPU utilization
    - Cost-saving recommendations with percentage savings
    - Summary statistics and potential savings

.EXAMPLE
    .\AzVM-CostOptimizer.ps1
    
    Runs the cost analysis for all VMs in all enabled subscriptions using default settings.
    Prompts for interactive Azure login unless -Identity is enabled for Managed Identity.

.LINK
    https://docs.microsoft.com/en-us/azure/automation/
    https://docs.microsoft.com/en-us/azure/virtual-machines/
    https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices
    https://learn.microsoft.com/en-us/azure/cost-management-billing/reservations/
    https://learn.microsoft.com/en-us/azure/cost-management-billing/savings-plan/
#>

#Requires -Version 7.2
#Requires -Modules Az.Accounts, Az.Compute, Az.Monitor, Az.Reservations

# Configuration
$Script:DaysToAnalyze = 30
$Script:HoursPerDay = 24
$Script:DaysInMonth = 30
$Script:RetailPricesAPI = "https://prices.azure.com/api/retail/prices"

# Savings Plan Discount Rates (when API data is not available)
# These are typical discounts - adjust based on your Azure agreement
$Script:SavingsPlan1YDiscounts = @{
    'A'  = 0.00   # A-series: 0% (not available)
    'Av' = 0.25   # Av2-series: 25%
    'B'  = 0.24   # B-series: 24%
    'D'  = 0.24   # D-series: 24%
    'E'  = 0.25   # E-series: 25%
    'F'  = 0.25   # F-series: 25%
    'M'  = 0.25   # M-series: 25%
    'L'  = 0.25   # L-series: 25%
    'N'  = 0.25   # N-series (GPU): 25%
}

$Script:SavingsPlan3YDiscounts = @{
    'A'  = 0.00   # A-series: 0% (not available)
    'Av' = 0.46   # Av2-series: 46%
    'B'  = 0.45   # B-series: 45%
    'D'  = 0.45   # D-series: 45%
    'E'  = 0.45   # E-series: 45%
    'F'  = 0.45   # F-series: 45%
    'M'  = 0.45   # M-series: 45%
    'L'  = 0.45   # L-series: 45%
    'N'  = 0.45   # N-series (GPU): 45%
}

# Default discount when VM series is not found in the map
$Script:DefaultSavingsPlan1YDiscount = 0.25  # 25%
$Script:DefaultSavingsPlan3YDiscount = 0.45  # 45%

Write-Output "==================================="
Write-Output "Azure VM Cost Analysis Script"
Write-Output "Started at: $(Get-Date)"
Write-Output "==================================="

# Connect using Managed Identity
Write-Output "`nConnecting to Azure using Managed Identity..."
try {
    $context = Connect-AzAccount #-Identity -ErrorAction Stop
    Write-Output "Successfully connected to Azure"
    Write-Output "Account: $($context.Context.Account.Id)"
}
catch {
    Write-Error "Failed to connect with Managed Identity: $_"
    throw
}

#region Helper Functions

function Get-CurrentUsage {
    param(
        [Parameter(Mandatory)]
        [object]$VM,
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )
    
    Write-Output "    Getting usage data for $($VM.Name)..."
    
    $startDate = (Get-Date).AddDays(-$Script:DaysToAnalyze)
    $endDate = Get-Date
    
    try {
        # Get Activity Log events - optimiert für Start/Stop Events
        $activityLogs = Get-AzActivityLog -ResourceId $VM.Id -StartTime $startDate -EndTime $endDate -WarningAction SilentlyContinue -ErrorAction Stop |
        Where-Object { 
            # Filter auf exakte Actions
            ($_.Properties.Content.message -eq 'Microsoft.Compute/virtualMachines/start/action' -or 
            $_.Properties.Content.message -eq 'Microsoft.Compute/virtualMachines/deallocate/action') -and 
            $_.Status -eq 'Succeeded'
        } |
        Select-Object EventTimestamp, @{N = 'Action'; E = {
                if ($_.Properties.Content.message -eq 'Microsoft.Compute/virtualMachines/start/action') { 
                    'Start' 
                }
                else { 
                    'Deallocate' 
                }
            }
        } |
        Sort-Object EventTimestamp
        
        Write-Output "    Found $($activityLogs.Count) start/stop events in last $($Script:DaysToAnalyze) days"
        
        $runningHours = 0
        $lastStartTime = $null
        $hasData = $true
        $runningPeriods = @()
        
        # Check if VM has no activity logs
        if ($activityLogs.Count -eq 0) {
            Write-Host "    No activity logs found - analyzing current state..." -ForegroundColor Yellow
            
            if ($VM.PowerState -eq 'VM running') {
                # No logs and running = assume 24/7 for analysis period
                $runningHours = ($endDate - $startDate).TotalHours
                Write-Host "    VM is running with no logs - assuming continuous operation: $([math]::Round($runningHours, 2)) hours" -ForegroundColor Yellow
                $runningPeriods += [PSCustomObject]@{
                    Start    = $startDate
                    End      = $endDate
                    Duration = $runningHours
                    Note     = "Assumed (no logs, currently running)"
                }
            }
            elseif ($VM.PowerState -match 'deallocated|stopped') {
                # No logs and stopped = assume always off
                $runningHours = 0
                Write-Host "    VM is deallocated/stopped with no logs - assuming 0 running hours" -ForegroundColor Yellow
            }
            else {
                # Unknown state
                $runningHours = 0
                Write-Host "    VM in unknown state - assuming 0 hours" -ForegroundColor Yellow
            }
            $hasData = $false
        }
        else {
            # Has activity logs - calculate exact running periods
            Write-Host "    Analyzing VM running periods..." -ForegroundColor Cyan
            
            # Check if first event is Deallocate - means VM was running at start of analysis period
            if ($activityLogs[0].Action -eq 'Deallocate') {
                $lastStartTime = $startDate
                Write-Host "    First event is Deallocate - VM was running at analysis start ($startDate)" -ForegroundColor Cyan
            }
            
            # Process all events to calculate running periods
            foreach ($log in $activityLogs) {
                if ($log.Action -eq 'Start') {
                    $lastStartTime = $log.EventTimestamp
                    Write-Verbose "    VM started at $($log.EventTimestamp)"
                }
                elseif ($log.Action -eq 'Deallocate' -and $lastStartTime) {
                    $duration = ($log.EventTimestamp - $lastStartTime).TotalHours
                    $runningHours += $duration
                    
                    # Track running period for detailed reporting
                    $runningPeriods += [PSCustomObject]@{
                        Start    = $lastStartTime
                        End      = $log.EventTimestamp
                        Duration = $duration
                        Note     = "Logged"
                    }
                    
                    Write-Verbose "    VM stopped at $($log.EventTimestamp) - ran for $([math]::Round($duration, 2)) hours"
                    $lastStartTime = $null
                }
            }
            
            # Add remaining time if VM is still running
            if ($lastStartTime) {
                $remainingHours = ($endDate - $lastStartTime).TotalHours
                $runningHours += $remainingHours
                
                # Track current running period
                $runningPeriods += [PSCustomObject]@{
                    Start    = $lastStartTime
                    End      = $endDate
                    Duration = $remainingHours
                    Note     = "Currently running"
                }
                
                Write-Host "    VM still running since $lastStartTime - adding $([math]::Round($remainingHours, 2)) hours" -ForegroundColor Cyan
            }
            
            # Show running periods summary
            if ($runningPeriods.Count -gt 0) {
                Write-Host "`n    Running Periods Summary:" -ForegroundColor Green
                $runningPeriods | ForEach-Object {
                    Write-Host "      $($_.Start.ToString('dd.MM HH:mm')) - $($_.End.ToString('dd.MM HH:mm')) | $([math]::Round($_.Duration, 2))h | $($_.Note)" -ForegroundColor Gray
                }
            }
        }
        
        # Calculate metrics
        $avgDailyHours = $runningHours / $Script:DaysToAnalyze
        $monthlyHours = $avgDailyHours * 30  # Projected monthly hours
        $utilizationPercent = ($avgDailyHours / 24) * 100
        
        Write-Output "`n    === Usage Summary ==="
        Write-Output "    Total running hours: $([math]::Round($runningHours, 2)) hours"
        Write-Output "    Average daily hours: $([math]::Round($avgDailyHours, 2)) hours/day"
        Write-Output "    Projected monthly hours: $([math]::Round($monthlyHours, 2)) hours/month"
        Write-Output "    Utilization: $([math]::Round($utilizationPercent, 1))%"
        Write-Output "    =====================`n"
        
        return @{
            TotalHours         = [math]::Round($runningHours, 2)
            AvgDailyHours      = [math]::Round($avgDailyHours, 2)
            MonthlyHours       = [math]::Round($monthlyHours, 2)
            UtilizationPercent = [math]::Round($utilizationPercent, 1)
            EventCount         = $activityLogs.Count
            HasSufficientData  = $hasData
            RunningPeriods     = $runningPeriods
            AnalysisPeriodDays = $Script:DaysToAnalyze
            AnalysisStart      = $startDate
            AnalysisEnd        = $endDate
        }
    }
    catch {
        Write-Warning "    Error getting usage data: $_"
        Write-Warning "    Exception: $($_.Exception.Message)"
        return @{
            TotalHours         = 0
            AvgDailyHours      = 0
            MonthlyHours       = 0
            UtilizationPercent = 0
            EventCount         = 0
            HasSufficientData  = $false
            RunningPeriods     = @()
            AnalysisPeriodDays = $Script:DaysToAnalyze
            AnalysisStart      = $startDate
            AnalysisEnd        = $endDate
        }
    }
}


function Get-VMPricingData {
    param(
        [Parameter(Mandatory)]
        [string]$VMSize,
        [Parameter(Mandatory)]
        [string]$Location,
        [Parameter(Mandatory)]
        [object]$VM
    )
    
    Write-Output "    Getting pricing for $VMSize in $Location..."
    
    # Normalize location name for API
    $apiLocation = $Location.ToLower() -replace '\s', ''
    
    # Determine OS type from VM
    $Windows = $false
    if ($VM.StorageProfile.OsDisk.OsType -eq 'Windows') {
        $Windows = $true
        Write-Output "    Detected OS: Windows"
    }
    else {
        Write-Output "    Detected OS: Linux"
    }
    
    # Build API filter
    $filter = "serviceName eq 'Virtual Machines' and armRegionName eq '$apiLocation' and armSkuName eq '$VMSize' and type eq 'Consumption'"
    
    try {
        $uri = "$Script:RetailPricesAPI`?api-version=2023-01-01-preview&`$filter=$filter"
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
        
        if ($response.Items -and $response.Items.Count -gt 0) {
            Write-Output "    Found $($response.Items.Count) pricing items, filtering..."
            
            # Filter out Spot instances and match OS type
            $filteredItems = $response.Items | Where-Object {
                # Exclude Spot instances
                $_.skuName -notmatch 'Spot' -and
                $_.meterName -notmatch 'Spot' -and
                # Match OS type
                (
                    ($Windows -and $_.productName -match 'Windows') -or
                    (!$Windows -and $_.productName -notmatch 'Windows')
                )
            }
            
            if ($filteredItems.Count -eq 0) {
                Write-Warning "    No matching items found after filtering. Available items:"
                foreach ($item in $response.Items) {
                    Write-Output "      - $($item.productName) / $($item.skuName) / $($item.meterName)"
                }
                # Fallback: take first non-spot item
                $filteredItems = $response.Items | Where-Object {
                    $_.skuName -notmatch 'Spot' -and $_.meterName -notmatch 'Spot'
                }
            }
            
            if ($filteredItems.Count -gt 0) {
                # Take the first filtered item
                $item = $filteredItems[0]
                Write-Output "    Selected: $($item.productName) / $($item.skuName)"
                Write-Output "    Found pricing: $($item.retailPrice) $($item.currencyCode)/hour"
                
                # Extract Savings Plan pricing if available
                $savingsPlan1Y = $null
                $savingsPlan3Y = $null
                
                if ($item.savingsPlan -and $item.savingsPlan.Count -gt 0) {
                    foreach ($plan in $item.savingsPlan) {
                        if ($plan.term -eq "1 Year") {
                            $savingsPlan1Y = $plan.retailPrice
                            Write-Output "    Found 1Y Savings Plan: $savingsPlan1Y $($item.currencyCode)/hour"
                        }
                        elseif ($plan.term -eq "3 Years") {
                            $savingsPlan3Y = $plan.retailPrice
                            Write-Output "    Found 3Y Savings Plan: $savingsPlan3Y $($item.currencyCode)/hour"
                        }
                    }
                }
                else {
                    Write-Output "    No Savings Plan pricing available in API response"
                }
                
                return @{
                    PricePerHour         = $item.retailPrice
                    SavingsPlan1YPerHour = $savingsPlan1Y
                    SavingsPlan3YPerHour = $savingsPlan3Y
                    Currency             = $item.currencyCode
                    VMSize               = $VMSize
                    Location             = $Location
                    MeterRegion          = $item.meterRegion
                    ProductName          = $item.productName
                    IsWindows            = $Windows
                }
            }
        }
        
        Write-Output "    No pricing found in API, using fallback"
    }
    catch {
        Write-Warning "    Failed to get pricing from API: $_"
    }
    
    # Fallback pricing
    Write-Output "    Using fallback pricing: 0.10 USD/hour"
    return @{
        PricePerHour         = 0.10
        SavingsPlan1YPerHour = $null
        SavingsPlan3YPerHour = $null
        Currency             = 'USD'
        VMSize               = $VMSize
        Location             = $Location
        MeterRegion          = $null
        ProductName          = "Unknown"
        IsWindows            = $false
    }
}




function Get-247Cost {
    param($PricingData)
    $cost = $PricingData.PricePerHour * $Script:HoursPerDay * $Script:DaysInMonth
    # Ensure single value
    if ($cost -is [array]) { $cost = $cost[0] }
    return [double]$cost
}

function Get-CostByUsage {
    param(
        $PricingData,
        [double]$AvgDailyHours
    )
    $cost = $PricingData.PricePerHour * $AvgDailyHours * $Script:DaysInMonth
    # Ensure single value
    if ($cost -is [array]) { $cost = $cost[0] }
    return [double]$cost
}

function Get-SavingsPlanPricing {
    param(
        [string]$VMSize,
        [string]$Location,
        [string]$Term  # "1 Year" or "3 Years"
    )
    
    $apiLocation = $Location.ToLower() -replace '\s', ''
    
    try {
        # Try with Consumption type that includes savingsPlan array
        $filter = "serviceName eq 'Virtual Machines' and armRegionName eq '$apiLocation' and armSkuName eq '$VMSize' and type eq 'Consumption'"
        $uri = "$Script:RetailPricesAPI`?api-version=2023-01-01-preview&`$filter=$filter"
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
        
        if ($response.Items -and $response.Items[0].savingsPlan) {
            $plan = $response.Items[0].savingsPlan | Where-Object { $_.term -eq $Term }
            if ($plan) {
                return $plan.retailPrice
            }
        }
    }
    catch {
        # Silent fail, will use fallback
    }
    
    return $null
}

function Get-VMSeriesFromSize {
    param([string]$VMSize)
    
    # Extract series from VMSize (e.g., Standard_B2ms -> B, Standard_D4s_v3 -> D, Standard_DS2_v2 -> D)
    if ($VMSize -match 'Standard_([A-Za-z]+)') {
        $series = $matches[1] -replace '\d+.*', ''  # Remove numbers and everything after
        
        # Handle special cases like DS -> D, Es -> E
        if ($series -match '^([A-Z])[sS]$') {
            return $matches[1]
        }
        
        return $series
    }
    
    return ""
}

function Get-1YSavingPlanCost {
    param($PricingData)
    
    Write-Host "    Getting 1Y Savings Plan pricing..." -ForegroundColor Gray
    
    # Priority 1: Use savingsPlan array from initial API call
    if ($PricingData.SavingsPlan1YPerHour) {
        Write-Host "    ✓ API 1Y Savings Plan: $($PricingData.SavingsPlan1YPerHour)/hour" -ForegroundColor Green
        $cost = $PricingData.SavingsPlan1YPerHour * $Script:HoursPerDay * $Script:DaysInMonth
        return [double]$cost
    }
    
    # Priority 2: Try additional API lookup
    $spPrice = Get-SavingsPlanPricing -VMSize $PricingData.VMSize -Location $PricingData.Location -Term "1 Year"
    if ($spPrice) {
        Write-Host "    ✓ Found 1Y Savings Plan via API: $spPrice/hour" -ForegroundColor Green
        return [double]($spPrice * $Script:HoursPerDay * $Script:DaysInMonth)
    }
    
    # Priority 3: Use series-based estimates from configuration
    $vmSeries = Get-VMSeriesFromSize -VMSize $PricingData.VMSize
    
    $discount = $Script:DefaultSavingsPlan1YDiscount
    
    # Try to find exact match in discount map
    if ($Script:SavingsPlan1YDiscounts.ContainsKey($vmSeries)) {
        $discount = $Script:SavingsPlan1YDiscounts[$vmSeries]
    }
    # Try with 'v' suffix (Av2, Dv3, etc.)
    elseif ($vmSeries -match '^([A-Z])v' -and $Script:SavingsPlan1YDiscounts.ContainsKey($matches[1] + 'v')) {
        $discount = $Script:SavingsPlan1YDiscounts[$matches[1] + 'v']
    }
    # Try base letter only
    elseif ($vmSeries.Length -gt 0 -and $Script:SavingsPlan1YDiscounts.ContainsKey($vmSeries[0].ToString())) {
        $discount = $Script:SavingsPlan1YDiscounts[$vmSeries[0].ToString()]
    }
    
    if ($discount -eq 0) {
        Write-Host "    ⚠ 1Y Savings Plan: Not available for $vmSeries-series VMs" -ForegroundColor Yellow
        return $null
    }
    
    $discountPercent = [math]::Round($discount * 100, 0)
    Write-Host "    ~ 1Y Savings Plan: Estimated (~$discountPercent% discount for $vmSeries-series)" -ForegroundColor Yellow
    return [double]((Get-247Cost -PricingData $PricingData) * (1 - $discount))
}

function Get-3YSavingPlanCost {
    param($PricingData)
    
    Write-Host "    Getting 3Y Savings Plan pricing..." -ForegroundColor Gray
    
    # Priority 1: Use savingsPlan array from initial API call
    if ($PricingData.SavingsPlan3YPerHour) {
        Write-Host "    ✓ API 3Y Savings Plan: $($PricingData.SavingsPlan3YPerHour)/hour" -ForegroundColor Green
        $cost = $PricingData.SavingsPlan3YPerHour * $Script:HoursPerDay * $Script:DaysInMonth
        return [double]$cost
    }
    
    # Priority 2: Try additional API lookup
    $spPrice = Get-SavingsPlanPricing -VMSize $PricingData.VMSize -Location $PricingData.Location -Term "3 Years"
    if ($spPrice) {
        Write-Host "    ✓ Found 3Y Savings Plan via API: $spPrice/hour" -ForegroundColor Green
        return [double]($spPrice * $Script:HoursPerDay * $Script:DaysInMonth)
    }
    
    # Priority 3: Use series-based estimates from configuration
    $vmSeries = Get-VMSeriesFromSize -VMSize $PricingData.VMSize
    
    $discount = $Script:DefaultSavingsPlan3YDiscount
    
    # Try to find exact match in discount map
    if ($Script:SavingsPlan3YDiscounts.ContainsKey($vmSeries)) {
        $discount = $Script:SavingsPlan3YDiscounts[$vmSeries]
    }
    # Try with 'v' suffix
    elseif ($vmSeries -match '^([A-Z])v' -and $Script:SavingsPlan3YDiscounts.ContainsKey($matches[1] + 'v')) {
        $discount = $Script:SavingsPlan3YDiscounts[$matches[1] + 'v']
    }
    # Try base letter only
    elseif ($vmSeries.Length -gt 0 -and $Script:SavingsPlan3YDiscounts.ContainsKey($vmSeries[0].ToString())) {
        $discount = $Script:SavingsPlan3YDiscounts[$vmSeries[0].ToString()]
    }
    
    if ($discount -eq 0) {
        Write-Host "    ⚠ 3Y Savings Plan: Not available for $vmSeries-series VMs" -ForegroundColor Yellow
        return $null
    }
    
    $discountPercent = [math]::Round($discount * 100, 0)
    Write-Host "    ~ 3Y Savings Plan: Estimated (~$discountPercent% discount for $vmSeries-series)" -ForegroundColor Yellow
    return [double]((Get-247Cost -PricingData $PricingData) * (1 - $discount))
}

function Get-1YReservationCost {
    param(
        $VM,
        $PricingData,
        [Parameter(Mandatory)]
        [string]$Location,
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )
    
    Write-Host "    Getting 1Y Reservation pricing using Get-AzReservationQuote..." -ForegroundColor Gray
    
    try {
        # Build billing scope
        $billingScopeId = "/subscriptions/$SubscriptionId"
        
        # Get reservation quote
        $quote = Get-AzReservationQuote -AppliedScopeType 'Shared' `
            -BillingPlan 'Monthly' `
            -billingScopeId $billingScopeId `
            -DisplayName "Quote-$($PricingData.VMSize)" `
            -Location $Location `
            -Quantity 1 `
            -ReservedResourceType 'VirtualMachines' `
            -Sku $PricingData.VMSize `
            -Term 'P1Y' `
            -ErrorAction Stop
        
        if ($quote -and $quote.BillingCurrencyTotal.Amount) {
            # Quote returns total price for the term, we need monthly
            $totalPrice = $quote.BillingCurrencyTotal.Amount
            $monthlyPrice = $totalPrice / 12  # 1 year = 12 months
            
            Write-Host "   ✓ API 1Y Reservation monthly cost: $monthlyPrice $($quote.BillingCurrencyTotal.CurrencyCode)" -ForegroundColor Green
            return [double]$monthlyPrice
        }
    }
    catch {
        Write-Host "   ⚠ 1Y Reservation not available: $_" -ForegroundColor Yellow
    }
    
    # Return null if not available
    Write-Host "   ⚠ 1Y Reservation: Not Available" -ForegroundColor Yellow
    return $null
}

function Get-3YReservationCost {
    param(
        $VM,
        $PricingData,
        [Parameter(Mandatory)]
        [string]$Location,
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )
    
    Write-Host "    Getting 3Y Reservation pricing using Get-AzReservationQuote..." -ForegroundColor Gray
    
    try {
        # Build billing scope
        $billingScopeId = "/subscriptions/$SubscriptionId"
        
        # Get reservation quote
        $quote = Get-AzReservationQuote -AppliedScopeType 'Shared' `
            -BillingPlan 'Monthly' `
            -billingScopeId $billingScopeId `
            -DisplayName "Quote-$($PricingData.VMSize)" `
            -Location $Location `
            -Quantity 1 `
            -ReservedResourceType 'VirtualMachines' `
            -Sku $PricingData.VMSize `
            -Term 'P3Y' `
            -ErrorAction Stop
        
        if ($quote -and $quote.BillingCurrencyTotal.Amount) {
            # Quote returns total price for the term, we need monthly
            $totalPrice = $quote.BillingCurrencyTotal.Amount
            $monthlyPrice = $totalPrice / 36  # 3 years = 36 months
            
            Write-Host "   ✓ API 3Y Reservation monthly cost: $monthlyPrice $($quote.BillingCurrencyTotal.CurrencyCode)" -ForegroundColor Green
            return [double]$monthlyPrice
        }
    }
    catch {
        Write-Host "   ⚠ 3Y Reservation not available: $_" -ForegroundColor Yellow
    }
    
    # Return null if not available
    Write-Host "   ⚠ 3Y Reservation: Not Available" -ForegroundColor Yellow
    return $null
}

function Get-SizingRecommendation {
    param($VM)
    
    try {
        $startTime = (Get-Date).AddDays(-$Script:DaysToAnalyze)
        $endTime = Get-Date
        
        $metrics = Get-AzMetric -ResourceId $VM.Id -MetricName "Percentage CPU" `
            -StartTime $startTime -EndTime $endTime -TimeGrain 01:00:00 `
            -AggregationType Average -WarningAction SilentlyContinue -ErrorAction Stop
        
        if ($metrics.Data -and $metrics.Data.Count -gt 0) {
            $validData = $metrics.Data | Where-Object { $null -ne $_.Average }
            if ($validData.Count -gt 0) {
                $avgCPU = ($validData | Measure-Object -Property Average -Average).Average
                $avgCPURounded = [math]::Round($avgCPU, 1)
                
                Write-Host "    Average CPU: $avgCPURounded%" -ForegroundColor Gray
                
                if ($avgCPU -lt 20) {
                    return "Scale Down ($avgCPURounded%)"
                }
                elseif ($avgCPU -gt 80) {
                    return "Scale Up ($avgCPURounded%)"
                }
                else {
                    return "Right-Sized ($avgCPURounded%)"
                }
            }
        }
    }
    catch {
        Write-Host "    CPU metrics not available: $_" -ForegroundColor Gray
    }
    
    return "No Data"
}

function Get-CostSavingRecommendation {
    param(
        $Cost247,
        $CostByUsage,
        $Cost1YSavingPlan,
        $Cost3YSavingPlan,
        $Cost1YReservation,
        $Cost3YReservation
    )
    
    # Ensure all inputs are converted to double (or null)
    $cost247Val = [double]$Cost247
    $costByUsageVal = [double]$CostByUsage
    $cost1YSPVal = [double]$Cost1YSavingPlan
    $cost3YSPVal = [double]$Cost3YSavingPlan
    
    $cost1YResVal = if ($null -ne $Cost1YReservation) { [double]$Cost1YReservation } else { $null }
    $cost3YResVal = if ($null -ne $Cost3YReservation) { [double]$Cost3YReservation } else { $null }
    
    Write-Host "    Cost247: $cost247Val" -ForegroundColor Gray
    Write-Host "    CostByUsage: $costByUsageVal" -ForegroundColor Gray
    Write-Host "    1Y SP: $cost1YSPVal" -ForegroundColor Gray
    Write-Host "    3Y SP: $cost3YSPVal" -ForegroundColor Gray
    Write-Host "    1Y Res: $(if ($cost1YResVal) { $cost1YResVal } else { 'N/A' })" -ForegroundColor Gray
    Write-Host "    3Y Res: $(if ($cost3YResVal) { $cost3YResVal } else { 'N/A' })" -ForegroundColor Gray
    
    # Build options list (only include available options)
    $options = @(
        @{ Name = "byUsage"; Cost = $costByUsageVal }
    )
    # Build options list (only include available options)
    $options = @(
        @{ Name = "byUsage"; Cost = $costByUsageVal }
    )
    
    if ($null -ne $Cost1YSavingPlan) {
        $options += @{ Name = "1Y SavingPlan"; Cost = $cost1YSPVal }
    }
    
    if ($null -ne $Cost3YSavingPlan) {
        $options += @{ Name = "3Y SavingPlan"; Cost = $cost3YSPVal }
    }
    
    if ($null -ne $cost1YResVal) {
        $options += @{ Name = "1Y Reservation"; Cost = $cost1YResVal }
    }
    
    if ($null -ne $cost3YResVal) {
        $options += @{ Name = "3Y Reservation"; Cost = $cost3YResVal }
    }
    $cheapest = $options | Sort-Object Cost | Select-Object -First 1
    
    if ($costByUsageVal -eq 0) {
        return "byUsage (current)"
    }
    
    $savingAmount = $costByUsageVal - $cheapest.Cost
    $savingPercent = [math]::Round(($savingAmount / $costByUsageVal) * 100, 0)
    
    if ($cheapest.Name -eq "byUsage") {
        return "byUsage (current)"
    }
    else {
        return "$($cheapest.Name) (-$savingPercent%)"
    }
}

function Format-HoursPerDay {
    param($Hours)
    
    
    # Handle null or invalid input
    if ($null -eq $Hours -or $Hours -eq '') {
        return "00:00"
    }
    
    # Handle arrays
    if ($Hours -is [array]) {
        $Hours = $Hours[0]
    }
    
    # Try to convert to double
    try {
        $hoursValue = [double]$Hours
    }
    catch {
        Write-Warning "Invalid hours value: $Hours (Type: $($Hours.GetType().Name))"
        return "00:00"
    }
    
    # Handle edge cases
    if ($hoursValue -lt 0) { $hoursValue = 0 }
    if ($hoursValue -gt 24) { $hoursValue = 24 }
    
    $h = [math]::Floor($hoursValue)
    $m = [math]::Round(($hoursValue - $h) * 60)
    
    # Handle rounding edge case
    if ($m -eq 60) {
        $h += 1
        $m = 0
    }
    
    # Ensure integers
    $h = [int]$h
    $m = [int]$m
    
    return "{0:D2}:{1:D2}" -f $h, $m
}

function Format-Cost {
    param($Cost)
    
    if ($null -eq $Cost) {
        return "0.00"
    }
    
    # Handle arrays - take first element
    if ($Cost -is [array]) {
        $Cost = $Cost[0]
    }
    
    $costVal = [double]$Cost
    return "{0:N2}" -f $costVal
}

function Format-CostWithSaving {
    param($Cost, $BaseCost)
    
    if ($null -eq $Cost -or $null -eq $BaseCost) {
        return "0.00"
    }
    
    # Handle arrays
    if ($Cost -is [array]) { $Cost = $Cost[0] }
    if ($BaseCost -is [array]) { $BaseCost = $BaseCost[0] }
    
    $costVal = [double]$Cost
    $baseVal = [double]$BaseCost
    
    if ($baseVal -eq 0) { return "0.00" }
    
    $saving = [math]::Round((($baseVal - $costVal) / $baseVal) * 100, 0)
    return "{0:N2} (-{1}%)" -f $costVal, $saving
}


#endregion

# Main execution
$allVMResults = [System.Collections.ArrayList]::new()

try {
    $subscriptions = Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' }
    Write-Output "`nFound $($subscriptions.Count) enabled subscription(s)"
    
    if ($subscriptions.Count -eq 0) {
        Write-Warning "No enabled subscriptions found!"
        exit
    }
    
    foreach ($sub in $subscriptions) {
        Write-Output "`n==================================="
        Write-Output "Processing Subscription: $($sub.Name)"
        Write-Output "Subscription ID: $($sub.Id)"
        Write-Output "==================================="
        
        $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop
        
        $vms = Get-AzVM -Status -ErrorAction Stop
        Write-Output "Found $($vms.Count) VMs in subscription"
        
        if ($vms.Count -eq 0) {
            Write-Output "No VMs found in this subscription, skipping..."
            continue
        }
        
        $vmCounter = 0
        foreach ($vm in $vms) {
            $vmCounter++
            $percentComplete = [math]::Round(($vmCounter / $vms.Count) * 100, 0) 
            Write-Progress -Activity "Analyzing VMs in $($sub.Name)" -Status "VM: $($vm.Name)" -PercentComplete $percentComplete 
            
            Write-Output "`n  [$vmCounter/$($vms.Count)] Analyzing VM: $($vm.Name)"
            Write-Output "  Resource Group: $($vm.ResourceGroupName)"
            Write-Output "  Size: $($vm.HardwareProfile.VmSize)"
            Write-Output "  Location: $($vm.Location)"
            Write-Output "  Power State: $($vm.PowerState)"
            
            try {
                # Get current usage from Activity Logs
                $usageData = Get-CurrentUsage -VM $vm -SubscriptionId $sub.Id
                
                # Get pricing information
                $pricingData = Get-VMPricingData -VMSize $vm.HardwareProfile.VmSize -Location $vm.Location -VM $vm
                
                # Calculate costs
                Write-Output "    Calculating costs..."
                $cost247 = Get-247Cost -PricingData $pricingData
                $costByUsage = Get-CostByUsage -PricingData $pricingData -AvgDailyHours $usageData.AvgDailyHours
                $cost1YSavingPlan = Get-1YSavingPlanCost -PricingData $pricingData
                $cost3YSavingPlan = Get-3YSavingPlanCost -PricingData $pricingData
                $cost1YReservation = Get-1YReservationCost -VM $vm -PricingData $pricingData -Location $vm.Location -SubscriptionId $sub.Id
                $cost3YReservation = Get-3YReservationCost -VM $vm -PricingData $pricingData -Location $vm.Location -SubscriptionId $sub.Id
                
                Write-Output "    Getting sizing recommendation..."
                $sizingRec = Get-SizingRecommendation -VM $vm

                Write-Output "    Determining cost saving recommendation..."
                $costSavingRec = Get-CostSavingRecommendation -Cost247 $cost247 -CostByUsage $costByUsage `
                    -Cost1YSavingPlan $cost1YSavingPlan -Cost3YSavingPlan $cost3YSavingPlan `
                    -Cost1YReservation $cost1YReservation -Cost3YReservation $cost3YReservation
                
                

                # Build result object
                $result = [PSCustomObject]@{
                    VMName           = $vm.Name
                    Subscription     = $sub.Name
                    ResourceGroup    = $vm.ResourceGroupName
                    Location         = $vm.Location
                    VMSize           = $vm.HardwareProfile.VmSize
                    PowerState       = $vm.PowerState
                    'Usage (h/d)'    = Format-HoursPerDay -Hours $usageData.AvgDailyHours
                    'Cost 24/7'      = Format-Cost -Cost $cost247
                    'Cost Actual'    = Format-Cost -Cost $costByUsage
                    '1Y SP'          = Format-Cost -Cost $cost1YSavingPlan
                    '3Y SP'          = Format-Cost -Cost $cost3YSavingPlan
                    '1Y Res'         = if ($null -ne $cost1YReservation) { Format-Cost -Cost $cost1YReservation } else { "N/A" }
                    '3Y Res'         = if ($null -ne $cost3YReservation) { Format-Cost -Cost $cost3YReservation } else { "N/A" }
                    'Sizing'         = $sizingRec
                    'Recommendation' = $costSavingRec
                    'Currency'       = $pricingData.Currency
                }
                
                $null = $allVMResults.Add($result)
                Write-Output "    ✓ VM analysis completed successfully"
                
            }
            catch {
                Write-Warning "  ✗ Error analyzing VM $($vm.Name): $_"
                Write-Warning "  Stack trace: $($_.ScriptStackTrace)"
            }
        }
    }
    Write-Progress -Activity "Analyzing VMs" -Completed
    Write-Output "`n==================================="
    Write-Output "Analysis Complete"
    Write-Output "==================================="
    Write-Output "Total VMs analyzed: $($allVMResults.Count)"
    
    if ($allVMResults.Count -gt 0) {
        Write-Output "`n==================================="
        Write-Output "RESULTS TABLE"
        Write-Output "==================================="
        
        #$allVMResults | Format-Table -AutoSize -Wrap | Out-String | Write-Output
        $allVMResults | Format-Table -Property VMName, Subscription, VMSize, 'Usage (h/d)', 'Cost Actual', '1Y SP', '3Y SP', '1Y Res', '3Y Res', 'Sizing', 'Recommendation', 'Currency' -AutoSize | Out-String | Write-Output

        # Summary statistics
        Write-Output "`n==================================="
        Write-Output "SUMMARY STATISTICS"
        Write-Output "==================================="
        
        [double]$totalCurrent = 0.0
        foreach ($result in $allVMResults) {
            $totalCurrent += [double](($result.'Cost 24/7') -replace '\.', '' -replace ',', '.')
        }
        
        Write-Output "Total Monthly Cost (24/7): $([math]::Round([double]$totalCurrent, 2))"

        $totalActual = 0
        $totalPotentialSavings = 0

        foreach ($result in $allVMResults) {
            $actualCost = [double](($result.'Cost Actual') -replace '\.', '' -replace ',', '.')
            $totalActual += $actualCost
            
            # Extract potential savings from recommendation
            if ($result.'Recommendation' -match '\((-\d+)%\)') {
                $savingsPercent = [int]$matches[1].Replace('-', '')
                $potentialSavings = $actualCost * ($savingsPercent / 100)
                $totalPotentialSavings += $potentialSavings
            }
        }

        Write-Output "Total Actual Monthly Cost (Current Usage): $([math]::Round($totalActual, 2))"
        Write-Output "Total Potential Monthly Savings: $([math]::Round($totalPotentialSavings, 2)) ($([math]::Round(($totalPotentialSavings / $totalActual) * 100, 1))%)"
        
        # Recommendation breakdown
        $recBreakdown = $allVMResults | Group-Object 'Recommendation'
        Write-Output "`nCost Saving Recommendations:"
        foreach ($rec in $recBreakdown) {
            Write-Output "  $($rec.Name): $($rec.Count) VMs"
        }
        
        # Sizing breakdown
        $sizingBreakdown = $allVMResults | Group-Object 'Sizing'
        Write-Output "`nSizing Recommendations:"
        foreach ($size in $sizingBreakdown) {
            Write-Output "  $($size.Name): $($size.Count) VMs"
        }
        
        # Export results
        $exportPath = "VM-Cost-Analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $allVMResults | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
        Write-Output "`n✓ Results exported to: $exportPath"

        # Nach CSV Export:
        $htmlReport = $allVMResults | ConvertTo-Html -Title "Azure VM Cost Analysis" -PreContent "<h1>Azure VM Cost Analysis Report</h1><p>Generated: $(Get-Date)</p>" -PostContent "<p>Total VMs: $($allVMResults.Count)</p>"
        $htmlPath = "VM-Cost-Analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        $htmlReport | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Output "✓ HTML report exported to: $htmlPath"
        
    }
    else {
        Write-Warning "No VMs were successfully analyzed!"
    }
    
}
catch {
    Write-Error "Critical error in main execution: $_"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    throw
}

Write-Output "`nScript completed at: $(Get-Date)"