<#
.SYNOPSIS
    Sends a single log entry to Log Analytics Workspace
    
.DESCRIPTION
    This function sends individual log entries to an Azure Log Analytics Workspace
    using the HTTP Data Collector API. Each call creates a new authentication
    signature (required by the API) and sends the log entry immediately.
    
.PARAMETER CustomerId
    The Workspace ID of your Log Analytics Workspace
    
.PARAMETER SharedKey
    The Primary or Secondary Key of your Workspace
    
.PARAMETER LogEntry
    The log entry as a Hashtable or PSCustomObject
    
.PARAMETER LogType
    Name of the Custom Log table (will appear as LogType_CL in Log Analytics)
    
.PARAMETER TimeStampField
    Optional: Name of the field containing the timestamp (default: TimeGenerated)
    
.EXAMPLE
    $log = @{
        Level = "Information"
        Message = "Application started"
    }
    
    Send-LogAnalyticsEntry -CustomerId "abc-123" `
                           -SharedKey "your-key" `
                           -LogEntry $log `
                           -LogType "MyApp"

.AUTHOR
    Simon Vedder

.VERSION
    1.0

.CHANGELOG
    1.0 - Initial release

.LASTUPDATE
    2025-10-07

#>
function Send-LogAnalyticsEntry {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CustomerId,
        
        [Parameter(Mandatory=$true)]
        [string]$SharedKey,
        
        [Parameter(Mandatory=$true)]
        [object]$LogEntry,
        
        [Parameter(Mandatory=$true)]
        [string]$LogType,
        
        [string]$TimeStampField = ""
    )
    
    try {
        # Convert log entry to JSON
        $json = @($LogEntry) | ConvertTo-Json -Compress
        $body = [System.Text.Encoding]::UTF8.GetBytes($json)
        
        # Prepare API call
        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        $contentLength = $body.Length
        
        # Build authentication signature
        $xHeaders = "x-ms-date:" + $rfc1123date
        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($SharedKey)
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $encodedHash = [Convert]::ToBase64String($calculatedHash)
        $signature = "SharedKey ${CustomerId}:${encodedHash}"
        
        # Build request
        $uri = "https://${CustomerId}.ods.opinsights.azure.com${resource}?api-version=2016-04-01"
        $headers = @{
            "Authorization" = $signature
            "Log-Type" = $LogType
            "x-ms-date" = $rfc1123date
            "time-generated-field" = $TimeStampField
        }
        
        # Send log entry
        $response = Invoke-WebRequest -Uri $uri `
                                      -Method $method `
                                      -ContentType $contentType `
                                      -Headers $headers `
                                      -Body $body `
                                      -UseBasicParsing
        
        if ($response.StatusCode -eq 200) {
            Write-Verbose "Log entry sent successfully"
            return $true
        }
        else {
            Write-Warning "Unexpected status code: $($response.StatusCode)"
            return $false
        }
    }
    catch {
        Write-Error "Error sending log entry: $_"
        return $false
    }
}

# ============================================================================
# EXAMPLE USAGE
# ============================================================================


# Configuration
$workspaceId = "your-workspace-id"
$workspaceKey = "your-primary-key"

# Create and send a log entry
$logEntry = @{
    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    Level = "Information"
    Message = "Application started successfully"
}

Send-LogAnalyticsEntry -CustomerId $workspaceId `
                       -SharedKey $workspaceKey `
                       -LogEntry $logEntry `
                       -LogType "MyApplicationLogs"
#>