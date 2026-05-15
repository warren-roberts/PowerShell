Import-Module Microsoft.Graph.Identity.DirectoryManagement

# --- Configuration ---
$RequiredScopes = @("Directory.Read.All")

# --- Logic ---
Write-Host "Checking Microsoft Graph Connection..." -ForegroundColor Cyan

try {
    # Check if already connected to avoid redundant login prompts
    $CurrentContext = Get-MgContext
    if (-not $CurrentContext) {
        Connect-MgGraph -Scopes $RequiredScopes -ContextScope Process
    }
} catch {
    Write-Error "Failed to connect to Microsoft Graph. Check permissions or network."
    exit
}

Write-Host "Successfully connected as: $($CurrentContext.Account)" -ForegroundColor Green

# 1. Get all active licenses
Write-Host "`nRetrieving active license subscriptions..." -ForegroundColor Yellow

try {
    # Using -All to ensure we don't hit pagination limits in larger tenants
    $Subscriptions = Get-MgDirectorySubscription -All
    
    if ($Subscriptions) {
        $Results = $Subscriptions | Select-Object @{
            Name = 'SkuName'
            Expression = { $_.SkuPartNumber }
        }, 
        @{Name = 'Total'; Expression = { $_.TotalLicenses }},
        Status,
        NextLifecycleDateTime

        $Results | Format-Table -AutoSize
    }
    else {
        Write-Warning "No subscriptions found in this tenant."
    }
} catch {
    Write-Error "Error retrieving subscriptions: $($_.Exception.Message)"
} finally {
    # Optional: Only disconnect if you want to force a fresh login next time
    # Disconnect-MgGraph 
    Write-Host "`nOperation complete." -ForegroundColor Gray
}