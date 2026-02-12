<#
.SYNOPSIS
Retrieves all active and PIM eligible Entra ID (Azure AD) role assignments.

.DESCRIPTION
This function retrieves all directory roles and both active and PIM eligible role assignments from Entra ID (Azure AD),
resolves the principals (users, groups, service principals), and outputs a detailed report including:

- Role information (name, description)
- Assignment type (Active / Eligible)
- Principal details (name, UPN, type)
- Directory scope
- Optional CSV export
- Optional console-friendly output
- App-only or delegated authentication support

.PARAMETER ExportPath
Optional. Path to export the report as a CSV file.

.PARAMETER ConsoleOutput
Optional switch. If specified, prints the report to the console.

.PARAMETER AppOnly
Optional switch. Uses app-only authentication instead of delegated user login.

.PARAMETER TenantId
Required if AppOnly is used. The tenant ID for app-only authentication.

.PARAMETER ClientId
Required if AppOnly is used. The client/application ID.

.PARAMETER CertificateThumbprint
Required if AppOnly is used. Certificate thumbprint for authentication.

.EXAMPLE
Get-EntraRoleAssignmentReport -ConsoleOutput

.Example
Get-EntraRoleAssignmentReport -ExportPath "C:\Reports\EntraRoles.csv"

.EXAMPLE
Get-EntraRoleAssignmentReport -AppOnly -TenantId "xxxx" -ClientId "xxxx" -CertificateThumbprint "xxxx" -ExportPath "C:\Reports\EntraRoles.csv"

.OUTPUTS
System.Collections.Generic.List[PSCustomObject] — Detailed report of all role assignments including PIM eligibility.

.NOTES
Author: Warren Roberts
Date: 2026-02-12
Environment: PowerShell 7.x or 5.1, requires Microsoft.Graph module.
#>


function Get-EntraRoleAssignmentReport {

[CmdletBinding()]
param(
    [string]$ExportPath,
    [switch]$ConsoleOutput,
    [switch]$AppOnly,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

# ----------------------------
# Connect to Graph
# ----------------------------

if (-not (Get-MgContext)) {

    if ($AppOnly) {

        if (-not ($TenantId -and $ClientId -and $CertificateThumbprint)) {
            throw "AppOnly authentication requires TenantId, ClientId and CertificateThumbprint."
        }

        Connect-MgGraph -TenantId $TenantId `
                        -ClientId $ClientId `
                        -CertificateThumbprint $CertificateThumbprint
    }
    else {
        Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Directory.Read.All"
    }
}

Write-Verbose "Connected to tenant $((Get-MgContext).TenantId)"

# ----------------------------
# Retrieve Roles
# ----------------------------

try {
    $roles = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
}
catch {
    throw "Failed retrieving role definitions: $_"
}

$rolesHt = @{}
foreach ($role in $roles) {
    $rolesHt[$role.Id] = [PSCustomObject]@{
        DisplayName = $role.DisplayName
        Description = $role.Description
    }
}

# ----------------------------
# Retrieve Active + Eligible
# ----------------------------

try {
    $activeAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop
    $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
}
catch {
    throw "Failed retrieving role assignments: $_"
}

# ----------------------------
# Collect Unique Principals
# ----------------------------

$principalIds = @(
    $activeAssignments.PrincipalId
    $eligibleAssignments.PrincipalId
) | Select-Object -Unique

# ----------------------------
# Resolve Principals (Bulk)
# ----------------------------

$usersHt = @{}
$counter = 0

foreach ($id in $principalIds) {

    $counter++
    Write-Progress -Activity "Resolving principals" `
                   -Status "$counter of $($principalIds.Count)" `
                   -PercentComplete (($counter / $principalIds.Count) * 100)

    $resolved = $false

    for ($attempt=1; $attempt -le 3; $attempt++) {
        try {
            $principal = Get-MgDirectoryObject -DirectoryObjectId $id -ErrorAction Stop

            $usersHt[$id] = [PSCustomObject]@{
                DisplayName       = $principal.AdditionalProperties.displayName
                UserPrincipalName = $principal.AdditionalProperties.userPrincipalName
                PrincipalType     = ($principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.','')
            }

            $resolved = $true
            break
        }
        catch {
            Start-Sleep -Seconds (2 * $attempt)
        }
    }

    if (-not $resolved) {
        $usersHt[$id] = [PSCustomObject]@{
            DisplayName       = $id
            UserPrincipalName = "Unresolved"
            PrincipalType     = "Unknown"
        }
    }
}

# ----------------------------
# Build Report
# ----------------------------

$totalAssignments = $activeAssignments.Count + $eligibleAssignments.Count
$report = [System.Collections.Generic.List[object]]::new($totalAssignments)

# Active
foreach ($assignment in $activeAssignments) {

    $roleMeta = $rolesHt[$assignment.RoleDefinitionId]

    $report.Add([PSCustomObject]@{
        RoleId          = $assignment.RoleDefinitionId
        RoleName        = $roleMeta.DisplayName
        RoleDescription = $roleMeta.Description
        AssignmentType  = "Active"
        Scope           = $assignment.DirectoryScopeId
        PrincipalId     = $assignment.PrincipalId
        PrincipalName   = $usersHt[$assignment.PrincipalId].DisplayName
        PrincipalUPN    = $usersHt[$assignment.PrincipalId].UserPrincipalName
        PrincipalType   = $usersHt[$assignment.PrincipalId].PrincipalType
    })
}

# Eligible (PIM)
foreach ($assignment in $eligibleAssignments) {

    $roleMeta = $rolesHt[$assignment.RoleDefinitionId]

    $report.Add([PSCustomObject]@{
        RoleId          = $assignment.RoleDefinitionId
        RoleName        = $roleMeta.DisplayName
        RoleDescription = $roleMeta.Description
        AssignmentType  = "Eligible (PIM)"
        Scope           = $assignment.DirectoryScopeId
        PrincipalId     = $assignment.PrincipalId
        PrincipalName   = $usersHt[$assignment.PrincipalId].DisplayName
        PrincipalUPN    = $usersHt[$assignment.PrincipalId].UserPrincipalName
        PrincipalType   = $usersHt[$assignment.PrincipalId].PrincipalType
    })
}

# ----------------------------
# Console Output (Optional)
# ----------------------------

if ($ConsoleOutput) {

    $grouped = $report | Group-Object RoleId

    foreach ($group in $grouped) {

        $roleMeta = $rolesHt[$group.Name]

        Write-Host "`nRole Name: $($roleMeta.DisplayName)" -ForegroundColor Yellow
        Write-Host "Description: $($roleMeta.Description)"
        Write-Host "Assignments:" -ForegroundColor Green

        foreach ($entry in $group.Group) {
            Write-Host " - $($entry.PrincipalName) ($($entry.PrincipalUPN)) [$($entry.AssignmentType)] <$($entry.PrincipalType)>"
        }
    }
}

# ----------------------------
# Export (Optional)
# ----------------------------

if ($ExportPath) {
    $report | Export-Csv $ExportPath -NoTypeInformation -Encoding UTF8
}

Disconnect-MgGraph

return $report

}
