<#
.SYNOPSIS
  Get SACL (audit) entries for the domain root, OUs, and optionally containers.

.DESCRIPTION
  Enumerates domainDNS and organizationalUnit objects (and containers if specified),
  reads their SACL audit ACEs, resolves schema GUIDs to human-readable names,
  and outputs results to the pipeline or optionally to a CSV file.

.PARAMETER SearchBase
  Distinguished Name to start searching from.
  Defaults to the current domain naming context.

.PARAMETER IncludeInherited
  Include inherited audit ACEs.
  By default, only explicit (non-inherited) ACEs are returned.

.PARAMETER IncludeContainer
  Include objectClass=container objects in addition to OUs and domain root.

.PARAMETER OutFile
  If specified, results are written incrementally to a CSV file.
  This is recommended for very large domains to reduce memory usage.

.EXAMPLE
  # Output explicit SACL entries to screen
  .\Get-DomainSACL.ps1

.EXAMPLE
  # Output and write to CSV
  .\Get-DomainSACL.ps1 -OutFile "C:\Reports\DomainSACL.csv"

.EXAMPLE
  # Include inherited ACEs and write to CSV
  .\Get-DomainSACL.ps1 -IncludeInherited -OutFile "C:\Reports\DomainSACL.csv"

.EXAMPLE
  # Start from a specific OU and include containers
  .\Get-DomainSACL.ps1 `
      -SearchBase "OU=Servers,DC=contoso,DC=com" `
      -IncludeContainer `
      -OutFile "C:\Reports\ServerOUSACL.csv"

.NOTES
  Requires:
    - RSAT Active Directory module
    - Rights to read SACLs ("Read audit information")

  PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeInherited,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeContainer,

    [Parameter(Mandatory = $false)]
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ensure the ActiveDirectory module is available (needed for AD: drive)
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT: Active Directory tools."
    exit 1
}
Import-Module ActiveDirectory

# RootDSE once
$rootDse = [ADSI]"LDAP://RootDSE"

# Default SearchBase to domain naming context
$domainDN = [string]$rootDse.defaultNamingContext
if ([string]::IsNullOrWhiteSpace($SearchBase)) {
    $SearchBase = $domainDN
}

#
# Build GUID -> friendly name map (schema + extended rights)
#
$GuidMap = @{}

# Map the empty GUID (NULL GUID) correctly
$GuidMap[[guid]::Empty] = "all object types or all properties"

# Schema classes/attributes (schemaIDGUID)
$schemaNC = [string]$rootDse.schemaNamingContext
$schemaSearcher = New-Object System.DirectoryServices.DirectorySearcher
$schemaSearcher.SearchRoot = [ADSI]"LDAP://$schemaNC"
$schemaSearcher.Filter = "(schemaIDGUID=*)"
$schemaSearcher.PageSize = 1000
$schemaSearcher.CacheResults = $false
$schemaSearcher.ServerTimeLimit = New-TimeSpan -Seconds 30
[void]$schemaSearcher.PropertiesToLoad.Add("lDAPDisplayName")
[void]$schemaSearcher.PropertiesToLoad.Add("schemaIDGUID")

foreach ($result in $schemaSearcher.FindAll()) {
    $name = $result.Properties["lDAPDisplayName"][0]
    $guidBytes = $result.Properties["schemaIDGUID"][0]
    if ($name -and $guidBytes) {
        $guid = New-Object Guid (,$guidBytes)
        $GuidMap[$guid] = [string]$name
    }
}

# Extended rights (controlAccessRight / rightsGuid)
$configNC = [string]$rootDse.configurationNamingContext
$rightsSearcher = New-Object System.DirectoryServices.DirectorySearcher
$rightsSearcher.SearchRoot = [ADSI]"LDAP://CN=Extended-Rights,$configNC"
$rightsSearcher.Filter = "(objectClass=controlAccessRight)"
$rightsSearcher.PageSize = 1000
$rightsSearcher.CacheResults = $false
$rightsSearcher.ServerTimeLimit = New-TimeSpan -Seconds 30
[void]$rightsSearcher.PropertiesToLoad.Add("name")
[void]$rightsSearcher.PropertiesToLoad.Add("rightsGuid")

foreach ($result in $rightsSearcher.FindAll()) {
    $name = $result.Properties["name"][0]
    $guid = $result.Properties["rightsGuid"][0]
    if ($name -and $guid) {
        $GuidMap[[guid]$guid] = [string]$name
    }
}

Write-Verbose "Schema/rights definitions loaded: $($GuidMap.Count) GUIDs"

function Resolve-GuidName {
    param(
        [Parameter(Mandatory = $true)]
        [guid]$GuidValue,
        [hashtable]$Map
    )
    if ($Map.ContainsKey($GuidValue)) { return $Map[$GuidValue] }
    return $GuidValue.Guid
}

# Optional: skip very noisy subtrees (DN prefix checks are cheap)
# Adjust to taste or remove if you truly want everything under SearchBase.
if ($IncludeContainer){
    $skipPrefixes = @(
        "CN=MicrosoftDNS,",   # can be huge
        "CN=System,"          # busy/system-managed
    )
}

# Prepare CSV streaming if requested
if ($OutFile) {
    # Ensure directory exists if needed
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

    if (Test-Path $OutFile) { Remove-Item -Force $OutFile }

    $csvHeaderWritten = $false
}

#
# Enumerate target objects efficiently using DirectorySearcher (faster than Get-ADObject at scale)
#

# Build ordered LDAP filters
$filters = @()

# Domain root FIRST
$filters += "(objectClass=domainDNS)"

# Then OUs
$filters += "(objectClass=organizationalUnit)"

# Then containers if requested
if ($IncludeContainer) {
    $filters += "(objectClass=container)"
}


foreach ($classFilter in $filters) {

    $enumSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $enumSearcher.SearchRoot = [ADSI]"LDAP://$SearchBase"
    $enumSearcher.Filter = $classFilter
    $enumSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $enumSearcher.PageSize = 1000
    $enumSearcher.CacheResults = $false
    $enumSearcher.ServerTimeLimit = New-TimeSpan -Seconds 30

    [void]$enumSearcher.PropertiesToLoad.Add("distinguishedName")
    [void]$enumSearcher.PropertiesToLoad.Add("objectClass")

    # Enumerate and process
    foreach ($r in $enumSearcher.FindAll()) {

        $dn = [string]$r.Properties["distinguishedname"][0]
        if ([string]::IsNullOrWhiteSpace($dn)) { continue }

        # DN prefix skip (cheap) before Get-Acl (expensive)
        if ($IncludeContainer)
        {
            $shouldSkip = $false
            foreach ($p in $skipPrefixes) {
                if ($dn.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $shouldSkip = $true
                    break
                }
            }
            if ($shouldSkip) { continue }
        }

        # objectClass is multivalued; last element is typically the most specific
        $objectClass = $null
        if ($r.Properties["objectclass"] -and $r.Properties["objectclass"].Count -gt 0) {
            $objectClass = [string]$r.Properties["objectclass"][$r.Properties["objectclass"].Count - 1]
        }

        try {
            $acl = Get-Acl "AD:$dn" -Audit
        }
        catch {
            Write-Warning "Failed to read SACL for $dn : $($_.Exception.Message)"
            continue
        }

        foreach ($sace in $acl.Audit) {

            if (-not $IncludeInherited -and $sace.IsInherited) { continue }

            # These are GUIDs
            $ot  = [guid]$sace.ObjectType
            $iot = [guid]$sace.InheritedObjectType

            $row = [PSCustomObject]@{
                DN                      = $dn
                ObjectClass             = $objectClass
                IdentityReference       = $sace.IdentityReference.Value
                ActiveDirectoryRights   = $sace.ActiveDirectoryRights
                AuditFlags              = $sace.AuditFlags
                ObjectType              = $ot
                ObjectTypeName          = Resolve-GuidName -GuidValue $ot  -Map $GuidMap
                InheritedObjectType     = $iot
                InheritedObjectTypeName = Resolve-GuidName -GuidValue $iot -Map $GuidMap
                InheritanceType         = $sace.InheritanceType
                InheritanceFlags        = $sace.InheritanceFlags
                PropagationFlags        = $sace.PropagationFlags
                IsInherited             = $sace.IsInherited
            }

            if ($OutFile) {
                if (-not $csvHeaderWritten) {
                    $row | Export-Csv -Path $OutFile -NoTypeInformation
                    $csvHeaderWritten = $true
                } else {
                    $row | Export-Csv -Path $OutFile -NoTypeInformation -Append
                }
            }
            else {
                # Stream to pipeline (no big in-memory array)
                $row
            }
        }
    }
}

if ($OutFile) {
    Write-Host "Wrote results to $OutFile"
}