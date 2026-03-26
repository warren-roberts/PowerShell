<#
.SYNOPSIS
Tests baseline SACL (audit) configuration on critical Active Directory objects.

.DESCRIPTION
This script evaluates whether expected System Access Control List (SACL) audit
entries are present on high-value Active Directory objects, including:

- Domain root
- Configuration partition
- Schema partition
- AdminSDHolder
- Domain Controllers OU
- Group Policy Objects container

The script does NOT modify any permissions. It performs a read-only assessment
and reports whether required audit rules are present or missing.

This is intended to validate auditing coverage for detection of:
- Privilege escalation
- ACL backdoors
- GPO abuse
- Domain controller compromise
- Persistence mechanisms (e.g., AdminSDHolder)

.PARAMETER PassThru
Returns full result objects for further processing (e.g., export to CSV or SIEM ingestion).

.OUTPUTS
PSCustomObject with the following properties:
- TargetName
- DistinguishedName
- Principal
- ExpectedInheritance
- AuditRulePresent
- MissingConfiguration
- ExpectedRights
- ExpectedAuditFlags
- ObjectType
- InheritedObjectType
- Error

.EXAMPLE
.\Test-AdSaclBaseline.ps1

Runs the assessment and displays a summary of missing audit rules.

.EXAMPLE
.\Test-AdSaclBaseline.ps1 -PassThru | Export-Csv .\AdSaclReport.csv -NoTypeInformation

Runs the assessment and exports detailed results to a CSV file.

.NOTES
- Requires ActiveDirectory PowerShell module (RSAT)
- Must be run with sufficient privileges to read AD security descriptors
- Does NOT enable audit policy (Audit Directory Service Access / Changes must be configured separately)
- Designed for read-only auditing validation, not enforcement

.LINK
https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-directory-service-changes
#>

[CmdletBinding()]
param(
    [switch]$PassThru
)

Import-Module ActiveDirectory -ErrorAction Stop

function Get-RootDseValues {
    $root = Get-ADRootDSE
    [pscustomobject]@{
        DefaultNamingContext       = $root.defaultNamingContext
        ConfigurationNamingContext = $root.configurationNamingContext
        SchemaNamingContext        = $root.schemaNamingContext
        RootDse                    = $root
    }
}

function New-TargetDefinition {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$PrincipalName,

        [Parameter(Mandatory)]
        [string]$DN,

        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AuditFlags]$AuditFlags,

        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectoryRights]$Rights,

        [guid]$ObjectType = [Guid]::Empty,

        [guid]$InheritedObjectType = [Guid]::Empty
    )

    [pscustomobject]@{
        Name                = $Name
        PrincipalName       = $PrincipalName
        DN                  = $DN
        InheritanceType     = $InheritanceType
        AuditFlags          = $AuditFlags
        Rights              = $Rights
        ObjectType          = $ObjectType
        InheritedObjectType = $InheritedObjectType
    }
}

function New-SaclExpectedRule {
    param(
        [Parameter(Mandatory)]
        [string]$PrincipalName,

        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType,

        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectoryRights]$Rights,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AuditFlags]$AuditFlags,

        [guid]$ObjectType = [Guid]::Empty,

        [guid]$InheritedObjectType = [Guid]::Empty
    )

    [pscustomobject]@{
        IdentityReference   = New-Object System.Security.Principal.NTAccount($PrincipalName)
        ActiveDirectoryRights = $Rights
        AuditFlags          = $AuditFlags
        InheritanceType     = $InheritanceType
        ObjectType          = $ObjectType
        InheritedObjectType = $InheritedObjectType
    }
}

function Get-AdSaclDescriptor {
    param(
        [Parameter(Mandatory)]
        [string]$DN
    )

    Get-Acl -Path ("AD:{0}" -f $DN) -Audit
}

function Test-AuditRulePresent {
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectorySecurity]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [pscustomobject]$ExpectedRule
    )

    $rules = $SecurityDescriptor.GetAuditRules($true, $true, [System.Security.Principal.NTAccount])

    foreach ($existing in $rules) {
        if (
            $existing.IdentityReference.Value -eq $ExpectedRule.IdentityReference.Value -and
            $existing.ActiveDirectoryRights -eq $ExpectedRule.ActiveDirectoryRights -and
            $existing.AuditFlags -eq $ExpectedRule.AuditFlags -and
            $existing.InheritanceType -eq $ExpectedRule.InheritanceType -and
            $existing.ObjectType -eq $ExpectedRule.ObjectType -and
            $existing.InheritedObjectType -eq $ExpectedRule.InheritedObjectType
        ) {
            return $true
        }
    }

    return $false
}

function Test-BaselineTarget {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target
    )

    if ([string]::IsNullOrWhiteSpace($Target.DN)) {
        return [pscustomobject]@{
            TargetName           = $Target.Name
            DistinguishedName    = $null
            Principal            = $Target.PrincipalName
            ExpectedInheritance  = $Target.InheritanceType
            AuditRulePresent     = $false
            MissingConfiguration = $null
            ExpectedRights       = $null
            ExpectedAuditFlags   = $null
            ObjectType           = $Target.ObjectType
            InheritedObjectType  = $Target.InheritedObjectType
            Error                = 'Target DN is empty.'
        }
    }

    $expectedRule = New-SaclExpectedRule `
        -PrincipalName $Target.PrincipalName `
        -InheritanceType $Target.InheritanceType `
        -Rights $Target.Rights `
        -AuditFlags $Target.AuditFlags `
        -ObjectType $Target.ObjectType `
        -InheritedObjectType $Target.InheritedObjectType

    try {
        $sd = Get-AdSaclDescriptor -DN $Target.DN
        $present = Test-AuditRulePresent -SecurityDescriptor $sd -ExpectedRule $expectedRule

        [pscustomobject]@{
            TargetName           = $Target.Name
            DistinguishedName    = $Target.DN
            Principal            = $Target.PrincipalName
            ExpectedInheritance  = $Target.InheritanceType
            AuditRulePresent     = $present
            MissingConfiguration = if ($present) { $null } else { 'Missing expected audit ACE' }
            ExpectedRights       = $expectedRule.ActiveDirectoryRights.ToString()
            ExpectedAuditFlags   = $expectedRule.AuditFlags.ToString()
            ObjectType           = $expectedRule.ObjectType
            InheritedObjectType  = $expectedRule.InheritedObjectType
            Error                = $null
        }
    }
    catch {
        [pscustomobject]@{
            TargetName           = $Target.Name
            DistinguishedName    = $Target.DN
            Principal            = $Target.PrincipalName
            ExpectedInheritance  = $Target.InheritanceType
            AuditRulePresent     = $false
            MissingConfiguration = $null
            ExpectedRights       = $expectedRule.ActiveDirectoryRights.ToString()
            ExpectedAuditFlags   = $expectedRule.AuditFlags.ToString()
            ObjectType           = $expectedRule.ObjectType
            InheritedObjectType  = $expectedRule.InheritedObjectType
            Error                = $_.Exception.Message
        }
    }
}

$ctx = Get-RootDseValues

$successAndFailure = `
    [System.Security.AccessControl.AuditFlags]::Success -bor `
    [System.Security.AccessControl.AuditFlags]::Failure

$successOnly = [System.Security.AccessControl.AuditFlags]::Success

$domainRootRights = `
    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::Self -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

$configRights = `
    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

$schemaRights = $configRights

$adminSdHolderRights = `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

$dcOuRights = `
    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor `
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

$gpoRights = $dcOuRights

# user class schemaIDGUID
$userClassGuid = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'

$targets = @(
    New-TargetDefinition `
        -Name 'Domain root' `
        -PrincipalName 'Everyone' `
        -DN $ctx.DefaultNamingContext `
        -InheritanceType ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::All) `
        -AuditFlags $successAndFailure `
        -Rights $domainRootRights

    New-TargetDefinition `
        -Name 'Configuration partition' `
        -PrincipalName 'Everyone' `
        -DN $ctx.ConfigurationNamingContext `
        -InheritanceType ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::All) `
        -AuditFlags $successAndFailure `
        -Rights $configRights

    New-TargetDefinition `
        -Name 'Schema partition' `
        -PrincipalName 'Everyone' `
        -DN $ctx.SchemaNamingContext `
        -InheritanceType ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) `
        -AuditFlags $successAndFailure `
        -Rights $schemaRights

    New-TargetDefinition `
        -Name 'AdminSDHolder' `
        -PrincipalName 'Everyone' `
        -DN "CN=AdminSDHolder,CN=System,$($ctx.DefaultNamingContext)" `
        -InheritanceType ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) `
        -AuditFlags $successAndFailure `
        -Rights $adminSdHolderRights

    New-TargetDefinition `
        -Name 'Domain Controllers OU' `
        -PrincipalName 'NT AUTHORITY\Authenticated Users' `
        -DN "OU=Domain Controllers,$($ctx.DefaultNamingContext)" `
        -InheritanceType ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents) `
        -AuditFlags $successOnly `
        -Rights $dcOuRights

    New-TargetDefinition `
        -Name 'GPO container' `
        -PrincipalName 'NT AUTHORITY\Authenticated Users' `
        -DN "CN=Policies,CN=System,$($ctx.DefaultNamingContext)" `
        -InheritanceType ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents) `
        -AuditFlags $successOnly `
        -Rights $gpoRights

    # Example of a user-descendant scoped rule. Change DN to the container you actually want.
    New-TargetDefinition `
        -Name 'MDI User objects' `
        -PrincipalName 'Everyone' `
        -DN $ctx.DefaultNamingContext `
        -InheritanceType ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents) `
        -AuditFlags $successAndFailure `
        -Rights $domainRootRights `
        -InheritedObjectType $userClassGuid
)

$results = foreach ($target in $targets) {
    Test-BaselineTarget -Target $target
}

$missing = $results | Where-Object { -not $_.AuditRulePresent -and -not $_.Error }
$errors  = $results | Where-Object { $_.Error }
$present = $results | Where-Object { $_.AuditRulePresent }

Write-Host ''
Write-Host 'Summary' -ForegroundColor Cyan
Write-Host '-------' -ForegroundColor Cyan
Write-Host ("Total targets checked : {0}" -f $results.Count)
Write-Host ("Present               : {0}" -f $present.Count)
Write-Host ("Missing               : {0}" -f $missing.Count)
Write-Host ("Errors                : {0}" -f $errors.Count)
Write-Host ''

if ($missing) {
    Write-Host 'Missing expected audit ACE' -ForegroundColor Yellow
    Write-Host '--------------------------' -ForegroundColor Yellow
    $missing |
        Select-Object TargetName, DistinguishedName, Principal, ExpectedInheritance, ExpectedRights, ExpectedAuditFlags, ObjectType, InheritedObjectType |
        Format-Table -AutoSize
    Write-Host ''
}

if ($errors) {
    Write-Host 'Errors' -ForegroundColor Red
    Write-Host '------' -ForegroundColor Red
    $errors |
        Select-Object TargetName, DistinguishedName, Error |
        Format-Table -AutoSize
    Write-Host ''
}

if ($PassThru) {
    $results
}