<#
    Create-TierAccountsFromUsers

    This will generate tiered accounts from standard users in Active Directory.
    Why? Suppose you have standard users with Domain Admin or highly privileged access, and you want to migrate this access to dedicated, tiered accounts.
    This script will take users as AD objects and create the tiered accounts in an Admin OU.

    Example 1: Get every Domain Admin, get their user objects, then pass to Create-TierAccountsFromUsers
    Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser | Create-TierAccountsFromUsers -Tier0DN `
    -Tier1DN "" -Tier2DN
#>
Import-Module ActiveDirectory

Function Create-TierAccountsFromUsers
{
    param (
        [Microsoft.ActiveDirectory.Management.ADAccount[]]$ADUsers,
        [String]$Tier0DN,
        [String]$Tier1DN,
        [String]$Tier2DN,
        [String[]]$SkipUsers = @("Administrator"),
        [bool]$WriteCredText = $false
    )
    $DC = Get-ADDomainController | select -ExpandProperty hostname
    $ADDomain = Get-ADDomain
    $DN = $ADDomain.DistinguishedName
    $Domain = $ADDomain.DNSRoot

    if (!$Tier0DN) { $Tier0DN = "OU=Users,OU=Tier0,OU=Admin," + $DN}
    if (!$Tier1DN) { $Tier1DN = "OU=Users,OU=Tier1,OU=Admin," + $DN}
    if (!$Tier2DN) { $Tier2DN = "OU=Users,OU=Tier2,OU=Admin," + $DN}

    foreach ($ADuser in $ADUsers)
    {
        if ($SkipUsers -and $SkipUsers.contains($ADUser.SamAccountName)) { <#Do nothing #> }
        else {

            for ($i=0; $i -lt 3; $i++)
            {
                Write-Output "Creating Tier$i User for $($ADuser.SamAccountName)"

                # Generate random 14 char password. We do not output this because scriptblock logging would leak it!
                $TempPw = -join ((65..90) + (97..122) | Get-Random -Count 13 | %{ [char]$_ }) + "!"

                switch ($i) {
                    0 {
                        $SamAccountName = $ADUser.SamAccountName + "_adm0"
                        $Description = "Tier0 Domain Admin"
                        $DisplayName = $ADUser.GivenName + " " + $ADUser.Surname + "- Tier0"
                        $OU = $Tier0DN
                    }
                    1 { 
                        $SamAccountName = $ADUser.SamAccountName + "_adm"
                        $Description = "Tier1 Server Admin"
                        $DisplayName = $ADUser.GivenName + " " + $ADUser.Surname + "- Tier1"
                        $OU = $Tier1DN
                     }
                    2 { 
                        $SamAccountName = $ADUser.SamAccountName + "_adm2"
                        $Description = "Tier2 Workstation Admin"
                        $DisplayName = $ADUser.GivenName + " " + $ADUser.Surname + "- Tier2"
                        $OU = $Tier2DN
                     }
                }

                Try {
                    $NewUserSplat = @{
                        SamAccountName = $SamAccountName
                        UserPrincipalName = $SamAccountName + "@" + $Domain
                        Name = $SamAccountName
                        GivenName = $ADUser.GivenName
                        Surname = $ADUser.Surname
                        Description = $Description
                        Department = $ADUser.Department
                        StreetAddress = $ADUser.StreetAddress
                        City = $ADUser.City
                        State = $ADUser.State
                        Country = $ADUser.Country
                        Company = $ADUser.Company
                        Title = $ADUser.Title
                        PostalCode = $ADUser.PostalCode
                        Server = $DC
                        AccountPassword = $TempPw | ConvertTo-SecureString -AsPlainText -Force
                        Path = $OU
                    }
                    $DisplayName = $ADuser.DisplayName
                }
                catch {
                    throw "Failed to create splat from AD User object data: $($ADUser.UserPrincipalName)"
                }
                
                # Check if account already exists
                if (Get-ADUser -filter {SamAccountName -eq $SamAccountName}) { Write-Warning "User already exists - $samaccountname" }
                else {
                    try {
                        New-ADUser  @NewUserSplat -DisplayName $DisplayName
                        Set-ADUser $SamAccountName -ChangePasswordAtLogon $true -Server $DC
                        if ($WriteCredText)
                        {
                            $SamAccountName + "," + $TempPw | Out-File Creds.txt -Append
                        }
                    }
                    catch {
                        Write-Error $_.exception.message
                    }
                }
                
                
            }
        }
    }
}