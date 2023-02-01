Import-Module ActiveDirectory

$BaseDN = (Get-ADDomain).DistinguishedName
$AdminDN = "OU=Admin," + $BaseDN
$Tier0DN = "OU=Tier0," + $AdminDN
$Tier1DN = "OU=Tier1," + $AdminDN
$Tier2DN = "OU=Tier2," + $AdminDN

# Admin root OU
if (!(Get-ADOrganizationalUnit $AdminDN))
{
    try {
        New-ADOrganizationalUnit -Name "Admin" -Path $BaseDN
    }
    catch {
        throw "Unable to create Admin OU. $_"
    }
}


# Tier OUs
New-ADOrganizationalUnit -Name "Tier0" -Path $AdminDN
New-ADOrganizationalUnit -Name "Tier1" -Path $AdminDN
New-ADOrganizationalUnit -Name "Tier2" -Path $AdminDN
New-ADOrganizationalUnit -Name "Groups" -Path $AdminDN

# User OUs
New-ADOrganizationalUnit -Name "Users" -Path $Tier0DN
New-ADOrganizationalUnit -Name "Users" -Path $Tier1DN
New-ADOrganizationalUnit -Name "Users" -Path $Tier2DN