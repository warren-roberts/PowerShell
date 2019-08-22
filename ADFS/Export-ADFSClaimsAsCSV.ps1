#Run this on an ADFS server
param(
    $ClaimName = "",
    $Filename = "ADFSClaims.csv"
)

$trusts = Get-AdfsRelyingPartyTrust | Where-Object {$_.name -like "*$ClaimName*"} | Sort-Object name

$trusts | ForEach-Object{
    [pscustomobject]@{
        Name = $_.name
        Enabled = $_.enabled
        Identifier = $_.identifier[0]
        Rules = ($_.issuancetransformrules).replace("@","").replace(",","").replace("c:[","").replace("]","").replace("`"","") # removes characters which cause CSV to break.
    }
} | export-csv -Path $Filename -NoTypeInformation