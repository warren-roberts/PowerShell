$DC = Read-Host
invoke-command -ComputerName $DC -ScriptBlock {
   dcdiag.exe /v /test:advertising 
}
