#
# Windows 11 Tweak script for gaming and performance sans breaking things
#

# Ensure running as Administrator
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You need to run this script as Administrator."
    exit
}

function Update-RegistryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {

        Write-Verbose "Registry path does not exist. Creating: $Path"

        try {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        catch {
            throw "Failed to create registry path '$Path'. Error: $_"
        }
    }
    else {
        Write-Verbose "Registry path already exists: $Path"
    }
}

function Test-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        $ExpectedValue,

        [ValidateSet("String","ExpandString","Binary","DWord","QWord","MultiString")]
        [string]$ExpectedType,

        [switch]$Detailed
    )

    if (-not (Test-Path $Path)) {
        if ($Detailed) {
            return [PSCustomObject]@{
                PathExists  = $false
                ValueExists = $false
                ValueMatch  = $false
                TypeMatch   = $false
                CurrentValue = $null
                CurrentType  = $null
            }
        }
        return $false
    }

    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
        if ($Detailed) {
            return [PSCustomObject]@{
                PathExists  = $true
                ValueExists = $false
                ValueMatch  = $false
                TypeMatch   = $false
                CurrentValue = $null
                CurrentType  = $null
            }
        }
        return $false
    }

    $currentValue = $item.$Name
    $currentType  = (Get-Item -Path $Path).GetValueKind($Name).ToString()

    $valueMatch = $true
    $typeMatch  = $true

    if ($PSBoundParameters.ContainsKey("ExpectedValue")) {
        $valueMatch = ($currentValue -eq $ExpectedValue)
    }

    if ($PSBoundParameters.ContainsKey("ExpectedType")) {
        $typeMatch = ($currentType -eq $ExpectedType)
    }

    if ($Detailed) {
        return [PSCustomObject]@{
            PathExists   = $true
            ValueExists  = $true
            ValueMatch   = $valueMatch
            TypeMatch    = $typeMatch
            CurrentValue = $currentValue
            CurrentType  = $currentType
        }
    }

    return ($valueMatch -and $typeMatch)
}



# -----------------------------
# 1. Disable Windows Ink Workspace
# -----------------------------
Write-Host "Disabling Windows Ink Workspace."

$WinInkWorkspacePath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
$KeyName = "AllowWindowsInkWorkspace"
$Type = "DWord"
$Value = 0

Update-RegistryPath -Path $WinInkWorkspacePath

if (-Not (Test-RegistryValue -Path $WinInkWorkspacePath `
                   -Name $KeyName `
                   -ExpectedValue $Value)) {
    New-ItemProperty -Path $WinInkWorkspacePath `
                 -Name $KeyName `
                 -PropertyType $Type `
                 -Value $Value `
                 -Force
} else {
    Write-Host "Already disabled: Windows Ink Workspace." -ForegroundColor Green
}

# -----------------------------
# 2. Adjust TouchPrediction settings
# -----------------------------
Write-Host "Adjusting TouchPrediction settings. Reboot required."

$TouchPredictionPath = "HKLM:\SOFTWARE\Microsoft\TouchPrediction"
Update-RegistryPath -Path $TouchPredictionPath

# Latency
$KeyName = "Latency"
$Type = "DWord"
$Value = 0

if (-Not (Test-RegistryValue -Path $TouchPredictionPath `
                   -Name $KeyName `
                   -ExpectedValue $Value)) {
    New-ItemProperty -Path $WinInkWorkspacePath `
                 -Name $KeyName `
                 -PropertyType $Type `
                 -Value $Value `
                 -Force
} else {
    Write-Host "Already disabled: TouchPrediction - Latency." -ForegroundColor Green
}

# Sampletime
$KeyName = "SampleTime"
$Type = "DWord"
$Value = 0

if (-Not (Test-RegistryValue -Path $TouchPredictionPath `
                   -Name $KeyName `
                   -ExpectedValue $Value)) {
    New-ItemProperty -Path $WinInkWorkspacePath `
                 -Name $KeyName `
                 -PropertyType $Type `
                 -Value $Value `
                 -Force
} else {
    Write-Host "Already disabled: TouchPrediction - SampleTime." -ForegroundColor Green
}

Write-Host "`nRegistry changes complete. Please restart your PC for changes to take effect." -ForegroundColor Yellow

#
# 3. Check for presence of hotfixes that cause performance issues
#
$BadCUs = @("KB5074109")
foreach ($CU in $BadCUs) {
    $result = [bool](Get-CimInstance Win32_QuickFixEngineering `
        -Filter "HotFixID = '$($CU)'" `
        -ErrorAction SilentlyContinue)
    if ($result) {
        "$CU detected. You should uninstall it."
    }
}
