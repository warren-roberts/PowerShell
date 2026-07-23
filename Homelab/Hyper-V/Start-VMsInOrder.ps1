#requires -Version 5.1
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Starts Hyper-V virtual machines in a specified order.

.DESCRIPTION
    Each VM is started and monitored until Hyper-V reports its state as Running.

    After the current VM reaches Running, the script waits three minutes before
    starting the next VM.

    Run from an elevated Windows PowerShell 5.1 session on the Hyper-V host.

.NOTES
    A Hyper-V state of Running means the VM has been powered on. It does not
    necessarily mean that Windows or the services inside the guest have
    finished starting.
#>

[CmdletBinding()]
param (
    [ValidateRange(0, 1440)]
    [int]$DelayMinutes = 3,

    [ValidateRange(1, 1440)]
    [int]$StartupTimeoutMinutes = 10,

    [ValidateRange(1, 300)]
    [int]$StatusCheckIntervalSeconds = 5
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Configure the startup order here.
# The first VM listed is started first.
# ---------------------------------------------------------------------------
$VMStartupOrder = @(
    'DomainController01'
    'DomainController02'
    'DatabaseServer01'
    'ApplicationServer01'
)

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$Timestamp] [$Level] $Message"
}

function Wait-VMRunning {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [int]$TimeoutMinutes,

        [Parameter(Mandatory)]
        [int]$CheckIntervalSeconds
    )

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $LastState = $null

    while ($Stopwatch.Elapsed.TotalMinutes -lt $TimeoutMinutes) {
        $VM = Get-VM -Name $VMName -ErrorAction Stop

        if ($VM.State -ne $LastState) {
            Write-Log -Message "VM '$VMName' state is now '$($VM.State)'."
            $LastState = $VM.State
        }

        if ($VM.State -eq 'Running') {
            $Stopwatch.Stop()
            return
        }

        Start-Sleep -Seconds $CheckIntervalSeconds
    }

    $Stopwatch.Stop()

    throw "VM '$VMName' did not reach the Running state within $TimeoutMinutes minute(s)."
}

try {
    if (-not $VMStartupOrder -or $VMStartupOrder.Count -eq 0) {
        throw 'The VM startup-order array is empty.'
    }

    $DuplicateVMs = $VMStartupOrder |
        Group-Object |
        Where-Object { $_.Count -gt 1 } |
        Select-Object -ExpandProperty Name

    if ($DuplicateVMs) {
        throw "The startup-order array contains duplicate VM names: $($DuplicateVMs -join ', ')"
    }

    # Validate all VM names before starting anything.
    foreach ($VMName in $VMStartupOrder) {
        $null = Get-VM -Name $VMName -ErrorAction Stop
    }

    Write-Log -Message "Beginning ordered startup of $($VMStartupOrder.Count) VM(s)."

    for ($Index = 0; $Index -lt $VMStartupOrder.Count; $Index++) {
        $VMName = $VMStartupOrder[$Index]
        $IsLastVM = $Index -eq ($VMStartupOrder.Count - 1)

        Write-Log -Message "Processing VM $($Index + 1) of $($VMStartupOrder.Count): '$VMName'."

        $VM = Get-VM -Name $VMName -ErrorAction Stop

        if ($VM.State -eq 'Running') {
            Write-Log -Message "VM '$VMName' is already running."
        }
        else {
            Write-Log -Message "Starting VM '$VMName'."

            Start-VM -VM $VM -ErrorAction Stop | Out-Null

            Wait-VMRunning `
                -VMName $VMName `
                -TimeoutMinutes $StartupTimeoutMinutes `
                -CheckIntervalSeconds $StatusCheckIntervalSeconds

            Write-Log -Message "VM '$VMName' is now running."
        }

        if (-not $IsLastVM -and $DelayMinutes -gt 0) {
            Write-Log -Message (
                "Starting the $DelayMinutes-minute delay before processing " +
                "the next VM."
            )

            Start-Sleep -Seconds ($DelayMinutes * 60)
        }
    }

    Write-Log -Message 'The ordered VM startup sequence completed successfully.'
}
catch {
    Write-Log -Level 'ERROR' -Message $_.Exception.Message
    exit 1
}