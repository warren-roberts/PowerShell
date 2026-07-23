#requires -Version 5.1
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Gracefully shuts down Hyper-V virtual machines in a specified order.

.DESCRIPTION
    Each VM is shut down and monitored until its Hyper-V state becomes Off.
    After the VM reaches Off, the script waits three minutes before beginning
    the shutdown of the next VM.

    Run this script from an elevated Windows PowerShell 5.1 session on the
    Hyper-V host.

.NOTES
    Stop-VM performs a guest operating system shutdown by default.
    The Hyper-V Guest Service Interface must be able to process the shutdown.
#>

[CmdletBinding()]
param (
    [ValidateRange(0, 1440)]
    [int]$DelayMinutes = 3,

    [ValidateRange(1, 1440)]
    [int]$ShutdownTimeoutMinutes = 20,

    [ValidateRange(1, 300)]
    [int]$StatusCheckIntervalSeconds = 5
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Configure the shutdown order here.
# The first VM listed is shut down first.
# ---------------------------------------------------------------------------
$VMShutdownOrder = @(
    'ApplicationServer01'
    'DatabaseServer01'
    'DomainController02'
    'DomainController01'
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

function Wait-VMOff {
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

        if ($VM.State -eq 'Off') {
            $Stopwatch.Stop()
            return
        }

        Start-Sleep -Seconds $CheckIntervalSeconds
    }

    $Stopwatch.Stop()

    throw "VM '$VMName' did not reach the Off state within $TimeoutMinutes minute(s)."
}

try {
    if (-not $VMShutdownOrder -or $VMShutdownOrder.Count -eq 0) {
        throw 'The VM shutdown-order array is empty.'
    }

    $DuplicateVMs = $VMShutdownOrder |
        Group-Object |
        Where-Object { $_.Count -gt 1 } |
        Select-Object -ExpandProperty Name

    if ($DuplicateVMs) {
        throw "The shutdown-order array contains duplicate VM names: $($DuplicateVMs -join ', ')"
    }

    Write-Log -Message "Beginning ordered shutdown of $($VMShutdownOrder.Count) VM(s)."

    for ($Index = 0; $Index -lt $VMShutdownOrder.Count; $Index++) {
        $VMName = $VMShutdownOrder[$Index]
        $IsLastVM = $Index -eq ($VMShutdownOrder.Count - 1)

        Write-Log -Message "Processing VM $($Index + 1) of $($VMShutdownOrder.Count): '$VMName'."

        $VM = Get-VM -Name $VMName -ErrorAction Stop

        if ($VM.State -eq 'Off') {
            Write-Log -Message "VM '$VMName' is already powered off."
        }
        else {
            Write-Log -Message "Requesting a graceful shutdown of VM '$VMName'."

            Stop-VM -VM $VM -Confirm:$false -ErrorAction Stop

            Wait-VMOff `
                -VMName $VMName `
                -TimeoutMinutes $ShutdownTimeoutMinutes `
                -CheckIntervalSeconds $StatusCheckIntervalSeconds

            Write-Log -Message "VM '$VMName' has powered off successfully."
        }

        # There is no reason to delay after the final VM.
        if (-not $IsLastVM -and $DelayMinutes -gt 0) {
            Write-Log -Message (
                "Starting the $DelayMinutes-minute delay before processing " +
                "the next VM."
            )

            Start-Sleep -Seconds ($DelayMinutes * 60)
        }
    }

    Write-Log -Message 'The ordered VM shutdown sequence completed successfully.'
}
catch {
    Write-Log -Level 'ERROR' -Message $_.Exception.Message
    exit 1
}