<#
    .DESCRIPTION
    ENTERPRISE MICROSOFT DHCP DATABASE MAINTENANCE

    Performs maintenance operations on the Active Directory DHCP database.
    This script will remove failed and pending requests, remove expired certificates, and compact the database.
    .PARAMETER BackupAge
    Only remove backups of the Certificate Services database that are older than this number of days.
    .PARAMETER DhcpDatabasePath
    .PARAMETER DhcpDatabaseBackupPath
    Specifies the location to create a backup.
    .PARAMETER DhcpLeaseBackupPath
    .PARAMETER SkipBackup
    Do not perform a backup of the DHCP database to a flat file.
    .PARAMETER SkipScopeReconcile
    Do not run a repair reconcile on DHCP scopes.
    .PARAMETER SkipCompact
    Do not perform database compaction.
    .PARAMETER SkipReplication
    Do not perform replication of changes to scope configurations and reservations.
    .PARAMETER SkipCleanBackups
    Do not perform cleanup of old backups in CaDatabaseBackupPath.
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2025-04-10

    Version:    1.1.2
#>

[CmdletBinding()]
Param (
    $BackupAge = 180,

    # Define required paths for the DHCP database and backup locations.
    $DhcpDatabasePath = "D:\DHCP\DB",
    $DhcpDatabaseBackupPath = "E:\DHCP\Backup_Automation",
    $DhcpLeaseBackupPath = "E:\DHCP\BackupLease_Automation",

    # Define the PrimaryDhcpServer. When performing replication jobs, the machine the script is running
    # from must match this or else the replication job is skipped.
    # This enables the same script and parameters to be pushed to all servers safely.
    $PrimaryDhcpServer = "WSNOCDHCP00",

    [Switch] $SkipBackup,
    [Switch] $SkipScopeReconcile,
    [Switch] $SkipCompact,
    [Switch] $SkipReplication,
    [Switch] $SkipCleanBackups
)


Start-Transcript -Path "$ENV:TEMP\Auto_DHCP_DatabaseMaintenance_$( (Get-Date -Format yyMMdd-HHmmss) )_$( (New-Guid).Guid.Split("-")[0] ).log"

# Variables
$sDhcpDatabaseBackupPath = $DhcpDatabaseBackupPath + "\" + (Get-Date -Format 'yyyyMMdd-hhmmss')
$sDhcpLeaseBackupPath = $DhcpLeaseBackupPath + "\" + (Get-Date -Format 'yyyyMMdd-hhmmss')

# Prepare
New-Item -ItemType Directory -Path $sDhcpDatabaseBackupPath -Force -ErrorAction Stop
New-Item -ItemType Directory -Path $sDhcpLeaseBackupPath -Force -ErrorAction Stop

# Backup the DHCP Database
if (!$SkipBackup) {
    Write-Verbose "Backing up the database"
    Backup-DhcpServer -Path $sDhcpDatabaseBackupPath -Verbose

    # Check if successful
    if (!$?) {
        Throw "Failed to complete DHCP database backup."
    }

    Write-Verbose "Exporting DHCP lease information."
    Export-DhcpServer -File $sDhcpLeaseBackupPath\dhcpexport.xml -Leases
}


if (!$SkipScopeReconcile) {
    Write-Verbose "Reconciling DHCP Scopes"

    # $confirm:$false doesn't seem to skip the confirmation. Use -Force

    Get-DhcpServerv4Scope | Foreach-Object {
        Write-Verbose "Repairing ScopeId $($_.ScopeId)"
        Repair-DhcpServerv4IPRecord -ScopeId $_.ScopeId -Force -Verbose
    }
}


<#
if (!$SkipCompact) {
    # NOTE
    # The compaction step relies on the JETPACK utility which is only present if the WINS Server
    # role is installed.

    Write-Verbose "Compacting DHCP Database"

    # Compact DHCP Database
    Stop-Service DhcpServer

    foreach ($oThisDatabase in (Get-ChildItem -Path "$DhcpDatabasePath\*.mdb")) {
        Write-Verbose "Compacting database $($oThisDatabase.FullName)"
        JETPACK.EXE "$($oThisDatabase.FullName)" "$($oThisDatabase.Directory)\tmp.mdb"
    }

    Start-Service DhcpServer
}
#>


if (!$SkipReplication) {
    # Performs replication of scopes.
    # Replicates properties, IP ranges, IP exclusions, and reservations.
    # Does not replicate lease information.

    # If using this option, the task must be run under a service account that is a member
    # of "DHCP Administrators" on all servers in the replication partnership.

    if ($PrimaryDhcpServer -ne $ENV:COMPUTERNAME) {
        Write-Verbose "Skipping replication due to active computer is not primary."
    }
    else {
        Write-Verbose "Performing scope replication"

        # $confirm:$false doesn't seem to skip the confirmation. Use -Force

        Get-DhcpServerv4Scope | Foreach-Object {
            Write-Verbose "Replicating ScopeId $($_.ScopeId)"
            Invoke-DhcpServerv4FailoverReplication -ScopeId $_.ScopeId -Force -Verbose
        }
    }
}


if (!$SkipCleanBackups) {
    Write-Verbose "Removing old backups"

    Get-ChildItem -Path $DhcpDatabaseBackupPath -Directory | Where-Object { $_.LastWriteTime -lt ((Get-Date).AddDays(-$BackupAge)) } | Foreach-Object {
        Write-Verbose "Removing Expired Backup: $($_.FullName)"
        Remove-Item -Path $_.FullName -Recurse -Confirm:$false
    }

    Get-ChildItem -Path $DhcpLeaseBackupPath -Directory | Where-Object { $_.LastWriteTime -lt ((Get-Date).AddDays(-$BackupAge)) } | Foreach-Object {
        Write-Verbose "Removing Expired Lease Backup: $($_.FullName)"
        Remove-Item -Path $_.FullName -Recurse -Confirm:$false
    }
}

