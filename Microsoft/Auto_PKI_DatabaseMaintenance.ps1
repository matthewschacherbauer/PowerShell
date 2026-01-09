<#
    .DESCRIPTION
    ENTERPRISE CERTIFICATE AUTHORITY DATABASE MAINTENANCE

    Performs maintenance operations on the Active Directory Certificate Services (AD CS) database.
    This script will remove failed and pending requests, remove expired certificates, and compact the database.
    .PARAMETER CertificateAge
    Only remove eligible entries from the Certificate Services database that are older than this number of days.
    .PARAMETER BackupAge
    Only remove backups of the Certificate Services database that are older than this number of days.
    .PARAMETER CaDatabasePath
    The path to the folder containing the database edb files.
    If blank, the value is automatically read from the system registry.
    .PARAMETER CaDatabaseBackupPath
    Specifies the location to create a backup.
    .PARAMETER RemoveOldFailedCertificates
    Performs cleanup of the ADCS Database to remove PENDING and FAILED certificates older than CertificateAge.
    .PARAMETER RemoveOldIssuedCertificates
    Performs cleanup of the ADCS Database to remove ISSUED and EXPIRED certificates older than CertificateAge.
    Note: Removing expired certificates from the database will cause those certificates to drop from the Certificate Revocation List.
          This will impact the revocation of signing certificates, which normally persist after expiration.
    .PARAMETER SkipCompact
    Do not perform database compaction.
    .PARAMETER SkipCleanBackups
    Do not perform cleanup of old backups in CaDatabaseBackupPath.
    .PARAMETER SkipRegistryExport
    Do not perform an export of the ADCS Configuration in the system registry.
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2024-07-08

    Version:    1.2.1
#>


[CmdletBinding()]
Param (
    $CertificateAge = 90,
    $BackupAge = 180,

    $CaDatabasePath = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration -Name DBDirectory).DBDirectory,

    $CaDatabaseBackupPath = "D:\ADCS\CertDB_Backup",

    [Switch] $RemoveOldFailedCertificates,
    [Switch] $RemoveOldIssuedCertificates,

    [Switch] $SkipCompact,
    [Switch] $SkipCleanBackups,
    [Switch] $SkipRegistryExport
)

Start-Transcript -Path "$ENV:TEMP\Auto_PKI_DatabaseMaintenance_$( (Get-Date -Format yyMMdd-HHmmss) )_$( (New-Guid).Guid.Split("-")[0] ).log"


# Variables
$sCertificateAgeDate = (Get-Date).AddDays(-$CertificateAge).ToString('MM/dd/yyyy')
$sCaDatabaseBackupPath = $CaDatabaseBackupPath + "\" + (Get-Date -Format 'yyyyMMdd-HHmmss')

# Prepare
New-Item -ItemType Directory -Path $sCaDatabaseBackupPath -ErrorAction Stop

# Backup the CA Database
Write-Verbose "Backing up the database"
CERTUTIL -backupDB $($sCaDatabaseBackupPath)

# Check if successful
if ($LASTEXITCODE -ne "0") {
    Throw "Failed to complete AD CS database backup."
}


# Note: Certutil -DeleteRow will return an error if ~3000 records are affected.
#       Should add logic to re-run the command if this error is returned. (939523027 ?)

# Remove Failed and Pending Requests Older Than
if ($RemoveOldFailedCertificates) {
    Write-Verbose "Cleaning Failed and Pending requests"
    CERTUTIL -DeleteRow $($sCertificateAgeDate) Request

    if ($LASTEXITCODE -eq "-939523027") {
        Write-Warning "Caught exit code indicating exhaustion of the versioning store. CERTUTIL -DeleteRow should be run again."
    }
}

# Remove Expired and Revoked Certificates Older Than
if ($RemoveOldIssuedCertificates) {
    Write-Verbose "Cleaning Expired and Revoked requests"
    CERTUTIL -DeleteRow $($sCertificateAgeDate) Cert

    if ($LASTEXITCODE -eq "-939523027") {
        Write-Warning "Caught exit code indicating exhaustion of the versioning store. CERTUTIL -DeleteRow should be run again."
    }
}


if (!$SkipCompact) {
    Write-Verbose "Compacting CA Database"

    # Compact CA Database
    Stop-Service CertSvc

    foreach ($oThisDatabase in (Get-ChildItem -Path "$CaDatabasePath\*.edb")) {
        Write-Verbose "Compacting database $($oThisDatabase.FullName)"
        ESENTUTL /d "$($oThisDatabase.FullName)"
    }

    Start-Service CertSvc
}


if (!$SkipCleanBackups) {
    Write-Verbose "Removing old backups"

    Get-ChildItem -Path $CaDatabaseBackupPath -Directory | Where-Object { $_.LastWriteTime -lt ((Get-Date).AddDays(-$BackupAge)) } | Foreach-Object {
        Write-Verbose "Removing Expired Backup: $($_.FullName)"
        Remove-Item -Path $_.FullName -Recurse -Confirm:$false
    }
}


# Export the ADCS Configuration from the system registry.
if (!$SkipRegistryExport) {
    REG EXPORT "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc" "$($sCaDatabaseBackupPath)\CertSvc.reg"
}

