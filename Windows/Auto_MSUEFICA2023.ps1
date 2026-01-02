<#
    .DESCRIPTION
    Applies the Microsoft UEFI CA 2023 updates.
    Revokes the PCA2011 UEFI CA (BlackLotus).

    https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d
    https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-e2b43f9f-b424-42df-bc6a-8476db65ab2f
    https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d

    In testing, this script is assigned without any parameters via a Group Policy scheduled task at startup.
    The script requires up to five reboots to apply all changes and mitigations.
    .PARAMETER SkipCAUpdate
    Do not install the updated UEFI CA 2023 certificates.
    .PARAMETER SkipRevocation
    Do not perform revocation of the Microsoft Windows Production PCA 2011 certificate.
    .PARAMETER SkipKEKUpdate
    Do not install the updated KEK certificate into the device firmware.
    .PARAMETER SkipCleanup
    Do not perform cleanup actions on the AvailableUpdates key.
    .PARAMETER SkipKEKUpdateOnVirtualHardware
    Attempt to detect if the machine is a virtual machine and skip the KEK update if so.
    .EXAMPLE
    .\Auto_MSUEFICA2023.ps1
    .EXAMPLE
    .\Auto_MSUEFICA2023.ps1 -SkipKEKUpdateOnVirtualHardware
    .NOTES
    Author:     Matthew Schacherbauer
    Email:      code.ffb23dda@mattschacherbauer.com
    Updated:    2025-12-31

    Version:    1.0

    ===============
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation, version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
    ===============
    .LINK
    https://github.com/matthewschacherbauer
    https://www.matthewschacherbauer.com
#>

#Requires -RunAsAdministrator
#Requires -Version 4.0


[CmdletBinding()]
Param (
    [Switch] $SkipCAUpdate,
    [Switch] $SkipRevocation,
    [Switch] $SkipKEKUpdate,
    [Switch] $SkipCleanup,

    [Switch] $SkipKEKUpdateOnVirtualHardware
)

#
# Helper Functions

Function RunSecureBootUpdateTask {

    [CmdletBinding()]
    Param()

    Write-Verbose "Running Secure-Boot-Update Task"

    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"

    $i = 1
    while ( (Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update").State -eq "Running" ) {
        Write-Verbose "Waiting for task to finish... ($($i))"
        Start-Sleep -Seconds $i
        $i = $i * 2
    }

}

Function ApplySecureBootUpdates {

    [CmdletBinding()]
    Param (
        $Value
    )

    Write-Verbose "Applying SecureBoot updates with value [0x$('{0:x}' -f $Value) ($($Value))]."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdates -Value $Value -Type DWord
    Start-Sleep -Seconds 2

    RunSecureBootUpdateTask -Verbose:$Verbose
}

#
# Definitions
$AvailableUpdatesDefinitions = @{
    #2 = "UNKNOWN_VALUE"
    4 = "APPLY_KEK_UPDATE"
    #8 = "UNKNOWN_VALUE"
    #16 = "LEGACY_APPLY_DBX" # Not used here
    #32 = "LEGACY_APPLY_SKUSIPOLICY" # Maybe? Not used here
    64 = "APPLY_DB_WINUEFICA2023"
    128 = "APPLY_DBX_PCA2011"
    256 = "APPLY_DB_UEFICA2023_BOOTMGR"
    512 = "APPLY_FW_SVNUPDATE"
    #1024 = "UNKNOWN_VALUE"
    2048 = "APPLY_DB_OPTIONROMUEFI2023"
    4096 = "APPLY_DB_MSUEFICA2023"
    #8192 = "UNKNOWN_VALUE"
    16384 = "IFEXIST_DB_PCA2011"
}


#
# Current Status Detection

$UEFICA2023State = [PSCustomObject] @{
    "Registry" = [PSCustomObject] @{
        "AvailableUpdates" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot").AvailableUpdates
        "UEFICA2023Status" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing").UEFICA2023Status
        "UEFICA2023Error" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing").UEFICA2023Error
        "WindowsUEFICA2023Capable" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing").WindowsUEFICA2023Capable
        "OEMManufacturerName" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes").OEMManufacturerName
        "OEMModelNumber" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes").OEMModelNumber
    }
    "DBInstallStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
    "ROMInstallStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Microsoft Option ROM UEFI CA 2023'
    "KEKInstallStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
    "ThirdPartyInstallStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Microsoft Corporation UEFI CA 2011'
    "DBXRevocationStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).bytes) -match 'Microsoft Windows Production PCA 2011'
}
$PerformedChanges = $false

# Virtual Hardware Detection
if ( !$SkipKEKUpdate -and $SkipKEKUpdateOnVirtualHardware ) {
    
    if ( $UEFICA2023State.Registry.OEMManufacturerName -in "Microsoft Corporation","VMware, Inc." ) {
        
        Write-Verbose "Detected virtual hardware. Will skip KEK update."
        $SkipKEKUpdate = $true

    }

}

# Blacklist Model Detection
if ( !$SkipKEKUpdate ) {

    # Blacklisted Models
    $BlacklistedOEMManufacturerName = @()

    if ( $UEFICA2023State.Registry.OEMManufacturerName -in $BlacklistedOEMManufacturerName ) {

        Write-Verbose "Current OEMManufacturerName is on KEK Update Blacklist. Will skip KEK update."
        $SkipKEKUpdate = $true

    }

}


# Force Status Update
RunSecureBootUpdateTask -Verbose:$Verbose

# Retrieve Current Status Information
Write-Verbose "=========="
Write-Verbose "Current Values"
Write-Verbose "AvailableUpdates: [0x$('{0:x}' -f $($UEFICA2023State.Registry.AvailableUpdates)) ($($($UEFICA2023State.Registry.AvailableUpdates)))]"
Write-Verbose "UEFICA2023Status: [$($UEFICA2023State.Registry.UEFICA2023Status)]"
Write-Verbose "WindowsUEFICA2023Capable: [$($UEFICA2023State.Registry.WindowsUEFICA2023Capable)]"
Write-Verbose "DBInstallStatus: [$($UEFICA2023State.DBInstallStatus)]"
Write-Verbose "ROMInstallStatus: [$($UEFICA2023State.ROMInstallStatus)]"
Write-Verbose "KEKInstallStatus: [$($UEFICA2023State.KEKInstallStatus)]"
Write-Verbose "ThirdPartyInstallStatus: [$($UEFICA2023State.ThirdPartyInstallStatus)]"
Write-Verbose "DBXRevocationStatus: [$($UEFICA2023State.DBXRevocationStatus)]"
Write-Verbose "=========="


#
# PHASE ONE
# Apply SecureBoot updates for Microsoft UEFI CA 2023
# KB5025885 - CVE-2023-24932
# KB5062713

if ( !$PerformedChanges -and !$SkipCAUpdate ) {

    # Check if update is applied
    if ( !$UEFICA2023State.DBInstallStatus -and `
         $UEFICA2023State.Registry.WindowsUEFICA2023Capable -eq "0" -and `
         $UEFICA2023State.Registry.UEFICA2023Status -eq "NotStarted" ) {

        Write-Verbose "Determined that the SecureBoot DB certificates need to be updated."

        # Determine update value # 0x5940
        Write-Verbose "Calculating update value"
        $NewValue = $UEFICA2023State.Registry.AvailableUpdates
        if ( !($NewValue -band 64) ) { $NewValue += 64 }          # APPLY_DB_WINUEFICA2023
        if ( !($NewValue -band 256) ) { $NewValue += 256 }        # APPLY_DB_UEFICA2023_BOOTMGR
        if ( !($NewValue -band 2048) ) { $NewValue += 2048 }      # APPLY_FW_SVNUPDATE
        if ( !($NewValue -band 4096) ) { $NewValue += 4096 }      # APPLY_DB_MSUEFICA2023
        if ( !($NewValue -band 16384) ) { $NewValue += 16384 }    # IFEXIST_DB_PCA2011

        # Update is needed
        ApplySecureBootUpdates -Value $NewValue -Verbose:$Verbose

        # Don't perform additional steps in same run.
        $PerformedChanges = $true

    }
    elseif ( $UEFICA2023State.DBInstallStatus ) {

        Write-Verbose "CA Update already completed."

    }
    else {

        Write-Verbose "Skipping CA Update. Failed prerequisites."
        Write-Verbose "DBInstallStatus: [$($UEFICA2023State.DBInstallStatus)]"
        Write-Verbose "UEFICA2023Status: [$($UEFICA2023State.Registry.UEFICA2023Status)]"

    }

}
else {

    Write-Verbose "Skipping CA Update. Skip Command."

}


#
# PHASE TWO
# Apply SecureBoot Revocations for PCA2011 UEFI CA
# KB5025885 - CVE-2023-24932
# This stage remediates for BlackLotus

if ( !$PerformedChanges -and !$SkipRevocation ) {

    # Check if revocation of old certificate is needed
    if ( $UEFICA2023State.DBInstallStatus -and `
         !$UEFICA2023State.DBXRevocationStatus -and `
         $UEFICA2023State.Registry.WindowsUEFICA2023Capable -eq "2" -and `
         $UEFICA2023State.Registry.UEFICA2023Status -eq "NotStarted" ) {

        Write-Verbose "Determined that the SecureBoot DBX needs to be updated."

        # Determine update value # 0x280
        Write-Verbose "Calculating update value"
        $NewValue = $UEFICA2023State.Registry.AvailableUpdates
        if ( !($NewValue -band 128) ) { $NewValue += 128 }        # APPLY_DBX_PCA2011
        if ( !($NewValue -band 512) ) { $NewValue += 512 }        # APPLY_FW_SVNUPDATE

        # Update is needed
        ApplySecureBootUpdates -Value $NewValue -Verbose:$Verbose

        # Don't perform additional steps in same run.
        $PerformedChanges = $true

    }
    elseif ( $UEFICA2023State.DBInstallStatus -and $UEFICA2023State.DBXRevocationStatus ) {

        Write-Verbose "DBX Update already completed."

    }
    else {

        Write-Verbose "Skipping DBX Update. Failed prerequisites."
        Write-Verbose "DBInstallStatus: [$($UEFICA2023State.DBInstallStatus)]"
        Write-Verbose "DBXRevocationStatus: [$($UEFICA2023State.DBXRevocationStatus)]"
        Write-Verbose "WindowsUEFICA2023Capable: [$($UEFICA2023State.Registry.WindowsUEFICA2023Capable)]"
        Write-Verbose "UEFICA2023Status: [$($UEFICA2023State.Registry.UEFICA2023Status)]"

    }

}
else {

    Write-Verbose "Skipping DBX Update. Skip Command."

}


#
# PHASE THREE
# Update the Key Exchange Key (KEK)
# This stage requires OEM support and may require a device firmware update.

if ( !$PerformedChanges -and !$SkipKEKUpdate ) {

    # Check if update is applied
    if ( $UEFICA2023State.DBInstallStatus -and `
         $UEFICA2023State.DBXRevocationStatus -and `
         !$UEFICA2023State.KEKInstallStatus -and `
         $UEFICA2023State.Registry.WindowsUEFICA2023Capable -eq "2" -and `
         $UEFICA2023State.Registry.UEFICA2023Status -eq "NotStarted" ) {

        Write-Verbose "Determined that the SecureBoot KEK certificates need to be updated."

        # Determine update value # 0x4
        Write-Verbose "Calculating update value"
        $NewValue = $UEFICA2023State.Registry.AvailableUpdates
        if ( !($NewValue -band 4) ) { $NewValue += 4 }        # APPLY_KEK_UPDATE

        # Update is needed
        ApplySecureBootUpdates -Value $NewValue -Verbose:$Verbose

        # Don't perform additional steps in same run.
        $PerformedChanges = $true

    }
    elseif ( $UEFICA2023State.DBInstallStatus -and $UEFICA2023State.DBXRevocationStatus -and $UEFICA2023State.KEKInstallStatus ) {

        Write-Verbose "KEK Update already completed."
        
    }
    else {

        Write-Verbose "Skipping KEK Update. Failed prerequisites."
        Write-Verbose "DBInstallStatus: [$($UEFICA2023State.DBInstallStatus)]"
        Write-Verbose "DBXRevocationStatus: [$($UEFICA2023State.DBXRevocationStatus)]"
        Write-Verbose "KEKInstallStatus: [$($UEFICA2023State.KEKInstallStatus)]"
        Write-Verbose "WindowsUEFICA2023Capable: [$($UEFICA2023State.Registry.WindowsUEFICA2023Capable)]"
        Write-Verbose "UEFICA2023Status: [$($UEFICA2023State.Registry.UEFICA2023Status)]"

        if ( $UEFICA2023State.Registry.UEFICA2023Status -eq "InProgress" -and $UEFICA2023State.Registry.UEFICA2023Error -eq "2147942419" ) {
            Write-Verbose "The KEK update is in progress and returned failure code [$($UEFICA2023State.Registry.UEFICA2023Error)]. This possibly means OEM support is not available."
        }

    }

}
elseif ( !$PerformedChanges -and $SkipKEKUpdate -and $UEFICA2023State.Registry.AvailableUpdates -band 4 ) {

    # Do revert of KEK flag
    Write-Verbose "Determined that the SecureBoot KEK update is queued and should be skipped. Will un-queue."

    # Determine update value # 0x4
    Write-Verbose "Calculating update value"
    $NewValue = $UEFICA2023State.Registry.AvailableUpdates
    if ( $NewValue -band 4 ) { $NewValue -= 4 }     # APPLY_KEK_UPDATE

    # Update is needed
    ApplySecureBootUpdates -Value $NewValue -Verbose:$Verbose

    # Don't perform additional steps in same run.
    $PerformedChanges = $true

}
else {

    Write-Verbose "Skipping KEK Update. Skip Command."

}


#
# PHASE FOUR
# Cleanup the residual 0x4000 value.

if ( !$PerformedChanges -and !$SkipCleanup ) {

    # Check if cleanup is needed
    if ( $UEFICA2023State.DBInstallStatus -and `
         $UEFICA2023State.DBXRevocationStatus -and `
         $UEFICA2023State.Registry.WindowsUEFICA2023Capable -eq "2" -and `
         $UEFICA2023State.Registry.AvailableUpdates -band 16384 ) {

        Write-Verbose "Determined that the SecureBoot DB certificates are present and cleanup is needed."

        # Determine update value # 0x4000
        Write-Verbose "Calculating update value"
        $NewValue = $UEFICA2023State.Registry.AvailableUpdates
        if ( $NewValue -band 16384 ) { $NewValue -= 16384 }     # IFEXIST_DB_PCA2011

        # Determine if KEK cleanup is needed
        if ( $SkipKEKUpdateOnVirtualHardware -and $NewValue -band 4 ) {

            Write-Verbose "Determined that KEK Update will be cancelled from pending operations."
            $NewValue = ( $NewValue - 4 ) # 0x4

        }

        # Update is needed
        ApplySecureBootUpdates -Value $NewValue -Verbose:$Verbose

        # Don't perform additional steps in same run.
        $PerformedChanges = $true

    }
    elseif ( $UEFICA2023State.DBInstallStatus -and `
             $UEFICA2023State.DBXRevocationStatus -and `
             $UEFICA2023State.Registry.WindowsUEFICA2023Capable -eq "2" -and `
             !($UEFICA2023State.Registry.AvailableUpdates -band 16384) ) {

        Write-Verbose "Cleanup already completed."

    }
    else {

        Write-Verbose "Skipping Cleanup. Failed prerequisites."
        Write-Verbose "DBInstallStatus: [$($UEFICA2023State.DBInstallStatus)]"
        Write-Verbose "DBXRevocationStatus: [$($UEFICA2023State.DBXRevocationStatus)]"
        Write-Verbose "WindowsUEFICA2023Capable: [$($UEFICA2023State.Registry.WindowsUEFICA2023Capable)]"
        Write-Verbose "AvailableUpdates: [0x$('{0:x}' -f $($UEFICA2023State.Registry.AvailableUpdates)) ($($($UEFICA2023State.Registry.AvailableUpdates)))]"
        Write-Verbose "UEFICA2023Status: [$($UEFICA2023State.Registry.UEFICA2023Status)]"

    }

}
else {

    Write-Verbose "Skipping Cleanup. Skip Command."

}


#
# Restart Notification
if ( $PerformedChanges ) {

    Write-Verbose "Changes written to the registry. Please restart to proceed."
    return 3010

}

if ( $UEFICA2023State.Registry.UEFICA2023Status -eq "InProgress" -and $UEFICA2023State.Registry.WindowsUEFICA2023Capable -eq 1 ) {

    Write-Verbose "Changes are in progress. Please restart to proceed."
    return 3010

}

return 0


<#
    Bit Setting
    BIN     HEX
    64      0x0040  P1  DB    Apply Windows UEFI CA 2023
    256     0x0100  P1  DB    Apply Windows UEFI CA 2023 Signed Boot Manager
    2048    0x0800  P1  DB    Apply Microsoft Option ROM UEFI CA 2023
    4096    0x1000  P1  DB    Apply Microsoft UEFI CA 2023
    16384   0x4000  P1  DB    Only apply 0x0800 and 0x1000 if old certificate was present

    128     0x0080  P2  DBX   Add Windows Production CA 2011 to Forbidden List (DBX)
    512     0x0200  P2        Apply SVN update to firmware

    4       0x0004  P3  DB    Apply Microsoft Corporation KEK 2K CA 2023 (Seems to fail on VM?)

    P1,P3 covers SecureBoot update
    P2 covers BlackLotus
#>

<#

    CERTIFICATE RENEWALS
    STORE   OLD                                         =>  NEW
    KEK     Microsoft Corporation KEK CA 2011               Microsoft Corporation KEK 2K CA 2023
    DB      Microsoft Windows Production PCA 2011           Windows UEFI CA 2023
    DB      Microsoft Corporation UEFI CA 2011 (*)          Microsoft UEFI CA 2023
    DB      Microsoft Corporation UEFI CA 2011 (*)          Microsoft Option ROM UEFI CA 2023
            (*) NEW is only added if OLD certificate is present

#>

