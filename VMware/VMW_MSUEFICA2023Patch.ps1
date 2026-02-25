<#
    .DESCRIPTION
    Updates VMware virtual machine secure boot certificate stores to contain the latest default certificates
    by deleting the NVRAM file.

    WARNING: Resets the NVRAM to the default state. This also resets the vTPM.

    https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d
    https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-e2b43f9f-b424-42df-bc6a-8476db65ab2f
    https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d
    https://knowledge.broadcom.com/external/article/421593/missing-microsoft-corporation-kek-ca-202.html
    .EXAMPLE
    .\VMW_MSUEFICA2023Patch.ps1
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2026-02-11

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

#Requires -Version 4.0


[CmdletBinding()]
Param (
    [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    $Name,
    [System.Management.Automation.PSCredential] $Credential,
    [Switch] $Force,
    [Switch] $Reboot,
    [Switch] $SkipStatusCheck,
    [Switch] $WhatIf
)

begin {

    #
    # Support Functions

    Function GetVmGuestOsUEFIPatchStatus {
        # Uses powershell remoting to retrieve the patch status from the target system.
        # Somewhat slow per machine.

        [CmdletBinding()]
        Param (
            $Name,
            [System.Management.Automation.PSCredential] $Credential
        )

        Write-Verbose "Querying secure boot status for [$($Name)]"

        $p = @{
            'ComputerName' = $Name
        }
        if ($Credential) { $p.add('Credential', $Credential) }
        Invoke-Command @p -ScriptBlock {

            $UEFICA2023State = [PSCustomObject] @{
                "RegistryAvailableUpdates" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot").AvailableUpdates
                "RegistryUEFISecureBootEnabled" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State").UEFISecureBootEnabled
                "RegistryUEFICA2023Status" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing").UEFICA2023Status
                "RegistryUEFICA2023Error" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing").UEFICA2023Error
                "RegistryWindowsUEFICA2023Capable" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing").WindowsUEFICA2023Capable
                "RegistryOEMManufacturerName" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes").OEMManufacturerName
                "RegistryOEMModelNumber" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes").OEMModelNumber

                "DBInstallStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
                "MSROMInstallStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes)-match 'Microsoft UEFI CA 2023'
                "OptROMInstallStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Microsoft Option ROM UEFI CA 2023'
                "KEKInstallStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
                "ThirdPartyInstallStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Microsoft Corporation UEFI CA 2011'
                "DBXRevocationStatus" = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).bytes) -match 'Microsoft Windows Production PCA 2011'
            }

            return $UEFICA2023State

        }

    }

    Function RemoveVmDatastoreNvramFile {
        # Deletes the NVRAM file for a virtual machine from the datastore.
        # Requires the machine to be powered off first.
        # Requires an existing connection to the vCenter server over powercli.

        # WARNING: The subsequent restart must be completed on a v8.0.2 or later host.
        #          Otherwise, the system will not have the updated keys and may fail to boot
        #          if the signing keys were updated or revoked in the OS previously.
        #          Temporarily disabling secure boot can recover the VM if this situation occurs.

        [CmdletBinding()]
        Param (
            $Vm,
            [Switch] $WhatIf
        )

        $oVm = Get-VM -Name $Vm

        # Verify VM is powered off
        if (!$WhatIf -and $oVm.PowerState -ne "PoweredOff") {
            Write-Warning "VM [$($oVm.Name)] must be powered off to continue. Skipping."
            return
        }

        # Verify VM has no snapshots
        if ($oVm | Get-Snapshot) {
            Write-Warning "VM [$($oVm.Name)] has an active snapshot that must be removed to continue. Skipping."
            return
        }

        $sVmxPath = $oVm.ExtensionData.Config.Files.VmPathName

        if ($sVmxPath -match '^\[(.+?)\]\s(.+)/[^/]+$') {
            $sVmDatastore = $matches[1]
            $sVmDatastorePath = $matches[2]
        }

        try {
            # Mount Datastore
            Write-Verbose "Connecting to datastore [$($sVmDatastore)]"
            $oDatastoreMount = New-PSDrive -Location (Get-Datastore $($sVmDatastore) -ErrorAction Stop) -Name DS -PSProvider VimDatastore -Root "\" -ErrorAction Stop

            # Get NVRAM backup files
            Write-Verbose "Querying path [DS:\$($sVmDatastorePath)\*.nvram.bak]"
            $oNvramBakFiles = $null
            $oNvramBakFiles = Get-ChildItem -Path "DS:\$($sVmDatastorePath)\*.nvram.bak" -ErrorAction Stop

            # Remove NVRAM backup files
            foreach ($thisNvramBakFile in $oNvramBakFiles) {
                Write-Verbose "Removing file [$($thisNvramBackFile)]."
                Remove-Item -Path $thisNvramBakFile -WhatIf:$WhatIf
            }

            # Get NVRAM files
            Write-Verbose "Querying path [DS:\$($sVmDatastorePath)\*.nvram]"
            $oNvramFiles = $null
            $oNvramFiles = Get-ChildItem -Path "DS:\$($sVmDatastorePath)\*.nvram" -ErrorAction Stop

            # Remove NVRAM files
            foreach ($thisNvramFile in $oNvramFiles) {
                Write-Verbose "Renaming NVRAM file [$($thisNvramFile.Name)] to [$($thisNvramFile.Name).bak]"
                Move-Item -Path $thisNvramFile -Destination "DS:\$($sVmDatastorePath)\$($thisNvramFile.Name.Replace(".nvram",".nvram.bak"))" -WhatIf:$WhatIf
            }

            if (!$oNvramFiles) {
                Write-Warning "No NVRAM files found for this VM."
            }
        }
        finally {
            # Unmount Datastore
            Remove-PSDrive -Name $oDatastoreMount | Out-Null
        }

    }

    Function ProcessVm {
        # Parent routine for committing changes to a VM.

        [CmdletBinding()]
        Param (
            $Vm,
            [Switch] $Force,
            [Switch] $Reboot,
            [Switch] $WhatIf
        )

        $oVm = Get-VM -Name $Vm

        # If no result, check if VM shortname is valid
        if (!$oVm) {
            Write-Verbose "Querying for short name [$($Vm.split(".")[0])]."
            $oVm = Get-VM -Name $Vm.split(".")[0]
        }

        if (!$oVm) {
            Write-Error "No virtual machines returned by query. Nothing to do."
            return
        }

        $bOriginalStateRunning = $false

        # Verify VM is powered off
        if (!$Reboot -and $oVm.PowerState -eq "PoweredOn") {
            Write-Warning "VM [$($oVm.Name)] must be powered off to continue. Use -Reboot to shutdown the VM."

            if (!$WhatIf) { return }
        }
        elseif ($oVm.PowerState -notin @("PoweredOn","PoweredOff")) {
            Write-Warning "Unhandled VM power state [$($oVm.PowerState)]. Skipping."
            return
        }
        elseif ($oVm.PowerState -eq "PoweredOn" -and $Reboot) {
            Write-Verbose "Shutting down VM [$($oVm.Name)]"
            $bOriginalStateRunning = $true

            # Invoke tools to gracefully shutdown VM
            Stop-VMGuest -VM $oVm -Confirm:$false -WhatIf:$WhatIf | Out-Null

            # Wait for VM shutdown to complete.
            $i = 0
            $iMax = 600
            while (!$WhatIf -and $oVm.PowerState -ne "PoweredOff") {
                Write-Verbose "Waiting for shutdown. Waited for [$($i)] seconds."
                Start-Sleep -Seconds 10
                $oVm = Get-VM -Name $oVm
                $i = $i + 10

                if ($i -ge $iMax) {
                    Write-Verbose "Wait limit reached. Continuing. This will probably fail."
                    break
                }
            }
        }

        # Remove NVRAM file
        RemoveVmDatastoreNvramFile -Vm $oVm.Name -WhatIf:$WhatIf

        # Restart VM if it was originally running
        if ($bOriginalStateRunning) {
            Start-VM -VM $oVm -WhatIf:$WhatIf | Out-Null
        }

    }

}

process {

    #
    # Main Loop

    foreach ($thisName in $Name.Split(",")) {

        # Retrieve current UEFI patching state
        $s = $null
        $p = @{
            'Name' = $thisName
        }
        if ($Credential) { $p.add('Credential', $Credential) }
        $s = GetVmGuestOsUEFIPatchStatus @p
        if ($s) { Write-Verbose $s | Format-List }

        # If no data is received, skip this machine unless we're forcing the config change anyways.
        if (!$SkipStatusCheck -and !$s) {
            Write-Error "Failed to retrieve status from the remote machine"

            if (!$Force) { continue }
        }

        # If secure boot is not enabled, skip this machine.
        if (!$SkipStatusCheck -and $s.RegistryUEFISecureBootEnabled -eq $false) {
            Write-Warning "Remote system [$($thisName)] is not enabled for secure boot or the status could not be verified."

            continue
        }

        # If the remote system is already patched, skip this machine unless we're forcing the config change.
        if ( ($s.RegistryUEFICA2023Status -and $s.RegistryUEFICA2023Status -eq "Updated") -or $s.KEKInstallStatus -eq $true) {
            Write-Verbose "Remote system [$($thisName)] is already patched."

            if (!$Force) { continue }
        }

        # Finally, perform the config change.
        if ($Force -or $SkipStatusCheck -or ($s.RegistryUEFICA2023Status -and $s.RegistryUEFICA2023Status -ne "Updated" -and $s.KEKInstallStatus -eq $false) ) {
            Write-Verbose "Running update on remote system [$($thisName)]."
            ProcessVm -Vm $thisName -Force:$Force -Reboot:$Reboot -WhatIf:$WhatIf
        }

    }

}

end {}


