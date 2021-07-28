<#

VMWARE VCENTER HOST MODULES
VMHostScratchLocation

Matthew Schacherbauer
2021-07-28

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

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

#>

#Requires -Version 3.0
#Requires -Modules VMware.VimAutomation.Core


Function ConvertVolumeNameToUuid {
    # Converts an ESXi Datastore Friendly Name to its UUID value.

    Param (
        [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        $Name,
        $VMHost
    )

    Begin {
        # Get the host view
        if ($VMHost) { $oHostView = Get-View (Get-VMHost $VMHost).Id }
        else { $oHostView = Get-View (Get-VMHost).Id }

        # Get storage subsystem view
        $oStorageSubsystemView = Get-View ($oHostView.ConfigManager.StorageSystem)

        # Result container
        $oResult = @()
    }

    Process {
        foreach ($oThisStorageSubsytemView in $oStorageSubsystemView) {
            foreach ($oThisMountInfo in $oThisStorageSubsytemView.FileSystemVolumeInfo.MountInfo) {
                if (($oThisMountInfo.Volume.Name -in $Name) -and ($oThisMountInfo.Volume.Name -notin $oResult.Name)) {
                    $oResult += [PSCustomObject] @{
                        "Name"      = $oThisMountInfo.Volume.Name
                        "UUID"      = $oThisMountInfo.Volume.Uuid
                    }
                }
            } #MountInfo
        } #StorageSubsystemView
    }

    End {
        $oResult
    }
}


Function ConvertVolumeUuidToName {
    # Converts an ESXi Datastore UUID to its Friendly Name value.

    Param (
        [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        $Uuid,
        $VMHost
    )

    Begin {
        # Get the host view
        if ($VMHost) { $oHostView = Get-View (Get-VMHost $VMHost).Id }
        else { $oHostView = Get-View (Get-VMHost).Id }

        # Get storage subsystem view
        $oStorageSubsystemView = Get-View ($oHostView.ConfigManager.StorageSystem)

        # Result container
        $oResult = @()
    }

    Process {
        foreach ($oThisStorageSubsytemView in $oStorageSubsystemView) {
            foreach ($oThisMountInfo in $oThisStorageSubsytemView.FileSystemVolumeInfo.MountInfo) {
                if (($oThisMountInfo.Volume.Uuid -in $Uuid) -and ($oThisMountInfo.Volume.Uuid -notin $oResult.Uuid)) {
                    $oResult += [PSCustomObject] @{
                        "Name"      = $oThisMountInfo.Volume.Name
                        "UUID"      = $oThisMountInfo.Volume.Uuid
                    }
                }
            } #MountInfo
        } #StorageSubsystemView
    }

    End {
        $oResult
    }

}


Function Get-VMHostScratchLocation {
    <#
    .SYNOPSIS
    Gets the VMware ESXi Hypervisor Scratch Location
    .DESCRIPTION
    The Get-VMHostScratchLocation function retrieves the Scratch Location configuration for a VMware ESXi Host.
    .PARAMETER Name
    One or more ESXi VM Host names to operate on.
    .PARAMETER ClusterName
    One or more ESXi Cluster names to operate on.
    .EXAMPLE
    Get-VMHostScratchLocation -Name ESXI-Host-01,ESXI-Host-02
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2021-07-28
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName="Host")]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Mandatory,Position=0,ParameterSetName="Cluster")]
        [ValidateNotNullOrEmpty()]
        $ClusterName
    )

    Begin { }

    Process {
        # Resolve parameters
        if ($Name) { $oVmHost = Get-VMHost $Name }
        if ($ClusterName) { $oVmHost = Get-Cluster $ClusterName | Get-VMHost }

        foreach ($oThisVmHost in $oVmHost) {
            Write-Verbose "Processing host $($oThisVmHost.Name)"

            # Make sure host is powered on and ready
            if ($oThisVmHost.ConnectionState -eq "NotResponding") {
                Write-Verbose "Skipped VMHost $($oThisVmHost): Not Responding"
                continue
            }
            
            # Get current scratch path
            $sScratchLocation = ($oThisVmHost | Get-AdvancedSetting -Name ScratchConfig.ConfiguredScratchLocation).Value
            $sCurrentScratchLocation = ($oThisVmHost | Get-AdvancedSetting -Name ScratchConfig.CurrentScratchLocation).Value

            # Convert scratch location UUID to Friendly Name for display
            $sScratchLocationUuid = $sScratchLocation.Split("/")[3]
            $sScratchLocationFriendlyName = ($sScratchLocationUuid | ConvertVolumeUuidToName -VMHost $oThisVmHost).Name
            if ($sScratchLocationFriendlyName) {
                $sScratchLocation = $sScratchLocation.Replace($sScratchLocationUuid, $sScratchLocationFriendlyName)
            }

            $sCurrentScratchLocationUuid = $sCurrentScratchLocation.Split("/")[3]
            $sScratchLocationFriendlyName = ($sCurrentScratchLocationUuid | ConvertVolumeUuidToName -VMHost $oThisVmHost).Name
            if ($sScratchLocationFriendlyName) {
                $sCurrentScratchLocation = $sCurrentScratchLocation.Replace($sCurrentScratchLocationUuid, $sScratchLocationFriendlyName)
            }

            # Return to pipe
            [PSCustomObject] @{
                "Name"                          = $oThisVmHost.Name
                "ConfiguredScratchLocation"     = $sScratchLocation
                "CurrentScratchLocation"        = $sCurrentScratchLocation
            }
        } # Foreach
    }

    End { }
}


Function Set-VMHostScratchLocation {
    <#
    .SYNOPSIS
    Sets the VMware ESXi Hypervisor Scratch Location
    .DESCRIPTION
    The Set-VMHostScratchLocation function creates a directory on the specified datastore and sets the hosts Scratch Location value to that directory.
    .PARAMETER Name
    One or more ESXi VM Host names to operate on.
    .PARAMETER ClusterName
    One or more ESXi Cluster names to operate on.
    .PARAMETER Datastore
    A single ESXi Datastore to assign as the Scratch Location. A top level directory will automatically be created.
    .PARAMETER Reboot
    Issue a reboot command upon completion, if the host is in maintenance mode.
    .EXAMPLE
    Set-VMHostScratchLocation -Name ESXI-Host-01,ESXI-Host-02 -Datastore ESXI-DS-01
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2021-07-28
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName="Host")]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Mandatory,Position=0,ParameterSetName="Cluster")]
        [ValidateNotNullOrEmpty()]
        $ClusterName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $Datastore,

        [switch] $Reboot
    )

    # Resolve parameters
    if ($Name) { $oVmHost = Get-VMHost $Name }
    if ($ClusterName) { $oVmHost = Get-Cluster $ClusterName | Get-VMHost }
    $oDatastore = Get-Datastore $Datastore

    try {
        # Connect to Datastore
        Write-Verbose "Connecting to datastore $($oDatastore.Name)"
        $oDatastoreMount = New-PSDrive -Location $oDatastore -Name DS -PSProvider VimDatastore -Root "\" -ErrorAction Stop
    
        foreach ($oThisVmHost in $oVmHost) {
            Write-Verbose "Processing host $($oThisVmHost.Name)"

            # Make sure host is powered on and ready
            if ($oThisVmHost.ConnectionState -eq "NotResponding") {
                Write-Verbose "Skipped VMHost $($oThisVmHost): Not Responding"
                continue
            }
            
            # Get current scratch path
            $oScratchLocation = $oThisVmHost | Get-AdvancedSetting -Name ScratchConfig.ConfiguredScratchLocation

            # Create locker directory
            Write-Verbose "Querying for existing scratch directory"
            $oScratchFolder = Get-Item -Path "DS:\.locker-$($oThisVmHost.Name.split(".")[0])" -ErrorAction SilentlyContinue
            if (!$oScratchFolder) {
                Write-Verbose "Creating new scratch directory on datastore"
                $oScratchFolder = New-Item -Path "DS:\.locker-$($oThisVmHost.Name.split(".")[0])" -ItemType Directory -ErrorAction Stop
            }

            # Set Advanced Setting ScratchLocation
            $sScratchLocation = "/vmfs/volumes/$($oScratchFolder.Datastore)/$($oScratchFolder.Name)"
            Write-Verbose "Setting scratch location to: $sScratchLocation"
            $null = $oScratchLocation | Set-AdvancedSetting -Value $sScratchLocation -Confirm:$false

            # Reboot?
            if ($Reboot) {
                # Check for maintenance mode
                if ($oThisVmHost.ConnectionState -eq "Maintenance") {
                    Write-Verbose "Issuing reboot command to $($oThisVmHost.Name)"
                    $null = Restart-VMHost -VMHost $oThisVmHost -Confirm:$false
                }
                else {
                    Write-Warning "Ignored reboot command for $($oThisVmHost.Name), host is not in maintenance mode."
                }
            }
        } # Foreach
    } # Try
    finally {
        # Remove Datastore Connection
        if ($oDatastoreMount) {
            Write-Verbose "Disconnecting from Datastore"
            Remove-PSDrive -Name $oDatastoreMount
        }
    }
}


# Exported Functions
Export-ModuleMember -Function `
    Get-VMHostScratchLocation, `
    Set-VMHostScratchLocation
