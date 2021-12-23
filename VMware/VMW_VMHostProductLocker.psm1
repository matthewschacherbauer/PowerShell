<#

VMWARE VCENTER HOST MODULES
VMHostProductLocker

Matthew Schacherbauer
2021-12-23

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


Function Copy-VMHostProductLockerContent {
    <#
    .SYNOPSIS
    Copies the Product Locker content to the target ESXi Datastore.
    .DESCRIPTION
    The Product Locker contains the VMTools packaged used by ESXi to determine if an upgrade is available for a Virtual Machine
    and contains the ISO images that are mounted when an installation or upgrade is performed.
    .PARAMETER Path
    The local path to the Product Locker content.
    .PARAMETER Datastore
    The target ESXi Datastore to store the Product Locker content.
    A folder will be created on the root of the datastore to house the Product Locker content.
    .PARAMETER Folder
    The name of the root folder on the target ESXi Datastore.
    The default name is "vmtoolsRepo"
    .EXAMPLE
    Copy-VMHostProductLockerContent -Path C:\Temp\vmtoolsRepo -Datastore ESXI-DS-01
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2021-11-23
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $Datastore,

        [ValidateNotNullOrEmpty()]
        $Folder = "vmtoolsRepo"
    )

    # Resolve parameters
    if ($Datastore) { $oDatastore = Get-Datastore $Datastore }

    try {
        # Connect to Datastore
        Write-Verbose "Connecting to datastore $($oDatastore.Name)"
        $oDatastoreMount = New-PSDrive -Location $oDatastore -Name DS -PSProvider VimDatastore -Root "\" -ErrorAction Stop

        # Create the Product Locker folder
        Write-Verbose "Querying for existing product locker directory"
        $oProductLockerFolder = Get-Item -Path "DS:\$($Folder)" -ErrorAction SilentlyContinue
        if (!$oProductLockerFolder) {
            Write-Verbose "Creating new directory on datastore"
            $oProductLockerFolder = New-Item -Path "DS:\$($Folder)" -ItemType Directory -ErrorAction Stop
        }
        else {
            Write-Verbose "Found existing folder $($oProductLockerFolder)"
        }

        # Upload the local content
        Write-Verbose "Checking local path $($Path)"
        if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
            Write-Verbose "Uploading content from $($Path)"
            Get-ChildItem -Path $Path | Copy-DatastoreItem -Destination $oProductLockerFolder -Recurse | Out-Null
        }
        else {
            Write-Error "The local path $($Path) is invalid."
        }
    }
    finally {
        # Remove the datastore mount
        if ($oDatastoreMount) {
            Write-Verbose "Removing datastore mount"
            Remove-PSDrive -Name $oDatastoreMount
        }
    }
}


Function Get-VMHostProductLockerLocation {
    <#
    .SYNOPSIS
    Gets the VMware ESXi Hypervisor VMTools Central Repository Location
    .DESCRIPTION
    The Get-VMHostProductLockerLocation function retrieves the VMTools Central Repository Location configuration for a VMware ESXi Host.
    .PARAMETER Name
    One or more ESXi VM Host names to operate on.
    .PARAMETER Cluster
    One or more ESXi Cluster names to operate on.
    .EXAMPLE
    Get-VMHostProductLockerLocation -Name ESXI-Host-01,ESXI-Host-02
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2021-11-23
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName="Host")]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Mandatory,Position=0,ParameterSetName="Cluster")]
        [ValidateNotNullOrEmpty()]
        $Cluster
    )

    Begin { }

    Process {
        # Resolve parameters
        if ($Name) { $oVmHost = Get-VMHost $Name }
        if ($Cluster) { $oVmHost = Get-Cluster $Cluster | Get-VMHost }

        foreach ($oThisVmHost in $oVmHost) {
            Write-Verbose "Processing host $($oThisVmHost.Name)"

            # Make sure host is powered on and ready
            if ($oThisVmHost.ConnectionState -eq "NotResponding") {
                Write-Verbose "Skipped VMHost $($oThisVmHost): Not Responding"
                continue
            }
            
            # Get current product locker path
            $sProductLockerLocation = $oThisVmHost.ExtensionData.QueryProductLockerLocation()

            # Convert scratch location UUID to Friendly Name for display
            $sProductLockerLocationUuid = $sProductLockerLocation.Split("/")[3]
            $sProductLockerLocationFriendlyName = ($sProductLockerLocationUuid | ConvertVolumeUuidToName -VMHost $oThisVmHost).Name
            if ($sProductLockerLocationFriendlyName) {
                $sProductLockerLocation = $sProductLockerLocation.Replace($sProductLockerLocationUuid, $sProductLockerLocationFriendlyName)
            }

            # Return to pipe
            [PSCustomObject] @{
                "Name"                              = $oThisVmHost.Name
                "VMToolsProductLockerLocation"      = $sProductLockerLocation
            }
        } # Foreach
    }

    End { }
}


Function Set-VMHostProductLockerLocation {
    <#
    .SYNOPSIS
    Sets the VMware ESXi Hypervisor Scratch Location
    .DESCRIPTION
    The Set-VMHostProductLockerLocation function creates a directory on the specified datastore and sets the hosts VMTools Central Repository value to that directory.
    .PARAMETER Name
    One or more ESXi VM Host names to operate on.
    .PARAMETER Cluster
    One or more ESXi Cluster names to operate on.
    .PARAMETER Datastore
    A single ESXi Datastore to assign as the Product Locker Location. A top level directory will automatically be created.
    .EXAMPLE
    Set-VMHostProductLockerLocation -Name ESXI-Host-01,ESXI-Host-02 -Datastore ESXI-DS-01
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2021-11-23

    NOTE: API calls require ESXi 6.7 Update 1 or later. TODO: Version Check
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName="Host")]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Mandatory,Position=0,ParameterSetName="Cluster")]
        [ValidateNotNullOrEmpty()]
        $Cluster,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $Datastore,

        [ValidateNotNullOrEmpty()]
        $Folder = "vmtoolsRepo"
    )

    Begin { }

    Process {
        # Resolve parameters
        if ($Name) { $oVmHost = Get-VMHost $Name }
        if ($Cluster) { $oVmHost = Get-Cluster $Cluster | Get-VMHost }
        if ($Datastore) { $oDatastore = Get-Datastore $Datastore }

        # Determine the full datastore path name
        $sDatastore = "/vmfs/volumes/$($oDatastore.Name)/$($Folder)"

        foreach ($oThisVmHost in $oVmHost) {
            Write-Verbose "Processing host $($oThisVmHost.Name)"

            # Make sure host is powered on and ready
            if ($oThisVmHost.ConnectionState -eq "NotResponding") {
                Write-Error "Unable to configure VMHost $($oThisVmHost): Not Responding"
                continue
            }

            # Set the Product Locker location
            # On ESXi 6.7 Update 1 and later, this API call does not require a reboot to be effective.
            $oThisVmHost.ExtensionData.UpdateProductLockerLocation($sDatastore) | Out-Null

            # Return to pipe
            [PSCustomObject] @{
                "Name"                              = $oThisVmHost.Name
                "VMToolsProductLockerLocation"      = $sDatastore
            }
        }

    }

    End { }
}


# Exported Functions
Export-ModuleMember -Function `
    Copy-VMHostProductLockerContent, `
    Get-VMHostProductLockerLocation, `
    Set-VMHostProductLockerLocation

