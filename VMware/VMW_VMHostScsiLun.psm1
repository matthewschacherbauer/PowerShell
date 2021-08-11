<#

VMWARE VCENTER HOST MODULES
VMHostScsiLun

Matthew Schacherbauer
2021-08-11

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

Functions for managing the removal of SCSI LUNs from ESXi hosts.
Typically used for the removal of RDMs where LUNs are not provisioned as datastores.
For instances where a proper datastore exists, using Unmount-Datastore and Detach-Datastore are preferred.

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


Function Attach-ScsiLun {
    <#
    .SYNOPSIS
    Detaches a SCSI LUN by CanonicalName.
    .PARAMETER CanonicalName
    Specify one or more canonical names of SCSI LUNs to be detached, separated by commas.
    .PARAMETER HostName
    Specify one or more hosts to operate on.
    Cannot be used with -ClusterName.
    .PARAMETER ClusterName
    Specify one or more clusters to operate on. All hosts in the designated cluster(s) will be affected.
    Cannot be used with -HostName.
    .EXAMPLE
    Attach-ScsiLun -CanonicalName "naa.60002abcd" -HostName "esxi-456320.infra.example.com"
    .EXAMPLE
    Attach-ScsiLun -CanonicalName "naa.60002abcd","naa.60002abce" -ClusterName "Prod_ESXI"
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2021-08-10

    Version:    1.0
    #>

    [CmdletBinding(SupportsShouldProcess)]
    Param (
        # Define the LUNs to be detached using the Canonical Names.
        [ValidateNotNullOrEmpty()]
        $CanonicalName,         # "naa.60002aabcd","naa.60002aabce","naa.60002aabcf"

        # Use this section when detaching from a single host.
        [Parameter(ParameterSetName="HostList")]
        $HostName,

        # Use this section when detaching from a cluster.
        [Parameter(ParameterSetName="ClusterList")]
        $ClusterName
    )

    # Resolve Parameters
    if ($HostName) {
        $oHostList = Get-VMHost -Name $HostName
    }
    elseif ($ClusterName) {
        $oHostList = Get-Cluster -Name $ClusterName | Get-VMHost
    }


    $i = 0
    foreach ($oThisHost in $oHostList) {
        Write-Verbose "Processing Host: $($oThisHost.Name)"
        # Progress Bar
        Write-Progress -Id 1 -Activity "Processing Host" -Status "Attaching LUN to $($oThisHost.Name)" -PercentComplete ($i++ / $oHostList.count * 100)

        # Ensure the host is accessible
        if ($oThisHost.ConnectionState -notin "Connected","MaintenanceMode") {
            Write-Error "Host ($($oThisHost.Name)) is not connected."
            continue
        }

        # Get host storage subsystem
        $oHostView = Get-View -VIObject $oThisHost
        $oHostStorageView = Get-View -Id $oHostView.ConfigManager.StorageSystem

        # Get matching LUN IDs from host
        $oLunList = $oThisHost | Get-ScsiLun -CanonicalName $CanonicalName

        $j = 0
        foreach ($oThisLun in $oLunList) {
            Write-Verbose "Processing LUN: $($oThisLun.CanonicalName)"
            Write-Progress -ParentId 1 -Activity "Attaching LUN" -Status "Attaching Device $($oThisLun.CanonicalName)" -PercentComplete ($j++ / $oLunList.count * 100)

            # Check state
            if ($oThisLun.ExtensionData.OperationalState -ne "OFF") {
                Write-Warning "Cannot attach LUN $($oThisLun.CanonicalName) to host $($oThisHost.Name): state is $($oThisLun.ExtensionData.OperationalState)."
                continue
            }

            # Detach
            if ($PSCmdlet.ShouldProcess($($oThisLun.CanonicalName),"Attach LUN")) {
                $oHostStorageView.AttachScsiLun($oThisLun.ExtensionData.Uuid)
            }
        }
        Write-Progress -Activity "Attaching LUN" -Completed
    }
    Write-Progress -Activity "Processing Host" -Completed
}


Function Detach-ScsiLun {
    <#
    .SYNOPSIS
    Detaches a SCSI LUN by CanonicalName.
    .PARAMETER CanonicalName
    Specify one or more canonical names of SCSI LUNs to be detached, separated by commas.
    .PARAMETER HostName
    Specify one or more hosts to operate on.
    Cannot be used with -ClusterName.
    .PARAMETER ClusterName
    Specify one or more clusters to operate on. All hosts in the designated cluster(s) will be affected.
    Cannot be used with -HostName.
    .EXAMPLE
    Detach-ScsiLun -CanonicalName "naa.60002abcd" -HostName "esxi-456320.infra.example.com"
    .EXAMPLE
    Detach-ScsiLun -CanonicalName "naa.60002abcd","naa.60002abce" -ClusterName "Prod_ESXI"
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2021-08-10

    Version:    1.0
    #>

    [CmdletBinding(SupportsShouldProcess)]
    Param (
        # Define the LUNs to be detached using the Canonical Names.
        [ValidateNotNullOrEmpty()]
        $CanonicalName,         # "naa.60002aabcd","naa.60002aabce","naa.60002aabcf"

        # Use this section when detaching from a single host.
        [Parameter(ParameterSetName="HostList")]
        $HostName,

        # Use this section when detaching from a cluster.
        [Parameter(ParameterSetName="ClusterList")]
        $ClusterName
    )

    # Resolve Parameters
    if ($HostName) {
        $oHostList = Get-VMHost -Name $HostName
    }
    elseif ($ClusterName) {
        $oHostList = Get-Cluster -Name $ClusterName | Get-VMHost
    }


    $i = 0
    foreach ($oThisHost in $oHostList) {
        Write-Verbose "Processing Host: $($oThisHost.Name)"
        # Progress Bar
        Write-Progress -Id 1 -Activity "Processing Host" -Status "Removing LUN from $($oThisHost.Name)" -PercentComplete ($i++ / $oHostList.count * 100)

        # Ensure the host is accessible
        if ($oThisHost.ConnectionState -notin "Connected","MaintenanceMode") {
            Write-Error "Host ($($oThisHost.Name)) is not connected."
            continue
        }

        # Get host storage subsystem
        $oHostView = Get-View -VIObject $oThisHost
        $oHostStorageView = Get-View -Id $oHostView.ConfigManager.StorageSystem

        # Get matching LUN IDs from host
        $oLunList = $oThisHost | Get-ScsiLun -CanonicalName $CanonicalName

        $j = 0
        foreach ($oThisLun in $oLunList) {
            Write-Verbose "Processing LUN: $($oThisLun.CanonicalName)"
            Write-Progress -ParentId 1 -Activity "Detaching LUN" -Status "Detaching Device $($oThisLun.CanonicalName)" -PercentComplete ($j++ / $oLunList.count * 100)

            # Check state
            if ($oThisLun.ExtensionData.OperationalState -ne "OK") {
                Write-Warning "Cannot detach LUN $($oThisLun.CanonicalName) from host $($oThisHost.Name): state is $($oThisLun.ExtensionData.OperationalState)."
                continue
            }

            # Detach
            if ($PSCmdlet.ShouldProcess($($oThisLun.CanonicalName),"Detach LUN")) {
                $oHostStorageView.DetachScsiLun($oThisLun.ExtensionData.Uuid)
            }
        }
        Write-Progress -Activity "Detaching LUN" -Completed
    }
    Write-Progress -Activity "Processing Host" -Completed
}
