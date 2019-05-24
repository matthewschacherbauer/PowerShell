<#
.SYNOPSIS
Bulk deploy virtual machines from a template file.
.DESCRIPTION
This script takes configuration from a CSV file to bulk deploy several Virtual Machines in succession.
.PARAMETER CsvConfiguration
The CSV file to read deployment instructions from.

	Sample CSV Header
	Name,Template,Folder,HostCluster,DatastoreCluster,CustomizationSpec,NetworkPortgroup,Ip,Subnet,Gateway,DNS0,DNS1,DNS2,DNSSuffix,AdDomainName,AdOuDn,NumCpu,MemoryGB,Disk1GB,Disk2GB,Disk3GB,Disk4GB,Disk5GB,Disk6GB,Disk7GB,Disk8GB,Disk9GB
.PARAMETER Server
The vCenter Server to perform operations against.
Required when the PowerShell session is connected to more than one vCenter.
.PARAMETER Credential
An Active Directory credential for domain join operations.
.PARAMETER DomainController
The Domain Controller to use for Active Directory operations.
If null, a random Domain Controller is used.
.PARAMETER DefaultAdministrator
The user account added to the virtual machine's local administrator group when domain join is performed during customization.
This parameter is ignored if the machine is not joined to Active Directory.
If omitted, defaults to the user running the script.
You must explicitly set this to $null to skip.
.PARAMETER SkipPreCreateAdObject
Skips the pre-creation of the Active Directory computer object.
Note that, if AD join is enabled VMware will still create the object (if needed) in the default
OU during the customization process.
.PARAMETER ReuseExistingAdObject
Reuses an existing Active Directory object with the same name. If the object is currently in use, any existing trust
will be destroyed.
.PARAMETER SkipAdJoin
Skips Active Directory join operations.
Does not pre-create AD objects or join the VM to the domain.
.PARAMETER GuestAdminPassword
The default password assigned to the built-in 'Administrator' or 'root' account in the guest machine during sysprep.
This value is stored and written as plain text and is not intended to be a permanent password.
You should use this value for bootstrapping only.
.PARAMETER SkipCustomization
Skips VM Customization operations. Produces an exact clone.
.PARAMETER SkipNetworking
Skips in-guest networking customizations.
The VM port group is still assigned if one is provided.
.PARAMETER SkipResources
Skips VM resource assignments.
Does not change CPU count or memory assignment.
.PARAMETER SkipStorage
Skips VM storage assignments.
Does not add or increase hard drive capacity.
.PARAMETER AllowDuplicateVmNames
Allows Virtual Machine creation to continue when another machine exists in vCenter with the same name.
If the machines collide on folder, cluster, or other resources, vCenter may reject the creation of the new machine.
.PARAMETER SetNetworkingStartConnected
Starts the VM with networking connected.
.PARAMETER StartVM
Starts the VM after the clone operation completes.
If $false, all configuration options are applied but the VM is left in a Powered Off state.
.PARAMETER Force
Forces operations to complete where possible.
Sets $AllowDuplicateVmNames=$true. Duplicate names in vCenter will be ignored.
Sets $ReuseExistingAdObject=$true. Existing objects in Active Directory will be reused.
.NOTES
Author:		Matthew Schacherbauer
Updated:	2019-05-23

Version:	1.0.1

Known Issues:
* A Windows security logon banner will prevent automatic first logon from occuring. This prevents the GuiRunOnce operation
  from automatically setting local administrators. Only accounts present in the template VM or added by Active Directory
  Group Policy will have administrator rights until the built-in ".\Administrator" account is logged in once.
* The GuestAdminPassword is not encrypted and may be output to the terminal in plaintext if Verbose is enabled. This option
  is intended only for bootstrapping the first login when the password in the template is not appropriate for use. It is
  expected that LAPS or another security mechanism will change this password.

Change Log:
2019-05-23	v1.0.1
	* Fix required modules syntax
2018-07-25	v1.0
	* Initial Release

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

#Requires -Modules VMware.PowerCLI,VMware.VimAutomation.Core,ActiveDirectory
#Requires -Version 3.0

[CmdletBinding(SupportsShouldProcess,DefaultParameterSetName="ActiveDirectory")]
Param (
	# Globally Mandatory Parameters
	[Parameter(Mandatory,Position=0)]
	[ValidateNotNullOrEmpty()]
	[string]		$CsvConfiguration				= ".\BulkDeployVmFromTemplate.csv",
					$Server,

	# Active Directory Join Parameters
	[Parameter(ParameterSetName="ActiveDirectory",Mandatory,HelpMessage="Active Directory join credentials")]
	[ValidateNotNullOrEmpty()]
	[PSCredential]	$Credential,
	[Parameter(ParameterSetName="ActiveDirectory")]
	[string]		$DomainController,
	[Parameter(ParameterSetName="ActiveDirectory")]
	[string]		$DefaultAdministrator			= $ENV:UserName,
	[Parameter(ParameterSetName="ActiveDirectory")]
	[switch]		$SkipPreCreateAdObject,
	[Parameter(ParameterSetName="ActiveDirectory")]
	[switch]		$ReuseExistingAdObject,

	# Workgroup Join Parameters
	[Parameter(ParameterSetName="Workgroup",Mandatory)]
	[ValidateNotNull()]
	[switch]		$SkipAdJoin,

	# Globally Optional Parameters
	[string]		$GuestAdminPassword,
	[switch]		$SkipCustomization,
	[switch]		$SkipNetworking,
	[switch]		$SkipResources,
	[switch]		$SkipStorage,
	[switch]		$AllowDuplicateVmNames,
	[bool]			$SetNetworkingStartConnected	= $true,
	[bool]			$StartVm						= $true,
	[switch]		$Force
)


# Import CSV configuration and assign it to a variable.
foreach ($thisDeployment in (Import-CSV -Path $CsvConfiguration)) {

	$vmConfig = [PSCustomObject] @{
		'Vm'						= [PSCustomObject] @{
			'Name'						= $thisDeployment.Name.ToLower()
			'Template'					= $thisDeployment.Template

			'FolderLocation'			= $thisDeployment.Folder

			'HostCluster'				= $thisDeployment.HostCluster
			'DatastoreCluster'			= $thisDeployment.DatastoreCluster
			'CustomizationSpec'			= $thisDeployment.CustomizationSpec

			'Notes'						= "Created by BulkDeployVmFromTemplate.ps1`nInvoked by " + $ENV:UserDomain + "\" + $ENV:UserName
			'GuestAdminPassword'		= $GuestAdminPassword
			'AdminUser'					= $DefaultAdministrator
		}

		'Net'						= [PSCustomObject] @{
			'Set'						= (-not $SkipNetworking)
			'Portgroup'					= $thisDeployment.NetworkPortgroup
			'Ip'						= $thisDeployment.Ip
			'Subnet'					= $thisDeployment.Subnet
			'Gateway'					= $thisDeployment.Gateway
			'Dns0'						= $thisDeployment.DNS0
			'Dns1'						= $thisDeployment.DNS1
			'Dns2'						= $thisDeployment.DNS2
			'DnsSuffix'					= $thisDeployment.DNSSuffix
			'StartConnected'			= $SetNetworkingStartConnected
		}
	
		'Resources'					= [PSCustomObject] @{
			'Set'						= (-not $SkipResources)
			'Cpu'						= $thisDeployment.NumCpu
			'MemoryGB'					= $thisDeployment.MemoryGB
		}

		'Storage'					= [PSCustomObject] @{
			'Set'						= (-not $SkipStorage)
			'SizeGB1'					= $thisDeployment.Disk1GB
			'SizeGB2'					= $thisDeployment.Disk2GB
			'SizeGB3'					= $thisDeployment.Disk3GB
			'SizeGB4'					= $thisDeployment.Disk4GB
			'SizeGB5'					= $thisDeployment.Disk5GB
			'SizeGB6'					= $thisDeployment.Disk6GB
			'SizeGB7'					= $thisDeployment.Disk7GB
			'SizeGB8'					= $thisDeployment.Disk8GB
			'SizeGB9'					= $thisDeployment.Disk9GB
			'Format'					= "Thin"
		}

		'ActiveDirectory'			= [PSCustomObject] @{
			'JoinAD'					= (-not $SkipAdJoin)
			'Credential'				= $null
			'Domain'					= $thisDeployment.AdDomainName
			'OuDn'						= $thisDeployment.AdOuDn
			'Description'				= "Created by BulkDeployVmFromTemplate.ps1`nInvoked by: " + $ENV:UserDomain + "\" + $ENV:UserName
			'ManagedBy'					= $null
		}
		
		'StartVm'					= $StartVm

		'VmHost'					= ""
		'VmDatastore'				= ""
	}

	# Static variables
	$tempCustomizationSpecName = "TempBuildSpec-" + ((New-Guid).Guid).SubString(0,8)

	# Force
	if ($Force) {
		$AllowDuplicateVmNames = $true
		$ReuseExistingAdObject = $true
	}

	# Cleanup/Reversal Object
	# Store a copy of newly created objects for cleanup operations in case of a failure.
	$cleanup = [PSCustomObject] @{
		'Vm'			= $null
		'Customization'	= $null
		'AdObject'		= $null
	}

	# Check for a connection to a vCenter Server.
	if (-not $Global:DefaultViServers) { Throw "Not currently connected to any vCenter Server" }
	if (($Server) -and ($Global:DefaultViServers -notcontains $Server)) { Throw "Not currently connected to the specified vCenter Server" }
	if (( ($Global:DefaultViServers).count -gt 1 ) -and (-not $Server)) { Throw "Connected to multiple vCenter Servers and -Server is not specified" }


	############################################################
	#region Resolve Parameters
	#
	# Resolve input parameters to vCenter objects.
	# Wildcards are supported but must return a single object.
	############################################################
	try {
		Write-Verbose "`n*****`nNEW VM SEQUENCE`nResolving input parameters to vCenter objects`n*****"

		#
		# Check for name entry. Skip lines without a VM name.
		# Used for test files.
		#
		if (-not $vmConfig.Vm.Name) { Throw "No virtual machine name specified." }

		#
		# Check for virtual machine naming collision.
		# If -AllowDuplicateVmNames is specified, duplicate names will be allowed. vCenter will reject duplicate names within the same resource.
		#
		Write-Verbose "Checking for duplicate virtual machine name."
		if (Get-VM -Name $vmConfig.Vm.Name -ErrorAction SilentlyContinue) {
			if (-not $AllowDuplicateVmNames) { Write-Error "Virtual Machine Name is in use: $($vmConfig.Vm.Name). This machine will be skipped."; continue }
			else { Write-Warning "Virtual Machine Name is in use: $($vmConfig.Vm.Name). Force continuing. vCenter will reject this request if the virtual machines overlap in resources." }
		}
		else { Write-Verbose "No duplicate names found." }

		#
		# Resolve virtual machine template.
		#
		Write-Verbose "Resolving virtual machine template."
		if ($vmConfig.Vm.Template) {
			$vmConfig.Vm.Template = (Get-Template -Name $vmConfig.Vm.Template -ErrorAction Stop)
			if ($vmConfig.Vm.Template.count -ne 1) {
				Write-Error "Multiple templates were found for the query. This is not supported. This machine will be skipped."
				Write-Verbose "The following templates were returned:"
				Write-Verbose ($vmConfig.Vm.Template | Out-String)
				continue
			}

			Write-Verbose "OK"
		}
		else { Throw "Missing required parameter: Vm.Template" }

		#
		# Resolve virtual machine folder location.
		#
		Write-Verbose "Resolving virtual machine folder location."
		if ($vmConfig.Vm.FolderLocation) {
			$vmConfig.Vm.FolderLocation = (Get-Folder -Name $vmConfig.Vm.FolderLocation -ErrorAction Stop)
			if ($vmConfig.Vm.FolderLocation.count -ne 1) {
				Write-Error "Multiple target folders were found for the query. This is not supported. This machine will be skipped."
				Write-Verbose "The following target folders were returned:"
				Write-Verbose ($vmConfig.Vm.FolderLocation | Out-String)
				continue
			}

			Write-Verbose "OK"
		}
		else {
			# Notify the user where we're putting the VMs, since no location was specified.
			Write-Warning "No folder location was specified. The default `"Discovered virtual machine`" folder will be used."
			$vmConfig.Vm.FolderLocation = (Get-Folder -Name "Discovered virtual machine" -ErrorAction Stop)
		}

		#
		# Resolve host cluster and select a random host within the cluster for use.
		#
		Write-Verbose "Resolving vCenter host cluster."
		if ($vmConfig.Vm.HostCluster) {
			$vmConfig.Vm.HostCluster = (Get-Cluster -Name $vmConfig.Vm.HostCluster -ErrorAction Stop)
			if ($vmConfig.Vm.HostCluster.count -ne 1) {
				Write-Error "Multiple host clusters were found for the query. This is not supported. This machine will be skipped."
				Write-Verbose "The following host clusters were returned:"
				Write-Verbose ($vmConfig.Vm.HostCluster | Out-String)
				continue
			}

			# Select a random host in a healthy state.
			$vmConfig.VmHost = ($vmConfig.Vm.HostCluster | Get-VMHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-Random)
			if (-not $vmConfig.VmHost) { Write-Error "No suitable host could be found for this VM. Check the available hosts in the cluster or assign another cluster. This machine will be skipped."; continue }

			Write-Verbose "OK"
		}
		else { Throw "Missing required parameter: Vm.HostCluster" }

		#
		# Resolve datastore cluster and select the datastore with the most free space within the cluster.
		#
		Write-Verbose "Resolving vCenter datastore cluster."
		if ($vmConfig.Vm.DatastoreCluster) {
			if ($vmConfig.Vm.DatastoreCluster -like "*vsanDatastore*") {
				# FIX ME
				# This is a code hack to get vsan datastores to be functional, since it isn't found in a cluster.
				$vmConfig.VmDatastore = (Get-Datastore -Name $vmConfig.Vm.DatastoreCluster -ErrorAction Stop)
				Write-Verbose "OK"
			}
			else {
				$vmConfig.Vm.DatastoreCluster = (Get-DatastoreCluster -Name $vmConfig.Vm.DatastoreCluster -ErrorAction Stop)
				if ($vmConfig.Vm.DatastoreCluster.count -ne 1) {
					Write-Error "Multiple datastore clusters were found for the query. This is not supported. This machine will be skipped."
					Write-Verbose "The following datastore clusters were returned:"
					Write-Verbose ($vmConfig.Vm.DatastoreCluster | Out-String)
					continue
				}

				# Select the datastore from the cluster with the most free space.
				$vmConfig.VmDatastore = ($vmConfig.Vm.DatastoreCluster | Get-Datastore | Sort-Object -Property FreeSpaceGB -Descending | Select-Object -First 1)

				Write-Verbose "OK"
			}
		}
		else { Throw "Missing required parameter: Vm.DatastoreCluster" }

		#
		# Resolve guest OS customization.
		#
		if ((-not $SkipCustomization) -and ($vmConfig.Vm.CustomizationSpec)) {
			Write-Verbose "Resolving vCenter guest OS customization specification."
			if ($vmConfig.Vm.CustomizationSpec) {
				$vmConfig.Vm.CustomizationSpec = (Get-OSCustomizationSpec -Name $vmConfig.Vm.CustomizationSpec -ErrorAction Stop)
				if ($vmConfig.Vm.CustomizationSpec.count -ne 1) {
					Write-Error "Multiple customization specifications were found for the query. This is not supported. This machine will be skipped."
					Write-Verbose "The following customization specifications were returned:"
					Write-Verbose ($vmConfig.Vm.CustomizationSpec | Out-String)
					continue
				}
				Write-Verbose "OK"
			}
		}
		else { Write-Verbose "Skipping guest OS customization"; $SkipCustomization = $true }

		#
		# Resolve port group on the host selected earlier.
		# It is required to use a virtual distributed port group. Standard switches are not supported.
		#
		if ($vmConfig.Net.Portgroup) {
			Write-Verbose "Resolving vCenter network portgroup."
			$vmConfig.Net.Portgroup = ($vmConfig.VmHost | Get-VDSwitch | Get-VDPortgroup | Where-Object {$_.Name -like $vmConfig.Net.Portgroup} )
			if ($vmConfig.Net.Portgroup.count -ne 1) {
				Write-Error "Multiple port groups were found for the query. This is not supported. This machine will be skipped."
				Write-Verbose "The following port groups were returned:"
				Write-Verbose ($vmConfig.Net.Portgroup | Out-String)
				continue
			}
			Write-Verbose "OK"
		}
		else { Write-Verbose "Skipping Portgroup." }

		#
		# Check for required networking configurations.
		#
		Write-Verbose "Validating client VM IP configuration."
		if (($vmConfig.Net.Set) -and ((-not $vmConfig.Net.Ip) -or (-not $vmConfig.Net.Subnet) -or (-not $vmConfig.Net.Gateway) -or (-not $vmConfig.Net.Dns0))) {
			Write-Error "Missing parameter: Net.Ip, Net.Subnet, Net.Gateway, or Net.Dns0. Check the networking configuration or use -SkipNetworking. This machine will be skipped."
			continue
		}
		elseif (-not $vmConfig.Net.Set) { Write-Verbose "Disabled by Configuration" }
		else { Write-Verbose "OK" }

		#
		# Check for valid storage format.
		# Valid storage types: 'EagerZeroedThick','Thick','Thick2GB','Thin','Thin2GB'
		#
		Write-Verbose "Validating storage format."
		if (($vmConfig.Storage.Set) -and ( ('EagerZeroedThick','Thick','Thick2GB','Thin','Thin2GB') -notcontains $vmConfig.Storage.Format)) {
			Write-Error "Invalid storage format: $($vmConfig.Storage.Format). This machine will be skipped."
			continue
		}
		else { Write-Verbose "OK" }

		#
		# Check for valid Active Directory join configuration.
		#
		if (($vmConfig.ActiveDirectory.JoinAD) -and ($vmConfig.ActiveDirectory.Domain)) {
			Write-Verbose "Validating ActiveDirectory join configuration."

			# Check for networking configuration (required for successful join)
			if (-not $vmConfig.Net.Set) {
				Write-Warning "No networking configuration was specified for this virtual machine. If DHCP is not available on the specified network segment, Active Directory join operations will fail."
			}

			# Validate credentials.
			Write-Verbose "Checking for Active Directory credentials."
			if ($Credential) {
				$vmConfig.ActiveDirectory.Credential = $Credential
				Write-Verbose "OK"
			}
			else {
				Write-Error "No Active Directory domain join credentials specified. Use the -Credential parameter to pass credentials for Active Directory operations, use -SkipAdJoin to ignore Active Directory instructions, or remove the AdDomain configuration in the CSV for this virtual machine. This machine will be skipped."
				continue
			}

			# Check for existing computer object
			Write-Verbose "Checking for existing Active Directory object."
			try { $adComputer = Get-ADComputer -Identity $vmConfig.Vm.Name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } catch {}		# Trap the warning message that occurs on a null result.
			if (($adComputer) -and (-not $ReuseExistingAdObject)) {
				Write-Error "An existing Active Directory computer object was found with the name ($($vmConfig.Vm.Name)). Remove the object, use -ReuseExistingAdObject to recycle the object, or use -SkipAdJoin to ignore the Active Directory instructions. This machine will be skipped."
				continue
			}
			elseif (($adComputer) -and ($ReuseExistingAdObject)) {
				Write-Warning "An existing Active Directory computer object was found with the name ($($vmConfig.Vm.Name)). ReuseExistingAdObject specified, this object will be reused and any existing trusts will be discarded."
				$SkipPreCreateAdObject = $true
			}
			else {
				Write-Verbose "No existing Active Directory computer object was found. A new one will be created."
			}
		}
		else { Write-Verbose "Active Directory join is disabled or a domain was not specified." }
	}
	catch {
		# Failures in the validation phase are soft failures. The pipeline will continue, but the machine will be skipped.
		Write-Warning "Failed to validate some required parameters. This machine will be skipped. Review the error, correct the problems, and re-run the operation.`nThe error returned was: $($Error[0].Exception.Message)"
		continue
	}
	#endregion Resolve parameters

	Write-Verbose "Deploying VM with the following:"
	Write-Verbose ($vmConfig | Out-String)


	############################################################
	#region Execute Operation
	#
	# Execute actions against vCenter
	# Clone guest OS customization templates and deploy new virtual machines.
	############################################################
	try {
		#############################################################
		#region Build customization template
		#
		# Clone the specified guest OS customization.
		############################################################
		Write-Verbose "`n*****`nSTART TASK`nOS Customization Template`n*****"

		if (-not $SkipCustomization) {
			#
			# Build the splatting variable for the temporary customization.
			#
			$customizationParams = @{
				'Type'			= "Persistent"
				'ErrorAction'	= "Stop"
			}

			# Set the DNS suffix for the machine.
			if (($vmConfig.Net.Set) -and ($vmConfig.Net.DnsSuffix)) {
				Write-Verbose "Adding DNS Suffix to the customization."
				$customizationParams.Add('DnsSuffix', $vmConfig.Net.DnsSuffix)
			}

			# Set the hostname for the machine.
			if ($vmConfig.Vm.Name) {
				Write-Verbose "Adding Hostname to the customization."
				$customizationParams.Add('NamingScheme', "Fixed")
				$customizationParams.Add('NamingPrefix', $vmConfig.Vm.Name)
			}

			# Set the Active Directory join credentials.
			# NOTE: Setting domain accounts in local groups during "GuiRunOnce" occurs at the first logon
			#		of the built-in "local" .\Administrator account. It's best to not depend on this
			#		setting and use an OU that correctly sets local administrators by policy.
			if ($vmConfig.ActiveDirectory.JoinAD) {
				# Set a default local administrator within the VM.
				if ($vmConfig.Vm.AdminUser) {
					$guiRunOnce = @("NET LOCALGROUP Administrators `"$($vmConfig.Vm.AdminUser)`" /ADD","NET USER Administrator /ACTIVE:YES","SHUTDOWN /R /T 5 /C `"Configuration complete. The system will now reboot.`"")
				}
				else {
					$guiRunOnce = @("SHUTDOWN /R /T 5 /C `"Configuration complete. The system will now reboot.`"")
				}

				Write-Verbose "Adding Active Directory join configuration to the customization."
				$customizationParams.Add('Domain', $vmConfig.ActiveDirectory.Domain)
				$customizationParams.Add('DomainUsername', $vmConfig.ActiveDirectory.Credential.GetNetworkCredential().Username)
				$customizationParams.Add('DomainPassword', $vmConfig.ActiveDirectory.Credential.GetNetworkCredential().Password)
				$customizationParams.Add('AutoLogonCount', "1")
				$customizationParams.Add('GuiRunOnce', $guiRunOnce)
			}

			# Set the default Administrator account password.
			# NOTE: This is accepted as plaintext and is not intended to be a permanent password.
			if ($vmConfig.Vm.GuestAdminPassword) {
				Write-Verbose "Adding Admin Password to the customization."
				$customizationParams.Add('AdminPassword', $vmConfig.Vm.GuestAdminPassword)
			}
			

			#
			# Create temporary customization specification.
			#
			if($PSCmdlet.ShouldProcess($vmConfig.Vm.CustomizationSpec,"Clone OS Customization Specification")) {
				$osCustSpec = $cleanup.Customization = Get-OSCustomizationSpec -Name $vmConfig.Vm.CustomizationSpec | New-OSCustomizationSpec -Name $tempCustomizationSpecName
				$osCustSpec | Set-OSCustomizationSpec @customizationParams | Out-Null
				Write-Verbose "OK"
			}

			#
			# Set the networking for NIC0 in the specification.
			#
			if ($vmConfig.Net.Set) {
				# Set IP addressing for the machine.
				if($PSCmdlet.ShouldProcess($osCustSpec,"Set Networking Configuration")) {
					$osCustSpec | Get-OSCustomizationNicMapping | Sort-Object -Property Position | Select-Object -First 1 | `
						Set-OSCustomizationNicMapping `
							-IpMode UseStaticIP `
							-IPAddress $vmConfig.Net.Ip `
							-SubnetMask $vmConfig.Net.Subnet `
							-DefaultGateway $vmConfig.Net.Gateway `
							-Dns $vmConfig.Net.Dns0,$vmConfig.Net.Dns1,$vmConfig.Net.Dns2 `
							-ErrorAction Stop | Out-Null
					Write-Verbose "OK"
				}
			}

			#
			# Refresh Object
			#
			if($PSCmdlet.ShouldProcess($osCustSpec,"Refresh OS Customization")) {
				$osCustSpec = $cleanup.Customization = Get-OSCustomizationSpec -Name $osCustSpec -ErrorAction Stop
			}
		}
		else { Write-Verbose "Skipping guest OS customization" }
		#endregion Build customization template


		#############################################################
		#region Clone and customize VM
		#
		#############################################################
		Write-Verbose "`n*****`nSTART TASK`nConfigure New Virtual Machine`n*****"

		#
		# Build the splatting variable for the virtual machine creation.
		#
		Write-Verbose "Building configuration options for New-VM."
		$newVmParams = @{
			'Name'				= $vmConfig.Vm.Name
			'Template'			= $vmConfig.Vm.Template
			'VMHost'			= $vmConfig.VmHost
			'Datastore'			= $vmConfig.VmDatastore
			'DiskStorageFormat'	= "Thin"
			'Location'			= $vmConfig.Vm.FolderLocation
			'ErrorAction'		= "Stop"
		}

		# Set OS Customization
		if ((-not $SkipCustomization) -and ($osCustSpec)) {
			Write-Verbose "Setting OS Customization."
			$newVmParams.Add('OSCustomizationSpec', $osCustSpec)
		}

		# Set VM Notes
		if ($vmConfig.Vm.Notes) {
			Write-Verbose "Setting VM notes."
			$newVmParams.Add('Notes', $vmConfig.Vm.Notes)
		}
		

		#
		# Start VM Cloning Process
		#
		Write-Verbose "Starting VM Clone Operation"
		if($PSCmdlet.ShouldProcess($vmConfig.Vm.Name,"Clone VM")) {
			$buildVm = $cleanup.Vm = New-VM @newVmParams
			Write-Verbose "OK"
		}

		#
		# Set VM resources
		#
		if (($vmConfig.Resources.Set) -and ($vmConfig.Resources.Cpu) -and ($vmConfig.Resources.MemoryGB)) {
			# Create splatting variable
			$setVmParams = @{
				'ErrorAction'		= "Continue"
				'Confirm'			= $false
			}

			# CPU Resource
			if ($vmConfig.Resources.Cpu) {
				Write-Verbose "Setting CPU Resource Allocation"
				$setVmParams.Add('NumCpu', $vmConfig.Resources.Cpu)
			}

			# Memory Resource
			if ($vmConfig.Resources.MemoryGB) {
				Write-Verbose "Setting Memory Resource Allocation"
				$setVmParams.Add('MemoryGB', $vmConfig.Resources.MemoryGB)
			}

			# Commit
			if($PSCmdlet.ShouldProcess($buildVm,"Set VM Resources")) {
				$buildVm | Set-VM @setVmParams | Out-Null
				if ($?) { Write-Verbose "OK" }
			}
		}

		#
		# Set VM storage
		# Check for an existing disk for disks 1-6. Expand the disk to the requested size if it exists, or create a new disk of it does not.
		#
		if ($vmConfig.Storage.Set) {
			Write-Verbose "Setting storage configuration"
			for ($i=1; $vmConfig.Storage."SizeGB$i"; $i++) {
				if ($vmConfig.Storage."SizeGB$i") {
					Write-Verbose "Checking for an existing Hard disk $i"
					$thisDisk = $buildVM | Get-HardDisk | Where-Object {$_.Name -eq "Hard disk $i"}

					if ($thisDisk) {
						Write-Verbose "Found. Will expand."
						# Don't check that the disk is smaller than the requested size. We'll allow and
						# suppress the failure if the user attempts to shrink the disk.
						if($PSCmdlet.ShouldProcess($buildVm,"Expanding Hard Drive $i")) {
							$thisDisk | Set-HardDisk `
								-CapacityGB $vmConfig.Storage."SizeGB$i" `
								-ErrorAction Continue `
								-Confirm:$false | Out-Null
							if ($?) { Write-Verbose "OK" }
						}
					}

					else {
						Write-Verbose "Not found. Will create."
						if($PSCmdlet.ShouldProcess($buildVm,"Create Hard Drive $i")) {
							$buildVm | New-HardDisk `
									-CapacityGB $vmConfig.Storage."SizeGB$i" `
									-StorageFormat $vmConfig.Storage.Format `
									-ErrorAction Continue `
									-Confirm:$false | Out-Null
							if ($?) { Write-Verbose "OK" }
						}
					}
				}
			}
			Write-Verbose "Storage configuration completed."
		}
		else { Write-Verbose "Storage configuration is disabled." }

		#
		# Set VM network portgroup
		#
		if ($vmConfig.Net.Portgroup) {
			if($PSCmdlet.ShouldProcess($buildVm,"Set Network Portgroup")) {
				$buildVm | Get-NetworkAdapter | Where-Object {$_.Name -eq "Network adapter 1"} | `
					Set-NetworkAdapter -Portgroup $vmConfig.Net.Portgroup -ErrorAction Continue -Confirm:$false | Out-Null
				if ($?) { Write-Verbose "OK" }
			}
		}

		#
		# Set VM network connectivity
		#
		if ($vmConfig.Net.StartConnected -ne $null) {
			if($PSCmdlet.ShouldProcess($buildVm,"Set Network Connectivity")) {
				$buildVm | Get-NetworkAdapter | Where-Object {$_.Name -eq "Network adapter 1"} | `
					Set-NetworkAdapter -StartConnected $vmConfig.Net.StartConnected -ErrorAction Continue -Confirm:$false | Out-Null
				if ($?) { Write-Verbose "OK" }
			}
		}


		#
		# Create Active Directory object
		#
		if (($vmConfig.ActiveDirectory.JoinAD) -and ($vmConfig.ActiveDirectory.Credential) -and ($vmConfig.ActiveDirectory.Domain) -and (-not $SkipPreCreateAdObject)) {
			if($PSCmdlet.ShouldProcess($vmConfig.ActiveDirectory.Domain,"Pre-Create Active Directory Object")) {
				# Create hash table New-ADComputer parameters
				$createParams = @{
					'Name'			= $vmConfig.Vm.Name
					'Credential'	= $vmConfig.ActiveDirectory.Credential
					'ManagedBy'		= $vmConfig.ActiveDirectory.ManagedBy
					'ErrorAction'	= "Continue"
				}

				# Add description, if present.
				if ($vmConfig.ActiveDirectory.Description) { $createParams.Add('Description', $vmConfig.ActiveDirectory.Description) }

				# Check for valid organizational unit. If invalid, clear the OU and use the default.
				if ($vmConfig.ActiveDirectory.AdOuDn) {
					$adOu = Get-ADOrganizationalUnit $vmConfig.ActiveDirectory.AdOuDn -ErrorAction SilentlyContinue

					if ($adOu) {
						Write-Verbose "Found OU"
						$createParams.Add('Path', $adOu)
					}
					else { Write-Verbose "No matching AD OU was found. The default will be used." }
				}
				else {
					Write-Verbose "No AD OU was specified. The computer object will be created in the default OU."
				}

				if($PSCmdlet.ShouldProcess($buildVm,"Create AD Computer Object")) {
					$cleanup.AdObject = New-ADComputer @createParams | Out-Null
					if ($?) { Write-Verbose "OK" }
				}
			}
		}
		else { Write-Verbose "Skipped pre-creation of Active Directory computer object." }

		#
		# Start VM.
		# Return the newly created VM object to the pipeline. This is the only data returned on a normal run.
		#
		if ($vmConfig.StartVm) {
			if($PSCmdlet.ShouldProcess($buildVm,"Start VM")) {
				$buildVm | Start-VM -ErrorAction Continue
				if ($?) { Write-Verbose "OK" }
			}
		}
		else {
			Get-Vm -Name $buildVm -ErrorAction Continue
		}
		#endregion Clone and customize VM
	}
	catch {
		#
		# Cleanup process for failure scenarios.
		# Removes unfinished Virtual Machine and Active Directory objects.
		#
		
		# Stop the pipe and notify the user that Virtual Machine creation failed.
		Write-Warning "

######################################################################################################
Virtual machine creation process failed or was interrupted.
Starting cleanup operations due to failure. Deletions are interactive.
You will be prompted for cleanup operations on objects created during the script run.

This failure halts the pipeline. Additional virtual machines will not be created in this run.
Correct the error(s) and re-run the script.
######################################################################################################

"

		# Remove created vCenter Virtual Machine object
		# If this value is $null, then no object was created and nothing should be done.
		if ($cleanup.Vm) {
			Write-Warning "`nA defunct Virtual Machine object was created in vCenter. Remove?`n$($cleanup.Vm)"
			$cleanup.Vm | Remove-VM -DeletePermanently -ErrorAction Continue -Confirm:$true
		}
		else { Write-Verbose "No virtual machine object was found for cleanup." }

		# Remove created Active Directory computer object
		# If this value is $null, then no object was created and nothing should be done.
		if ($cleanup.AdObject) {
			Write-Warning "`nA defunct Active Directory computer object was created. Remove?`n$($cleanup.Ad)"
			$cleanup.AdObject | Remove-ADComputer -ErrorAction Continue -Confirm:$true
		}
		else { Write-Verbose "No Active Directory computer object was found for cleanup." }

		# Customization will be cleaned up in the finally{} stage

		# Bailing out permanently.
		Throw $Error[0]
	}
	finally {
		#
		# Cleanup temporary OS customization template
		#
		if ($osCustSpec) {
			if($PSCmdlet.ShouldProcess($osCustSpec,"Remove OS Customization")) {
				Get-OSCustomizationSpec -Name $osCustSpec -ErrorAction Continue | Remove-OSCustomizationSpec -ErrorAction Continue -Confirm:$false
			}
		}
	}
	#endregion Execute operation
}


####################
## SIGNATURE
####################	
