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

# SIG # Begin signature block
# MIIl4AYJKoZIhvcNAQcCoIIl0TCCJc0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6r+Gkh7D3aJwQjJyHGwW7UG+
# nHKggh/5MIIEhDCCA2ygAwIBAgIQQhrylAmEGR9SCkvGJCanSzANBgkqhkiG9w0B
# AQUFADBvMQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNV
# BAsTHUFkZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRU
# cnVzdCBFeHRlcm5hbCBDQSBSb290MB4XDTA1MDYwNzA4MDkxMFoXDTIwMDUzMDEw
# NDgzOFowgZUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJVVDEXMBUGA1UEBxMOU2Fs
# dCBMYWtlIENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEhMB8G
# A1UECxMYaHR0cDovL3d3dy51c2VydHJ1c3QuY29tMR0wGwYDVQQDExRVVE4tVVNF
# UkZpcnN0LU9iamVjdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM6q
# gT+jo2F4qjEAVZURnicPHxzfOpuCaDDASmEd8S8O+r5596Uj71VRloTN2+O5bj4x
# 2AogZ8f02b+U60cEPgLOKqJdhwQJ9jCdGIqXsqoc/EHSoTbL+z2RuufZcDX65OeQ
# w5ujm9M89RKZd7G3CeBo5hy485RjiGpq/gt2yb70IuRnuasaXnfBhQfdDWy/7gbH
# d2pBnqcP1/vulBe3/IW+pKvEHDHd17bR5PDv3xaPslKT16HUiaEHLr/hARJCHhrh
# 2JU022R5KP+6LhHC5ehbkkj7RwvCbNqtMoNB86XlQXD9ZZBt+vpRxPm9lisZBCzT
# bafc8H9vg2XiaquHhnUCAwEAAaOB9DCB8TAfBgNVHSMEGDAWgBStvZh6NLQm9/rE
# JlTvA73gJMtUGjAdBgNVHQ4EFgQU2u1kdBScFDyr3ZmpvVsoTYs8ydgwDgYDVR0P
# AQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAGBgRVHSAAMEQG
# A1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9BZGRUcnVz
# dEV4dGVybmFsQ0FSb290LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGG
# GWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEFBQADggEBAE1C
# L6bBiusHgJBYRoz4GTlmKjxaLG3P1NmHVY15CxKIe0CP1cf4S41VFmOtt1fcOyu9
# 08FPHgOHS0Sb4+JARSbzJkkraoTxVHrUQtr802q7Zn7Knurpu9wHx8OSToM8gUmf
# ktUyCepJLqERcZo20sVOaLbLDhslFq9s3l122B9ysZMmhhfbGN6vRenf+5ivFBjt
# pF72iZRF8FUESt3/J90GSkD2tLzx5A+ZArv9XQ4uKMG+O18aP5cQhLwWPtijnGMd
# ZstcX9o+8w8KCTUi29vAPwD55g1dZ9H9oB4DK9lA977Mh2ZUgKajuPUZYtXSJrGY
# Ju6ay0SnRVqBlRUa9VEwggTmMIIDzqADAgECAhBiXE2QjNVC+6supXM/8VQZMA0G
# CSqGSIb3DQEBBQUAMIGVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCVVQxFzAVBgNV
# BAcTDlNhbHQgTGFrZSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdv
# cmsxITAfBgNVBAsTGGh0dHA6Ly93d3cudXNlcnRydXN0LmNvbTEdMBsGA1UEAxMU
# VVROLVVTRVJGaXJzdC1PYmplY3QwHhcNMTEwNDI3MDAwMDAwWhcNMjAwNTMwMTA0
# ODM4WjB6MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEg
# MB4GA1UEAxMXQ09NT0RPIFRpbWUgU3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCqgvGEqVvYcbXSXSvt9BMgDPmb6dGPdF5u7uspSNjI
# vizrCmFgzL2SjXzddLsKnmhOqnUkcyeuN/MagqVtuMgJRkx+oYPp4gNgpCEQJ0Ca
# WeFtrz6CryFpWW1jzM6x9haaeYOXOh0Mr8l90U7Yw0ahpZiqYM5V1BIR8zsLbMaI
# upUu76BGRTl8rOnjrehXl1/++8IJjf6OmqU/WUb8xy1dhIfwb1gmw/BC/FXeZb5n
# OGOzEbGhJe2pm75I30x3wKoZC7b9So8seVWx/llaWm1VixxD9rFVcimJTUA/vn9J
# AV08m1wI+8ridRUFk50IYv+6Dduq+LW/EDLKcuoIJs0ZAgMBAAGjggFKMIIBRjAf
# BgNVHSMEGDAWgBTa7WR0FJwUPKvdmam9WyhNizzJ2DAdBgNVHQ4EFgQUZCKGtkqJ
# yQQP0ARYkiuzbj0eJ2wwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMEIGA1Ud
# HwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VVE4tVVNFUkZp
# cnN0LU9iamVjdC5jcmwwdAYIKwYBBQUHAQEEaDBmMD0GCCsGAQUFBzAChjFodHRw
# Oi8vY3J0LnVzZXJ0cnVzdC5jb20vVVROQWRkVHJ1c3RPYmplY3RfQ0EuY3J0MCUG
# CCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEB
# BQUAA4IBAQARyT3hBeg7ZazJdDEDt9qDOMaSuv3N+Ntjm30ekKSYyNlYaDS18Ash
# U55ZRv1jhd/+R6pw5D9eCJUoXxTx/SKucOS38bC2Vp+xZ7hog16oYNuYOfbcSV4T
# p5BnS+Nu5+vwQ8fQL33/llqnA9abVKAj06XCoI75T9GyBiH+IV0njKCv2bBS7vzI
# 7bec8ckmONalMu1Il5RePeA9NbSwyVivx1j/YnQWkmRB2sqo64sDvcFOrh+RMrjh
# JDt77RRoCYaWKMk7yWwowiVp9UphreAn+FOndRWwUTGw8UH/PlomHmB+4uNqOZrE
# 6u4/5rITP1UDBE0LkHLU6/u8h5BRsjgZMIIE/jCCA+agAwIBAgIQK3PbdGMRTFpb
# MkryMFdySTANBgkqhkiG9w0BAQUFADB6MQswCQYDVQQGEwJHQjEbMBkGA1UECBMS
# R3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFD
# T01PRE8gQ0EgTGltaXRlZDEgMB4GA1UEAxMXQ09NT0RPIFRpbWUgU3RhbXBpbmcg
# Q0EwHhcNMTkwNTAyMDAwMDAwWhcNMjAwNTMwMTA0ODM4WjCBgzELMAkGA1UEBhMC
# R0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9y
# ZDEYMBYGA1UECgwPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDDCJTZWN0aWdvIFNI
# QS0xIFRpbWUgU3RhbXBpbmcgU2lnbmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAv1I2gjrcdDcNeNV/FlAZZu26GpnRYziaDGayQNungFC/aS42Lwpn
# P0ChSopjNZvQGcx0qhcZkSu1VSAZ+8AaOm3KOZuC8rqVoRrYNMe4iXtwiHBRZmns
# d/7GlHJ6zyWB7TSCmt8IFTcxtG2uHL8Y1Q3P/rXhxPuxR3Hp+u5jkezx7M5ZBBF8
# rgtgU+oq874vAg/QTF0xEy8eaQ+Fm0WWwo0Si2euH69pqwaWgQDfkXyVHOaeGWTf
# dshgRC9J449/YGpFORNEIaW6+5H6QUDtTQK0S3/f4uA9uKrzGthBg49/M+1BBuJ9
# nj9ThI0o2t12xr33jh44zcDLYCQD3npMqwIDAQABo4IBdDCCAXAwHwYDVR0jBBgw
# FoAUZCKGtkqJyQQP0ARYkiuzbj0eJ2wwHQYDVR0OBBYEFK7u2WC6XvUsARL9jo2y
# VXI1Rm/xMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMEAGA1UdIAQ5MDcwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYB
# BQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMEIGA1UdHwQ7MDkwN6A1oDOG
# MWh0dHA6Ly9jcmwuc2VjdGlnby5jb20vQ09NT0RPVGltZVN0YW1waW5nQ0FfMi5j
# cmwwcgYIKwYBBQUHAQEEZjBkMD0GCCsGAQUFBzAChjFodHRwOi8vY3J0LnNlY3Rp
# Z28uY29tL0NPTU9ET1RpbWVTdGFtcGluZ0NBXzIuY3J0MCMGCCsGAQUFBzABhhdo
# dHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQUFAAOCAQEAen+pStKw
# pBwdDZ0tXMauWt2PRR3wnlyQ9l6scP7T2c3kGaQKQ3VgaoOkw5mEIDG61v5MzxP4
# EPdUCX7q3NIuedcHTFS3tcmdsvDyHiQU0JzHyGeqC2K3tPEG5OfkIUsZMpk0uRlh
# dwozkGdswIhKkvWhQwHzrqJvyZW9ljj3g/etfCgf8zjfjiHIcWhTLcuuquIwF4Mi
# KRi14YyJ6274fji7kE+5Xwc0EmuX1eY7kb4AFyFu4m38UnnvgSW6zxPQ+90rzYG2
# V4lO8N3zC0o0yoX/CLmWX+sRE+DhxQOtVxzhXZIGvhvIPD+lIJ9p0GnBxcLJPufF
# cvfqG5bilK+GLjCCCGMwggZLoAMCAQICE3sAAAAfz58lqdBV4CsAAwAAAB8wDQYJ
# KoZIhvcNAQELBQAwZzETMBEGCgmSJomT8ixkARkWA25ldDEaMBgGCgmSJomT8ixk
# ARkWCndvbGZzcGlyaXQxEzARBgoJkiaJk/IsZAEZFgNsYW4xHzAdBgNVBAMTFldv
# bGZTcGlyaXQtTmV0LVJvb3QtQ0EwHhcNMTgwMjA0MDQzMjA0WhcNMjMwMjAzMDQz
# MjA0WjBsMRMwEQYKCZImiZPyLGQBGRYDbmV0MRowGAYKCZImiZPyLGQBGRYKd29s
# ZnNwaXJpdDETMBEGCgmSJomT8ixkARkWA2xhbjEkMCIGA1UEAxMbV29sZlNwaXJp
# dC1OZXQtV1NOT0NDQTAxLUNBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEA7Amp0eKHbgrd53sEGpveLh6jCqQb+FTX3GcJyEXXYJK+ENRCEOfkyk6E3gQ7
# GdAurQ5jyQ4pKcbbdPOx0hH5M0cWUW6gcmwd4xF8TXLlytyfPuEeW+6pk+GaVwvn
# qHSn1l4v+c1/QvucinJmiE3g+l4Ugy9of6Bs0RR1ElPTrU6WJrXTDdy0v+6KAfko
# Tda6Er9IQYv8auuP6oSVNK4Re1JAVnLOsIF025US6HzevXYQ8/MBVvIH+SIrPCd/
# Vyv+GjfhtBv8cR3wArUzgRle2m12aM2IcDspFF3ghEj+MtANIGK5iiAZfqHqbaOA
# VHYCsJ+SYjhEgTSsbcU5iuUOqjA8QHlnhDcjgLF3PFpNy1CSphzs0JdUgXB14udp
# YHe2fpuL2YGvjTmKFzQ7nyRCg1LH9M0Lz6BE8nYwMmIY9aWqHuDyrM8NHOwQsTgh
# z2H+ujv1aAh4LqQhKpl1dcqJxh4wfX3PXbuj925lAfhFt/nXhmxjH8cuOWz2Xbjj
# TwbixrcjE0+bSz/CXgAl2+TAdbvOpSb2bvR9+wacY5aQfvlizMYVlkXxkMUA50x8
# HTCIjRg2hyqiCnCSJwHSZ4Cv9GT2myLVoj2nMgGRaKLZHjsv2uR7YKavpANToxXN
# Ais+oXggSDuCH316SHrDy31egM487xsQ4A5bCvkkV7Mcp3MCAwEAAaOCAwEwggL9
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBSYQgSmxSAKbwFuM3B80LHwHKck
# qTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAOBgNVHQ8BAf8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSYNr4hokUsroVXWcTxntn1wArMxDCC
# ASkGA1UdHwSCASAwggEcMIIBGKCCARSgggEQhoHJbGRhcDovLy9DTj1Xb2xmU3Bp
# cml0LU5ldC1Sb290LUNBKDMpLENOPVdTLVJDQSxDTj1DRFAsQ049UHVibGljJTIw
# S2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1s
# YW4sREM9d29sZnNwaXJpdCxEQz1uZXQ/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
# dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50hkJodHRwOi8v
# Y3JsLndvbGZzcGlyaXQubmV0L2NybC9XUy1SQ0EvV29sZlNwaXJpdC1OZXQtUm9v
# dC1DQSgzKS5jcmwwggE+BggrBgEFBQcBAQSCATAwggEsMIG/BggrBgEFBQcwAoaB
# smxkYXA6Ly8vQ049V29sZlNwaXJpdC1OZXQtUm9vdC1DQSxDTj1BSUEsQ049UHVi
# bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
# bixEQz1sYW4sREM9d29sZnNwaXJpdCxEQz1uZXQ/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwaAYIKwYBBQUHMAKG
# XGh0dHA6Ly9jcmwud29sZnNwaXJpdC5uZXQvY3JsL1dTLVJDQS9XUy1SQ0EubGFu
# LndvbGZzcGlyaXQubmV0X1dvbGZTcGlyaXQtTmV0LVJvb3QtQ0EoMykuY3J0MA0G
# CSqGSIb3DQEBCwUAA4ICAQAPl7/8lCaUo11v0vmjA20OFgONmbouCH0sA8+PNwpZ
# 1Ma/F0TOs+SYmO51Sbeq88qDEyjVQJIZHBzLGUOjK793eV6VFHFwAp8mSdgqhDq2
# PiBip0tNUTK2hGasjI8VOt8u4u/6z6bBco0gemTNaOdDDwj6rYr33pPWFvIt3jVM
# tIWZG6YS3nCP0rFv7b6Vxftrn7MnsOrVZDSRoYZviz+igt6vsOrNhgQer0vElQ+s
# 8pvNJQSFzSDXWBwQA6F4jAw3Jtd59iWlbSPr8JIr3CVQ876A8v2sEIpNgsDbzC5B
# z2QEcFW871dnEacllxZ9rSEGVxMvXl1QsAoYlHlJ1SrCIkINJuurKgVAGzn7r+xj
# dJjLMKqBm5T9SguyvFzWWriTYVow+m9pCbNRiSIavKoaUHgXMedyVMTX9YG29QBB
# vvHIrccq6tEcoZkveipX52uHmxImn379jvJNHyZ3Qw1MTJ+D4nKR/1gYMuc2O1ec
# oiuUBV/3j4u73EKHFx9FrP06SjWUUSorwFh/5bQhp2x/5DYlASSXsrazgcG2uNjE
# eGAvaFtO2J3tT8QgITf5QU+qii3HEnsthLXnhkmUQm13WtGeksUPV2lYBwlXjUQ2
# u+UuC4CeBgz0SQD3SsG7Jm0wqr5ekyfQ920FJx5YjpCFNwbRe4thNTxM253tWyPx
# 7zCCCRowggcCoAMCAQICE2MAAAEYGCPlSld5JaIAAAAAARgwDQYJKoZIhvcNAQEL
# BQAwbDETMBEGCgmSJomT8ixkARkWA25ldDEaMBgGCgmSJomT8ixkARkWCndvbGZz
# cGlyaXQxEzARBgoJkiaJk/IsZAEZFgNsYW4xJDAiBgNVBAMTG1dvbGZTcGlyaXQt
# TmV0LVdTTk9DQ0EwMS1DQTAeFw0xOTAxMjAyMjQ2MDhaFw0yMDAxMjAyMjQ2MDha
# MIGcMRMwEQYKCZImiZPyLGQBGRYDbmV0MRowGAYKCZImiZPyLGQBGRYKd29sZnNw
# aXJpdDETMBEGCgmSJomT8ixkARkWA2xhbjETMBEGA1UECxMKV29sZlNwaXJpdDEO
# MAwGA1UECxMFVXNlcnMxDzANBgNVBAsTBkh1bWFuczEeMBwGA1UEAxMVTWF0dGhl
# dyBTY2hhY2hlcmJhdWVyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# zCLOeIK9NQaXU1u1clCuYWXhafHBV81Ds/Ye97+0fsjLK7kcyA4TFbJO1ZAubDk/
# ts5Usa1L3fV6eWt4PsaKuW7NyBYaeDeb7by/AWz66axDWLNissrbW3og9ZfwepA/
# 84/+cXF2Tp/1MPrEvTzEUQQEtBgtA79uJ7jpfhCyV5ItT1dB74O3ekGR3LY2LMme
# bWKEX1dV3Ksh3rwLO90qQzxFredKPaNZ9L21IGCcF5q3+A2vQf9VCw/hssD2FiKp
# yOfiiZJEowCQmYv2CENVVeerqpS37P7RpCZTSQT8ahWSm+JqYtcltyAFKHQkw3x7
# cQXvL8yjhTa7OctgL/qp+alFS6B7ZJ8pUAePR5FaCxNi2ti4CvlsaWnT96953xTE
# DtkUKzPFT8dIfklvQuPu0uWQE/FNh8xE758qqZOZPwJd5+Lkfnr5zqRWgyuJck4x
# 51frnXqRVL4TCcEYzeSmzjpSwlBysdn0FBvsbdu1xjAR0Jh1iKQTSaCbg/iw0sXY
# /IAtTvEC2epU0RaA4nmoYj6boihPo8jTCg3x8NcfnF8nTdvd+wNe/gShjrsNU3YH
# saBkW4c1v/e6wGUXnEDYkBvGiOK5uIf/uOV742tUy7kQPr0fOg+/dWK9BWQn3mS0
# iWG2BHgUG57knHEoQF9Mrc2G3GPZFlwKMmMsy7roBWECAwEAAaOCA4IwggN+MD0G
# CSsGAQQBgjcVBwQwMC4GJisGAQQBgjcVCILfjEGCwqxsgo2XIYP39QqGqIp3DIOZ
# 3ymC2KYmAgFkAgEcMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIH
# gDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMDMDUGA1UdEQQuMCygKgYKKwYB
# BAGCNxQCA6AcDBptYXR0aGV3QGxhbi53b2xmc3Bpcml0Lm5ldDAdBgNVHQ4EFgQU
# cqNJ8XykqG3Z4l1lHcQbaZL5fwQwHwYDVR0jBBgwFoAUmEIEpsUgCm8BbjNwfNCx
# 8BynJKkwggEzBgNVHR8EggEqMIIBJjCCASKgggEeoIIBGoaBzmxkYXA6Ly8vQ049
# V29sZlNwaXJpdC1OZXQtV1NOT0NDQTAxLUNBLENOPVdTTk9DQ0EwMSxDTj1DRFAs
# Q049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmln
# dXJhdGlvbixEQz1sYW4sREM9d29sZnNwaXJpdCxEQz1uZXQ/Y2VydGlmaWNhdGVS
# ZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBv
# aW50hkdodHRwOi8vY3JsLndvbGZzcGlyaXQubmV0L2NybC9XU05PQ0NBMDEvV29s
# ZlNwaXJpdC1OZXQtV1NOT0NDQTAxLUNBLmNybDCCAUsGCCsGAQUFBwEBBIIBPTCC
# ATkwgcQGCCsGAQUFBzAChoG3bGRhcDovLy9DTj1Xb2xmU3Bpcml0LU5ldC1XU05P
# Q0NBMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bGFuLERDPXdvbGZzcGlyaXQsREM9
# bmV0P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9u
# QXV0aG9yaXR5MHAGCCsGAQUFBzAChmRodHRwOi8vY3JsLndvbGZzcGlyaXQubmV0
# L2NybC9XU05PQ0NBMDEvV1NOT0NDQTAxLmxhbi53b2xmc3Bpcml0Lm5ldF9Xb2xm
# U3Bpcml0LU5ldC1XU05PQ0NBMDEtQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQDU
# 5wX+jmLjXyf6pjvIFBLz2I7ZKAtAcunfaMYeD6sOzTnA497zSZZ6WW/yn9QHpBxx
# xQnjigdiP1+86sNAYSp6p+M/YTgpANHSZGh4ykMNT0zu47l0DW1+n/U/9FMYIEW+
# 2TPCQ2zbtiem/IdViBWLXLmsvQcxZkJ132Ys1CUruMmQCex+06jWQQgmzK0hC409
# xx5YDUs7Ije/XkID/Hm5OTm3Bg1VrV67yOdt9CkMovbk0brA3kMWrLB5DPUjswVa
# 7l8LFWNZw/RiehJvzK0XmMJi7dSYCzHG67b4a91DJTYKsEpK5RSVZHC5Sol7PKLL
# 8GMCrtf524GKtsYCTz/A/6neOpexop2IfD54v4MVTsyPad8HLWmuqfN2J+WjZ3Wh
# CSPwn/8DlDnyXMnTZRmomBc1e+SFyySRJwKMxnPCz61kUPe4mH2Lax5tHBeEwQz/
# JDnFe5SXjLtloYdjd3xGjFq9VxssDqGXm4w2Oniwrxb+r0fMsFhIxwp9BGJ9LRHJ
# ibcHx7OQ0aS+aIyx70Y73+beu4rTCMhfAnRetd4kVfc4Ixt1niEdFau9bhIay/fC
# do1DJqH5dj9sDrQA9xIzX8fS61yDfYNJothMQ9lEhU6dPN2kODr7CtGTgCmnsAu3
# qpmqRTGY6ovfOGSCtEFn1X5Ol89wPCbRu+j1xjCjzDGCBVEwggVNAgEBMIGDMGwx
# EzARBgoJkiaJk/IsZAEZFgNuZXQxGjAYBgoJkiaJk/IsZAEZFgp3b2xmc3Bpcml0
# MRMwEQYKCZImiZPyLGQBGRYDbGFuMSQwIgYDVQQDExtXb2xmU3Bpcml0LU5ldC1X
# U05PQ0NBMDEtQ0ECE2MAAAEYGCPlSld5JaIAAAAAARgwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FL1zASbWHjcQvg39GvnSqfNfxXoaMA0GCSqGSIb3DQEBAQUABIICAAVJFqBXoGH0
# hmDlZS3melfidK+67XdjdRifW9eqL+TCkACvNhFUxWGNpQTfI5sTojXzhYUTVJdW
# 8f1Qhqh9djRIGFRduEuh7VkeEDuFdipkh/nHYMRfUFLWK68OeSJqgS4h6NM2yuRF
# XlnORzIJM8gNbvHjxmXdCb8hSZb22bwq7zH42MdlnS9IPyk2A8vh+d0hwGA35VPo
# HwXZShGmo9cc2YdTMdsSccUdgUOQQfYjuntEKCaa1l5dqVLx+zzw2vot8ei4FWhS
# FaQnoYTMvp0k/mOPc6N/RYaO2oJ5yFNipdpKukbA3lAYjYzPKR+3zpfNn7gG8bXo
# tIZU7spT1I2ub5H2MogqHHE6145iuAbumLvvF5xsGmNz46+0G6k9aNOC77Ljg1uw
# ydi9toaIqEhunjV2aHfTmo1Mr5pjl/LvcZmzZy+4pM8XHk5l81ERBFrkzYExk9y7
# /0kRP1j/jtnJsGo7hwbISY5qNWNQW6/2JXN0Wsza8099wEC+/YLxO1ymSRoQGk77
# Y32Tr3v4MgFtHaLvEoEMt9+U8kKTyfJFWdOqARD9J6+YpZfU7m9U8hMQ7gTkUStl
# bSXzZ79L2TV+IePhrC9hckc3qyNeDBdFhqrzcip2fhl8DT6dgsnd4ISWAUawYwpw
# FnJi9VnM7zi1kV1/PHYyslfqDUJvmfVzoYICKDCCAiQGCSqGSIb3DQEJBjGCAhUw
# ggIRAgEBMIGOMHoxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNo
# ZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1p
# dGVkMSAwHgYDVQQDExdDT01PRE8gVGltZSBTdGFtcGluZyBDQQIQK3PbdGMRTFpb
# MkryMFdySTAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMTkwNTI0MTUzNjA1WjAjBgkqhkiG9w0BCQQxFgQUi71z
# RKuWLTu6t/tWtD/gv7pUL+wwDQYJKoZIhvcNAQEBBQAEggEADsRXVx202JEnlatm
# /kYWdytz/gIV5E2NiNey63uXKMelOlTGuli1y38rbvTNo7ADEQzNdripZ+e7tUf1
# Oy+4hXNI2aU5D0oCjC3L4QYSVsb4mgXc/5HwGeJA64AwiP2SQcR4e6/548fIcvdw
# 2jFhBLzp4r6HrNbhzRWNPXGu/I2uTd8gl+ymRVbRBJitaoFaavl/PNoZb4GnM2Rw
# 7bt91bfnZABxfWqNh/vRrQIAkuIDySudFBWtxxf0/9Un0svzzwmci9MUDGrMjYoC
# m5hJid3XcPLIQ95RaGVbjNks1SYpSoTeW8gkRR5I310uMiXxuFJkRgwKCKJsnOHy
# TWzi8Q==
# SIG # End signature block
