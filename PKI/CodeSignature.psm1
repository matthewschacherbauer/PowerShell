<#

CODE SIGNING MODULE

Matthew Schacherbauer
2024-04-29

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

===============

Signs code using a code signing certificate in the local certificate store.

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


Function ChooseSigningCertificate {
	<#
	.NOTES
	Author:		Matt Schacherbauer
	Updated:	2019-07-09
	
	Version:	1.5

	Helper Function
	Display a list of valid code signing certificates for the current user and prompt
	the user to select a certificate.
	#>

	Param (
		$Thumbprint
	)

	# Variables
	[int] $iCertificateIndex = -1

	# Get list of valid signing certificates for the calling user.
	[System.Security.Cryptography.X509Certificates.X509Certificate2[]] $oCertificates = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert

	# Filter expired certificates.
	$oCertificates = $oCertificates | Where-Object { $_.NotAfter -ge (Get-Date) }

	# Thumbprint specified.
	if ($Thumbprint) {
		$oCertificates = $oCertificates | Where-Object { $_.Thumbprint -eq $Thumbprint }

		if (-not $oCertificates) {
			Throw "The supplied thumbprint does not exist or is not valid for use."
		}
	}

	# Choose a certificate
	[int] $iCertificatesCount = $oCertificates.count
	if ($iCertificatesCount -eq 0) { #IF no valid certificates.
		Throw "No signing certificates were found in the system. The script cannot continue.`nPlease install one or more signing certificates into the certificate store."; break
	} #ENDIF no valid certificates.
	elseif ($iCertificatesCount -eq 1) { #IF one valid certificate.
		Write-Verbose "Only one valid certificate was found in the system. It will be selected automatically."
		$sCertificateThumbprint = $oCertificates.Thumbprint
	} #ENDIF one valid certificate.
	else { #IF choose a certificate to use.
		Write-Warning "Multiple valid certificates are available, and no certificate was specified. Here are a list of current certificates in the system. Enter the thumbprint of the certificate you want to use for signing."
		Write-Host $($oCertificates | Select-Object Thumbprint,Subject,Issuer,EnhancedKeyUsageList,NotAfter | Format-List | Out-String)
		$sCertificateThumbprint = ""
	} #ENDIF choose a certificate to use.

	while ( -not ($oCertificates | Where-Object {$_.Thumbprint -eq $sCertificateThumbprint} ) ) { #WHILE cert choice not valid.
		[string] $sCertificateThumbprint = (Read-Host "Signing certificate thumbprint").Trim()
	} #END WHILE cert choice not valid.

	# Return selected certificate
	return $oCertificates | Where-Object { $_.Thumbprint -eq $sCertificateThumbprint }
}


Function New-CodeSignature {
	<#
	.SYNOPSIS
	Signs a PowerShell script using a code signing certificate from the certificate store.
	.EXAMPLE
	New-CodeSignature -FilePaths .\filename.ps1
	.NOTES
	Author:		Matt Schacherbauer
	Updated:	2023-04-07
	
	Version:	1.6
	.LINK
	https://github.com/matthewschacherbauer
	http://www.matthewschacherbauer.com
	#>

	[CmdletBinding(SupportsShouldProcess)]
	Param(
		# Input files
		[Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
		[Alias('FullName')]
		[ValidateScript({Test-Path -Path $_})]
		[string[]]	$Path,
		
		[ValidateSet('SHA1','SHA256')]
		[string]	$HashAlgorithm		= "SHA256",

		[System.Security.Cryptography.X509Certificates.X509Certificate2]	$Certificate,
		[string]	$Thumbprint,

		# Timestamp Configuration
		[switch]	$SkipTimestamp		= $false,
		[ValidateNotNullOrEmpty()]
		[string]	$TimestampServer	= "http://timestamp.comodoca.com",

		# Configuration
		[switch]	$SkipSigned			= $false,
		[switch]	$SkipUnsigned		= $false
	)

	Begin {
		# Validate or select a code signing certificate
		if ($Certificate) { #IF signing certificate specified.
			Write-Verbose "Using provided code signing certificate."
			[System.Security.Cryptography.X509Certificates.X509Certificate2] $oCertificate = $Certificate
		}
		elseif ($Thumbprint) { #IF signing certificate thumbprint specified.
			Write-Verbose "Using provided code signing thumbprint."
			[System.Security.Cryptography.X509Certificates.X509Certificate2] $oCertificate = ChooseSigningCertificate -Thumbprint $Thumbprint
		}
		else { #ELSEIF no signing certificate specified.
			Write-Verbose "No code signing certificate specified."
			[System.Security.Cryptography.X509Certificates.X509Certificate2] $oCertificate = ChooseSigningCertificate
		}

		$oSigningConfiguration = [PSCustomObject] @{
			'Subject'			= $oCertificate.Subject
			'Issuer'			= $oCertificate.Issuer
			'Thumbprint'		= $oCertificate.Thumbprint
			'NotBefore'			= $oCertificate.NotBefore
			'NotAfter'			= $oCertificate.NotAfter
			'TimeServer'		= $TimestampServer
			'SkipTimeServer'	= $SkipTimestamp
			'SkipSigned'		= $SkipSigned
			'SkipUnSigned'		= $SkipUnsigned
		}
		
		Write-Verbose "*** The following certificate will be used for signing ***"
		Write-Verbose ($oSigningConfiguration | Out-String)
	}


	Process {
		# Loop over files to sign.
		foreach ($thisPath in $Path) { #FOREACH file
			if ((Test-Path $thisPath) -eq $true) { #IF file path is valid.
				Write-Verbose "Processing file: $thisPath"
				$thisPath = Get-Item -Path $thisPath
				
				if ($SkipUnsigned) { #IF skipUnsigned certs requested.
					if ((Get-AuthenticodeSignature $thisPath | Select-Object -ExpandProperty Status ) -ne 'Valid') {
						Write-Verbose "File skipped (-skipUnsigned): Unsigned or invalid."
						continue
					}
				} #ENDIF skipUnsigned
				
				if ($SkipSigned) { #IF skipSigned certs requested.
					if ((Get-AuthenticodeSignature $thisPath | Select-Object -ExpandProperty Status ) -eq 'Valid') {
						Write-Warning "File skipped (-skipSigned): Valid."
						continue
					}
				} #ENDIF skipSigned

				# Sign the script with the certificate.
				if ($pscmdlet.ShouldProcess("$thisPath", "Signing File")) {
					$p = @{
						"FilePath" = $thisPath
						"Certificate" = $oCertificate
						"HashAlgorithm" = $HashAlgorithm
						"IncludeChain" = "All"
					}
					if (-not $SkipTimestamp) { $p.Add('TimestampServer', $TimestampServer) }

					$oSignatureStatus = Set-AuthenticodeSignature @p

					if ($oSignatureStatus.Status -eq 'Valid') { Write-Verbose "Signed successfully: $thisPath" }
					else { Write-Error "Error signing: $thisPath" }
				}
			} #ENDIF file path is valid.
			else { Write-Warning "The path ($thisPath) doesn't exist. Skipping this entry."; } #ELSE file path is invalid.
		} #END FOREACH file
	}


	End { }

}


# Exported Functions
Export-ModuleMember -Function New-CodeSignature

