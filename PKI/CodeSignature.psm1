<#

Code Signing Module

Matthew Schacherbauer
2019-03-15

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


Function New-CodeSignature {
	<#
	.SYNOPSIS
	Signs a PowerShell script using a code signing certificate from the certificate store.
	.EXAMPLE
	New-CodeSignature -FilePaths .\filename.ps1
	.NOTES
	Author:		Matt Schacherbauer
	Updated:	2017-12-11
	
	Version:	1.3.1
	.LINK
	http://www.matthewschacherbauer.com
	#>

	[CmdletBinding(SupportsShouldProcess=$True)]
	param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[Alias('FullName')]
		[string[]]	$filePaths,
		[int]		$certSignIndex		= -1,
		[string]	$timestampServer	= "http://timestamp.comodoca.com",
		[switch]	$skipSigned			= $false,
		[switch]	$skipUnsigned		= $false,
		[switch]	$skipTimestamp		= $false
	)


	begin {
		Function ChooseSigningCertificate {
			[CmdletBinding()]
			param(
				[int]		$certSignIndex		= -1
			)

			# Get list of valid signing certificates for the calling user.
			$signingCertificates = Get-ChildItem cert:\CurrentUser\My -codesign

			# Choose a certificate
			$signingCertificatesCount = $signingCertificates.count - 1
			if ($signingCertificatesCount -lt 0) { #IF no valid certificates.
				Throw "No signing certificates were found in the system. The script cannot continue.`nPlease install one or more signing certificates into the certificate store."; break
			} #ENDIF no valid certificates.
			elseif ($signingCertificatesCount -eq 0) { #IF one valid certificate.
				Write-Host "Only one valid certificate was found in the system. It will be selected automatically."
				$certSignIndex = 0
			} #ENDIF one valid certificate.
			else { #IF choose a certificate to use.
				Write-Host "`nHere are a list of current certificates in the system. Enter the index of the certificate you want to use for signing beginning with 0."
				Get-ChildItem cert:\CurrentUser\My -codesign
			} #ENDIF choose a certificate to use.

			while (($certSignIndex -lt 0) -or ($certSignIndex -gt $signingCertificatesCount)) { #WHILE cert choice not valid.
				[int] $certSignIndex = Read-Host "Signing certificate index number [0-$signingCertificatesCount]"
			} #END WHILE cert choice not valid.

			# Return selected certificate
			return $signingCertificates[$certSignIndex]
		}
		
		$signingCertificate = ChooseSigningCertificate -certSignIndex $certSignIndex
		
		$signingConfiguration = $signingCertificate | Select-Object Subject,Issuer,Thumbprint,NotBefore,NotAfter,
			@{Label="TimeServer"; Expression={$timestampserver}},
			@{Label="SkipTimeServer"; Expression={$skipTimestamp}},
			@{Label="SkipSigned"; Expression={$skipSigned}},
			@{Label="SkipUnSigned"; Expression={$skipUnsigned}}
		
		Write-Host "*** The following certificate will be used for signing ***"
		$signingConfiguration | Out-String
		Write-Host "**********************************************************"
	}


	process {
		# Loop over files to sign.
		foreach ($filePath in $filePaths) { #FOREACH file
			if ((Test-Path $filePath) -eq $true) { #IF file path is valid.
				Write-Verbose "Processing file: $filePath"
				
				if ($skipUnsigned) { #IF skipUnsigned certs requested.
					if ((Get-AuthenticodeSignature $filePath | Select-Object -ExpandProperty Status ) -ne 'Valid') {
						Write-Verbose "File skipped (-skipUnsigned): Unsigned or invalid."
						continue
					}
				} #ENDIF skipUnsigned
				
				if ($skipSigned) { #IF skipSigned certs requested.
					if ((Get-AuthenticodeSignature $filePath | Select-Object -ExpandProperty Status ) -eq 'Valid') {
						Write-Warning "File skipped (-skipSigned): Valid."
						continue
					}
				} #ENDIF skipSigned

				# Sign the script with the certificate.
				if ($pscmdlet.ShouldProcess("$filePath", "Signing Certificate")) {
					if ($skipTimestamp) { $SignatureStatus = Set-AuthenticodeSignature -FilePath $filePath -Certificate $signingCertificate } # Skip Timestamp Countersignature
					else { $SignatureStatus = Set-AuthenticodeSignature -FilePath $filePath -Certificate $signingCertificate -TimestampServer $timestampServer } # Use Timestamp Countersignature

					if ($SignatureStatus.Status -eq 'Valid') { Write-Host "Signed successfully: $filePath" }
					else { Write-Error "Error signing: $filePath" }
				}
			} #ENDIF file path is valid.
			else { Write-Warning "The path ($filePath) doesn't exist. Skipping this entry."; } #ELSE file path is invalid.
		} #END FOREACH file
	}


	end { }

}


# Exported Functions
Export-ModuleMember -Function New-CodeSignature


# SIG # Begin signature block
# MIIcJAYJKoZIhvcNAQcCoIIcFTCCHBECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUckXbHSG+RO4Y8lh8Oeaa5yQm
# j/+gghYiMIIEmTCCA4GgAwIBAgIPFojwOSVeY45pFDkH5jMLMA0GCSqGSIb3DQEB
# BQUAMIGVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCVVQxFzAVBgNVBAcTDlNhbHQg
# TGFrZSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxITAfBgNV
# BAsTGGh0dHA6Ly93d3cudXNlcnRydXN0LmNvbTEdMBsGA1UEAxMUVVROLVVTRVJG
# aXJzdC1PYmplY3QwHhcNMTUxMjMxMDAwMDAwWhcNMTkwNzA5MTg0MDM2WjCBhDEL
# MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
# BxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKjAoBgNVBAMT
# IUNPTU9ETyBTSEEtMSBUaW1lIFN0YW1waW5nIFNpZ25lcjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAOnpPd/XNwjJHjiyUlNCbSLxscQGBGue/YJ0UEN9
# xqC7H075AnEmse9D2IOMSPznD5d6muuc3qajDjscRBh1jnilF2n+SRik4rtcTv6O
# KlR6UPDV9syR55l51955lNeWM/4Og74iv2MWLKPdKBuvPavql9LxvwQQ5z1IRf0f
# aGXBf1mZacAiMQxibqdcZQEhsGPEIhgn7ub80gA9Ry6ouIZWXQTcExclbhzfRA8V
# zbfbpVd2Qm8AaIKZ0uPB3vCLlFdM7AiQIiHOIiuYDELmQpOUmJPv/QbZP7xbm1Q8
# ILHuatZHesWrgOkwmt7xpD9VTQoJNIp1KdJprZcPUL/4ygkCAwEAAaOB9DCB8TAf
# BgNVHSMEGDAWgBTa7WR0FJwUPKvdmam9WyhNizzJ2DAdBgNVHQ4EFgQUjmstM2v0
# M6eTsxOapeAK9xI1aogwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2Ny
# bC51c2VydHJ1c3QuY29tL1VUTi1VU0VSRmlyc3QtT2JqZWN0LmNybDA1BggrBgEF
# BQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20w
# DQYJKoZIhvcNAQEFBQADggEBALozJEBAjHzbWJ+zYJiy9cAx/usfblD2CuDk5oGt
# Joei3/2z2vRz8wD7KRuJGxU+22tSkyvErDmB1zxnV5o5NuAoCJrjOU+biQl/e8Vh
# f1mJMiUKaq4aPvCiJ6i2w7iH9xYESEE9XNjsn00gMQTZZaHtzWkHUxY93TYCCojr
# QOUGMAu4Fkvc77xVCf/GPhIudrPczkLv+XZX4bcKBUCYWJpdcRaTcYxlgepv84n3
# +3OttOe/2Y5vqgtPJfO44dXddZhogfiqwNGAwsTEOYnB9smebNd0+dmX+E/CmgrN
# Xo/4GengpZ/E8JIh5i15Jcki+cPwOoRXrToW9GOUEB1d0MYwgghjMIIGS6ADAgEC
# AhN7AAAAH8+fJanQVeArAAMAAAAfMA0GCSqGSIb3DQEBCwUAMGcxEzARBgoJkiaJ
# k/IsZAEZFgNuZXQxGjAYBgoJkiaJk/IsZAEZFgp3b2xmc3Bpcml0MRMwEQYKCZIm
# iZPyLGQBGRYDbGFuMR8wHQYDVQQDExZXb2xmU3Bpcml0LU5ldC1Sb290LUNBMB4X
# DTE4MDIwNDA0MzIwNFoXDTIzMDIwMzA0MzIwNFowbDETMBEGCgmSJomT8ixkARkW
# A25ldDEaMBgGCgmSJomT8ixkARkWCndvbGZzcGlyaXQxEzARBgoJkiaJk/IsZAEZ
# FgNsYW4xJDAiBgNVBAMTG1dvbGZTcGlyaXQtTmV0LVdTTk9DQ0EwMS1DQTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOwJqdHih24K3ed7BBqb3i4eowqk
# G/hU19xnCchF12CSvhDUQhDn5MpOhN4EOxnQLq0OY8kOKSnG23TzsdIR+TNHFlFu
# oHJsHeMRfE1y5crcnz7hHlvuqZPhmlcL56h0p9ZeL/nNf0L7nIpyZohN4PpeFIMv
# aH+gbNEUdRJT061Olia10w3ctL/uigH5KE3WuhK/SEGL/Grrj+qElTSuEXtSQFZy
# zrCBdNuVEuh83r12EPPzAVbyB/kiKzwnf1cr/ho34bQb/HEd8AK1M4EZXtptdmjN
# iHA7KRRd4IRI/jLQDSBiuYogGX6h6m2jgFR2ArCfkmI4RIE0rG3FOYrlDqowPEB5
# Z4Q3I4CxdzxaTctQkqYc7NCXVIFwdeLnaWB3tn6bi9mBr405ihc0O58kQoNSx/TN
# C8+gRPJ2MDJiGPWlqh7g8qzPDRzsELE4Ic9h/ro79WgIeC6kISqZdXXKicYeMH19
# z127o/duZQH4Rbf514ZsYx/HLjls9l24408G4sa3IxNPm0s/wl4AJdvkwHW7zqUm
# 9m70ffsGnGOWkH75YszGFZZF8ZDFAOdMfB0wiI0YNocqogpwkicB0meAr/Rk9psi
# 1aI9pzIBkWii2R47L9rke2Cmr6QDU6MVzQIrPqF4IEg7gh99ekh6w8t9XoDOPO8b
# EOAOWwr5JFezHKdzAgMBAAGjggMBMIIC/TAQBgkrBgEEAYI3FQEEAwIBADAdBgNV
# HQ4EFgQUmEIEpsUgCm8BbjNwfNCx8BynJKkwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgw
# FoAUmDa+IaJFLK6FV1nE8Z7Z9cAKzMQwggEpBgNVHR8EggEgMIIBHDCCARigggEU
# oIIBEIaByWxkYXA6Ly8vQ049V29sZlNwaXJpdC1OZXQtUm9vdC1DQSgzKSxDTj1X
# Uy1SQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bGFuLERDPXdvbGZzcGlyaXQsREM9bmV0
# P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxE
# aXN0cmlidXRpb25Qb2ludIZCaHR0cDovL2NybC53b2xmc3Bpcml0Lm5ldC9jcmwv
# V1MtUkNBL1dvbGZTcGlyaXQtTmV0LVJvb3QtQ0EoMykuY3JsMIIBPgYIKwYBBQUH
# AQEEggEwMIIBLDCBvwYIKwYBBQUHMAKGgbJsZGFwOi8vL0NOPVdvbGZTcGlyaXQt
# TmV0LVJvb3QtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENO
# PVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bGFuLERDPXdvbGZzcGlyaXQs
# REM9bmV0P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0
# aW9uQXV0aG9yaXR5MGgGCCsGAQUFBzAChlxodHRwOi8vY3JsLndvbGZzcGlyaXQu
# bmV0L2NybC9XUy1SQ0EvV1MtUkNBLmxhbi53b2xmc3Bpcml0Lm5ldF9Xb2xmU3Bp
# cml0LU5ldC1Sb290LUNBKDMpLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAD5e//JQm
# lKNdb9L5owNtDhYDjZm6Lgh9LAPPjzcKWdTGvxdEzrPkmJjudUm3qvPKgxMo1UCS
# GRwcyxlDoyu/d3lelRRxcAKfJknYKoQ6tj4gYqdLTVEytoRmrIyPFTrfLuLv+s+m
# wXKNIHpkzWjnQw8I+q2K996T1hbyLd41TLSFmRumEt5wj9Kxb+2+lcX7a5+zJ7Dq
# 1WQ0kaGGb4s/ooLer7DqzYYEHq9LxJUPrPKbzSUEhc0g11gcEAOheIwMNybXefYl
# pW0j6/CSK9wlUPO+gPL9rBCKTYLA28wuQc9kBHBVvO9XZxGnJZcWfa0hBlcTL15d
# ULAKGJR5SdUqwiJCDSbrqyoFQBs5+6/sY3SYyzCqgZuU/UoLsrxc1lq4k2FaMPpv
# aQmzUYkiGryqGlB4FzHnclTE1/WBtvUAQb7xyK3HKurRHKGZL3oqV+drh5sSJp9+
# /Y7yTR8md0MNTEyfg+Jykf9YGDLnNjtXnKIrlAVf94+Lu9xChxcfRaz9Oko1lFEq
# K8BYf+W0Iadsf+Q2JQEkl7K2s4HBtrjYxHhgL2hbTtid7U/EICE3+UFPqootxxJ7
# LYS154ZJlEJtd1rRnpLFD1dpWAcJV41ENrvlLguAngYM9EkA90rBuyZtMKq+XpMn
# 0PdtBSceWI6QhTcG0XuLYTU8TNud7Vsj8e8wggkaMIIHAqADAgECAhNjAAABGBgj
# 5UpXeSWiAAAAAAEYMA0GCSqGSIb3DQEBCwUAMGwxEzARBgoJkiaJk/IsZAEZFgNu
# ZXQxGjAYBgoJkiaJk/IsZAEZFgp3b2xmc3Bpcml0MRMwEQYKCZImiZPyLGQBGRYD
# bGFuMSQwIgYDVQQDExtXb2xmU3Bpcml0LU5ldC1XU05PQ0NBMDEtQ0EwHhcNMTkw
# MTIwMjI0NjA4WhcNMjAwMTIwMjI0NjA4WjCBnDETMBEGCgmSJomT8ixkARkWA25l
# dDEaMBgGCgmSJomT8ixkARkWCndvbGZzcGlyaXQxEzARBgoJkiaJk/IsZAEZFgNs
# YW4xEzARBgNVBAsTCldvbGZTcGlyaXQxDjAMBgNVBAsTBVVzZXJzMQ8wDQYDVQQL
# EwZIdW1hbnMxHjAcBgNVBAMTFU1hdHRoZXcgU2NoYWNoZXJiYXVlcjCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMwizniCvTUGl1NbtXJQrmFl4WnxwVfN
# Q7P2Hve/tH7Iyyu5HMgOExWyTtWQLmw5P7bOVLGtS931enlreD7GirluzcgWGng3
# m+28vwFs+umsQ1izYrLK21t6IPWX8HqQP/OP/nFxdk6f9TD6xL08xFEEBLQYLQO/
# bie46X4QsleSLU9XQe+Dt3pBkdy2NizJnm1ihF9XVdyrId68CzvdKkM8Ra3nSj2j
# WfS9tSBgnBeat/gNr0H/VQsP4bLA9hYiqcjn4omSRKMAkJmL9ghDVVXnq6qUt+z+
# 0aQmU0kE/GoVkpviamLXJbcgBSh0JMN8e3EF7y/Mo4U2uznLYC/6qfmpRUuge2Sf
# KVAHj0eRWgsTYtrYuAr5bGlp0/eved8UxA7ZFCszxU/HSH5Jb0Lj7tLlkBPxTYfM
# RO+fKqmTmT8CXefi5H56+c6kVoMriXJOMedX6516kVS+EwnBGM3kps46UsJQcrHZ
# 9BQb7G3btcYwEdCYdYikE0mgm4P4sNLF2PyALU7xAtnqVNEWgOJ5qGI+m6IoT6PI
# 0woN8fDXH5xfJ03b3fsDXv4EoY67DVN2B7GgZFuHNb/3usBlF5xA2JAbxojiubiH
# /7jle+NrVMu5ED69HzoPv3VivQVkJ95ktIlhtgR4FBue5JxxKEBfTK3Nhtxj2RZc
# CjJjLMu66AVhAgMBAAGjggOCMIIDfjA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3
# FQiC34xBgsKsbIKNlyGD9/UKhqiKdwyDmd8pgtimJgIBZAIBHDATBgNVHSUEDDAK
# BggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAKBggr
# BgEFBQcDAzA1BgNVHREELjAsoCoGCisGAQQBgjcUAgOgHAwabWF0dGhld0BsYW4u
# d29sZnNwaXJpdC5uZXQwHQYDVR0OBBYEFHKjSfF8pKht2eJdZR3EG2mS+X8EMB8G
# A1UdIwQYMBaAFJhCBKbFIApvAW4zcHzQsfAcpySpMIIBMwYDVR0fBIIBKjCCASYw
# ggEioIIBHqCCARqGgc5sZGFwOi8vL0NOPVdvbGZTcGlyaXQtTmV0LVdTTk9DQ0Ew
# MS1DQSxDTj1XU05PQ0NBMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
# Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bGFuLERDPXdvbGZz
# cGlyaXQsREM9bmV0P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmpl
# Y3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIZHaHR0cDovL2NybC53b2xmc3Bp
# cml0Lm5ldC9jcmwvV1NOT0NDQTAxL1dvbGZTcGlyaXQtTmV0LVdTTk9DQ0EwMS1D
# QS5jcmwwggFLBggrBgEFBQcBAQSCAT0wggE5MIHEBggrBgEFBQcwAoaBt2xkYXA6
# Ly8vQ049V29sZlNwaXJpdC1OZXQtV1NOT0NDQTAxLUNBLENOPUFJQSxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPWxhbixEQz13b2xmc3Bpcml0LERDPW5ldD9jQUNlcnRpZmljYXRlP2Jhc2U/
# b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBwBggrBgEFBQcwAoZk
# aHR0cDovL2NybC53b2xmc3Bpcml0Lm5ldC9jcmwvV1NOT0NDQTAxL1dTTk9DQ0Ew
# MS5sYW4ud29sZnNwaXJpdC5uZXRfV29sZlNwaXJpdC1OZXQtV1NOT0NDQTAxLUNB
# LmNydDANBgkqhkiG9w0BAQsFAAOCAgEA1OcF/o5i418n+qY7yBQS89iO2SgLQHLp
# 32jGHg+rDs05wOPe80mWellv8p/UB6QcccUJ44oHYj9fvOrDQGEqeqfjP2E4KQDR
# 0mRoeMpDDU9M7uO5dA1tfp/1P/RTGCBFvtkzwkNs27YnpvyHVYgVi1y5rL0HMWZC
# dd9mLNQlK7jJkAnsftOo1kEIJsytIQuNPcceWA1LOyI3v15CA/x5uTk5twYNVa1e
# u8jnbfQpDKL25NG6wN5DFqyweQz1I7MFWu5fCxVjWcP0YnoSb8ytF5jCYu3UmAsx
# xuu2+GvdQyU2CrBKSuUUlWRwuUqJezyiy/BjAq7X+duBirbGAk8/wP+p3jqXsaKd
# iHw+eL+DFU7Mj2nfBy1prqnzdiflo2d1oQkj8J//A5Q58lzJ02UZqJgXNXvkhcsk
# kScCjMZzws+tZFD3uJh9i2sebRwXhMEM/yQ5xXuUl4y7ZaGHY3d8RoxavVcbLA6h
# l5uMNjp4sK8W/q9HzLBYSMcKfQRifS0RyYm3B8ezkNGkvmiMse9GO9/m3ruK0wjI
# XwJ0XrXeJFX3OCMbdZ4hHRWrvW4SGsv3wnaNQyah+XY/bA60APcSM1/H0utcg32D
# SaLYTEPZRIVOnTzdpDg6+wrRk4App7ALt6qZqkUxmOqL3zhkgrRBZ9V+TpfPcDwm
# 0bvo9cYwo8wxggVsMIIFaAIBATCBgzBsMRMwEQYKCZImiZPyLGQBGRYDbmV0MRow
# GAYKCZImiZPyLGQBGRYKd29sZnNwaXJpdDETMBEGCgmSJomT8ixkARkWA2xhbjEk
# MCIGA1UEAxMbV29sZlNwaXJpdC1OZXQtV1NOT0NDQTAxLUNBAhNjAAABGBgj5UpX
# eSWiAAAAAAEYMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAA
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBT+Jx5fIvchRo5EdxxKw3MJRtSW7zAN
# BgkqhkiG9w0BAQEFAASCAgCTbhgfZqcE/a/GzRuuHKNlnRg4RrKGcFLhOhutfrLR
# YqsKiieJgY/JiHmx7aHl0aOK6nvV1xBErpZ+3xgFETG3lPQncfNvyWZjPXT6c7iY
# v4i6jgXNWQMxYUmVXKEEVntdg0VY/Ay1PnVV58jwUAswoyqClA5mIrLIiu300dyN
# iI88uDHPID4tfCdHcFEXry2uvDuEM9WMyJUnDAC7OWLA1Yuts9Np42nQn78LnWJ/
# SNOj5X0YSl879Cm36yTatciq2eTMrRWIQwaf1qnlwDl1HSgZP1WlLjFtrEmtIkih
# U5WplgP87ftM64h6rNZnpsVKVSggU8/k8vKjXdQNlZFUGt6bfsPWCvZCgTBxF9HQ
# Ube6Ql+HowonJGB0FEPArRtXqSydftIsX7msP8LbhVnwjSbeavdTSI809RVcpT9h
# +2wzGQHeZ56gTRihaavf+x6uvX72t89ECSjnq0R8+4lct67x2BGoPnv5WpSbcvS+
# 8VGHIYur09MaFOQyb1pYXeogL6z8SLubFeba0aQnWLtBPgZX8U1SDv83fDV1uJPS
# t7cgma6h7Klp8VFHVFS/BENyOS4czAxRrumJMy+CpnaH/LDcRxpwSzYDMkeEfBDc
# vMOdsLu19rz01yrW9UDrmv2uR/gyh3dbc6BWRaiYY7JTmcEHayXr38mLHmYGStuL
# a6GCAkMwggI/BgkqhkiG9w0BCQYxggIwMIICLAIBATCBqTCBlTELMAkGA1UEBhMC
# VVMxCzAJBgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2UgQ2l0eTEeMBwGA1UE
# ChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExhodHRwOi8vd3d3LnVz
# ZXJ0cnVzdC5jb20xHTAbBgNVBAMTFFVUTi1VU0VSRmlyc3QtT2JqZWN0Ag8WiPA5
# JV5jjmkUOQfmMwswCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTE5MDMxNjAyNTI0OVowIwYJKoZIhvcNAQkEMRYE
# FOr4mRxaarVC1M1spJwBAWncal/NMA0GCSqGSIb3DQEBAQUABIIBAB3+P/Dzdyx8
# jvRITs+ybqPCDklao3kUk0rJHPUCj+83Ga4WUgb9YyXIFNgVqV7kvhdqOaxLv3qP
# Dxmbwyb6bxEeJOSgpUGsj/C2nki4LLmqhixZHrzgUl9cLxKU2wXRk2US524wAC77
# NAbX5Pg3O3zDZZsFvY8ZZ+XHCGMajIdSMNeh4IudwxtYqvF+5LM4km7Xn/YZzUhI
# t1LxgwlJt1MZ/M30QuXTzVb5ZE82TIb7MRvF75CU1gGWI13cCMuCuT/bCeC7W0Yj
# +akh5s+7HFW7zphL15XwsBO67J9RLXA9ZdGRBw2GemJV8NfGZldVbdNfNtAE98f6
# BYd/gIIQzkg=
# SIG # End signature block
