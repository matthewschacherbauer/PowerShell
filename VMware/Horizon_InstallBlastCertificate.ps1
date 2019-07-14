<#

VMWARE BLAST DESKTOP AGENT - CERTIFICATE INSTALLATION

Matthew Schacherbauer
2019-07-13

v1.0

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

===============

DESCRIPTION

This script installs an enterprise trusted certificate to the local VMBlast service to resolve the TLS trust error that occurs when a client connects by browser without tunneling (typically an internal HTML5 client). This method does not rely on a wildcard certificate.

A valid certificate should exist in the local machine store. The certificate may pre-exist or be obtained by an autoenroll mechanism.

To be considered valid, the certificate must meet the following criteria:
1) Be valid for Server Authentication
2) Have an associated Private Key
3) The Private Key must be exportable
4) The certificate must be valid for the local FQDN
5) Specific ADCS requirements must be met

If no valid certificate is available, the script will output an error and the Blast service will continue with a self-signed certificate.
If the automatically selected certificate is not valid for use, the Blast service will generate a new self-signed certificate automatically.

HORIZON VIEW CONFIGURATION PREREQUISITES

For this to work, the horizon client must connect using the DNS name of the machine.

See the following VMware documentation:
https://docs.vmware.com/en/VMware-Horizon-7/7.1/com.vmware.horizon-view.installation.doc/GUID-8E7FBB9D-F2DB-4787-B11B-7506126DEB7F.html

MICROSOFT ADCS CONFIGURATION PREREQUISITES

You must create a dedicated certificate template with the following required settings.

Start by cloning the default "Computer" template.
Compatibility > Set appropriately. In testing, I used CA: Server 2012, Recipient: Windows 7.
Request Handling > [X] Allow private key to be exported
Cryptography > Provider Category > [X] Legacy Cryptographic Service Provider (REQUIRED)
Cryptography > Minimum Key Size > [X] 2048
Subject Name > Subject name format > [X] DNS name (This may not be necessary)
Subject Name > Include this information in alternate subject name > [X] DNS name

The resulting certificate template must be a version 2 template.

INSTALLATION

This script does not require any parameters.
It is suggested to use a Group Policy startup script option to execute this
script on the VDI machines.

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


# Sanity check. Stop the execution if the Blast service doesn't exist.
if (! (Get-Service VMBlast -ErrorAction SilentlyContinue) ) {
	Throw "The VMBlast service was not found."
}

# Get a list of valid certificates.
$oCertList = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
	$_.EnhancedKeyUsageList -like "*Server Authentication*" -and
	$_.HasPrivateKey -and
	$_.DnsNameList -like "*.$($ENV:USERDNSDOMAIN)" -and
	$_.PrivateKey.CspKeyContainerInfo.Exportable -eq $true
}

if ($oCertList.count -gt 1) {
	Write-Warning "Found $($oCertList.count) eligible certificates in the local machine store."
}

foreach ($thisCert in $oCertList) {
	# Stop the Blast service
	Write-Host "Stopping the VMBlast Service."
	Stop-Service VMBlast -Force

	# One or more certificates were found.
	# Since we have no logic to pick one, the first one is as good as any other.
	# This converts the thumbprint to the required format.
	$sCertThumbprint = ($thisCert.Thumbprint.ToLower() -replace '(..(?!$))','$1 ')

	# Write the thumbprint into the registry.
	Write-Host "Installing Certificate Thumbprint: $sCertThumbprint"
	REG ADD "HKLM\SOFTWARE\VMware, Inc.\VMware Blast\Config" /V "SslHash" /D "$sCertThumbprint" /T reg_sz /F

	# Restart the Blast service.
	Write-Host "Restarting VMBlast Service."
	Start-Service VMBlast

	# Exit the loop once we've found a valid certificate to use.
	break
}

if (!$sCertThumbprint) {
	# No eligible certificates were found.

	# TODO: Write code here to enroll for and retrieve a certificate.
	# Otherwise, rely on autoenroll to figure things out eventually.

	# For now, throw an error.
	Throw "No valid certificates were found in the local certificate store.`nTo be considered valid, a certificate must`n1) Be valid for Server Authentication`n2) Have a Private Key`n3) The Private Key must be exportable`n4) The certificate must be valid for the local FQDN"
}


# SIG # Begin signature block
# MIIrtAYJKoZIhvcNAQcCoIIrpTCCK6ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDv282Wi25gOA617glrn6SsW4
# zAmggiXNMIIEhDCCA2ygAwIBAgIQQhrylAmEGR9SCkvGJCanSzANBgkqhkiG9w0B
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
# cvfqG5bilK+GLjCCBdAwggO4oAMCAQICEEFxbGuXPYiATs5STyUAMskwDQYJKoZI
# hvcNAQELBQAwZzETMBEGCgmSJomT8ixkARkWA25ldDEaMBgGCgmSJomT8ixkARkW
# CndvbGZzcGlyaXQxEzARBgoJkiaJk/IsZAEZFgNsYW4xHzAdBgNVBAMTFldvbGZT
# cGlyaXQtTmV0LVJvb3QtQ0EwHhcNMTYwMjI1MTY0OTU2WhcNMzYwMjI1MTY1OTU1
# WjBnMRMwEQYKCZImiZPyLGQBGRYDbmV0MRowGAYKCZImiZPyLGQBGRYKd29sZnNw
# aXJpdDETMBEGCgmSJomT8ixkARkWA2xhbjEfMB0GA1UEAxMWV29sZlNwaXJpdC1O
# ZXQtUm9vdC1DQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKRv9HV2
# D+8b5mWFNeynifCWBSj4iuvxiHESsULIp+G2aOtkkaf1rIy+A6JfkvdnW363weeL
# d0ncPRJEiE+yRhg5SDV0JogNb+EKYUuznd2R0Ku9bxyaTnlEf/M+kMdZKKFGedZ2
# Om3LgO1FfLQoVkSnSgzY+aMRoh7e3+tR4fMRQvo3w7D9HMUopXvGaDACN5ucAOH5
# p8yoUkEgZmhzxOkKTouYhdqI8BlZiz7LmTZycuM/zL51+Md3JvAVxjDp5T2ViLRh
# V/3cLoXNG/h4BT6MW3ca5ACFtt0B2GWxDsQByzHtw3fb8J+VDsgbM+de1pXsSZL6
# YEm0jH6WWpvb2whThE2EKc7WLOrBcH2KAXbUOuMC/7Pg+3IXw2NN421xLlIbgYSh
# jYRxnRifjGApOPYlAMUWRT/k7a9v1sIXdYmsKW6/5sslNKGEJ0I9HZ+IJgEXxJu8
# 7xC3QYZsftOl7kPeff0iKw0vMDZ/4bq/0GFERDhbyB4PYdiL2vLgywGraoCHlZDS
# kQeArp5ZcspqWDdSqU59SCRZJ6ZkqS6tY5p2abT33TeB+RSfIqgIclvmEf5JCt70
# tP0tZDNu1ZvPc8AelN0pC7vPUcDCmiFwL0n2wOEh13Yb/QLVsmrNRSyUjUHXgQuS
# B3bFE84iKV3QkNs5YUkQ+3qgJbgCVgHqquBbAgMBAAGjeDB2MAsGA1UdDwQEAwIB
# hjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSYNr4hokUsroVXWcTxntn1wArM
# xDASBgkrBgEEAYI3FQEEBQIDAwADMCMGCSsGAQQBgjcVAgQWBBRXGDnMVbZ9/N/o
# eV5aDKxnVEODhDANBgkqhkiG9w0BAQsFAAOCAgEAT2ie0agiFJrZXjXzYFuADrQT
# 5Xg5ZKmdzzPrIPwWEQA/nb0Bq8ZaNM2qnPYIPHu6spHf3hKrwZLpYqEukPe/TM0b
# E/GzrhDNVgrodLWylz/OHfjPQn8UjdP4Ma/UQ+YD/gZo6k/Exp41LXxSMMfb+9fC
# iWnm28IpbF7FWnfEhyD+/LiREksE9BFhq5mTiiw/UfkjKQLFSkIRcbNkUoEpHnFV
# ec+t/pgBesMf6Tt8X9fzgsGuAPruczo7zoSbtR4KtawNSkGiE5GHKt7Dmgrig7vY
# jxMewNxfG4/yBxyMWLB8Y9xnKU3aXxWQ1PjXVW3H34YtJz4gqtju2Zx5Lo7dBg9N
# NFmTunI+r0O2h0Ub1/8MecKKx1xchLWtXGFftSB6zNhOxrB6lwhwWpOaKgZ/vqot
# 6C9kAQ0kJRjA/JZnxixGQCxlrRnxJsFYlLu8Sxcc86VQW/zNu7ta78foe/dYfSmu
# XHDPIUYws8ZBkxFoONbSoRhaO0bkUvS6PUqRUURj5KUHw9j0C/cTFGkJNr8cUVsE
# /kV5njERkr/zslwCi3s23dePZVo0m4JopK4XTN+eiqdBb4KG1PH+p4JQiezF8HAi
# zrWLEQf7DmJm5Jk7p2J7dgK85vLi0gX33sZoo/5vkhieU9pcSmHs7Jl5Ozq+ZbVo
# lyjB8iOpp3jSixNAW7wwgghjMIIGS6ADAgECAhN7AAAAH8+fJanQVeArAAMAAAAf
# MA0GCSqGSIb3DQEBCwUAMGcxEzARBgoJkiaJk/IsZAEZFgNuZXQxGjAYBgoJkiaJ
# k/IsZAEZFgp3b2xmc3Bpcml0MRMwEQYKCZImiZPyLGQBGRYDbGFuMR8wHQYDVQQD
# ExZXb2xmU3Bpcml0LU5ldC1Sb290LUNBMB4XDTE4MDIwNDA0MzIwNFoXDTIzMDIw
# MzA0MzIwNFowbDETMBEGCgmSJomT8ixkARkWA25ldDEaMBgGCgmSJomT8ixkARkW
# CndvbGZzcGlyaXQxEzARBgoJkiaJk/IsZAEZFgNsYW4xJDAiBgNVBAMTG1dvbGZT
# cGlyaXQtTmV0LVdTTk9DQ0EwMS1DQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAOwJqdHih24K3ed7BBqb3i4eowqkG/hU19xnCchF12CSvhDUQhDn5MpO
# hN4EOxnQLq0OY8kOKSnG23TzsdIR+TNHFlFuoHJsHeMRfE1y5crcnz7hHlvuqZPh
# mlcL56h0p9ZeL/nNf0L7nIpyZohN4PpeFIMvaH+gbNEUdRJT061Olia10w3ctL/u
# igH5KE3WuhK/SEGL/Grrj+qElTSuEXtSQFZyzrCBdNuVEuh83r12EPPzAVbyB/ki
# Kzwnf1cr/ho34bQb/HEd8AK1M4EZXtptdmjNiHA7KRRd4IRI/jLQDSBiuYogGX6h
# 6m2jgFR2ArCfkmI4RIE0rG3FOYrlDqowPEB5Z4Q3I4CxdzxaTctQkqYc7NCXVIFw
# deLnaWB3tn6bi9mBr405ihc0O58kQoNSx/TNC8+gRPJ2MDJiGPWlqh7g8qzPDRzs
# ELE4Ic9h/ro79WgIeC6kISqZdXXKicYeMH19z127o/duZQH4Rbf514ZsYx/HLjls
# 9l24408G4sa3IxNPm0s/wl4AJdvkwHW7zqUm9m70ffsGnGOWkH75YszGFZZF8ZDF
# AOdMfB0wiI0YNocqogpwkicB0meAr/Rk9psi1aI9pzIBkWii2R47L9rke2Cmr6QD
# U6MVzQIrPqF4IEg7gh99ekh6w8t9XoDOPO8bEOAOWwr5JFezHKdzAgMBAAGjggMB
# MIIC/TAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUmEIEpsUgCm8BbjNwfNCx
# 8BynJKkwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0PAQH/BAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUmDa+IaJFLK6FV1nE8Z7Z9cAK
# zMQwggEpBgNVHR8EggEgMIIBHDCCARigggEUoIIBEIaByWxkYXA6Ly8vQ049V29s
# ZlNwaXJpdC1OZXQtUm9vdC1DQSgzKSxDTj1XUy1SQ0EsQ049Q0RQLENOPVB1Ymxp
# YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
# REM9bGFuLERDPXdvbGZzcGlyaXQsREM9bmV0P2NlcnRpZmljYXRlUmV2b2NhdGlv
# bkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIZCaHR0
# cDovL2NybC53b2xmc3Bpcml0Lm5ldC9jcmwvV1MtUkNBL1dvbGZTcGlyaXQtTmV0
# LVJvb3QtQ0EoMykuY3JsMIIBPgYIKwYBBQUHAQEEggEwMIIBLDCBvwYIKwYBBQUH
# MAKGgbJsZGFwOi8vL0NOPVdvbGZTcGlyaXQtTmV0LVJvb3QtQ0EsQ049QUlBLENO
# PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
# YXRpb24sREM9bGFuLERDPXdvbGZzcGlyaXQsREM9bmV0P2NBQ2VydGlmaWNhdGU/
# YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MGgGCCsGAQUF
# BzAChlxodHRwOi8vY3JsLndvbGZzcGlyaXQubmV0L2NybC9XUy1SQ0EvV1MtUkNB
# Lmxhbi53b2xmc3Bpcml0Lm5ldF9Xb2xmU3Bpcml0LU5ldC1Sb290LUNBKDMpLmNy
# dDANBgkqhkiG9w0BAQsFAAOCAgEAD5e//JQmlKNdb9L5owNtDhYDjZm6Lgh9LAPP
# jzcKWdTGvxdEzrPkmJjudUm3qvPKgxMo1UCSGRwcyxlDoyu/d3lelRRxcAKfJknY
# KoQ6tj4gYqdLTVEytoRmrIyPFTrfLuLv+s+mwXKNIHpkzWjnQw8I+q2K996T1hby
# Ld41TLSFmRumEt5wj9Kxb+2+lcX7a5+zJ7Dq1WQ0kaGGb4s/ooLer7DqzYYEHq9L
# xJUPrPKbzSUEhc0g11gcEAOheIwMNybXefYlpW0j6/CSK9wlUPO+gPL9rBCKTYLA
# 28wuQc9kBHBVvO9XZxGnJZcWfa0hBlcTL15dULAKGJR5SdUqwiJCDSbrqyoFQBs5
# +6/sY3SYyzCqgZuU/UoLsrxc1lq4k2FaMPpvaQmzUYkiGryqGlB4FzHnclTE1/WB
# tvUAQb7xyK3HKurRHKGZL3oqV+drh5sSJp9+/Y7yTR8md0MNTEyfg+Jykf9YGDLn
# NjtXnKIrlAVf94+Lu9xChxcfRaz9Oko1lFEqK8BYf+W0Iadsf+Q2JQEkl7K2s4HB
# trjYxHhgL2hbTtid7U/EICE3+UFPqootxxJ7LYS154ZJlEJtd1rRnpLFD1dpWAcJ
# V41ENrvlLguAngYM9EkA90rBuyZtMKq+XpMn0PdtBSceWI6QhTcG0XuLYTU8TNud
# 7Vsj8e8wggkaMIIHAqADAgECAhNjAAABGBgj5UpXeSWiAAAAAAEYMA0GCSqGSIb3
# DQEBCwUAMGwxEzARBgoJkiaJk/IsZAEZFgNuZXQxGjAYBgoJkiaJk/IsZAEZFgp3
# b2xmc3Bpcml0MRMwEQYKCZImiZPyLGQBGRYDbGFuMSQwIgYDVQQDExtXb2xmU3Bp
# cml0LU5ldC1XU05PQ0NBMDEtQ0EwHhcNMTkwMTIwMjI0NjA4WhcNMjAwMTIwMjI0
# NjA4WjCBnDETMBEGCgmSJomT8ixkARkWA25ldDEaMBgGCgmSJomT8ixkARkWCndv
# bGZzcGlyaXQxEzARBgoJkiaJk/IsZAEZFgNsYW4xEzARBgNVBAsTCldvbGZTcGly
# aXQxDjAMBgNVBAsTBVVzZXJzMQ8wDQYDVQQLEwZIdW1hbnMxHjAcBgNVBAMTFU1h
# dHRoZXcgU2NoYWNoZXJiYXVlcjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAMwizniCvTUGl1NbtXJQrmFl4WnxwVfNQ7P2Hve/tH7Iyyu5HMgOExWyTtWQ
# Lmw5P7bOVLGtS931enlreD7GirluzcgWGng3m+28vwFs+umsQ1izYrLK21t6IPWX
# 8HqQP/OP/nFxdk6f9TD6xL08xFEEBLQYLQO/bie46X4QsleSLU9XQe+Dt3pBkdy2
# NizJnm1ihF9XVdyrId68CzvdKkM8Ra3nSj2jWfS9tSBgnBeat/gNr0H/VQsP4bLA
# 9hYiqcjn4omSRKMAkJmL9ghDVVXnq6qUt+z+0aQmU0kE/GoVkpviamLXJbcgBSh0
# JMN8e3EF7y/Mo4U2uznLYC/6qfmpRUuge2SfKVAHj0eRWgsTYtrYuAr5bGlp0/ev
# ed8UxA7ZFCszxU/HSH5Jb0Lj7tLlkBPxTYfMRO+fKqmTmT8CXefi5H56+c6kVoMr
# iXJOMedX6516kVS+EwnBGM3kps46UsJQcrHZ9BQb7G3btcYwEdCYdYikE0mgm4P4
# sNLF2PyALU7xAtnqVNEWgOJ5qGI+m6IoT6PI0woN8fDXH5xfJ03b3fsDXv4EoY67
# DVN2B7GgZFuHNb/3usBlF5xA2JAbxojiubiH/7jle+NrVMu5ED69HzoPv3VivQVk
# J95ktIlhtgR4FBue5JxxKEBfTK3Nhtxj2RZcCjJjLMu66AVhAgMBAAGjggOCMIID
# fjA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiC34xBgsKsbIKNlyGD9/UKhqiK
# dwyDmd8pgtimJgIBZAIBHDATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8E
# BAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzA1BgNVHREELjAsoCoG
# CisGAQQBgjcUAgOgHAwabWF0dGhld0BsYW4ud29sZnNwaXJpdC5uZXQwHQYDVR0O
# BBYEFHKjSfF8pKht2eJdZR3EG2mS+X8EMB8GA1UdIwQYMBaAFJhCBKbFIApvAW4z
# cHzQsfAcpySpMIIBMwYDVR0fBIIBKjCCASYwggEioIIBHqCCARqGgc5sZGFwOi8v
# L0NOPVdvbGZTcGlyaXQtTmV0LVdTTk9DQ0EwMS1DQSxDTj1XU05PQ0NBMDEsQ049
# Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
# bmZpZ3VyYXRpb24sREM9bGFuLERDPXdvbGZzcGlyaXQsREM9bmV0P2NlcnRpZmlj
# YXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRp
# b25Qb2ludIZHaHR0cDovL2NybC53b2xmc3Bpcml0Lm5ldC9jcmwvV1NOT0NDQTAx
# L1dvbGZTcGlyaXQtTmV0LVdTTk9DQ0EwMS1DQS5jcmwwggFLBggrBgEFBQcBAQSC
# AT0wggE5MIHEBggrBgEFBQcwAoaBt2xkYXA6Ly8vQ049V29sZlNwaXJpdC1OZXQt
# V1NOT0NDQTAxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxD
# Tj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWxhbixEQz13b2xmc3Bpcml0
# LERDPW5ldD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
# dGlvbkF1dGhvcml0eTBwBggrBgEFBQcwAoZkaHR0cDovL2NybC53b2xmc3Bpcml0
# Lm5ldC9jcmwvV1NOT0NDQTAxL1dTTk9DQ0EwMS5sYW4ud29sZnNwaXJpdC5uZXRf
# V29sZlNwaXJpdC1OZXQtV1NOT0NDQTAxLUNBLmNydDANBgkqhkiG9w0BAQsFAAOC
# AgEA1OcF/o5i418n+qY7yBQS89iO2SgLQHLp32jGHg+rDs05wOPe80mWellv8p/U
# B6QcccUJ44oHYj9fvOrDQGEqeqfjP2E4KQDR0mRoeMpDDU9M7uO5dA1tfp/1P/RT
# GCBFvtkzwkNs27YnpvyHVYgVi1y5rL0HMWZCdd9mLNQlK7jJkAnsftOo1kEIJsyt
# IQuNPcceWA1LOyI3v15CA/x5uTk5twYNVa1eu8jnbfQpDKL25NG6wN5DFqyweQz1
# I7MFWu5fCxVjWcP0YnoSb8ytF5jCYu3UmAsxxuu2+GvdQyU2CrBKSuUUlWRwuUqJ
# ezyiy/BjAq7X+duBirbGAk8/wP+p3jqXsaKdiHw+eL+DFU7Mj2nfBy1prqnzdifl
# o2d1oQkj8J//A5Q58lzJ02UZqJgXNXvkhcskkScCjMZzws+tZFD3uJh9i2sebRwX
# hMEM/yQ5xXuUl4y7ZaGHY3d8RoxavVcbLA6hl5uMNjp4sK8W/q9HzLBYSMcKfQRi
# fS0RyYm3B8ezkNGkvmiMse9GO9/m3ruK0wjIXwJ0XrXeJFX3OCMbdZ4hHRWrvW4S
# Gsv3wnaNQyah+XY/bA60APcSM1/H0utcg32DSaLYTEPZRIVOnTzdpDg6+wrRk4Ap
# p7ALt6qZqkUxmOqL3zhkgrRBZ9V+TpfPcDwm0bvo9cYwo8wxggVRMIIFTQIBATCB
# gzBsMRMwEQYKCZImiZPyLGQBGRYDbmV0MRowGAYKCZImiZPyLGQBGRYKd29sZnNw
# aXJpdDETMBEGCgmSJomT8ixkARkWA2xhbjEkMCIGA1UEAxMbV29sZlNwaXJpdC1O
# ZXQtV1NOT0NDQTAxLUNBAhNjAAABGBgj5UpXeSWiAAAAAAEYMAkGBSsOAwIaBQCg
# eDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJ
# BDEWBBRr6LYl6BDqN0tY0B8SgNoUBITt3DANBgkqhkiG9w0BAQEFAASCAgA05vsl
# y/YF/Asnm82u7X6z9ZLrAB70GrISaiXh7W4JdX9DzijzKfOjxDrSY/wrQT68Iu5l
# QTo2a4DNRif17Ql+nmWvqeRqFM5z1/NN/fcRtK3lBEasY/iLV0nI7cCI4fzaZkPM
# o9+oFYKIz2Rfc7znrH/qKKjnqOCrXUWmjggEwIPdhd5fntHfE1/WlTozZ/xfnq6+
# brI+Fs0UCbEAxgPQnr/e8H+omgnOLmxzxtIAVFcSQIm0c3nDGJ45MHwl0+b45M/q
# Eb1/ebeZMNdTbfkK9/zSB6A1+JR6v3XFxSpvIFxqc24pWJHktu9VwT6kApU7K7Ta
# dQoWTZNjnrAq40n5g1i8WpaqxjRJ/CK6Fa1XKwjB6aLyX2/S7u/2NTi+9s+6T/lw
# Yke7eIoPSoT7zSuoBKXuLT5vfjzQqJTiAQjNNThUzBvd+tEc70CqWpCO2K9JmzG6
# OxP36rQG6KpwOS6SXRfbG6kfeIUDK1BmetLcqP/eqlKRhE+soHOjB5RaEmSLn8Ck
# 5uP1iwEHro6Ff1Erm9POW79CQE81WMLHIS9xdMWqEG48fO7BDCjiyL9c2s9Rx8mr
# UKv4VDlJDGlaDt64/EHQNAHq2G2w1kg5a9SVolejBfrtXxJ89nIlIzn6pZzQeMJZ
# H/N/d9blqkwVXheJsgMtF27Dz/ZcvncddgGCbaGCAigwggIkBgkqhkiG9w0BCQYx
# ggIVMIICEQIBATCBjjB6MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBN
# YW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0Eg
# TGltaXRlZDEgMB4GA1UEAxMXQ09NT0RPIFRpbWUgU3RhbXBpbmcgQ0ECECtz23Rj
# EUxaWzJK8jBXckkwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTE5MDcxNDAwMTM0OVowIwYJKoZIhvcNAQkEMRYE
# FJ57KNeoHTFVyCmLs60kxK+FJQJeMA0GCSqGSIb3DQEBAQUABIIBALsBKr3RW3nc
# PFszfe/cRpHAy2OM6aRjrnBx73OsX/ZggAMHlzih5PAJQbcue4JuKg48+drGJ8dr
# Zok+I2h+htGNXFKOgGYnXmaVqa6rnn4l9ewdv+ao3xL66/6Kg4qn4GpdH473A4Wd
# OpBOj/DBIMV8+kAMBBpm98/ptq+2+6xk7sVyQ1HSqWw/YYQutvyng4JFUETivE3x
# MvNyRxIgeZyCk3OQZ8/iTCXNO0mF2DMp7OK9RLyoC4FAdlqpBoIETG+Be7GM8CuT
# e9PFsDxcCFaLvi3SNqAZqpGOkw9RM87G3AzRagxdq59Oc8KtxpSmOAEN9lVx1tzO
# fjw74LWOccM=
# SIG # End signature block
