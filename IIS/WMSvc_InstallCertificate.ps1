<#

IIS WEB MANAGEMENT SERVICE (WMSVC) - CERTIFICATE INSTALLATION

Matthew Schacherbauer
2022-02-16

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

v1.2.1

===============

DESCRIPTION

This script checks the status of the existing IIS Web Management Service certificate and replaces the certificate when necessary.
A self-signed certificate is always replaced.
A certificate nearing its expiration will be replaced.
Replacement certificates are issued from a local Enterprise Certificate Authority using the AD CS Template specified.

For automation, this script can be ran as a scheduled tasked or managed by Group Policy.
The script will not take action unless a renewal is necessary.


AD CS Template Notes:
* Must use Legacy CSP
* Private Key must be Exportable
* Default Key is 2048 bits


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


[CmdletBinding()]
Param (
    # Define the domain template
    [ValidateNotNullOrEmpty()]
    $Template				= "WS-RSA-WMSvc",

    # Define the Certificate Friendly Name to use
    [ValidateNotNullOrEmpty()]
    $FriendlyName			= "WMSvc-SHA2",

    # Define the minimum number of days left on the certificate
    # Less than this and the certificate will be replaced
    [ValidateNotNullOrEmpty()]
    $MinimumDaysRemaining	= 30
)


# Test for the required service
if (-not (Get-Service -Name "wmsvc" -ErrorAction SilentlyContinue) ) { Throw "The required service wmsvc is not present" }

# Initialize Variables
$iRequiresReplacement = $false

# Test for an existing, trusted certificate
# FriendlyName should be unique, and this should only return a maximum of one certificate
$oCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -eq $FriendlyName}


# Check for validity
if (!$oCert) {
    Write-Verbose "No existing certificate found. A new certificate will be requested."
    $iRequiresReplacement = $true
}

if ($oCert.SubjectName.Name -eq $oCert.IssuerName.Name) {
    # Certificate is self-signed
    Write-Warning "Self-signed certificate detected and will be replaced."
    $iRequiresReplacement = $true
}
elseif ( (Get-Date) -gt $oCert.NotAfter.AddDays(-$($MinimumDaysRemaining)) ) {
    # Certificate expiring soon
    Write-Verbose "Certificate is expiring soon and will be replaced."
    $iRequiresReplacement = $true
}
else {
    # Certificate is not self-signed
    if (Test-Certificate -Cert $oCert) {
        Write-Verbose "Certificate validated successfully. No replacement will be performed."
        # Tests OK
    }
    else {
        # Fails test
        Write-Verbose "Certificate failed validation and will be replaced."
        $iRequiresReplacement = $true
    }
}


# Replace certificate
if ($iRequiresReplacement) {
    # Request new certificate
    $oNewCert = Get-Certificate -Template $Template -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop

    # Verify we got a certificate issued. Halt if we didn't.
    if (-not $oNewCert) { Throw "Error creating or retrieving new certificate." }

    # Delete the old certificate
    if ($oCert) {
        Remove-Item -Path $oCert.PSPath
        Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $oCert.Thumbprint} | Remove-Item
    }

    # Set the friendly name on the new certificate
    $oNewCert.Certificate.FriendlyName = $oCert.FriendlyName
    #(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $oNewCert.Certificate.Thumbprint}).FriendlyName = $oCert.FriendlyName

    # Use the new certificate going forward
    $oCert = $oNewCert.Certificate
}


# Convert the certificate thumbprint to the required syntax
[Byte[]] $sCertificateBytes = for($i = 0; $i -lt $oCert.Thumbprint.Length; $i += 2) { [convert]::ToByte($oCert.Thumbprint.SubString($i, 2), 16) }

# Replace the thumbprint and restart services if the best certificate is not the currently installed one
if (Compare-Object $sCertificateBytes (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WebManagement\Server\").SslCertificateHash ) {
    # Install the new certificate
    Write-Verbose "Installing Certificate with Thumbprint: $($oCert.Thumbprint)"

    # Stop the Web Management Service
    Stop-Service WMSvc

    # Update the certificate
    if (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue) { # Powershell Method
        Write-Verbose "Updating installed certificate using PowerShell method."
        Import-Module WebAdministration

        Remove-Item -Path IIS:\SslBindings\0.0.0.0!8172
        New-Item -Path IIS:\SslBindings\0.0.0.0!8172 -Value $oCert
    }
    else { # NETSH Method
        # Source: https://stackoverflow.com/questions/53490537/how-do-i-set-the-iis-10-0-management-service-ssl-certificate-via-a-powershell-sc
        # Install the new certificate
        Write-Verbose "Updating installed certificate using NETSH method."

        $sGuid = New-Guid
        netsh http delete sslcert ipport=0.0.0.0:8172
        netsh http add sslcert ipport=0.0.0.0:8172 certhash=$($oCert.Thumbprint) appid=`{$sGuid`} certstorename="MY"
    }

    # Convert thumbprint to bytes and update registry
    Write-Verbose "Updating installed certificate registry information."
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server' -Name IPAddress -Value "*";
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server' -Name SslCertificateHash -Value $sCertificateBytes

    # Start the Web Management Service
    Start-Service WMSvc
}
else {
    Write-Verbose "Determined the best certificate for use is already installed."
}


# SIG # Begin signature block
# MIIoTgYJKoZIhvcNAQcCoIIoPzCCKDsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUoo4ijcbNDjUFWUTlodDirNap
# /EyggiE3MIIFQzCCAyugAwIBAgIQbaYpQoiUJahFer2y6ylZejANBgkqhkiG9w0B
# AQsFADAzMTEwLwYDVQQDEyhXb2xmU3Bpcml0Lk5ldCBSU0EgU0hBMjU2IFJvb3Qg
# Q0EgLSAyMDIwMCAXDTIwMDQxNjIzMjMzNVoYDzIwOTUwNDE2MjMzMzM0WjAzMTEw
# LwYDVQQDEyhXb2xmU3Bpcml0Lk5ldCBSU0EgU0hBMjU2IFJvb3QgQ0EgLSAyMDIw
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxK8CuLktR2vUFz04EyDI
# 6l/r+BCguT15GGOZlMIjBv8qVB3LKSulQJwg9JVFs5efxr6q0G+5gpeeT57myJLm
# jKOMIv/DC5FAzk97+YganwSyy6ixKgjxVO/N3xuRHjRJ5m4p+3b1sovDmpNHFUO3
# RwZyrV5v8kpuEcPcMa+fRPObbukAy6uPx+4K/YRRxqticu7DP5P2vMnlGsiaWqWR
# SzOmUfSYyYVGW37VaGVtQXiKYgBzM1Qx0K0efwH4UgXFCEpl5MJWLx6UKAs+qZXA
# Ka83ZsGhEnzpffn6dxhqV6X1zRw1+a5Djn/ZsAcu7iOduIk5+X3g7ZfCjZIw45xP
# a0mniWP6lCoRmRQLh9nCxRHzW7klH/zLqhMkus/pr+8iP0/DthGly7x1lSY9qwQW
# yYqspYeZdSXGRsTENJ+U8T1useSCHe4dsEHzyM+YgO+jIYSW+gK/ct9xj8oufCsa
# bJn3UhwWBxEUeYh/WyeIh4O/wiS06q7dok7Dt3QyYoUYuclQbMzGHZ50el9fWbgd
# 7clAJjsmD5KGtw3djMBeJs40ALDtK2jKuFhf0fIqBNmHdhr8rT4IzMFzUVxuXWQy
# 8iWg6EOAcggP1WxAzNJLqNq1yyn4f4+UBqmvcbRmy85P5G0jP3NMqMfzDdHRFyy8
# IvN70ElTimOYQt9pzvonw2ECAwEAAaNRME8wCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHQYDVR0OBBYEFMhV95R6whowuTaPvkK4NwOEh1YJMBAGCSsGAQQB
# gjcVAQQDAgEAMA0GCSqGSIb3DQEBCwUAA4ICAQAtBI1V4nEqO2x+HvgUG2OxmWMU
# 1cSKMJ86xsTuXknR90LsG5jfkScjetqB6LkAqaMubqY11bqhS5rAd5tFixJQ3kgx
# 2mdk9Bk0Rm9XEAgj6iTYaMxYVhmuPl4zEQrktITSbVByxo47Dja9LCkTu2jna31W
# Dvv/8XxxIV8E2qjGutEJZb+7c3jinDJmaHPzv5ntJifPXyX88qf4/6CLCKM+sJ8G
# wgsO5DpY8nCadm9bvXF8s+fzoMwq+lom+iP7Ht2VifXQNbNYTwC6dfffYQDO9hmq
# opEJ7rYgK+XUpzUklbDFuMA2129S9O+W0za/7pTewGkq46sRvRyO5vE3TRtfkhpO
# R5TZ5YfjawPqPOE+x7BGlr7HqjHVEDLItTvqMpj7DYkoTiahidien0IJmqf/R//l
# wTTLKys9o7GZkwMI5czuS+kPNT/DmR+rkPnXEYLwyyX6xooRXnXff8EQN4tSmS4S
# 4cJctBYULQlxxOQrzXfBngA4w4lO4OPjXRjlqYblmQQc/qNLPOH66aO924ynMQ4W
# PrRBKD3puhwpQ0Kw+4V439PIvWdBgTJQ/2pAzCPEhwBHgp38MIg7WL4gOCHF0YVU
# WyqfF0z2XcOfx0opdwdINEiACUX564jT2KWCMufovhefgpkDmKK2kMEBcXXdCvq2
# EczYFPELi8nO3FM8qTCCBnEwggRZoAMCAQICE1QAAAACX3ZeHaW7AMEAAAAAAAIw
# DQYJKoZIhvcNAQELBQAwMzExMC8GA1UEAxMoV29sZlNwaXJpdC5OZXQgUlNBIFNI
# QTI1NiBSb290IENBIC0gMjAyMDAeFw0yMDA0MjAyMDAzMzZaFw0zNTA0MjAyMDEz
# MzZaMHgxEzARBgoJkiaJk/IsZAEZFgNuZXQxGjAYBgoJkiaJk/IsZAEZFgp3b2xm
# c3Bpcml0MRMwEQYKCZImiZPyLGQBGRYDbGFuMTAwLgYDVQQDEydXb2xmU3Bpcml0
# Lk5ldCBSU0EgU0hBMjU2IElzc3VpbmcgQ0EgMjAwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC0/E6yL2DqawmKesaFVqjg56pXT3ik/Uqq4k4HZdW8uFJG
# jHGmFPFEX9bsqoZL270yaGTvMvjFU7DWvkkBf71Do+sCIoQsa1dzHgaHbzQudSU3
# 6VMroqbf8FDOfj5zBUfhFbBcfSxyb8OP5CC6yNebMcGUd1+i3ACw5k/ySxx4E11s
# qxJ+xhtWMB2pjw5ZOGKbC9AoilLRdpxjlWP+cQk4jqtPkKyMz9gqjLv1oFUWDzT1
# Br11WOQmI1sPrdPPUzpt75Oif+blF/UexB8q07rdWGrKU1cMQ6mjHu1hjOaXDdqi
# F9pKTJlLl7JW7Yttys+TNyeAZfHjgLWI33dTQWL3NWqK1FrtQuS8nZUckE8Tejdb
# uNsEnCd0chFobkxC+SzPFuDsAfgU9RyQgmJJJ3HmpKyjn4UHOotd2UpWirkxugGC
# PfxaWe0Xd+GcIKRLq+u6zA+crjwNCTMi3el89/iboMUI+i+6Bw5qPaC7aOsodeDU
# tymZmlFELLEHFPoKHN+Se2l+YnU9Kk7RrqM7jrIsrs/l5OkksZ+n5M5RKheg6RF3
# 6ovCnazC8BesBsMRMGYu0jaTBej4SpO+tMGDo3XcLdUC+Xq8hdPd+AUmp9vquQ9m
# 97AiEVhlynFUweo2slZsf1pDQvO8dDji1vivhg338boeqqClAiD5tp+hzqs0IQID
# AQABo4IBNzCCATMwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFMg6cQtic4Ch
# YgqQB1wYPodCY4i/MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFMhV95R6whowuTaPvkK4
# NwOEh1YJME0GA1UdHwRGMEQwQqBAoD6GPGh0dHA6Ly9wa2kud29sZnNwaXJpdC5u
# ZXQvQ1JML1dvbGZTcGlyaXQtUlNBLVNIQTI1Ni0yMDIwLmNybDBXBggrBgEFBQcB
# AQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly9wa2kud29sZnNwaXJpdC5uZXQvQ0Ev
# V29sZlNwaXJpdC1SU0EtU0hBMjU2LTIwMjAuY2VyMA0GCSqGSIb3DQEBCwUAA4IC
# AQBXvaM/M89z482GF7jnskgFc0GBGOZj7essPpj6s7TcAwSf5wye7xWj+ZCEYOHj
# fKsXw4sMnTKOXwmBZ1G6EaPdaEYhYLnVmV5RqHYRRWHFo8E3iY/3YneLDsF86ct/
# Oqg5Hz8mwz4kqvNFTjaCH6dOvjjRnl+PP+U5CJUZL7diH3XsLV4rJ1YuQl7/W/zw
# UC2UagBsGsb1bt7WsBMmf8dHVp1lKGmYaQwTSPSjA7StbKxrhvgpe7XyPMN3NRl/
# 3HyhR7s7/IqXMhrhJzIVCJY7wt10xFVE8kZkcNXO1KEWkHcLJHrtIf9x0r6cRyQI
# dBDfM3lHsr5B6hViZsI2CacRPTe1sr6VD0f0ssAXOGCZQSSDA1w5UTkfeJ26kzGH
# aKuiGCn0VzsKtY5s5wMuBJrCmGZNPUd2gtUDdGqlMSo0peHBIQ9b3RstHFtEi9io
# 7nKuVmJrVvQh/iIlwY7H7qpMbH0eUIJyDxKhocQjDWSVecAe2Dj+kPfwXhipEocF
# 0B1+CHdFweIdQRFmTMYexig1+Oj/ep6y+xSnp+bHvDujncksz7Mo/snB0LzkoV0C
# 1vYdo1XYQht3XlhtsB9ixAYQ5koYqdphuuVCr6cuuohWC14prdeXVi6s1eut5rrH
# 4n/JhuWPri9sONJYupb1EkmD2Sk8jse4/PFFud/kUwZUGTCCBuwwggTUoAMCAQIC
# EDAPb6zdZph0fKlGNqd4LbkwDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwG
# A1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3Qg
# UlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE5MDUwMjAwMDAwMFoXDTM4
# MDExODIzNTk1OVowfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFu
# Y2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1p
# dGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyBsBr9ksfoiZfQGYPyCQvZyAIVST
# uc+gPlPvs1rAdtYaBKXOR4O168TMSTTL80VlufmnZBYmCfvVMlJ5LsljwhObtoY/
# AQWSZm8hq9VxEHmH9EYqzcRaydvXXUlNclYP3MnjU5g6Kh78zlhJ07/zObu5pCNC
# rNAVw3+eolzXOPEWsnDTo8Tfs8VyrC4Kd/wNlFK3/B+VcyQ9ASi8Dw1Ps5EBjm6d
# J3VV0Rc7NCF7lwGUr3+Az9ERCleEyX9W4L1GnIK+lJ2/tCCwYH64TfUNP9vQ6oWM
# ilZx0S2UTMiMPNMUopy9Jv/TUyDHYGmbWApU9AXn/TGs+ciFF8e4KRmkKS9G493b
# kV+fPzY+DjBnK0a3Na+WvtpMYMyou58NFNQYxDCYdIIhz2JWtSFzEh79qsoIWId3
# pBXrGVX/0DlULSbuRRo6b83XhPDX8CjFT2SDAtT74t7xvAIo9G3aJ4oG0paH3uhr
# DvBbfel2aZMgHEqXLHcZK5OVmJyXnuuOwXhWxkQl3wYSmgYtnwNe/YOiU2fKsfqN
# oWTJiJJZy6hGwMnypv99V9sSdvqKQSTUG/xypRSi1K1DHKRJi0E5FAMeKfobpSKu
# pcNNgtCN2mu32/cYQFdz8HGj+0p9RTbB942C+rnJDVOAffq2OVgy728YUInXT50z
# vRq1naHelUF6p4MCAwEAAaOCAVowggFWMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh
# 2JvAnfKyA2bLMB0GA1UdDgQWBBQaofhhGSAPw0F3RSiO0TVfBhIEVTAOBgNVHQ8B
# Af8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcD
# CDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2Ny
# bC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3Jp
# dHkuY3JsMHYGCCsGAQUFBwEBBGowaDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC51
# c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUFkZFRydXN0Q0EuY3J0MCUGCCsGAQUF
# BzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4IC
# AQBtVIGlM10W4bVTgZF13wN6MgstJYQRsrDbKn0qBfW8Oyf0WqC5SVmQKWxhy7VQ
# 2+J9+Z8A70DDrdPi5Fb5WEHP8ULlEH3/sHQfj8ZcCfkzXuqgHCZYXPO0EQ/V1cPi
# vNVYeL9IduFEZ22PsEMQD43k+ThivxMBxYWjTMXMslMwlaTW9JZWCLjNXH8Blr5y
# Umo7Qjd8Fng5k5OUm7Hcsm1BbWfNyW+QPX9FcsEbI9bCVYRm5LPFZgb289ZLXq2j
# K0KKIZL+qG9aJXBigXNjXqC72NzXStM9r4MGOBIdJIct5PwC1j53BLwENrXnd8uc
# Lo0jGLmjwkcd8F3WoXNXBWiap8k3ZR2+6rzYQoNDBaWLpgn/0aGUpk6qPQn1BWy3
# 0mRa2Coiwkud8TleTN5IPZs0lpoJX47997FSkc4/ifYcobWpdR9xv1tDXWU9UIFu
# q/DQ0/yysx+2mZYm9Dx5i1xkzM3uJ5rloMAMcofBbk1a0x7q8ETmMm8c6xdOlMN4
# ZSA7D0GqH+mhQZ3+sbigZSo04N6o+TzmwTC7wKBjLPxcFgCo0MR/6hGdHgbGpm0y
# XbQ4CStJB6r97DDa8acvz7f9+tCjhNknnvsBZne5VhDhIG7GrrH5trrINV0zdo7x
# fCAMKneutaIChrop7rRaALGMq+P5CslUXdS5anSevUiumDCCBwcwggTvoAMCAQIC
# EQCMd6AAj/TRsMY9nzpIg41rMA0GCSqGSIb3DQEBDAUAMH0xCzAJBgNVBAYTAkdC
# MRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQx
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0Eg
# VGltZSBTdGFtcGluZyBDQTAeFw0yMDEwMjMwMDAwMDBaFw0zMjAxMjIyMzU5NTla
# MIGEMQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAw
# DgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNV
# BAMMI1NlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgU2lnbmVyICMyMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkYdLLIvB8R6gntMHxgHKUrC+eXldCWYG
# LS81fbvA+yfaQmpZGyVM6u9A1pp+MshqgX20XD5WEIE1OiI2jPv4ICmHrHTQG2K8
# P2SHAl/vxYDvBhzcXk6Th7ia3kwHToXMcMUNe+zD2eOX6csZ21ZFbO5LIGzJPmz9
# 8JvxKPiRmar8WsGagiA6t+/n1rglScI5G4eBOcvDtzrNn1AEHxqZpIACTR0FqFXT
# bVKAg+ZuSKVfwYlYYIrv8azNh2MYjnTLhIdBaWOBvPYfqnzXwUHOrat2iyCA1C2V
# B43H9QsXHprl1plpUcdOpp0pb+d5kw0yY1OuzMYpiiDBYMbyAizE+cgi3/kngqGD
# UcK8yYIaIYSyl7zUr0QcloIilSqFVK7x/T5JdHT8jq4/pXL0w1oBqlCli3aVG2br
# 79rflC7ZGutMJ31MBff4I13EV8gmBXr8gSNfVAk4KmLVqsrf7c9Tqx/2RJzVmVnF
# VmRb945SD2b8mD9EBhNkbunhFWBQpbHsz7joyQu+xYT33Qqd2rwpbD1W7b94Z7Zb
# yF4UHLmvhC13ovc5lTdvTn8cxjwE1jHFfu896FF+ca0kdBss3Pl8qu/CdkloYtWL
# 9QPfvn2ODzZ1RluTdsSD7oK+LK43EvG8VsPkrUPDt2aWXpQy+qD2q4lQ+s6g8wiB
# GtFEp8z3uDECAwEAAaOCAXgwggF0MB8GA1UdIwQYMBaAFBqh+GEZIA/DQXdFKI7R
# NV8GEgRVMB0GA1UdDgQWBBRpdTd7u501Qk6/V9Oa258B0a7e0DAOBgNVHQ8BAf8E
# BAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBABgNV
# HSAEOTA3MDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3Nl
# Y3RpZ28uY29tL0NQUzBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8vY3JsLnNlY3Rp
# Z28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcmwwdAYIKwYBBQUHAQEE
# aDBmMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29S
# U0FUaW1lU3RhbXBpbmdDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNl
# Y3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBKA3iQQjPsexqDCTYzmFW7nUAG
# MGtFavGUDhlQ/1slXjvhOcRbuumVkDc3vd/7ZOzlgreVzFdVcEtO9KiH3SKFple7
# uCEn1KAqMZSKByGeir2nGvUCFctEUJmM7D66A3emggKQwi6Tqb4hNHVjueAtD88B
# N8uNovq4WpquoXqeE5MZVY8JkC7f6ogXFutp1uElvUUIl4DXVCAoT8p7s7Ol0gCw
# YDRlxOPFw6XkuoWqemnbdaQ+eWiaNotDrjbUYXI8DoViDaBecNtkLwHHwaHHJJSj
# sjxusl6i0Pqo0bglHBbmwNV/aBrEZSk1Ki2IvOqudNaC58CIuOFPePBcysBAXMKf
# 1TIcLNo8rDb3BlKao0AwF7ApFpnJqreISffoCyUztT9tr59fClbfErHD7s6Rd+gg
# E+lcJMfqRAtK5hOEHE3rDbW4hqAwp4uhn7QszMAWI8mR5UIDS4DO5E3mKgE+wF6F
# oCShF0DV29vnmBCk8eoZG4BU+keJ6JiBqXXADt/QaJR5oaCejra3QmbL2dlrL03Y
# 3j4yHiDk7JxNQo2dxzOZgjdE1CYpJkCOeC+57vov8fGP/lC4eN0Ult4cDnCwKoVq
# sWxo6SrkECtuIf3TfJ035CoG1sPx12jjTwd5gQgT/rJkXumxPObQeCOyCSziJmK/
# O6mXUczHRDKBsq/P3zCCB3wwggVkoAMCAQICEx4AAAAJHUHnoaekE7YAAAAAAAkw
# DQYJKoZIhvcNAQELBQAweDETMBEGCgmSJomT8ixkARkWA25ldDEaMBgGCgmSJomT
# 8ixkARkWCndvbGZzcGlyaXQxEzARBgoJkiaJk/IsZAEZFgNsYW4xMDAuBgNVBAMT
# J1dvbGZTcGlyaXQuTmV0IFJTQSBTSEEyNTYgSXNzdWluZyBDQSAyMDAeFw0yMDA2
# MDcwNDUxMzFaFw0yMjA2MDcwNDUxMzFaMIGcMRMwEQYKCZImiZPyLGQBGRYDbmV0
# MRowGAYKCZImiZPyLGQBGRYKd29sZnNwaXJpdDETMBEGCgmSJomT8ixkARkWA2xh
# bjETMBEGA1UECxMKV29sZlNwaXJpdDEOMAwGA1UECxMFVXNlcnMxDzANBgNVBAsT
# Bkh1bWFuczEeMBwGA1UEAxMVTWF0dGhldyBTY2hhY2hlcmJhdWVyMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0VqQPXWkbwomUX3mL3TUR0xu4KsoKiav
# /NXsEatdGdPsOv3fKKOwRL7aELrgOndwawBb4SwGmP+siMNGPHft4AV2vOlCj4v9
# XbMw25JyJpreA9+eK9MTvT4dw1pNO5XkXyZdszE59P/t1n86iBOqo12nr1xTADLQ
# +6oF7ToN7Uk2EL7S5f/uVof9FvpNEGoqLMiiU8m0NIxltEDnviDCt3POKVDcgJgO
# LK6oarv2qq3gprWM/KP2O5clHD/AAgZSv9E762141/GRB54O4ZaWp8xHB2hLjaYr
# v/eEARWu0x7+M0hYf0Khokjag1uVTlfufezZZtebrjb4hyUwi8e1ZUE45Mfp5+n9
# AMcDriIq1TxdtwHkY6+tRanbDkaIMn7Oozxd7V2ZqUPz+BvXwSykjoWa/vkksk3L
# vRwtVKeCILEZQTY/rTT3GLlion67wHqIiRI9MEdPgkXUY3PMJTU+eErlf4Ds2y8/
# sL8hTvHDH56glNOOUl0SN9lIHRJVDrxoGbNf9s9luGANKci4hQdrbFw2KMnuAc03
# 6zt74bYEt6QzsYvnkvQHjUzbCUFsYrfWwgJBchIoXmdm0L3dXJVGnTQ1NzQU4Szz
# Eltp3vQdQRWLhkTz9YBIy4e0sU3XQCNlRrECuOAXH8KuXa89B5PbhAAsgk19siCn
# T2scoFMq47ECAwEAAaOCAdgwggHUMD0GCSsGAQQBgjcVBwQwMC4GJisGAQQBgjcV
# CILfjEGCwqxsgo2XIYP39QqGqIp3DILkkhKB6ZBHAgFkAgECMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsG
# AQUFBwMDMB0GA1UdDgQWBBToZurMEYGWIcEjAngfHLGe1dj/AjAfBgNVHSMEGDAW
# gBTIOnELYnOAoWIKkAdcGD6HQmOIvzBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8v
# cGtpLndvbGZzcGlyaXQubmV0L0NSTC9Xb2xmU3Bpcml0LVJTQS1TSEEyNTYtSVNT
# VS0yMC5jcmwwgYcGCCsGAQUFBwEBBHsweTBKBggrBgEFBQcwAoY+aHR0cDovL3Br
# aS53b2xmc3Bpcml0Lm5ldC9DQS9Xb2xmU3Bpcml0LVJTQS1TSEEyNTYtSVNTVS0y
# MC5jZXIwKwYIKwYBBQUHMAGGH2h0dHA6Ly9vY3NwLndvbGZzcGlyaXQubmV0L29j
# c3AwNQYDVR0RBC4wLKAqBgorBgEEAYI3FAIDoBwMGm1hdHRoZXdAbGFuLndvbGZz
# cGlyaXQubmV0MA0GCSqGSIb3DQEBCwUAA4ICAQCXg3SbXISR1WN4cskUu9jLebdA
# 1WTNJeWGZcEO1OJCxaYHCtbP7+LAFtAIqPhBuNxycFfeeFF3LK3q/hteUvPKSqC1
# X8/B2Dgw509FiUH2UAm062PwURuBltlczRCMH9FV92gMWfEGGjOL2/eP307StXH0
# /oVl1Eua4mxgfJGtTWHsYwCRHMMyHzkWhmx6EBj5JPC87XdmRmR6m2lIxjcEdc2v
# /st9l0ghJzMSebH7lnk7j7VzDgsfeynS7fto6FeCBBJdwl3XaWe9WIRFKTlqILkW
# BnhVmDBQ5CBb3poVJe3a/brFqChSxw/mKf7piFyYIJ3SkdX/7/jYqSfwEv6Le9Qf
# m2EbBoIibmhf4zZvcn7ufRgKUbQZbG7t6/L6B1ZAxN6IuZdfOmrnrpZcstW2aGvU
# 8JPK8kbjDWQVEKq8lqnba+ac/VEhH9pmwsH2b0vK95RpP2mck2Fx2EnAubKSIe6c
# XzWnmMbefnfyI5pRxuIX3gmHTcTqbq0LierdhLj+P2lWdjH5Rn4jkx5uKq/3QBVB
# LN9TVZ5aTCqol/KW8xiMbuHc+GUaV2zoJnB9TBZu28JfeBL7X6X8xFPGv9IieSQT
# Z9nTgB5viz1/4kPXutYMb5NqLAUHMx/JqSDM6RLO1CR5IdIEBaRD+NRXMkUmpwE2
# Lm1dBNMO7KfbEi9N2DGCBoEwggZ9AgEBMIGPMHgxEzARBgoJkiaJk/IsZAEZFgNu
# ZXQxGjAYBgoJkiaJk/IsZAEZFgp3b2xmc3Bpcml0MRMwEQYKCZImiZPyLGQBGRYD
# bGFuMTAwLgYDVQQDEydXb2xmU3Bpcml0Lk5ldCBSU0EgU0hBMjU2IElzc3Vpbmcg
# Q0EgMjACEx4AAAAJHUHnoaekE7YAAAAAAAkwCQYFKw4DAhoFAKB4MBgGCisGAQQB
# gjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGmWqp1j
# L+6CmhWsy1iuJyYcCPJDMA0GCSqGSIb3DQEBAQUABIICAC9t0sMBolMZu4SE9/DG
# M/YGS2Jeu/vR3BNN4aZU8EaCupXLr9kZl1NNHdlJpdR0BzfUBZuCV0qrkQOQqwBU
# HpfIqTk1pHwk7TqQ/LcIQRGTfAmgiM7X5U+rG0klWrcT5J1bzEoX7de5EnmZnNzp
# 6ZKcwUwqjC8s7QkYNYd3uTSgTGQ9nV5+vZeC1tXTqPdKY3O3f5+yl/mKW7t6E+Dn
# hsInV+MOR0s9jS5z8Dz1HYD7xfgyiP71TTEsWrLkY0dpBp52JIlCDlYPM1RVcgZz
# pwbSWVl0c8jcHjVURRHI8mBoEh2GEQe7Mk/hs3wTvXFGW1KzBlRXZTkO+jl7lpxz
# Jcy6bho8bE2NxP+E/kp0c2au+yX4xmK6D+n1pJuQaLPFbCHzVIj8mm0dAkmHLLR0
# 3iLRZ2pPrs8FbfrFVs2mm8p3IQxG2wEFtFp9ulCZmuKNomNccGrpJECo/VCw1UGn
# fN5csypM3MBYtm79DSAJS0BbhT37tArij13m/ygEtD8i+CBsiH8mZm4qcsKa0slC
# JS3ZYEvcDX+1mgJFAS7sAXKuK+aMGOtsIa6OITyKO+VIFLDZaPV+MEzWygOEdsD9
# GFbqyj3fbnCOm6ouiv+H/7adCEG0P4iLIyza0Vzb+YlHPdrShFj4PWdBn3dg4qz6
# CY7uYY/0rkI2WJHLwx9Y1pcwoYIDTDCCA0gGCSqGSIb3DQEJBjGCAzkwggM1AgEB
# MIGSMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIx
# EDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDElMCMG
# A1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBDQQIRAIx3oACP9NGwxj2f
# OkiDjWswDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yMTA3MDQyMjM5NDZaMD8GCSqGSIb3DQEJBDEyBDBl
# pZIR/QBLERwLp/QfWAltwQZS/se+/M8bhFC2fC/yWKklSm8Iayxs8WyE1ZlAQIUw
# DQYJKoZIhvcNAQEBBQAEggIALV1cSpQhOBuDbC1kXELx0mBOhDrOTxPT8XJJ3gU8
# 3Ft+Domr4Sg76yRZLsQJ+9A8rQHFp1tX0TNyKJK3kcOqFBy471eLIXQoizo8ap1Q
# OdIRmQOoQNc/fSMXJBPm0S3yVGbUJqq1S72XbkCEYiUtzEP5isByAyzkNlySBAV6
# 5ux0LnAbUHbNEsh4IDBkn2QzRdUB5f1RVszdVzsctJMysT3DrdDZAjAGs2+UlZ/B
# ZmyI6ZQ1HaqpesRFAd8U1XRbgFydKPlh6rWeaG2mJ8Ul2wZDRFy7ZowYf075MAMN
# 4V9BY+IJzy+1452i3nN8HSyT8eKcCwJYCi3OVo/Asud41/7Yo+KWH7TpVHKuxXkN
# rzRkLmCsSvF2RmCDnMtbnP6ehS5mw0IGvoWmmGVz9XdZZJVylHiFXCCiT8i6yDuG
# wNxZiKZsEt1la5A0sZ7gNJwATUPxo1UW9a7uja1TofPFIH34O1M1qcktUMU4iVvy
# SwM3Ui90Un0HmfSt/mLnHOr8Ex0YUyNV7tXde/o1VUY4lisFOXyTfiPf2x3h5gAO
# cCBQLaDCXINM0Fis4u2ZZs1U1p6jTaytuBxUzZeio21THv5mXNSYD6lXQaIgeG6G
# iuuWJqJK2IOxS2hzFdOOJfJDveyDkyD8BlcFbaXAN49IYFgFcDLezT/y04OupzC0
# x3A=
# SIG # End signature block
