<#

IIS WEB MANAGEMENT SERVICE (WMSVC) - CERTIFICATE INSTALLATION

Matthew Schacherbauer
2020-08-01

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

v1.0

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
    $MinimumDaysRamaining	= 30
)


# Test for the required service
if (-not (Get-Service -Name "wmsvc" -ErrorAction SilentlyContinue) ) { Throw "The required service wmsvc is not present" }

# Initialize Variables
$iRequiresReplacement = 0

# Test for an existing, trusted certificate
# FriendlyName should be unique, and this should only return a maximum of one certificate
$oCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -eq $FriendlyName}


# Check for validity
if (!$oCert) { Throw "No certificate found for replacement." }
if ($oCert.SubjectName.Name -eq $oCert.IssuerName.Name) {
    # Certificate is self-signed
    Write-Warning "Self-signed certificate detected and will be replaced."
    $iRequiresReplacement = 1
}
elseif ( (Get-Date) -gt $oCert.NotAfter.AddDays(-$($MinimumDaysRemaining)) ) {
    # Certificate expiring soon
    Write-Verbose "Certificate is expiring soon and will be replaced."
    $iRequiresReplacement = 1
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
        $iRequiresReplacement = 1
    }
}


# Replace certificate
if ($iRequiresReplacement -eq 1) {
    # Request new certificate
    $oNewCert = Get-Certificate -Template $Template -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop

    # Delete the old certificate
    if ($oCert) {
        Remove-Item -Path $oCert.PSPath
        Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Thumbprint -eq $oCert.Thumbprint} | Remove-Item
    }

    # Set the friendly name on the new certificate
    $oNewCert.Certificate.FriendlyName = $oCert.FriendlyName
    #(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $oNewCert.Certificate.Thumbprint}).FriendlyName = $oCert.FriendlyName

    # Install the new certificate
    if (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue) { # Powershell Method
        Import-Module WebAdministration
        Stop-Service WMSvc
        Remove-Item -Path IIS\SslBindings\0.0.0.0!8172
        New-Item -Path IIS:\SslBindings\0.0.0.0!8172 -Value $oNewCert
        Start-Service WMSvc
    }
    else { # NETSH Method
        # Source: https://stackoverflow.com/questions/53490537/how-do-i-set-the-iis-10-0-management-service-ssl-certificate-via-a-powershell-sc
        # Install the new certificate
        Stop-Service WMSvc
        $sGuid = New-Guid
        netsh http delete sslcert ipport=0.0.0.0:8172
        netsh http add sslcert ipport=0.0.0.0:8172 certhash=$($oNewCert.Certificate.Thumbprint) appid=`{$sGuid`} certstorename="MY"

        # Convert thumbprint to bytes and update registry
        $sBytes = for($i = 0; $i -lt $oNewCert.Certificate.Thumbprint.Length; $i += 2) { [convert]::ToByte($oNewCert.Certificate.Thumbprint.SubString($i, 2), 16) }
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server' -Name IPAddress -Value "*";
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server' -Name SslCertificateHash -Value $sBytes
        Start-Service WMSvc
    }
}


# SIG # Begin signature block
# MIIoTAYJKoZIhvcNAQcCoIIoPTCCKDkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdWE50EVf6QORxK2nkZKF38v+
# kCKggiE2MIIFQzCCAyugAwIBAgIQbaYpQoiUJahFer2y6ylZejANBgkqhkiG9w0B
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
# fCAMKneutaIChrop7rRaALGMq+P5CslUXdS5anSevUiumDCCBwYwggTuoAMCAQIC
# ED0aNXIwFYJjMNATcX6CQQgwDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0Ix
# GzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBU
# aW1lIFN0YW1waW5nIENBMB4XDTE5MDUwMjAwMDAwMFoXDTMwMDgwMTIzNTk1OVow
# gYQxCzAJBgNVBAYTAkdCMRswGQYDVQQIDBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
# BgNVBAcMB1NhbGZvcmQxGDAWBgNVBAoMD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UE
# AwwjU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzEwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDLUVD/Vv78eGNwAZNanhj0O1P2B68hbPWi
# D30dcC2EdEiLnIqVBT1ZhPmRgHlRLNmKt8ELmroKis1mTwOLAbswyqu928BPEl78
# CsziRbABOIq7TefUHFSY7TlYz1vCL0WYMQr5NTi4MS5ttB45cuG4Kr6fjIwapUau
# CytMmf4sS/wouSI6ZhfQqlaKIcDzliS00IUma7rwb2SYeaatvVzYU2srCtZyioVG
# 4w0YBtrGe0FWNpsVPvFqEaD3ZvUY0IBVY4doZusOeVWCXKPtSbhxhp6TN7Bro+pi
# bKOului5/YurxvZZWwA8VyAYLXADp5zvkut5ocdd7Hy0j0vf6138oyDdkjjlalE6
# a4WcTKCYCGlbBucqGdCVk4s7a4oFCSnY1trb43L6XEovexVWhjK/fwUJnS0qz1Dh
# 5mEg28cGgFxOFEa+rldxoqpsMJMcfnfLBulXzZH11TNyHOHaym7r8w/seVu7J57o
# Hv4v8rt/6eXQZ+u4DXykK1kDi5XtIijN+iw7xxYRr+PWsVBnacWO9XnQrf+HzPh/
# qvmi7WH4yI1p2rH0UZHrZ1fRZBHrZMsDvUlVOkVDGCwlbNEvDC1v9UE1JKDyY1kW
# X9mk6SxO27sxEsZt+FtuA9zLFY8bjXLs2w8VkNYSTu7iADElkzVvalulEmNAAYq5
# aYg6iLgPGQIDAQABo4IBeDCCAXQwHwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1
# XwYSBFUwHQYDVR0OBBYEFG9NhgfYMieeLCnS0BMDgIHdBYMpMA4GA1UdDwEB/wQE
# AwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEAGA1Ud
# IAQ5MDcwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2Vj
# dGlnby5jb20vQ1BTMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuc2VjdGln
# by5jb20vU2VjdGlnb1JTQVRpbWVTdGFtcGluZ0NBLmNybDB0BggrBgEFBQcBAQRo
# MGYwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1JT
# QVRpbWVTdGFtcGluZ0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2Vj
# dGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAMBo7bPY1FCb79N1yw879yTTejdF
# jSzvFvtRqSwftSW1ip9dC8IbIHSNZg82y6r2Ng0Pfo9LSnRDZawNKvYK7WttxQk4
# 7QAb+OXcpgpABUfvhMoJvENmg7+f7duOPdFBZLFwAi0DV1sYbxwsyx6yAOi6CS9b
# gQQ1ualjbY4IxRjR4SGs+RIKFMAS234lnawdEMBapYPSHxpmVfybKuLsN1eO5d+W
# MPjAkwtDGPkCb6lRr7hXCvMcB2k5jzecbdeRrqUuSelK3rPQjL85kA3Agc7wKgc6
# DKYtUdJy81PG+b3v7wxpSXefLFbE6aEIPQeuxR7WhCLHvH1DG1g4Yk7RBSWExUL4
# Hy/22/qrjFTsRYpsEk0wWlLlpBcJIubvb/VfhkPfoS29SkaSoIGWLGGXf0Bv2D+M
# NVqr0cagO4VmVIDvHxr18ZuwoSd9sucLz/YtnFgTlKmG/EVSoihtf3QPUpFJeukS
# +Kk7sJL9fZEU6VttSJTyyJbuBTizxewwP+EHIASx2Iu8/bM+b/ICUwb0oO3JmnKj
# l18A+8tj0OjNdP11ydQ2Rbp7Elly7efyelAAePhDmkbY379U1F6xx9G8G4P0K+cL
# 6EfIU57MGqz2+op1U2wghanVuGq6JI6KKwiRnzcEHPZvot00qpH/xhUuHkIaCSlP
# 9MbN4pGi00AMjnjjMIIHfDCCBWSgAwIBAgITHgAAAAkdQeehp6QTtgAAAAAACTAN
# BgkqhkiG9w0BAQsFADB4MRMwEQYKCZImiZPyLGQBGRYDbmV0MRowGAYKCZImiZPy
# LGQBGRYKd29sZnNwaXJpdDETMBEGCgmSJomT8ixkARkWA2xhbjEwMC4GA1UEAxMn
# V29sZlNwaXJpdC5OZXQgUlNBIFNIQTI1NiBJc3N1aW5nIENBIDIwMB4XDTIwMDYw
# NzA0NTEzMVoXDTIyMDYwNzA0NTEzMVowgZwxEzARBgoJkiaJk/IsZAEZFgNuZXQx
# GjAYBgoJkiaJk/IsZAEZFgp3b2xmc3Bpcml0MRMwEQYKCZImiZPyLGQBGRYDbGFu
# MRMwEQYDVQQLEwpXb2xmU3Bpcml0MQ4wDAYDVQQLEwVVc2VyczEPMA0GA1UECxMG
# SHVtYW5zMR4wHAYDVQQDExVNYXR0aGV3IFNjaGFjaGVyYmF1ZXIwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDRWpA9daRvCiZRfeYvdNRHTG7gqygqJq/8
# 1ewRq10Z0+w6/d8oo7BEvtoQuuA6d3BrAFvhLAaY/6yIw0Y8d+3gBXa86UKPi/1d
# szDbknImmt4D354r0xO9Ph3DWk07leRfJl2zMTn0/+3WfzqIE6qjXaevXFMAMtD7
# qgXtOg3tSTYQvtLl/+5Wh/0W+k0QaiosyKJTybQ0jGW0QOe+IMK3c84pUNyAmA4s
# rqhqu/aqreCmtYz8o/Y7lyUcP8ACBlK/0TvrbXjX8ZEHng7hlpanzEcHaEuNpiu/
# 94QBFa7THv4zSFh/QqGiSNqDW5VOV+597Nlm15uuNviHJTCLx7VlQTjkx+nn6f0A
# xwOuIirVPF23AeRjr61FqdsORogyfs6jPF3tXZmpQ/P4G9fBLKSOhZr++SSyTcu9
# HC1Up4IgsRlBNj+tNPcYuWKifrvAeoiJEj0wR0+CRdRjc8wlNT54SuV/gOzbLz+w
# vyFO8cMfnqCU045SXRI32UgdElUOvGgZs1/2z2W4YA0pyLiFB2tsXDYoye4BzTfr
# O3vhtgS3pDOxi+eS9AeNTNsJQWxit9bCAkFyEiheZ2bQvd1clUadNDU3NBThLPMS
# W2ne9B1BFYuGRPP1gEjLh7SxTddAI2VGsQK44Bcfwq5drz0Hk9uEACyCTX2yIKdP
# axygUyrjsQIDAQABo4IB2DCCAdQwPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGCNxUI
# gt+MQYLCrGyCjZchg/f1CoaoincMguSSEoHpkEcCAWQCAQIwEwYDVR0lBAwwCgYI
# KwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFOhm6swRgZYhwSMCeB8csZ7V2P8CMB8GA1UdIwQYMBaA
# FMg6cQtic4ChYgqQB1wYPodCY4i/MFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9w
# a2kud29sZnNwaXJpdC5uZXQvQ1JML1dvbGZTcGlyaXQtUlNBLVNIQTI1Ni1JU1NV
# LTIwLmNybDCBhwYIKwYBBQUHAQEEezB5MEoGCCsGAQUFBzAChj5odHRwOi8vcGtp
# LndvbGZzcGlyaXQubmV0L0NBL1dvbGZTcGlyaXQtUlNBLVNIQTI1Ni1JU1NVLTIw
# LmNlcjArBggrBgEFBQcwAYYfaHR0cDovL29jc3Aud29sZnNwaXJpdC5uZXQvb2Nz
# cDA1BgNVHREELjAsoCoGCisGAQQBgjcUAgOgHAwabWF0dGhld0BsYW4ud29sZnNw
# aXJpdC5uZXQwDQYJKoZIhvcNAQELBQADggIBAJeDdJtchJHVY3hyyRS72Mt5t0DV
# ZM0l5YZlwQ7U4kLFpgcK1s/v4sAW0Aio+EG43HJwV954UXcsrer+G15S88pKoLVf
# z8HYODDnT0WJQfZQCbTrY/BRG4GW2VzNEIwf0VX3aAxZ8QYaM4vb94/fTtK1cfT+
# hWXUS5ribGB8ka1NYexjAJEcwzIfORaGbHoQGPkk8Lztd2ZGZHqbaUjGNwR1za/+
# y32XSCEnMxJ5sfuWeTuPtXMOCx97KdLt+2joV4IEEl3CXddpZ71YhEUpOWoguRYG
# eFWYMFDkIFvemhUl7dr9usWoKFLHD+Yp/umIXJggndKR1f/v+NipJ/AS/ot71B+b
# YRsGgiJuaF/jNm9yfu59GApRtBlsbu3r8voHVkDE3oi5l186aueullyy1bZoa9Tw
# k8ryRuMNZBUQqryWqdtr5pz9USEf2mbCwfZvS8r3lGk/aZyTYXHYScC5spIh7pxf
# NaeYxt5+d/IjmlHG4hfeCYdNxOpurQuJ6t2EuP4/aVZ2MflGfiOTHm4qr/dAFUEs
# 31NVnlpMKqiX8pbzGIxu4dz4ZRpXbOgmcH1MFm7bwl94EvtfpfzEU8a/0iJ5JBNn
# 2dOAHm+LPX/iQ9e61gxvk2osBQczH8mpIMzpEs7UJHkh0gQFpEP41FcyRSanATYu
# bV0E0w7sp9sSL03YMYIGgDCCBnwCAQEwgY8weDETMBEGCgmSJomT8ixkARkWA25l
# dDEaMBgGCgmSJomT8ixkARkWCndvbGZzcGlyaXQxEzARBgoJkiaJk/IsZAEZFgNs
# YW4xMDAuBgNVBAMTJ1dvbGZTcGlyaXQuTmV0IFJTQSBTSEEyNTYgSXNzdWluZyBD
# QSAyMAITHgAAAAkdQeehp6QTtgAAAAAACTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUoR2Ooi6u
# TLDbWchFagYH7cDs/ZAwDQYJKoZIhvcNAQEBBQAEggIADub3SzeW55ADcZ+xnQYP
# GTpHaACFlxShqZbRRt89u1JX5t/9djUhvsCB29SJHMLSdZ+/Ob21XTnawJD7H7iJ
# bO3ppOpywAtL+X0bpy6VgCBDwS3aiRYG5+d96+ty4wu4gZGp00dVm83myAJDEOvV
# EPdJptmjiuM5nh6BeVCVBFP7ZSg/vssyf5+AJbAyPGQ4mNs1lCbmYdYoY+I+VYjl
# +jAeXluLFZsPIr224E2CId6+BguGjyGOisWRWl2wHtR1C1IzjBXThXdjbkx9dbEM
# 6T1bOU0N9Mtmp5xLp13lbhLNVu8Lb7PgDs7gYVFUgQ09CKW/cYboN8YwEll/pSQC
# IRw8mHTDPxLCyCNxtNqusInVsdqOLKvARdFOjlfBvzuZlOVzUr7Vy4OhU+K6uia7
# 9X6j4ODXDGwsZ3HjQNKRKSBxCt5Nz6N4ckckb7mcfY2FednGLtRZVmA4mEdxfX0z
# 6mZeygFRJTiw9Jpd9ni/NuxIIuEEv49l3uc81VY3m2JJxGkdyNQlT+uDm+brJThW
# L4Qik9MIJomlziuM8mAGhlzDoHb4/0coGfy+aULcTp8WuL5KwIaMPHillvm1QfhC
# MRNF7vvdslif0zV/5zlbcU8SxkPvdxmzpPBS4qc1Taz3MeB6y7MEhGBKn6vPkvr5
# EVXu8iQ5EtN2bySFi+I46x6hggNLMIIDRwYJKoZIhvcNAQkGMYIDODCCAzQCAQEw
# gZEwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQ
# MA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYD
# VQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBAhA9GjVyMBWCYzDQE3F+
# gkEIMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMjAwODAxMTU0NzQyWjA/BgkqhkiG9w0BCQQxMgQwDKfX
# GuMQLiRaz9CwVdATn1jVM6MbnQpOVt7PoHqscUb4ByV0HGHFm5c9L4HWiwvGMA0G
# CSqGSIb3DQEBAQUABIICAGHo460d5i2LsfcnBghc9C7zobANzBBjEPP34DUZworU
# 4maZlqTHdXRPV/vEq3Tefbsl5tGccqNJAb1MK1yLocrg31FscRVshIENPCzB382A
# 1RmfWZ+N6+YB8SOBH1ZRwoqc3R5ZM8Rt37Q13Tvt4tEqX27XsaXeJ5a8sbKCMQcA
# ihPRuMrBDhIZ49DMQDyD6COZSC5AYQ31E5kBb3Ql22eTokA2W2pO7l2we/S3K9wk
# urb8KxJzGzpt0DZKIEB66CP305wS9Bo0dOO/cMjbsN6SdFfthf7mJUyOW0bG3rAS
# gTmAOjAi/xRgMmoUsGm0PQR+/SqiurPsm+fSKtWncZfUq3pIYtlhe3nagNxw2F+O
# YuVGkOPf9RA7PTtIX5BX/rtmxSLb0ntQgF+nb5GShhOn7KAZEvPtvekUp0zkA/Xg
# EiHN7iLKRv8jihkYk8ZNwDxI9w5SvSENOs/eohCaTLifcGkvkQLO1x+VgqcKRZbK
# Yh0djyl8W9lnZg/CtW76jkjB7RK/baY8vNHdhkN1eQ0bQ+u+G88f7lf7M8CS81Ro
# k3CcLf2D8qJAs+Rb91EX94xAP95r7+rZ9y+mMze1ZrYZ2KLkCR8idx0rO+VWREzq
# eO0kvxw2H3U9l6hQZYCDGK4Mlv0jaG41yzGvScdMvXn1gV7LOjVcsAAzVJyUNzqj
# SIG # End signature block
