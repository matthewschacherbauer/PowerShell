<#

VMWARE BLAST DESKTOP AGENT - CERTIFICATE INSTALLATION

Matthew Schacherbauer
2021-03-13

v2.0

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

===============

DESCRIPTION

This script installs an enterprise trusted certificate to the local VMBlast service to resolve the TLS trust error that occurs when a client connects by browser without tunneling (typically an internal HTML5 client). This method does not rely on a wildcard certificate.

A valid certificate should exist in the local machine store.
The certificate may pre-exist or be obtained by an enrollment mechanism. This script will attempt to use autoenroll mechanisms provided by an Enterprise Active Directory Certificate Authority to obtain a valid certificate when none are pre-installed.

To be considered valid, the certificate must meet the following criteria:
1) Be valid for Server Authentication
2) Have an associated Private Key
3) The Private Key must be exportable
4) The certificate must be valid for the local FQDN
5) Specific ADCS requirements must be met

If the automatically selected certificate is not valid for use, the Blast service will generate a new self-signed certificate on startup.


HORIZON VIEW CONFIGURATION PREREQUISITES

For this to work, the Horizon Client must connect using the DNS name of the machine.

See the following VMware documentation:
https://docs.vmware.com/en/VMware-Horizon-7/7.1/com.vmware.horizon-view.installation.doc/GUID-8E7FBB9D-F2DB-4787-B11B-7506126DEB7F.html


MICROSOFT ADCS CONFIGURATION PREREQUISITES

You must create a dedicated certificate template with the following required settings.

Start by cloning the default "Computer" template.
Genearl > Validity Period > Set this to a value greater than the MinimumDaysRemaining value used in this script.
Compatibility > Set appropriately. In testing, I used CA: Server 2012, Recipient: Windows 7.
Request Handling > [X] Allow private key to be exported
Cryptography > Provider Category > [X] Legacy Cryptographic Service Provider (REQUIRED)
Cryptography > Minimum Key Size > [X] 2048
Subject Name > Subject name format > [X] DNS name
Subject Name > Include this information in alternate subject name > [X] DNS name

Optional: Do not store certificate requests in the CA database.
          For non-persistent environments where certificates are frequently reissued, it may be desirable to not store these short lived certificates in the CA database.
          The certificate must contain valid revocation data even if the certificate is not stored in the CA database.
Server > [X] Do not store certificates and requests in the CA database
Server > [ ] Do not include revocation information in issued certificates

Optional: To allow the script to specify custom Subject Name and Subject Alternate Name values, use the following.
Note: This may pose a security issue as machines can arbitrarily request ANY named certificate.
      Not recommended in a production environment.
Subject Name > [X] Supply in Request

The resulting certificate template must be a version 2 template.


INSTALLATION

It is suggested to use a Group Policy Scheduled Task operation to execute this script on the VDI machines.
In practice, I found that triggering on the following events were extremely reliable.
    Microsoft-Windows-GroupPolicy/Operational   8000    (Boot Policy Processing Completed)
    Microsoft-Windows-GroupPolicy/Operational   8004    (Computer Policy Processing Completed)

The script is safe to run repeatedly and will not attempt to restart the Blast service unless a better certificate is found.
For the safest approach, use -NoRestartIfActive to check for active user sessions.

You may edit the default parameters and resign the script, or supply parameters at call time.


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

.PARAMETER Template
Specify the name of the Active Directory Certificate Services Template to use for enrollment.
.PARAMETER FriendlyName
Specify a FriendlyName value.
If an existing certificate with this value is found, it will be given preference.
If a new certificate is obtained, it will be assigned this value.
.PARAMETER MinimumDaysRemaining
If the selected certificate has fewer than this many days remaining, it will be automatically renewed using the template specified by -Template.
.PARAMETER IpFilter
When requesting custom SAN values, only local IPs matching this value will be used.
Wildcards accepted.
.PARAMETER NoRestartIfActive
If the system has one or more active user sessions, the certificate will not be applied.
A certificate will still be checked and obtained, if needed, regardless of this value.
.PARAMETER SkipDisconnectWarning
Skips the notification message sent to users prior to restarting the VMBlast service.
Restarting the VMBlast service will disconnect Blast sessions.
.EXAMPLE
Horizon_InstallBlastCertificate.ps1 -Template WS-RSA-VMwareBlastService -FriendlyName VMBlast -MinimumDaysRemaining 5 -IpFilter "10.*"
.EXAMPLE
Horizon_InstallBlastCertificate.ps1 -Template WS-RSA-VMwareBlastService -FriendlyName VMBlast -MinimumDaysRemaining 2 -NoRestartIfActive

#>

#Requires -Version 3.0

[CmdletBinding()]
Param (
    $Template				= "WS-RSA-VMwareBlastService",
    $FriendlyName			= "VMBlast",
    $MinimumDaysRamaining	= 5,
    $IpFilter               = "10.*",
	
	[Switch] $NoRestartIfActive,
	[Switch] $SkipDisconnectWarning
)


Function formatThumbprint {
    # Formats the certificate thumbprint.
    # Converts the thumbprint to lower case and with a space after every two characters.

    Param (
        $Thumbprint
    )

    return $Thumbprint.ToLower() -replace '(..(?!$))','$1 '
}

Function numberLoggedOnUsers {
	# Gets the number of active user sessions.
	# TODO: Exclude disconnected sessions from session count.
	
	$num = $(QUSER).count
	
	if ($num -ge 1) { return $num - 1 }
	return 0
}


# Test for the required service
if (-not (Get-Service VMBlast -ErrorAction SilentlyContinue) ) { Throw "The required service VMBlast is not present." }


# Initialize Variables
$iRequiresReplacement = $false


# Check for an existing certificate
# If a certificate exists with the specified FriendlyName, use it. Otherwise, use any valid certificate.
# If no valid certificate exists, attempt to enroll for a certificate.
$oCertList = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList -like "*Server Authentication*" -and
    $_.HasPrivateKey -and
    $_.DnsNameList -like "*.$( (Get-WmiObject Win32_Computersystem).Domain )" -and
    $_.PrivateKey.CspKeyContainerInfo.Exportable -eq $true
}

Write-Verbose "Found $($oCertList.count) qualified certificates in the computer certificate store."


# Select a certificate, either by FriendlyName or by the longest validity time
if ($oCertList) {
    $oCert = $oCertList | Where-Object { $_.FriendlyName -eq $FriendlyName }
    if ($oCert) {
        Write-Verbose "Selected existing certificate with FriendlyName ($($FriendlyName)) and Thumbprint ($(formatThumbprint -Thumbprint $oCert.Thumbprint))"
    }
    else {
        Write-Verbose "No certificate found with the FriendlyName ($($FriendlyName)). Selecting the certificate with the longest remaining life."
        $oCert = $oCertList | Sort-Object NotAfter | Select-Object -Last 1
    }
}
else {
    Write-Verbose "No usable certificate was found in the local certificate store."
    $iRequiresReplacement = $true
}


# If an existing cert exists, validate it.
if ($oCert) {
	Write-Verbose "Validating selected certificate."
	
    # Check for validity
    if ($oCert.SubjectName.Name -eq $oCert.IssuerName.Name) {
        # Certificate is self-signed
        Write-Warning "Self-signed certificate detected and will be replaced."
        $iRequiresReplacement = $true
    }
    elseif ( (Get-Date) -gt $oCert.NotAfter.AddDays(-$($MinimumDaysRamaining)) ) {
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
}


# Replace certificate
if ($iRequiresReplacement) {
	Write-Verbose "Requesting a new certificate."

    # Request new certificate
    # Determine DnsName List and attempt to enroll a certificate with these as SAN values.
    # If the CA Administrator has not enabled the "Supply in Request" feature, then our values will be discarded and replaced by the CA.
    # TODO: The interface IPs are included as DNSNAME entries, which is incorrect.
	# NOTE: Get-Certificate can pop a dialog when an error occurs. This may cause the script to hang when run headless.
    $DnsNameList = @("$( (Get-WmiObject Win32_Computersystem).Name ).$( (Get-WmiObject Win32_Computersystem).Domain )","$( (Get-WmiObject Win32_Computersystem).Name )")
    $DnsNameList += Get-NetIPAddress | Where-Object {$_.IPAddress -like $IpFilter} | Select-Object -ExpandProperty IPAddress
    Write-Verbose "Requesting a certificate with the following SAN values: $($DnsNameList)"
	$oNewCert = Get-Certificate -Template $Template -CertStoreLocation Cert:\LocalMachine\My -SubjectName "CN=$($DnsNameList[0])" -DnsName $DnsNameList -ErrorAction Stop

    if (-not $oNewCert) { Throw "Failed to request a new certificate and no existing certificate is valid for use. Aborting." }

    # Delete the old certificate only if matched by FriendlyName
    # We don't want to delete some random certificate that we may have matched
    if ($oCert.FriendlyName -eq $FriendlyName) {
        Write-Verbose "Removing the old certificate from the local certificate store with FriendlyName ($($FriendlyName)) and Thumbprint ($(formatThumbprint -Thumbprint $oCert.Thumbprint))."
	    Remove-Item -Path $oCert.PSPath
        Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $oCert.Thumbprint} | Remove-Item
    }

	# Set the friendly name on the new certificate
	Write-Verbose "Assigning the FriendlyName value ($($FriendlyName)) to the new certificate."
    $oNewCert.Certificate.FriendlyName = $FriendlyName
    
    # Use the new certificate going forward
    $oCert = $oNewCert.Certificate
}


# Convert the certificate thumbprint to the required syntax
$sCertThumbprint = (formatThumbprint -Thumbprint $oCert.Thumbprint)

# Replace the thumbprint and restart services if the best certificate is not the currently installed one
if (-not ($sCertThumbprint -like (Get-ItemProperty -Path "HKLM:\SOFTWARE\VMware, Inc.\VMware Blast\Config\").SslHash )) {
    Write-Verbose "Installing Certificate with Thumbprint: $sCertThumbprint"
	
	if (numberLoggedOnUsers -ge 1) {
		if ($NoRestartIfActive) {
			Write-Verbose "System has active user sessions. Aborting installation of new certificate."
			break
		}
		else {
			Write-Warning "The VMBlast service will be restarted. $(numberLoggedOnUsers) active user sessions will be disconnected."
			
			if (-not $SkipDisconnectWarning) {
				Write-Verbose "Showing disconnect warning to end users."
				MSG * /TIME:10 The VMBlast service will be restarted for a certificate update. Your session may be disconnected. Please logon again.
				Start-Sleep -Seconds 12
			}
		}
	}
	else {
		Write-Verbose "No active sessions detected. Proceeding with service restart."
	}

    # Install certificate
    # Stop the Blast service
    Stop-Service VMBlast -Force

    # Write the thumbprint into the registry.
    REG ADD "HKLM\SOFTWARE\VMware, Inc.\VMware Blast\Config" /V "SslHash" /D "$sCertThumbprint" /T reg_sz /F

    # Restart the Blast service.
    Start-Service VMBlast
}
else {
    Write-Verbose "Determined the best certificate for use is already installed."
}



# SIG # Begin signature block
# MIIoTgYJKoZIhvcNAQcCoIIoPzCCKDsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxfdqlx3pmlTX7JawFnjiFeus
# Z7GggiE3MIIFQzCCAyugAwIBAgIQbaYpQoiUJahFer2y6ylZejANBgkqhkiG9w0B
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOh/I66z
# 5QNXmIyHHaW9vkuL6zR4MA0GCSqGSIb3DQEBAQUABIICAIlvX4mZ5mJx3kW4y1rt
# jL0OjO1Brzhd+tip86W+6wTu2xal7qJY37VGh1lcGAlxGoGSpVWtT4QiXwIlPgsl
# yLtyE0oFqdKQr5eViI165eDAMGRsBugGay7zcmJegqJUbaCNn2gygh07RIClAqgs
# V0pbLEw7sIrxhC90SFwAcfBIVUXaN9IDPHQKqz15u6Oyg7aEjmnyXWSp7CAr6riE
# 41gBxdzpuWwPR7Xdk2OtAcHDhjL3WtOgSFMEB9/aOzY0DCoM6ec+C20dOO4MN/WE
# ZV6OvuEsd6cpn4pyicEptjOHD+I2t+MV6ViRe2utxvO+tC0TwnopCGJVtvYdgtMU
# 7dFQ+IQ6i8P0+AOFwM888ETBSAq2aP2CADTX/frGxOgPPpyoa6wPEsYuyyV+rCmz
# vxooIMc9PyYnaOwAHx4QRJPJv2cCQnG8lwLToi05aOvHw1QKurQjeBMAbNjvMM4f
# RaIGs6hTFWZJuKBF5iflycwYBP6uttjvCiGpZdOy5WpwmJ6s1BRqPmsUzQllncWt
# w5kgC4F31/3+aMWDx3yhL8dAgrqgu19Gt52frI1Y9bW2N0yAVAC1AAEc1RdKT4Dp
# C8wv/4zFUojSBMMZPdw4HTNE/nRrSIRtcu4ysZrG5NhXmlgVyirO/sak8G8pANZF
# /qXNH8oxrjPh0om8f6lLnwD9oYIDTDCCA0gGCSqGSIb3DQEJBjGCAzkwggM1AgEB
# MIGSMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIx
# EDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDElMCMG
# A1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBDQQIRAIx3oACP9NGwxj2f
# OkiDjWswDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yMTAzMTMxNTIxNTZaMD8GCSqGSIb3DQEJBDEyBDB6
# D0ImKHOmdgV11yyP1RuXS5wj4RvD1J0gtYJTg/SlmVF0ogwkuAPljjftrhEBrCQw
# DQYJKoZIhvcNAQEBBQAEggIAgYLczZuVg+rvlpmcUFOgZRpBC2+/mvzMOwiNPY1V
# QnnV9YSy2mpnCZujoXhywxCG5PeIbB7fhDmnpHADtKM2yjSZdMASBf7It2OCN2Wp
# sSdfdEfG6u3iCT8CatCKl67TL6yTZKxTJFJY3v6k7Al65LU04pfjfMMORAOaHjOr
# h9CkkrOWWAB7To8+JEGN2QNnE7wwVqDD2B++4VN8tbE/6dthjarWfeEhKPXSYJ4t
# MKf0oogIcuztf4IZCWTZ2LfAErcDpeG+xxL7q3FBCr1V8hSdRFV7ECJNTyc1yTue
# p+goIc0SVmhBVOlEHJZNamq0WJ/8LrfEiDZ5ub3cx6KTvNO8J0L4VCHsETcE7k3z
# 21nUjiESSL3rBaOn4bIWReIzfPNqBD6WXG27PYfQQBI05C9/8ydvVAaUdugv7Ptl
# PYG5nUolDo6pa0BZuUHrshu7kPVx1A5NLOTDD+RjBqK/HoNZGRdJ9RZk4/axrqTK
# xPqlqM2fWDgdK8I/y0jubvNZSwQjwZ6TGK+VF8Vfc6W5mObM1FV0eBANkH23UBjw
# O+2DUEfk1357wQFIkx/J/WqmfFBEAu20WshCEm3U9Xn0z7pgDrVwNYBthBVbBPCJ
# KQ2npquAqzyfwnplPiPrpv+1U0Mpkn2MeXVVmfSNQ5nV3nNzZRmZ0LQsJQXVks0X
# 9rk=
# SIG # End signature block
