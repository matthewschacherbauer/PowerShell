<#

VMWARE BLAST DESKTOP AGENT - CERTIFICATE INSTALLATION

Matthew Schacherbauer
2021-08-11

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
    $Template               = "WS-RSA-VMwareBlastService",
    $FriendlyName           = "VMBlast",
    $MinimumDaysRamaining   = 5,
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
$bRequiresReplacement = $false


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
        Write-Verbose "Selected existing certificate with Thumbprint ($(formatThumbprint -Thumbprint $oCert.Thumbprint))"
    }
}
else {
    Write-Verbose "No usable certificate was found in the local certificate store."
    $bRequiresReplacement = $true
}


# If an existing cert exists, validate it.
if ($oCert) {
    Write-Verbose "Validating selected certificate."
    
    # Check for validity
    if ($oCert.SubjectName.Name -eq $oCert.IssuerName.Name) {
        # Certificate is self-signed
        Write-Warning "Self-signed certificate detected and will be replaced."
        $bRequiresReplacement = $true
    }
    elseif ( (Get-Date) -gt $oCert.NotAfter.AddDays(-$($MinimumDaysRamaining)) ) {
        # Certificate expiring soon
        Write-Verbose "Certificate is expiring soon and will be replaced."
        $bRequiresReplacement = $true
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
            $bRequiresReplacement = $true
        }
    }
}


# Replace certificate
if ($bRequiresReplacement) {
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
                Start-Process CMD.EXE -ArgumentList "/C MSG * /TIME:10 The VMBlast service will be restarted for a certificate update. Your session may be disconnected. Please logon again."
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
    Set-ItemProperty -Path "HKLM:\SOFTWARE\VMware, Inc.\VMware Blast\Config" -Name "SslHash" -Value $sCertThumbprint -Force

    # Restart the Blast service.
    Start-Service VMBlast
}
else {
    Write-Verbose "Determined the best certificate for use is already installed."
}
