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

