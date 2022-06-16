<#

IIS WEB MANAGEMENT SERVICE (WMSVC) - CERTIFICATE INSTALLATION

Matthew Schacherbauer
2022-05-08

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

v1.4

===============

DESCRIPTION

This script checks the status of the existing IIS Web Management Service certificate and replaces the certificate when necessary.
A self-signed certificate is always replaced.
A certificate nearing its expiration will be replaced.
Replacement certificates are issued from a local Enterprise Certificate Authority using the AD CS Template specified.

For automation, this script can be ran as a scheduled tasked or managed by Group Policy.
The script will not take action unless a renewal is necessary.


AD CS Template Notes:
* Must have EKU Server Authentication
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
    $Template               = "WS-RSA-WMSvc",

    # Define the Certificate FriendlyName to use
    # If the FriendlyName is not null, it is expected that the certificate is unique to this service and this
    # script will attempt to fully manage the certificate, including deletion and replacement.
    # If you are sharing a certificate with another service then you must set this to an empty string ("").
    $FriendlyName           = "WMSvc-SHA2",

    # Require FriendlyName
    # Only the certificate with this FriendlyName will be used. If no such certificate exists, one will be requested.
    [switch] $RequireFriendlyName,

    # Never request a replacement certificate
    # Forces the script to use the most appropriate existing certificate. It may be necessary to reduce the
    # value of MinimumDaysRemaining.
    [switch] $NoNewCertificate,

    # Define the minimum number of days left on the certificate
    # Less than this and the certificate will be replaced
    [ValidateNotNullOrEmpty()]
    $MinimumDaysRemaining   = 30
)


# Test for the required service
if (-not (Get-Service -Name "wmsvc" -ErrorAction SilentlyContinue) ) { Throw "The required service wmsvc is not present" }

# Initialize Variables
$bRequiresReplacement = $false
$sComputerFqdn = "$($ENV:COMPUTERNAME).$( (Get-WmiObject Win32_Computersystem).Domain )"

# Check for an existing certificate
# If a certificate exists with the specified FriendlyName, use it. Otherwise, use any valid certificate.
# If no valid certificate exists, attempt to enroll for a certificate.
$oCertList = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList -like "*Server Authentication*" -and                    # EKU contains Server Authentication
    $_.HasPrivateKey -and                                                           # Has a Private Key
    $_.DnsNameList -contains $sComputerFqdn -and                                    # Has valid DNS name
    $_.Subject -like "*CN=$($sComputerFqdn)*" -and                                  # Must have Subject Name
    $_.SubjectName.Name -ne $_.SubjectName.IssuerName.Name -and                     # Is not Self Signed
    $_.PrivateKey.CspKeyContainerInfo.Exportable -eq $true                          # Private Key is Exportable
}

Write-Verbose "Found $($oCertList.count) qualified certificates in the computer certificate store."

# Select a certificate, either by FriendlyName or by the longest validity time
if ($oCertList) {
    if ($FriendlyName) {
        Write-Verbose "Checking for certificate with FriendlyName ($($FriendlyName))."
        $oCert = $oCertList | Where-Object { $_.FriendlyName -eq $FriendlyName }

        if (!$oCert) {
            Write-Verbose "No certificate found with the FriendlyName ($($FriendlyName))."
        }
    }
    else {
        Write-Verbose "No FriendlyName specified. Will use any viable certificate."
    }

    if (!$oCert) {      # Implies no FriendlyName value or the designated cert doesn't exist.
        if (!$RequireFriendlyName) {
            # Select the best certificate regardless of FriendlyName
            Write-Verbose "Selecting the certificate with the longest remaining life."
            $oCert = $oCertList | Sort-Object NotAfter | Select-Object -Last 1
        }
        else {
            Write-Verbose "No certificate found with the FriendlyName ($($FriendlyName)). A new certificate will be requested."
            $bRequiresReplacement = $true
        }
    }
}
else {
    Write-Verbose "No usable certificate was found in the local certificate store."
    $bRequiresReplacement = $true
}

# Output the selected certificate
if ($oCert) {
    Write-Verbose "Selected the following certificate:"
    Write-Verbose "-> Thumbprint:   $($oCert.Thumbprint)"
    Write-Verbose "-> FriendlyName: $($oCert.FriendlyName)"
    Write-Verbose "-> Subject:      $($oCert.Subject)"
    Write-Verbose "-> DNS Names:    $($oCert.DnsNameList)"
    Write-Verbose "-> EKU:          $($oCert.EnhancedKeyUsageList)"
    Write-Verbose "-> Issued By:    $($oCert.Issuer)"
    Write-Verbose "-> Valid Until:  $($oCert.NotAfter)"
}


# Check for validity
if (!$oCert) {
    Write-Verbose "No existing certificate found. A new certificate will be requested."
    $bRequiresReplacement = $true
}

else {
    Write-Verbose "Performing checks on the selected certificate."

    if ( (Get-Date) -gt $oCert.NotAfter.AddDays(-$($MinimumDaysRemaining)) ) {
        # Certificate expiring soon
        Write-Verbose "Certificate is expiring soon and will be replaced. Expiration: $($oCert.NotAfter)"
        $bRequiresReplacement = $true
    }
    else {
        if (Test-Certificate -Cert $oCert) {
            # Certificate tests OK
            Write-Verbose "Certificate validated successfully. No replacement will be performed."
        }
        else {
            # Fails test
            Write-Verbose "Certificate failed validation and will be replaced."
            $bRequiresReplacement = $true
        }
    }
}


# Replace certificate
if ($bRequiresReplacement -and !$NoNewCertificate) {
    # Request new certificate
    Write-Verbose "Requesting a new certificate."
    $oNewCert = Get-Certificate -Template $Template -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop

    # Verify we got a certificate issued. Halt if we didn't.
    if ($oNewCert) { Write-Verbose "Got a new certificate with thumbprint ($($oNewCert.Certificate.Thumbprint))"}
    else { Throw "Error creating or retrieving a new certificate. No certificate was issued by the Enterprise Certificate Authority." }

    # Delete the old certificate only if matched by FriendlyName
    # We don't want to delete some random certificate that we may have matched
    if ($FriendlyName -and ($oCert.FriendlyName -eq $FriendlyName)) {
        Write-Verbose "Removing the old certificate from the local certificate store with FriendlyName ($($FriendlyName)) and Thumbprint ($($oCert.Thumbprint))."
        Remove-Item -Path $oCert.PSPath
        #Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $oCert.Thumbprint} | Remove-Item
    }

    # Set the friendly name on the new certificate if the certificate is net-new or if it was present on the old certificate
    if (!$oCert -or ($FriendlyName -and ($oCert.FriendlyName -eq $FriendlyName) ) ) {
        Write-Verbose "Setting friendly name ($($FriendlyName)) on new certificate."
        $oNewCert.Certificate.FriendlyName = $FriendlyName
        #(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $oNewCert.Certificate.Thumbprint}).FriendlyName = $oCert.FriendlyName
    }

    # Use the new certificate going forward
    $oCert = $oNewCert.Certificate

    Write-Verbose "Obtained the following certificate:"
    Write-Verbose "-> Thumbprint:   $($oCert.Thumbprint)"
    Write-Verbose "-> FriendlyName: $($oCert.FriendlyName)"
    Write-Verbose "-> Subject:      $($oCert.Subject)"
    Write-Verbose "-> DNS Names:    $($oCert.DnsNameList)"
    Write-Verbose "-> EKU:          $($oCert.EnhancedKeyUsageList)"
    Write-Verbose "-> Issued By:    $($oCert.Issuer)"
    Write-Verbose "-> Valid Until:  $($oCert.NotAfter)"
}
elseif ($bRequiresReplacement -and $NoNewCertificate) {
    Write-Error "Certificate flagged for replacement but certificate requests are disabled."
    return
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

