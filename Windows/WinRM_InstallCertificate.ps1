<#

Windows Remote Management (WinRM) - CERTIFICATE INSTALLATION

Matthew Schacherbauer
2025-09-30

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

v1.2.1

===============

DESCRIPTION

This script checks the status of the existing WinRM certificate and replaces the certificate when necessary.
A self-signed certificate is always replaced.
A certificate nearing its expiration will be replaced.
Replacement certificates are issued from a local Enterprise Certificate Authority using the AD CS Template specified.

This script only manipulates the HTTPS listener. WinRM is expected to have already been configured.

For automation, this script can be ran as a scheduled tasked or managed by Group Policy.
The script will not take action unless a renewal is necessary.

In practice, I found that triggering on the following events were extremely reliable.
    Microsoft-Windows-GroupPolicy/Operational   8000    (Boot Policy Processing Completed)
    Microsoft-Windows-GroupPolicy/Operational   8004    (Computer Policy Processing Completed (Manual))
    Microsoft-Windows-GroupPolicy/Operational   8006    (Computer Policy Processing Completed (Periodic))

If the script should run after a separate process replaces the certificate, such as autoenroll, use these.    
    Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational    1001    (Certificate has been replaced)
    Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational    1006    (Certificate has been installed)


AD CS Template Notes:
* Must have EKU Server Authentication
* Must have Subject Name (set to DNS Name in testing)


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
#Requires -RunAsAdministrator

[CmdletBinding()]
Param (
    # Define the domain template
    [ValidateNotNullOrEmpty()]
    $Template				= "WS-RSA-WinRM",

    # Define the Certificate FriendlyName to use
    # If the FriendlyName is not null, it is expected that the certificate is unique to this service and this
    # script will attempt to fully manage the certificate, including deletion and replacement.
    # If you are sharing a certificate with another service then you must set this to an empty string ("").
    $FriendlyName			= "WinRM-SHA2",

    # Require FriendlyName
    # Only the certificate with this FriendlyName will be used. If no such certificate exists, one will be requested.
    [switch] $RequireFriendlyName,

    # Remove CredSSP thumbprint
    [switch] $CleanCredSSP,

    # Never request a replacement certificate
    # Forces the script to use the most appropriate existing certificate. It may be necessary to reduce the
    # value of MinimumDaysRemaining.
    [switch] $NoNewCertificate,

    # Define the minimum number of days left on the certificate
    # Less than this and the certificate will be replaced
    [ValidateNotNullOrEmpty()]
    $MinimumDaysRemaining	= 30
)

# Test for the required service
if (-not (Get-Service -Name "WinRM" -ErrorAction SilentlyContinue) ) { Throw "The required service WinRM is not present" }

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
    $_.SubjectName.Name -ne $_.SubjectName.IssuerName.Name                          # Is not Self Signed
}

Write-Verbose "Found $($oCertList.count) qualified certificates in the computer certificate store."

# Select a certificate, either by FriendlyName or by the longest validity time
if ($oCertList) {
    if ($FriendlyName) {
        Write-Verbose "Checking for certificate with FriendlyName ($($FriendlyName))."
        $oCert = $oCertList | Where-Object { $_.FriendlyName -eq $FriendlyName } | Sort-Object NotAfter | Select-Object -Last 1

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


# Request new certificate
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


# Replace the thumbprint and restart services if the best certificate is not the currently installed one
#$sExistingThumbprint = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener\*+HTTPS\").certThumbprint
Write-Verbose "Getting information about an existing WinRM HTTPS Listener."
$oExistingListener = Get-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*";Transport="HTTPS"}
$sExistingThumbprint = $oExistingListener.CertificateThumbprint

if (!$sExistingThumbprint -or (Compare-Object $oCert.Thumbprint $sExistingThumbprint) ) {
    # Install the new certificate
    Write-Verbose "Installing Certificate with Thumbprint: $($oCert.Thumbprint)"

    # Ensure the WinRM service is running
    Start-Service WinRM

    # Check if an existing listener exists, and remove it.
    if ($sExistingThumbprint) {
        Write-Verbose "Removing the existing WinRM HTTPS listener."
        Remove-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address=$oExistingListener.Address;Transport="HTTPS"}
        #winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
    }

    # Check for and remove the CredSSP thumbprint
    if ( (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service\").credssp_thumbprint ) {
        if ($CleanCredSSP) {
            Write-Verbose "Removing the existing CredSSP certificate thumbprint."
            winrm set winrm/config/service @{CertificateThumbprint=""}

            # I've tried setting this to the new thumbprint, but CredSSP fails no matter what if this is populated it seems.
        }
        else {
            Write-Warning "An old CredSSP thumbprint exists at HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service\credssp_thumbprint and may need to be deleted."
        }
    }
    else {
        Write-Verbose "No existing CredSSP certificate thumbprint was found."
    }

    # Create a new listener instance
    if ($oExistingListener) {
        Write-Verbose "Creating new WinRM HTTPS listener using parameters from the existing listener."
        New-WSManInstance -ResourceURI winrm/config/Listener `
            -SelectorSet @{Address=$oExistingListener.Address;Transport="HTTPS"} `
            -ValueSet @{Hostname=$sComputerFqdn;CertificateThumbprint=$($oCert.Thumbprint)}
    }
    else {
        Write-Verbose "Creating new WinRM HTTPS listener using default parameters."
        New-WSManInstance -ResourceURI winrm/config/Listener `
            -SelectorSet @{Address="*";Transport="HTTPS"} `
            -ValueSet @{Hostname=$sComputerFqdn;CertificateThumbprint=$($oCert.Thumbprint)}
            
        #winrm create --% winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=`"$($sComputerFqdn)`";CertificateThumbprint=`"$($oCert.Thumbprint)`"}
    }
}
else {
    Write-Verbose "Determined the best certificate for use is already installed."
}

