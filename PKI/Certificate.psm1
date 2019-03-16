<#

Certificate Generation Module

Matthew Schacherbauer
2019-03-15

https://github.com/matthewschacherbauer
https://www.matthewschacherbauer.com

===============

Creates a CSR using OpenSSL
Submits the CSR to a Microsoft Enterprise CA for signing
Converts the resulting signed certificate to several popular formats
Provides additional support functions to manipulate certificates and private keys

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


Function isEncryptedPrivateKey {
	<#
	.SYNOPSIS
	Checks if the Private Key is encrypted.
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory)]
		[string]	$OpenSslPath,

		# Source Data
		[string]	$KeyFile,
		$KeyData
	)

	# Attempt to read the key text for ENCRYPTED in the string.
	if ($KeyFile -and (Test-Path -Path $KeyFile -ErrorAction SilentlyContinue)) {
		$KeyData = Get-Content -Path $KeyFile
	}
	elseif (!$KeyData) {
		Throw "No Private Key data to parse."
	}

	if ($KeyData -like "*ENCRYPTED*") {
		return $true
	}

	# For PFX files, use OpenSSL to parse the private key.
	if ((Get-ChildItem -Path $KeyFile).Extension -eq ".pfx") {
		$result = CMD.EXE /C "`"$($OpenSslPath)`" pkcs12 -in `"$($KeyFile)`" -cacerts -nokeys -noout -passin pass:" '2>&1'
		if ($result -like "Mac verify error*") {
			return $true
		}
	}

	return $false
}


Function New-OpenSslCertificateConfiguration {
	<#
	.SYNOPSIS
	Creates a configuration file for a new RSA Public/Private KeyPair.
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-15
		
	Version:	1.1
	.LINK
	https://www.matthewschacherbauer.com
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory)]
		[string[]]	$Hostname,
		[ValidateSet('1024','2048','4096')]
		[int]		$Bits					= "4096",

		# Encryption Options
		[switch]	$Encrypt,

		# Distinguished Name
		[Parameter(Mandatory)]
		[string]	$CountryName,
		[Parameter(Mandatory)]
		[string]	$State,
		[Parameter(Mandatory)]
		[string]	$Locality,
		[string]	$PostalCode,
		[string]	$StreetAddress,
		[Parameter(Mandatory)]
		[string]	$Organization,
		[Parameter(Mandatory)]
		[string]	$OrganizationalUnitName,
		[string]	$Email
	)

	Write-Verbose "Call New-OpenSslCertificateConfiguration"

	# Format the SAN attribute
	foreach ($thisHost in $Hostname) {
		if ($sanList) { $sanList += "," }
		$sanList += "DNS:$($thisHost)"
	}

	# Format the encryption value
	if ($Encrypt) { $sEncrypt = "yes" }
	else { $sEncrypt = "no" }

	$config = "# OpenSSL configuration to generate a new key with signing request for a x509v3
# multidomain certificate

[ req ]
default_bits       = $($Bits)
default_md         = sha512
#default_keyfile   = key.pem		# Overridden by -keyout
prompt             = no
encrypt_key        = $($sEncrypt)
#string_mask       = nombstr

# base request
distinguished_name = req_distinguished_name

# extensions
req_extensions     = v3_req

# distinguished_name
[ req_distinguished_name ]
countryName            = `"$($CountryName)`"             # C=
stateOrProvinceName    = `"$($State)`"                   # ST=
localityName           = `"$($Locality)`"                # L=
$( if (!$PostalCode) { "#" } )postalCode            = `"$($PostalCode)`"              # L/postalcode=
$( if (!$StreetAddress) { "#" } )streetAddress         = `"$($StreetAddress)`"           # L/street=
organizationName       = `"$($Organization)`"            # O=
organizationalUnitName = `"$($OrganizationalUnitName)`"  # OU=
commonName             = `"$($Hostname[0])`"             # CN=
$( if (!$Email) { "#" } )emailAddress           = `"$($Email)`"                   # CN/emailAddress=

# req_extensions
[ v3_req ]
# Key Restrictions
basicConstraints       = CA:false
keyUsage               = digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth, clientAuth

# The subject alternative name extension allows various literal values to be 
# included in the configuration file
# http://www.openssl.org/docs/apps/x509v3_config.html
subjectAltName  = $($sanList)"

	return $config
}


Function New-CertificateSigningRequest {
	<#
	.SYNOPSIS
	Generates a new private key and PKCS10 certificate signing request
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-08
		
	Version:	1.0
	.LINK
	https://www.matthewschacherbauer.com
	https://www.openssl.org/docs/manmaster/man1/req.html
	#>

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Options
		[ValidateSet('1024','2048','4096')]
		[int]			$Bits,

		# Encryption Options
		[securestring]	$Passphrase,
		[switch]		$Encrypt,

		# Source Files
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$ConfigFile,

		# Output Files
		[Parameter(Mandatory,ParameterSetName="FileOut")]
		[string]		$OutKeyFile,
		[Parameter(Mandatory,ParameterSetName="FileOut")]
		[string]		$OutRequestFile,

		# Options
		[Parameter(Mandatory,ParameterSetName="TextOut")]
		[switch]		$Text
	)

	Write-Verbose "Call New-CertificateSigningRequest"

	# Variables
	$ENV:RANDFILE	= $ENV:USERPROFILE + "\.rnd"

	# Check Encryption
	if ($Encrypt) {
		if (!$Passphrase) {
			Write-Verbose "Encryption requested without a supplied passphrase."
			$Passphrase = Read-Host "Private Key Passphrase" -AsSecureString
		}
		
		# Decode Passphrase
		Write-Verbose "Decoding passphrase."
		$sPassphrase = Unprotect-SecureString -SecureString $Passphrase	
	}

	# Build the command line
	Write-Verbose "Building OpenSSL command."
	$cmd = "`"$($OpenSslPath)`" req -new -newkey rsa:$($Bits) -config `"$($ConfigFile)`""

	if ($Encrypt) {
		Write-Verbose "Generate private key with encryption."
		$cmd += " -passout pass:`"$($sPassphrase)`""
	}
	else {
		Write-Verbose "Generate private key without encryption."
		$cmd += " -nodes"
	}

	if ($Text) {
		Write-Verbose "Write data to console."
		$cmd += " -text"
	}
	else {
		Write-Verbose "Write data to file."
		$cmd += " -keyout `"$($OutKeyFile)`" -out `"$($OutRequestFile)`""
	}

	# Execute Command
	Write-Verbose "Executing Command: $($cmd)"
	$result = CMD.EXE /C $cmd '2>&1'

	# TODO: Capture and parse OpenSSL response.
	Write-Verbose ($result | Out-String)

	# Return Data
	return [PSCustomObject] @{
		"PrivateKey"				= [PSCustomObject] @{
			"Encrypted"				= $Encrypt
			"Passphrase"			= $Passphrase
			"File"					= $( if ($OutKeyFile) { Get-ChildItem -Path $OutKeyFile } )
			"Data"					= $( if ($OutKeyFile) { Get-Content -Path $OutKeyFile } )
			"Bits"					= $Bits
		}

		"CertificateRequest"		= [PSCustomObject] @{
			"File"					= $( if ($OutKeyFile) { Get-ChildItem -Path $OutRequestFile } )
			"Data"					= $( if ($OutKeyFile) { Get-Content -Path $OutRequestFile } )
		}
	}
}


Function New-SelfSignedCertificate {
	<#
	.SYNOPSIS
	Generates a self signed certificate using a provate key and certificate signing request file.
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-08
		
	Version:	1.0
	.LINK
	https://www.matthewschacherbauer.com
	https://www.openssl.org/docs/manmaster/man1/x509.html
	#>

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Options
		[Parameter(Mandatory)]
		[int]			$ValidityDays,

		# Encryption Options
		[securestring]	$Passphrase,
		[switch]		$Encrypt,

		# Source Files
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$ConfigFile,
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$KeyFile,
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$RequestFile,

		# Output Files
		[Parameter(Mandatory,ParameterSetName="FileOut")]
		[string]		$OutCertFile,

		# Options
		[Parameter(Mandatory,ParameterSetName="TextOut")]
		[switch]		$Text
	)

	Write-Verbose "Call New-SelfSignedCertificate"

	# Variables
	$ENV:RANDFILE	= $ENV:USERPROFILE + "\.rnd"

	# Check for Encrypted Private Key
	if (!$Encrypt -and (isEncryptedPrivateKey -OpenSslPath $OpenSslPath -KeyFile $KeyFile)) {
		Write-Verbose "Detected encrypted private key without encryption declared."
		$Encrypt = $true
	}

	# Check Encryption
	if ($Encrypt) {
		if (!$Passphrase) {
			Write-Verbose "Encryption requested without a supplied passphrase."
			$Passphrase = Read-Host "Private Key Passphrase" -AsSecureString
		}
		
		# Decode Passphrase
		Write-Verbose "Decoding passphrase."
		$sPassphrase = Unprotect-SecureString -SecureString $Passphrase	
	}

	# Build the command line
	Write-Verbose "Building OpenSSL command."

	$cmd = "`"$($OpenSslPath)`" x509 -signkey `"$($KeyFile)`" -req -days $($ValidityDays) -extfile `"$($ConfigFile)`" -extensions v3_req -in `"$($RequestFile)`""

	if ($Encrypt) {
		Write-Verbose "Use encrypted private key."
		$cmd += " -passin pass:`"$($sPassphrase)`""
	}
	else {
		Write-Verbose "Use plaintext private key."
		#$cmd += ""
	}

	if ($Text) {
		Write-Verbose "Write data to console."
		$cmd += " -text"
	}
	else {
		Write-Verbose "Write data to file."
		$cmd += " -out `"$($OutCertFile)`""
	}

	# Execute Command
	Write-Verbose "Executing Command: $($cmd)"
	$result = CMD.EXE /C $cmd '2>&1'

	# TODO: Capture and parse OpenSSL response.
	Write-Verbose ($result | Out-String)

	# Return Data
	return [PSCustomObject] @{
		"PrivateKey"				= [PSCustomObject] @{
			"Encrypted"				= $Encrypt
			"Passphrase"			= $Passphrase
			"File"					= $( if ($KeyFile) { Get-ChildItem -Path $KeyFile } )
			"Data"					= $( if ($KeyFile) { Get-Content -Path $KeyFile } )
		}

		"Certificate"				= [PSCustomObject] @{
			"File"					= $( if ($OutCertFile) { Get-ChildItem -Path $OutCertFile } )
			"Data"					= $( if ($OutCertFile) { Get-Content -Path $OutCertFile } )
		}
	}
}


Function New-EnterpriseCertificateAuthoritySignature {
	<#
	.SYNOPSIS
	Submits a certificate signing request to an Active Directory Certificate Authority
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-09
		
	Version:	1.0
	.LINK
	https://www.matthewschacherbauer.com
	#>

	[CmdletBinding()]
	Param (
		# Options
		[Parameter(Mandatory)]
		[string]		$AdcsTemplate,
		[Parameter(Mandatory)]
		[string]		$AdcsServer,

		# Source Files
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$RequestFile,

		# Output Files
		[Parameter(Mandatory)]
		[string]		$OutCertFile,
		[Parameter(Mandatory)]
		[string]		$OutChainP7bFile,
		[Parameter(Mandatory)]
		[string]		$OutChainRspFile
	)

	Write-Verbose "Call New-EnterpriseCertificateAuthoritySignature"

	# Submit CertReq to Certificate Authority.
	$result = CMD.EXE /C "`"$ENV:WINDIR\System32\CERTREQ.EXE`" -attrib `"CertificateTemplate:$($AdcsTemplate)`" -config `"$($AdcsServer)`" -submit `"$($RequestFile)`" `"$($OutCertFile)`" `"$($OutChainP7bFile)`" `"$($OutChainRspFile)`"" '2>&1'

	# TODO: Capture and parse CertReq response.
	Write-Verbose ($result | Out-String)

	# Return Data
	return [PSCustomObject] @{
		"AdcsTemplate"		= $AdcsTemplate
		"AdcsServer"		= $AdcsServer

		"Certificate"		= [PSCustomObject] @{
			"CrtFile"		= $( if ($OutCertFile) { Get-ChildItem -Path $OutCertFile } )
			"CrtData"		= $( if ($OutCertFile) { Get-Content -Path $OutCertFile } )
			"P7bFile"		= $( if ($OutChainP7bFile) { Get-ChildItem -Path $OutChainP7bFile } )
			"RspFile"		= $( if ($OutChainRspFile) { Get-ChildItem -Path $OutChainRspFile } )
		}
	}
}


Function ConvertTo-Pkcs1 {
	<#
	.SYNOPSIS
	Converts a PCKS8 Private Key to PKCS1
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-09
		
	Version:	1.0
	.LINK
	https://www.matthewschacherbauer.com
	https://www.openssl.org/docs/manmaster/man1/rsa.html
	#>

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Encryption Options
		[securestring]	$Passphrase,
		[switch]		$Encrypt,
		[ValidateSet('aes128','aes192','aes256','aria128','aria192','aris256','camellia128','camellia192','camellia256','des3')]
		[string]		$Cipher			= "aes256",

		# Source Files
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$Key,

		# Output Files
		[Parameter(Mandatory,ParameterSetName="FileOut")]
		[string]		$OutKey,

		# Options
		[Parameter(Mandatory,ParameterSetName="TextOut")]
		[switch]		$Text
	)

	Write-Verbose "Call ConvertTo-Pkcs1"

	# Variables
	$ENV:RANDFILE	= $ENV:USERPROFILE + "\.rnd"

	# Check for Encrypted Private Key
	if (!$Encrypt -and (isEncryptedPrivateKey -OpenSslPath $OpenSslPath -KeyFile $Key)) {
		Write-Verbose "Detected encrypted private key without encryption declared."
		$Encrypt = $true
	}

	# Check Encryption
	if ($Encrypt) {
		if (!$Passphrase) {
			Write-Verbose "Encryption requested without a supplied passphrase."
			$Passphrase = Read-Host "Private Key Passphrase" -AsSecureString
		}
		
		# Decode Passphrase
		Write-Verbose "Decoding passphrase."
		$sPassphrase = Unprotect-SecureString -SecureString $Passphrase	
	}

	# Build the command line
	Write-Verbose "Building OpenSSL command."

	$cmd = "`"$($OpenSslPath)`" rsa -in `"$($Key)`""

	if ($Encrypt) {
		Write-Verbose "Use encrypted private key."
		$cmd += " -passin pass:`"$($sPassphrase)`" -passout pass:`"$($sPassphrase)`" -$($Cipher)"
	}
	else {
		Write-Verbose "Use plaintext private key."
		#$cmd += ""
	}

	if ($Text) {
		Write-Verbose "Write data to console."
		$cmd += " -text"
	}
	else {
		Write-Verbose "Write data to file."
		$cmd += " -out `"$($OutKey)`""
	}

	# Execute Command
	Write-Verbose "Executing Command: $($cmd)"
	$result = CMD.EXE /C $cmd '2>&1'

	# TODO: Capture and parse OpenSSL response.
	Write-Verbose ($result | Out-String)

	# Return Data
	return [PSCustomObject] @{
		"PrivateKey"				= [PSCustomObject] @{
			"Encrypted"				= $Encrypt
			"Passphrase"			= $Passphrase
			"File"					= $( if ($OutKey) { Get-ChildItem -Path $OutKey } )
			"Data"					= $( if ($OutKey) { Get-Content -Path $OutKey } )
		}
	}
}


Function ConvertTo-Pkcs8 {
	<#
	.SYNOPSIS
	Converts a PKCS1 Private Key to PKCS8
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-09
		
	Version:	1.0
	.LINK
	https://www.matthewschacherbauer.com
	https://www.openssl.org/docs/man1.0.2/man1/openssl-pkcs8.html
	#>

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Encryption Options
		[securestring]	$Passphrase,
		[switch]		$Encrypt,

		# Source Files
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$Key,

		# Output Files
		[Parameter(Mandatory,ParameterSetName="FileOut")]
		[string]		$OutKey,

		# Options
		[Parameter(Mandatory,ParameterSetName="TextOut")]
		[switch]		$Text
	)

	Write-Verbose "Call ConvertTo-Pkcs8"

	# Variables
	$ENV:RANDFILE	= $ENV:USERPROFILE + "\.rnd"

	# Check for Encrypted Private Key
	if (!$Encrypt -and (isEncryptedPrivateKey -OpenSslPath $OpenSslPath -KeyFile $Key)) {
		Write-Verbose "Detected encrypted private key without encryption declared."
		$Encrypt = $true
	}

	# Check Encryption
	if ($Encrypt) {
		if (!$Passphrase) {
			Write-Verbose "Encryption requested without a supplied passphrase."
			$Passphrase = Read-Host "Private Key Passphrase" -AsSecureString
		}
		
		# Decode Passphrase
		Write-Verbose "Decoding passphrase."
		$sPassphrase = Unprotect-SecureString -SecureString $Passphrase	
	}

	# Build the command line
	Write-Verbose "Building OpenSSL command."

	$cmd = "`"$($OpenSslPath)`" pkcs8 -topk8 -in `"$($Key)`" -out `"$($OutKey)`""

	if ($Encrypt) {
		Write-Verbose "Use encrypted private key."
		$cmd += " -passin pass:`"$($sPassphrase)`" -passout pass:`"$($sPassphrase)`" -v2 des3 -v2prf hmacWithSHA256"
	}
	else {
		Write-Verbose "Use plaintext private key."
		$cmd += " -nocrypt"
	}

	if ($Text) {
		Write-Verbose "Write data to console."
		$cmd += " -text"
	}
	else {
		Write-Verbose "Write data to file."
		$cmd += " -out `"$($OutKey)`""
	}

	# Execute Command
	Write-Verbose "Executing Command: $($cmd)"
	$result = CMD.EXE /C $cmd '2>&1'

	# TODO: Capture and parse OpenSSL response.
	Write-Verbose ($result | Out-String)

	# Return Data
	return [PSCustomObject] @{
		"PrivateKey"				= [PSCustomObject] @{
			"Encrypted"				= $Encrypt
			"Passphrase"			= $Passphrase
			"File"					= $( if ($OutKey) { Get-ChildItem -Path $OutKey } )
			"Data"					= $( if ($OutKey) { Get-Content -Path $OutKey } )
		}
	}
}

Function ConvertTo-Pem {
	<#
	.SYNOPSIS
	Converts various certificate formats to a PEM certificate.
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-09
		
	Version:	1.0
	.LINK
	https://www.matthewschacherbauer.com
	#>

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Source Files
		[Parameter(Mandatory)]
		[ValidateSet("crt","x509","p7b","pkcs7")]
		[string]		$SourceFormat,
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$CertFile,

		# Output Files
		[Parameter(Mandatory)]
		[string]		$OutCertFile
	)

	Write-Verbose "Call ConvertTo-Pem"

	# Variables
	$ENV:RANDFILE	= $ENV:USERPROFILE + "\.rnd"

	Switch ($SourceFormat) {
		{$_ -in "crt","x509"} { # .CRT
			CMD.EXE /C "`"$($OpenSslPath)`" x509 -in `"$($CertFile)`" -out `"$($OutCertFile).tmp`""
			Get-Content "$($OutCertFile).tmp" | Remove-CertificateBagAttributes | Set-Content "$($OutCertFile)" -Encoding ASCII
			Remove-Item "$($OutCertFile).tmp"
		}
		{$_ -in "p7b","pkcs7"} { # .P7B
			CMD.EXE /C "`"$($OpenSslPath)`" pkcs7 -print_certs -in `"$($CertFile)`" -outform pem -out `"$($OutCertFile).tmp`""
			Get-Content "$($OutCertFile).tmp" | Remove-CertificateBagAttributes | Set-Content "$($OutCertFile)" -Encoding ASCII
			Remove-Item "$($OutCertFile).tmp"
		}
		default { Throw "Unexpected Source Format" }
	}
}

Function ConvertTo-Der {
	<#
	.SYNOPSIS
	Converts various certificate formats to a DER certificate
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-09
		
	Version:	1.0
	.LINK
	https://www.matthewschacherbauer.com
	#>

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Source Files
		[Parameter(Mandatory)]
		[ValidateSet("pem","p7b","pkcs7")]
		[string]		$SourceFormat,
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$CertFile,

		# Output Files
		[Parameter(Mandatory)]
		[string]		$OutCertFile
	)

	Write-Verbose "Call ConvertTo-Der"

	# Variables
	$ENV:RANDFILE	= $ENV:USERPROFILE + "\.rnd"

	Switch ($SourceFormat) {
		"pem" { # .PEM
			CMD.EXE /C "`"$($OpenSslPath)`" x509 -outform der -in `"$($CertFile)`" -out `"$($OutCertFile)`""
		}
		{$_ -in "p7b","pkcs7"} { #.P7B
			CMD.EXE /C "`"$($OpenSslPath)`" pkcs7 -in `"$($CertFile)`" -outform der -out `"$($OutCertFile)`""
		}
		default { Throw "Unexpected Source Format" }
	}
}

Function ConvertTo-Pfx {
	<#
	.SYNOPSIS
	Converts various certificate formats to a PFX certificate
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-09
		
	Version:	1.0
	.LINK
	https://www.matthewschacherbauer.com
	https://www.openssl.org/docs/manmaster/man1/pkcs12.html
	#>

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Encryption Options
		[securestring]	$Passphrase,
		[switch]		$Encrypt,
		[ValidateSet('aes128','aes192','aes256','aria128','aria192','aris256','camellia128','camellia192','camellia256','des3')]
		[string]		$Cipher			= "aes256",

		# Source Files
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$CertFile,
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		[string]		$KeyFile,

		# Output Files
		[Parameter(Mandatory)]
		[string]		$OutCertFile
	)

	Write-Verbose "Call ConvertTo-Pfx"

	# Variables
	$ENV:RANDFILE	= $ENV:USERPROFILE + "\.rnd"

	# Check for Encrypted Private Key
	if (!$Encrypt -and (isEncryptedPrivateKey -OpenSslPath $OpenSslPath -KeyFile $KeyFile)) {
		Write-Verbose "Detected encrypted private key without encryption declared."
		$Encrypt = $true
	}

	# Check Encryption
	if ($Encrypt) {
		if (!$Passphrase) {
			Write-Verbose "Encryption requested without a supplied passphrase."
			$Passphrase = Read-Host "Private Key Passphrase" -AsSecureString
		}
		
		# Decode Passphrase
		Write-Verbose "Decoding passphrase."
		$sPassphrase = Unprotect-SecureString -SecureString $Passphrase	
	}

	# Build the command line
	Write-Verbose "Building OpenSSL command."

	$cmd = "`"$($OpenSslPath)`" pkcs12 -export -in `"$($CertFile)`" -inkey `"$($KeyFile)`" -out `"$($OutCertFile)`""

	if ($Encrypt) {
		Write-Verbose "Use encrypted private key."
		$cmd += " -passin pass:`"$($sPassphrase)`" -passout pass:`"$($sPassphrase)`" -$($Cipher)"
	}
	else {
		Write-Verbose "Use plaintext private key."
		$cmd += " -nodes -passout pass:"
	}

	# Execute Command
	Write-Verbose "Executing Command: $($cmd)"
	$result = CMD.EXE /C $cmd '2>&1'

	# TODO: Capture and parse OpenSSL response.
	Write-Verbose ($result | Out-String)

	# Return Data
	return [PSCustomObject] @{
		"Encrypted"				= $Encrypt
		"Passphrase"			= $Passphrase
		"File"					= $( if ($OutCertFile) { Get-ChildItem -Path $OutCertFile } )
	}
}

Function Export-CaChain {
	<#
	.SYNOPSIS
	Exports a certificate authority chain file from a source certificate.
	Essentially, spits out only the parents of a given certificate.
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-09
		
	Version:	1.0
	.LINK
	https://www.matthewschacherbauer.com
	#>

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Encryption Options
		[securestring]	$Passphrase,
		[switch]		$Encrypt,

		# Source Files
		[Parameter(Mandatory)]
		[ValidateSet("pfx","pkcs12")]
		$SourceFormat,
		[Parameter(Mandatory)]
		[ValidateScript({Test-Path -Path $_})]
		$CertFile,

		# Output Files
		[Parameter(Mandatory)]
		$OutFile
	)

	Write-Verbose "Call Export-CaChain"

	# Variables
	$ENV:RANDFILE	= $ENV:USERPROFILE + "\.rnd"

	# Check for Encrypted Private Key
	if (!$Encrypt -and (isEncryptedPrivateKey -OpenSslPath $OpenSslPath -KeyFile $CertFile)) {
		Write-Verbose "Detected encrypted private key without encryption declared."
		$Encrypt = $true
	}

	# Check Encryption
	if ($Encrypt) {
		if (!$Passphrase) {
			Write-Verbose "Encryption requested without a supplied passphrase."
			$Passphrase = Read-Host "Private Key Passphrase" -AsSecureString
		}
		
		# Decode Passphrase
		Write-Verbose "Decoding passphrase."
		$sPassphrase = Unprotect-SecureString -SecureString $Passphrase

		$encryptString = " -passin pass:$($sPassphrase) -passout pass:$($sPassphrase)"
	}
	else {
		Write-Verbose "Use plaintext private key."
		$encryptString = " -nodes -passin pass:"
	}

	Switch ($SourceFormat) {
		{$_ -in "pfx","pkcs12"} { # .PFX
			Write-Verbose "Executing Command: `"$($OpenSslPath)`" pkcs12 -in `"$($CertFile)`" -cacerts -nokeys $($encryptString) -out `"$($OutFile).tmp`""
			CMD.EXE /C "`"$($OpenSslPath)`" pkcs12 -in `"$($CertFile)`" -cacerts -nokeys $($encryptString) -out `"$($OutFile).tmp`""
			Get-Content "$($OutFile).tmp" | Remove-CertificateBagAttributes | Set-Content "$($OutFile)" -Encoding ASCII
			Remove-Item "$($OutFile).tmp"
		}
		default { Throw "Unexpected Source Format" }
	}
}

Function Protect-PrivateKey {
	<#
	.SYNOPSIS
	Adds encryption to a Private Key
	#>

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Encryption Option
		[Parameter(Mandatory)]
		[Securestring]	$Passphrase,

		# Source Files
		[Parameter(Mandatory)]
		$KeyFile,

		# Output Files
		[Parameter(Mandatory)]
		$OutKey
	)

	# Decode Secure String
	$sPassphrase = Unprotect-SecureString -SecureString $Passphrase

	# PKCS8
	# Encrypt with AES256 with hmacWithSHA256
	# https://www.openssl.org/docs/man1.1.0/man1/openssl-pkcs8.html
	CMD.EXE /C "`"$OpenSslPath`" pkcs8 -topk8 -v2 aes-256-cbc -passin pass: -passout pass:$sPassphrase -in `"$($KeyFile)`" -out `"$($OutKey).tmp`""
	Get-Content "$($OutKey).tmp" | Remove-CertificateBagAttributes | Set-Content "$($OutKey)" -Encoding ASCII
	Remove-Item "$($OutKey).tmp"

	# PKCS1
	# Encrypt with AES256
	#CMD.EXE /C "`"$OpenSslPath`" rsa -aes256 -passin pass: -passout pass:$sPassphrase -in `"$($KeyFile)`" -out `"$($OutKey).tmp`""
	#Get-Content "$($OutKey).tmp" | Remove-CertificateBagAttributes | Set-Content "$($OutKey)" -Encoding ASCII
	#Remove-Item "$($OutKey).tmp"
}

Function Unprotect-PrivateKey {

	[CmdletBinding()]
	Param (
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Encryption Option
		[Parameter(Mandatory)]
		[Securestring]	$Passphrase,

		# Source Files
		[Parameter(Mandatory)]
		$KeyFile,

		# Output Files
		[Parameter(Mandatory)]
		$OutKey
	)

	# Decode Secure String
	$sPassphrase = Unprotect-SecureString -SecureString $Passphrase

	# PKCS8
	# Strip app encryption
	# https://www.openssl.org/docs/man1.1.0/man1/openssl-pkcs8.html
	CMD.EXE /C "`"$OpenSslPath`" pkcs8 -topk8 -nocrypt -passin pass:$sPassphrase -passout pass: -in `"$($KeyFile)`" -out `"$($OutKey).tmp`""
	Get-Content "$($OutKey).tmp" | Remove-CertificateBagAttributes | Set-Content "$($OutKey)" -Encoding ASCII
	Remove-Item "$($OutKey).tmp"

	# PKCS1
	# Strip app encryption
	CMD.EXE /C "`"$OpenSslPath`" rsa -passin pass:$sPassphrase -passout pass: -in `"$($KeyFile)`" -out `"$($OutKey).rsa.tmp`""
	Get-Content "$($OutKey).rsa.tmp" | Remove-CertificateBagAttributes | Set-Content "$($OutKey).rsa" -Encoding ASCII
	Remove-Item "$($OutKey).rsa.tmp"
}

Function Remove-CertificateBagAttributes {
	<#
	.SYNOPSIS
	Removes Bag Attributes from a certificate.
	.NOTES
	This function is private to this module and should not be exported.
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory,Position=0,ValueFromPipeline)]
		$Certificate
	)

	Begin {
		Write-Verbose "Call Remove-CertificateBagAttributes"
	}

	Process {
		return $Certificate | Where-Object {
			$_ -notlike "Bag Attributes*" -and `
			$_ -notlike "subject=*" -and `
			$_ -notlike "issuer=*" -and `
			$_ -notlike "" -and `
			$_ -notlike "    *" -and `
			$_ -notlike "Key *"
		}
	}

	End { }
}

Function Unprotect-SecureString {
	<#
	.SYNOPSIS
	Removes encryption from a SecureString variable.
	.NOTES
	This function is private to this module and should not be exported.
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory,Position=0,ValueFromPipeline)]
		[securestring]	$SecureString
	)

	Begin {
		Write-Verbose "Call Unprotect-SecureString"
	}

	Process {
		# Decode Secure String
		$sSecureString = $SecureString | ConvertFrom-SecureString -ErrorAction Stop
		$sSecureString = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "NULL", ($sSecureString | ConvertTo-SecureString)
		$sSecureString = $sSecureString.GetNetworkCredential().Password

		$sSecureString
	}

	End { }
}

Function New-CertificateKeyPair {
	<#
	.SYNOPSIS
	Creates a new RSA Public/Private KeyPair, submits the certificate for a signature, and converts the resulting certificate to several popular formats.
	.NOTES
	Author:		Matthew Schacherbauer
	Updated:	2019-03-15

	Version:	1.3
	#>

	Param (
		# Resources
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OpenSslPath	= $ENV:OpenSsl + "\bin\openssl.exe",

		# Certificate Options
		[string]		$ConfigFile,
		[Parameter(Mandatory,Position=0)]
		[string[]]		$Hostname,
		[ValidateSet('1024','2048','4096')]
		[int]			$Bits			= "4096",
		[string]		$CountryName	= "US",
		[string]		$State			= "California",
		[string]		$Locality		= "Sacramento",
		[string]		$PostalCode,
		[string]		$StreetAddress,
		[string]		$Organization	= "WolfSpiritNet",
		[string]		$OrganizationalUnitName	= "Test Lab",
		[string]		$Email,

		# Self-Signed Certificate Length
		[int]			$ValidityDays	= "1826",

		# Active Directory Certificate Services Options
		[string]		$AdcsTemplate	= "WS-WebServer-v2",
		[string]		$AdcsServer		= "WSNOCCA01.lan.wolfspirit.net\WolfSpirit-Net-WSNOCCA01-CA",

		# Encryption Options
		[securestring]	$Passphrase,
		[switch]		$Encrypt,

		# Output Files
		[ValidateScript({Test-Path -Path $_})]
		[string]		$OutPath		= "\\LAN.WOLFSPIRIT.NET\DFS\Documentation\WS PKI\Issued Certificates\" + (Get-Date -Format yyyy),

		[switch]		$OnlyCsr
	)

	Write-Verbose "Call New-CertificateKeyPair"

	# Check Encryption
	if ($Encrypt -and (!$Passphrase)) {
		Write-Verbose "Encryption requested without a supplied passphrase."
		$Passphrase = Read-Host "Private Key Passphrase" -AsSecureString
	}

	# Variables
	[PSCustomObject] $certFile = [Ordered] @{
		"Directory"		= $OutPath + "\" + $Hostname[0] + "\"
	}
	$certFile += [Ordered] @{													######
		"Config"		= $certFile.Directory + $Hostname[0] + ".cfg"			# Create various certificate formats for every application imaginable
		"Csr"			= $certFile.Directory + $Hostname[0] + ".csr"			#
																				#	EXTENSION		FORMAT		HAS CHAIN		HAS PRIVATE KEY
		"EncryptedKey"	= $Encrypt												#	=========		======		=========		===============
		"Key"			= $certFile.Directory + $Hostname[0] + ".key"			#	.KEY			PKCS8		NO				YES					(Private Key Only)
		"RsaKey"		= $certFile.Directory + $Hostname[0] + ".rsa.key"		#	.RSA.KEY		PKCS1		NO				YES					(Private Key Only)
		"CrtSelf"		= $certFile.Directory + $Hostname[0] + ".self.crt"		#	.SELF.CRT		x509		NO				NO
		"Crt"			= $certFile.Directory + $Hostname[0] + ".crt"			#	.CRT			x509		NO				NO					(Source from ADCS)
		"P7bChain"		= $certFile.Directory + $Hostname[0] + ".chain.p7b"		#	.CHAIN.P7B		PKCS7		YES				NO					(Source from ADCS)
		"RspChain"		= $certFile.Directory + $Hostname[0] + ".chain.rsp"		#	.CHAIN.RSP		RSP			YES				NO					(Source from ADCS)
		"Pem"			= $certFile.Directory + $Hostname[0] + ".pem"			#	.PEM			PEM			NO				NO
		"Der"			= $certFile.Directory + $Hostname[0] + ".der"			#	.DER			DER			NO				NO
		"CrtChain"		= $certFile.Directory + $Hostname[0] + ".chain.crt"		#	.CHAIN.CRT		x509		YES				NO
		"PemChain"		= $certFile.Directory + $Hostname[0] + ".chain.pem"		#	.CHAIN.PEM		PEM			YES				NO
		"DerChain"		= $certFile.Directory + $Hostname[0] + ".chain.der"		#	.CHAIN.DER		DER			YES				NO
		"Pfx"			= $certFile.Directory + $Hostname[0] + ".pfx"			#	.PFX			PKCS12		YES				YES
		"CaChain"		= $certFile.Directory + "cachain.pem"					######
	}

	# Create certificate directory
	Write-Verbose "Creating certificate output directory."
	New-Item -ItemType Directory -Path $certFile.Directory -ErrorAction Inquire | Out-Null

	if ($ConfigFile) {
		Write-Verbose "Using input OpenSSL configuration file."
		$certFile.Config = $ConfigFile
	}
	else {
		Write-Verbose "Generating new OpenSSL configuration file with input parameters."
		New-OpenSslCertificateConfiguration `
			-Hostname $Hostname `
			-CountryName $CountryName `
			-State $State `
			-Locality $Locality `
			-PostalCode $PostalCode `
			-StreetAddress $StreetAddress `
			-Organization $Organization `
			-OrganizationalUnitName $OrganizationalUnitName `
			-Email $Email `
			-Bits $Bits `
			-Encrypt:$Encrypt `
			-ErrorAction Stop |
			Out-File -FilePath "$($certFile.Directory)$($Hostname[0]).cfg" -Encoding ASCII -ErrorAction Stop
	}

	# Create Private Key and CSR from Config file
	$null = New-CertificateSigningRequest `
		-OpenSslPath $OpenSslPath `
		-Bits $Bits `
		-Encrypt:$Encrypt `
		-Passphrase $Passphrase `
		-ConfigFile $certFile.Config `
		-OutKeyFile $certFile.Key `
		-OutRequestFile $certFile.Csr `
		-ErrorAction Stop

	# Convert the Private Key to PKCS1 Format
	$null = ConvertTo-Pkcs1 `
		-OpenSslPath $OpenSslPath `
		-Encrypt:$Encrypt `
		-Passphrase $Passphrase `
		-Key $certFile.Key `
		-OutKey $certFile.RsaKey `
		-ErrorAction Continue

	# Use the Private Key to create a Self Signed Certificate
	$null = New-SelfSignedCertificate `
		-OpenSslPath $OpenSslPath `
		-ValidityDays $ValidityDays `
		-Encrypt:$Encrypt `
		-Passphrase $Passphrase `
		-ConfigFile $certFile.Config `
		-KeyFile $certFile.Key `
		-RequestFile $certFile.Csr `
		-OutCertFile $certFile.CrtSelf `
		-ErrorAction Continue
	
	if ($OnlyCsr) { break }		# Stop after generating the Certificate Signing Request

	# Submit the CSR to an Enterprise CA for Signing
	# Returns a signed x509 certificate, a PKCS7 certificate chain, and a third file (that looks like a reversed chain)
	$null = New-EnterpriseCertificateAuthoritySignature `
		-AdcsTemplate $AdcsTemplate `
		-AdcsServer $AdcsServer `
		-RequestFile $certFile.Csr `
		-OutCertFile $certFile.Crt `
		-OutChainP7bFile $certFile.P7bChain `
		-OutChainRspFile $certFile.RspChain `
		-ErrorAction Inquire

	# Convert the Signed x509 Certificate to PEM
	$null = ConvertTo-Pem `
		-OpenSslPath $OpenSslPath `
		-SourceFormat "x509" `
		-CertFile $certFile.Crt `
		-OutCertFile $certFile.Pem

	# Convert the PEM Certificate to DER
	$null = ConvertTo-Der `
		-OpenSslPath $OpenSslPath `
		-SourceFormat "pem" `
		-CertFile $certFile.Pem `
		-OutCertFile $certFile.Der

	# Convert the PKCS7 (.p7b) Certificate Chain to PEM
	$null = ConvertTo-Pem `
		-OpenSslPath $OpenSslPath `
		-SourceFormat "pkcs7" `
		-CertFile $certFile.P7bChain `
		-OutCertFile $certFile.PemChain

	# Convert the PKCS7 (.p7b) Certificate Chain to DER
	$null = ConvertTo-Der `
		-OpenSslPath $OpenSslPath `
		-SourceFormat "pkcs7" `
		-CertFile $certFile.P7bChain `
		-OutCertFile $certFile.DerChain

	# Combine the PEM Certificate Chain with the Private Key to PKCS12 (.pfx) with the Private Key
	$null = ConvertTo-Pfx `
		-OpenSslPath $OpenSslPath `
		-Encrypt:$Encrypt `
		-Passphrase $Passphrase `
		-CertFile $certFile.PemChain `
		-KeyFile $certFile.Key `
		-OutCertFile $certFile.Pfx

	# Create the CA Chain file
	$null = Export-CaChain `
		-OpenSslPath $OpenSslPath `
		-Encrypt:$Encrypt `
		-Passphrase $Passphrase `
		-SourceFormat "pkcs12" `
		-CertFile $certFile.Pfx `
		-OutFile $certFile.CaChain `
		-ErrorAction Continue

	# Return Generated Certificate Paths
	return $certFile
}

# Exported Functions
Export-ModuleMember -Function New-CertificateSigningRequest, New-SelfSignedCertificate, New-EnterpriseCertificateAuthoritySignature, ConvertTo-Pkcs1, ConvertTo-Pkcs8, ConvertTo-Pem, ConvertTo-Der, ConvertTo-Pfx, Export-CaChain, Protect-PrivateKey, Unprotect-PrivateKey, New-CertificateKeyPair


# SIG # Begin signature block
# MIIcJAYJKoZIhvcNAQcCoIIcFTCCHBECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOlFE6WvtgdWg83LpMle7Y6DR
# j+OgghYiMIIEmTCCA4GgAwIBAgIPFojwOSVeY45pFDkH5jMLMA0GCSqGSIb3DQEB
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
# BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQc0VxOA6vOD2KV1CNzquKpSkXZlzAN
# BgkqhkiG9w0BAQEFAASCAgDLFV6oJSZRPgRP493ItlHdFwj8u8SSuYZ1QfZl1KN+
# m8D+4kc1pbxQ5ntygE6hBpKupZJLo+62NJtwBP17khRCWpl4dChGjQHQy+XE9v0I
# +b0InY1sXojJp+hqwonkAPsxs4EpBJc1z6vqbH4VeK/k9V/ZXk7tosYdPLVHXnYG
# ERuqzvZHXVFR4osvEGnasTmzAlGELVttFCZ/e45ZHcC4rAs1x974LWJcbaEcgwAl
# OXwY4Eh2maLSagOmOwVfOTfM53/NWgUqeg1swQvp85+unzYkX5vj6nj2vMtpUHBV
# oRSS5pFwqmJ8LU/MRUBwz7LTDxyfteyL/Ue7SKGthgjD1y5mdxfhn+mCJgMxnPr/
# w86teCWMmGYAJBoG9pAfvmUlt+N1ji1ON095E2DNeqs5oX5Q636InBj1usRqIp0Q
# Jjh/xdyIeGXfddADRQJlb6k33YiplrfhGu0vzRDpcac8nvR6ogwk6I18XsV+oq0U
# 7Brwtb0+npdkL4Q0AASkdrAFuy2X6KZXhujeUxe147ZQYI0XMAblDtGn/Pur/QQv
# rNAcKy6Mp7nj8y3Q/C4wTLi6PWmzokdY3Ot/TLtTjAGEWhw8962WlzAknZPM5DZW
# l+e8JJfFb2b6hbpc7yPO/20k0/hkpXOuqiPTFsEMMyg3li4Mzz2bRktxCrzoMy7i
# RKGCAkMwggI/BgkqhkiG9w0BCQYxggIwMIICLAIBATCBqTCBlTELMAkGA1UEBhMC
# VVMxCzAJBgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2UgQ2l0eTEeMBwGA1UE
# ChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExhodHRwOi8vd3d3LnVz
# ZXJ0cnVzdC5jb20xHTAbBgNVBAMTFFVUTi1VU0VSRmlyc3QtT2JqZWN0Ag8WiPA5
# JV5jjmkUOQfmMwswCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTE5MDMxNjAyNDgyNVowIwYJKoZIhvcNAQkEMRYE
# FE3awRR8NuDEg/k80ZrCjY1yQeESMA0GCSqGSIb3DQEBAQUABIIBAIlbAe9hiZgz
# dfP5AUzgpqCYjL6vkZjRC1FL2Iug1nkaVavVk4qlrMz1eDOgMZf7YOY5NGax84FN
# S9mJ3dEPaZSHaxqEswZxJznNTV9wWPXLd8eZSWEUkYjibV7qczKAwiAl4A7lTtCK
# PGPTy0l/REv3vUAQ9TcykKBA6ezuS34IHWYMu2DKLP/y+YOHzWrMo/8vjtahshKq
# v1Wrhgu5OPJ5v2S7qYRztKA6gDNI0deJwMSWx9OP3vNaRZY9lgbfAlXzHHXWwie3
# nqv56qhYf8ytHJH2m+ve0+5GX43rvjsPEketeM4/IkXqMpKlYXNfQ783whPhT5ia
# JrR5TN5uIZM=
# SIG # End signature block
