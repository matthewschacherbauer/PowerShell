<#
    .DESCRIPTION
    Log Directory Cleanup

    Performs cleanup of files based on date. Used for purging old log files.
    .NOTES
    Author:     Matthew Schacherbauer
    Updated:    2026-01-01

    Version:    1.0
#>

[CmdletBinding()]
Param (
    [ValidateNotNullOrEmpty()]
    $LogBasePath,
    [ValidateNotNullOrEmpty()]
    $Age = "90",
    
    [Switch] $RemoveEmptyDirectory
)


Write-Verbose "Performing cleanup on directory: [$($LogBasePath)]"

$oDirectories = Get-ChildItem -Path $LogBasePath -Directory -Recurse

foreach ( $thisDirectory in $oDirectories ) {

    # Get all files older than 90 days.
    $oFiles = $null
    $oFiles = @(Get-ChildItem -Path $thisDirectory.FullName -File | Where-Object { $_.LastWriteTime -lt ((Get-Date).AddDays(-$Age)) })

    if ( $oFiles ) {

        Write-Verbose "Found [$($oFiles.count)] files for removal in directory [$($thisDirectory.FullName)]"
        
        foreach ( $thisFile in $oFiles ) {

            Write-Verbose "Removing file [$($thisFile.FullName)]"

            # Delete those files.
            $thisFile | Remove-Item -Confirm:$false

        }

    }

    if ( $RemoveEmptyDirectory ) {

        # Check if directory is empty.
        $oFiles = $null
        $oFiles = Get-ChildItem -Path $thisDirectory.FullName

        if ( !$oFiles ) {

            Write-Verbose "Removing empty directory [$($thisDirectory.FullName)]"

            # Remove empty directory.
            $thisDirectory | Remove-Item -Confirm:$false

        }

    }

}

