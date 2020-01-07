$TempDir = "C:\Temp\Datto Logs"
$Date = Get-Date -Format yyyMMdd
function Get-InstalledSoftware {
    <#
	.SYNOPSIS
		Retrieves a list of all software installed on a Windows computer.
	.EXAMPLE
		PS> Get-InstalledSoftware
		
		This example retrieves all software installed on the local computer.
	.PARAMETER ComputerName
		If querying a remote computer, use the computer name here.
	
	.PARAMETER Name
		The software title you'd like to limit the query to.
	
	.PARAMETER Guid
		The software GUID you'e like to limit the query to
	#>
    [CmdletBinding()]
    param (
		
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,
		
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
		
        [Parameter()]
        [guid]$Guid
    )
    process {
        try {
            $scriptBlock = {
                $args[0].GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value }
				
                $UninstallKeys = @(
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                )
                New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
                $UninstallKeys += Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object {
                    "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                }
                if (-not $UninstallKeys) {
                    Write-Warning -Message 'No software registry keys found'
                } else {
                    foreach ($UninstallKey in $UninstallKeys) {
                        $friendlyNames = @{
                            'DisplayName'    = 'Name'
                            'DisplayVersion' = 'Version'
                        }
                        Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
                        if ($Name) {
                            $WhereBlock = { $_.GetValue('DisplayName') -like "$Name*" }
                        } elseif ($GUID) {
                            $WhereBlock = { $_.PsChildName -eq $Guid.Guid }
                        } else {
                            $WhereBlock = { $_.GetValue('DisplayName') }
                        }
                        $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
                        if (-not $SwKeys) {
                            Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
                        } else {
                            foreach ($SwKey in $SwKeys) {
                                $output = @{ }
                                foreach ($ValName in $SwKey.GetValueNames()) {
                                    if ($ValName -ne 'Version') {
                                        $output.InstallLocation = ''
                                        if ($ValName -eq 'InstallLocation' -and 
                                            ($SwKey.GetValue($ValName)) -and 
                                            (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\'))) {
                                            $output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
                                        }
                                        [string]$ValData = $SwKey.GetValue($ValName)
                                        if ($friendlyNames[$ValName]) {
                                            $output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
                                        } else {
                                            $output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
                                        }
                                    }
                                }
                                $output.GUID = ''
                                if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b') {
                                    $output.GUID = $SwKey.PSChildName
                                }
                                New-Object -TypeName PSObject -Prop $output
                            }
                        }
                    }
                }
            }
			
            if ($ComputerName -eq $env:COMPUTERNAME) {
                & $scriptBlock $PSBoundParameters
            } else {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $PSBoundParameters
            }
        } catch {
            Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
}
function Get-InstalledProduct {
    
    $DWA = Get-InstalledSoftware -ComputerName $env:COMPUTERNAME -Name 'datto windows agent'   
    $ProductInfo = @{ }
    if ($null -eq $DWA) { $ShadowSnap = Get-InstalledSoftware -ComputerName $env:COMPUTERNAME -Name 'shadowsnap' }
    if ($null -ne $DWA) { $ProductInfo.Product = 'Datto'; $ProductInfo.Version = $DWA[0].Version }
    elseif ($null -ne $ShadowSnap) { $ProductInfo.Product = 'Shadowsnap'; $ProductInfo.Version = $ShadowSnap[0].Version}
    else { Write-Error -Message 'Unable to detect installed backup software' }

    return $ProductInfo
}
function Get-DattoLogPath {
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline)]
    $Product
    )
    
    BEGIN 
    {
        $LogPaths = @{}
    }
    PROCESS 
    {
        # Build the log paths if the $Product object is initialized
        if ($null -ne $Product) {
            Switch([System.Environment]::Is64BitOperatingSystem) {
                $false {$PF = 'Program Files'}
                $true {$PF = 'Program Files (x86)'}
            }
        
        
            Switch ($Product.Product) {
                'Datto' {

                    $LogPaths.AppLog = "$env:SystemDrive\Windows\System32\config\systemprofile\AppData\Local\Datto\Datto Windows Agent"

                    # Set the installation log depending on the minor version of DWA
                    $Version = $Product.Version 
                    if ($Version.Minor -lt 1){ 
                        $LogPaths.InstallLog = "$env:SystemDrive\$PF\Datto"
                    }
                    else { $LogPaths.InstallLog = "$env:LOCALAPPDATA\Temp" }
                    }
                
                'Shadowsnap' { 
                    $LogPaths.AppLog = "$env:SystemDrive\$PF\StorageCraft\ShadowProtect\ShadowSnap"
                
                }
            }
            return $LogPaths
        }
        else { 
            Write-Error -Message 'Backup software not found'
        }
    }
    END 
    {
        
    }
}
function ZipFiles( $zipfilename, $sourcedir ){
   Add-Type -Assembly System.IO.Compression.FileSystem
   $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
   [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir,
        $zipfilename, $compressionLevel, $false)
}
# Get the paths to log files
$Product = Get-InstalledProduct
$Paths = Get-DattoLogPath (Get-InstalledProduct)
# Create a directory in C:\Temp if it doesn't exist and copy all log files
if ((Test-Path -PathType Container $TempDir) -eq $false) { New-Item -ItemType Directory -Path $TempDir}

$SystemLog = Get-WmiObject Win32_NTEventLogFile | Where-Object {$_.LogFileName -eq "System"}
$ApplicationLog = Get-WmiObject Win32_NTEventLogFile | Where-Object { $_.LogFileName -eq "Application"}

# Save windows event logs
$SystemLog.BackupEventLog("$TempDir\$env:COMPUTERNAME-system-$Date.evt")
$ApplicationLog.BackupEventLog("$TempDir\$env:COMPUTERNAME-application-$Date.evt")

# Copy Datto log files

if ($Product.Product -match 'Datto') {
    New-Item -Path "$TempDir\Installation"-ItemType Directory
    New-Item -Path "$TempDir\Application" -ItemType Directory
    Get-ChildItem -Path $Paths.AppLog -Exclude 'certs','config.json','*.zip' | Copy-Item -Destination "$TempDir\Application" -Recurse -Force
    Get-ChildItem -Path "$($Paths.InstallLog)\Datto*.log" | Copy-Item -Destination "$TempDir\Installation" -Force
}

if ($Product.Name -eq "Shadowsnap"){
    Copy-Item -Path "$($Paths.AppLog)\log\raw_agent.log" -Destination $TempDir
    Copy-Item -Path "$($Paths.AppLog)\log\log.txt" -Destination $TempDir
    Copy-Item "$($Paths.AppLog)\endptconfig.sqlite3" -Destination $TempDir
}

# Zip it all up
ZipFiles -zipfilename "$env:USERPROFILE\Desktop\$env:COMPUTERNAME-datto-logs-$Date.zip" -sourcedir $TempDir
Remove-Item $TempDir -Recurse -Force
