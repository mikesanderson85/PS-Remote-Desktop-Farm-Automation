<#
.SYNOPSIS
This PowerShell script is used for the deployment of a Windows Server 2012/16 Remote Desktop Farm. It also includes the ability to install applications on specific hosts if the corresponding apps.csv file is completed

.DESCRIPTION
Complete the associated parameters and apps.csv file to deploy a Remote Desktop Farm. This script will create a broker, sessions hosts, install applications on session hosts, create and configure gateway, add web access and a license server. It will then publish required applications to collections.

Script should be ran external to the computers the farm is being deployed on but if not possible can be run from a Gateway, License or Web Access servers as these servers are not restarted as part of the deployment process

.PARAMETER InstallApps
	Switch to determine if applications should be installed (requires the apps.csv file to be populated)

.PARAMETER InstallCerts
	Swtich to determine if certificates should be installed. Certificates should be named as per their corresponding servers `
	(e.g. broker01.domain.local.pfx) and placed in the Certificates folder

.PARAMETER FQDN
	The fully qualified domain name of the deployment

.PARAMETER sessionHost
	The hostname of the servers that are to be session hosts within the deployment. Multipe hosts should be seperated by a comma (,)

.PARAMETER webAccessServerName
	The hostname of the Web Access server

.PARAMETER brokerServerName
	The hostname of the Connection Broker

.PARAMETER licenseServerName
	The hostname of the License server

.PARAMETER gatewayServerName
	The hostname of the Gateway server

.PARAMETER gatewayExternalFQDN
	The external FQDN for the Gateway

.PARAMETER csvName
	Only required if applications are to be installed. The CSV should be pre-populated wtih values before deployment

.PARAMETER installDIsk
	The disk the 'Software' folder will be copied to

.EXAMPLE
		./REDdeploy_GREEN_v1.0.ps1 -installApps -FQDN domain.local -sessionHost host011, host012 -webAccessServerName webaccess01 -brokerServerName broker01 -licenseServerName license01 -gatewayServerName gateway01 -gatewayExternalFQDN gateway01.domain.local -csvName apps.csv -installDisk D 
		
		Deploy a RDS farm, install applications but no certificates

.EXAMPLE
		./REDdeploy_GREEN_v1.0.ps1 -FQDN domain.local -sessionHost host011, host012 -webAccessServerName webaccess01 -brokerServerName broker01 -licenseServerName license01 -gatewayServerName gateway01 -gatewayExternalFQDN gateway01.domain.local

		Deploy a RDS farm only and no applications

.EXAMPLE		
		./REDdeploy_GREEN_v1.0.ps1 -installApps -installCerts -FQDN domain.local -sessionHost host011, host012 -webAccessServerName webaccess01 -brokerServerName broker01 -licenseServerName license01 -gatewayServerName gateway01 -gatewayExternalFQDN gateway01.domain.local -csvName apps.csv -installDisk D 
	
		Deploy a RDS farm with applications and certificates

.NOTES
Author: Michael Sanderson
Date: 11OCT2017
Updated: 11OCT2017
UpdNote: Added help
#>

[CmdletBinding()]
Param
(
	[switch]$installCerts,
	[switch]$installApps,
	[string]$FQDN = "magicmike.com",
	[array]$sessionHost = @("magicmike02", "magicmike03"),
	[string]$webAccessServerName = "magicmike04",
	[string]$brokerServerName = "magicmike01",
	[string]$licenseServerName = "magicmike05",
	[string]$gatewayServerName = "magicmike06",
	[string]$gatewayExternalFQDN = "magicmike06.magicmike.com",
	[string]$csvName = "apps.csv",
	[string]$installDisk = "D"
)

#Write log function
function Write-Log {
	Param
	(
		[string]$logString,
		[String]$infoType = "INFO",
		[Switch]$writeHostInfo,
		[Switch]$writeHostError,
		[Switch]$writeHostGeneral,
		[Switch]$writeHostYellow
	)
	
	$logDateTime = Get-Date -Format f
	Add-Content $logFile -Value (($logDateTime + ": " + $infoType + " ") + ($logString))
	if ($writeHostInfo) {
		Write-Host $logString -ForegroundColor Green -BackgroundColor Black
	} ElseIf ($writeHostError) {
		Write-Host $logString -ForegroundColor Red -BackgroundColor Black
	} ElseIf ($writeHostGeneral) {
		Write-Host $logString -ForegroundColor White -BackgroundColor Black
	} ElseIf ($writeHostYellow) {
		Write-Host $logString -ForegroundColor Yellow -BackgroundColor Black
	}
	
}

#VALIDATE THE DEPLOYMENT
function Validate-RDSDeployment ($collName) {
	If (Test-Path "$scriptDir\$csvName") {
		$CSVImport = Import-CSV "$scriptDir\$csvName"
		
		forEach ($line in $CSVImport) {
			$displayName += @($line.displayName)
			$collectionName += @($line.collectionName)
		}
	}
	
	$displayName = $displayName | Select -Unique
	$collectionName = $collectionName | ? {
		$_
	} | Select -Unique
	
	Write-Log "S T A R T  V A L I D A T I O N" -writeHostInfo
	$errorFound = 0
	$roleType = "RDS-Connection-Broker"
	Write-Log "Checking $roleType role has been installed on $brokerServerName..." -writeHostYellow
	if (Get-WindowsFeature $roleType -ComputerName $brokerServerName | Where-Object {
			$_.Installed -eq $true
		}) {
		Write-Log "$roleType role was succesfully installed" -writeHostInfo
	} else {
		Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
		$errorFound++
	}
	
	$roleType = "RDS-Licensing"
	Write-Log "Checking $roleType role has been installed on $licenseServerName..." -writeHostYellow
	if (Get-WindowsFeature $roleType -ComputerName $licenseServerName | Where-Object {
			$_.Installed -eq $true
		}) {
		Write-Log "$roleType role was succesfully installed" -writeHostInfo
	} else {
		Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
		$errorFound++
	}
	
	$roleType = "RDS-Gateway"
	Write-Log "Checking $roleType role has been installed on $gatewayServerName..." -writeHostYellow
	if (Get-WindowsFeature $roleType -ComputerName $gatewayServerName | Where-Object {
			$_.Installed -eq $true
		}) {
		Write-Log "$roleType role was succesfully installed" -writeHostInfo
	} else {
		Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
		$errorFound++
	}
	
	$roleType = "RDS-Web-Access"
	Write-Log "Checking $roleType role has been installed on $webAccessServerName..." -writeHostYellow
	if (Get-WindowsFeature $roleType -ComputerName $webAccessServerName | Where-Object {
			$_.Installed -eq $true
		}) {
		Write-Log "$roleType role was succesfully installed" -writeHostInfo
	} else {
		Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
		$errorFound++
	}
	
	forEach ($sessionHost in $sessionHostFQDN) {
		$roleType = "RDS-RD-Server"
		Write-Log "Checking $roleType role has been installed on $sessionHost..." -writeHostYellow
		if (Get-WindowsFeature $roleType -ComputerName $sessionHost | Where-Object {
				$_.Installed -eq $true
			}) {
			Write-Log "$roleType role was succesfully installed" -writeHostInfo
		} else {
			Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
			$errorFound++
		}
	}
	
	Write-Log "Checking collection has been created..." -writeHostYellow
	forEach ($collName in $collectionName) {
		if (Get-RDSessionCollection -ConnectionBroker $brokerServerName | Where-Object {
				$_.CollectionName -eq $collName
			}) {
			Write-Log "Collection name, '$collName', succesfully found" -writeHostInfo
		} else {
			Write-Log "Collection name, '$collName', NOT found" -infoType "ERROR" -writeHostError
			$errorFound++
		}
	}
	
	forEach ($collName in $collectionName) {
		if (Get-RDSessionCollection -ConnectionBroker $brokerServerName | Where-Object {
				$_.CollectionName -eq $collName
			}) {
			$appNames = $displayName
			forEach ($app in $appNames) {
				Write-Log "Checking '$app' has been published in collection, '$collName'..." -writeHostYellow
				if (Get-RDRemoteApp -collectionName $collName -connectionBroker $brokerServerName -displayName $app) {
					Write-Log "The RemoteApp, '$app', is published" -writeHostInfo
				} else {
					Write-Log "The RemoteApp, '$app', could not be found in collection '$collName'. It may be the app is not required for this collection. Check apps.csv for details" -infoType "ERROR" -writeHostError
					$errorFound++
				}
			}
		} else {
			Write-Log "Apps will not be checked as the collection, '$collName', does not exist" -infoType "ERROR" -writeHostError
		}
	}
	
	if ($errorFound -gt 0) {
		Write-Log "There were errors found when validating deployment. Check log for details." -writeHostError
	} else {
		Write-Log "V A L I D A T I O N   S U C C E S S F U L" -writeHostInfo
	}
}

#Append FQDN to each session host value
$sessionHostFQDN = @()
ForEach ($arrayItem in $sessionHost) {
	$sessionHostFQDN += "$arrayItem.$FQDN"
}
$webAccessServerName = "$webAccessServerName.$FQDN"
$brokerServerName = "$brokerServerName.$FQDN"
if ($licenseServerName) {
	$licenseServerName = "$licenseServerName.$FQDN"
}
$gatewayServerName = "$gatewayServerName.$FQDN"

#The location of where the script is ran from
$scriptDir = $PSScriptRoot

#Import the Remote Desktop PowerShell module
Import-Module RemoteDesktop

#CREATE A LOG FILE
$logFile = "$PSScriptRoot\RDdeploy_GREEN.log"

#Catch all errors
$ErrorActionPreference = "Stop" #terminate on all errors

#BEGIN LOG
Write-Log "====== STARTING SCRIPT 'RDSdeploy.ps1' ======" -writeHostInfo

#Check switches
If ($installApps -eq $True) {
	Write-Log "Will install apps" -writeHostInfo
} else {
	Write-Log "Will not install apps" -writeHostInfo
}

If ($installCerts -eq $True) {
	Write-Log "Will install certs" -writeHostInfo
} else {
	Write-Log "Will not install certs" -writeHostInfo
}

#Ask for a password for the certificates if they are to be installed
if ($installCerts -eq $True) {
	$certPassword = Read-Host -AsSecureString "Please enter the password for the RDS Farm certificates"
}

#create an array of all server entires
$allServersArray = @($webAccessServerName, $brokerServerName, $licenseServerName, $gatewayServerName)
forEach ($hostFQDN in $sessionHostFQDN) {
	$allServersArray += $hostFQDN
}
#REMOVE BLANK ENTIRES
$allServersArray = $allServersArray | ? {
	$_
}

#Import module Get-Pending Reboot
."$scriptDir\Get-PendingReboot.ps1"

#START SCRIPT
#TEST CONNECTIONS TO EACH SERVER
ForEach ($computer in $allServersArray) {
	if (!(Test-Connection $computer -Count 1 -ErrorAction SilentlyContinue)) {
		Write-Log "A connection to $computer could not be established. Script will exit. Error: $($Error[0])" -writeHostError
		Start-Sleep -Seconds 5
		Exit
	}
}

#Check for pending reboots on each server
ForEach ($server in $allServersArray) {
	Write-Log "Checking if a reboot is pending on $server..."
	$isRebootRequired = Get-PendingReboot -ComputerName $server -WarningAction SilentlyContinue
	if ($isRebootRequired.RebootPending -eq $true) {
		Write-Log "Reboot pending on $server... Restarting server"
		try {
			Restart-Computer -ComputerName $server -Force -Wait -For Wmi -ErrorAction SilentlyContinue
			Write-Log "Reboot complete on $server"
		} catch {
			Write-Log "$server could not be restarted but will continue to attempt deployment..." -infoType "WARNING"
		}
	} elseIf ($isRebootRequired.RebootPending -eq $false) {
		Write-Log "No reboot required on $server"
	} else {
		Write-Log "Information on reboot status could not be found for computer: $server" -infoType "WARNING"
	}
}

Write-Log "Starting deployment using broker $brokerServerName" -writeHostInfo

#START RDS FARM DEPLOYMENT
try {
	New-RDSessionDeployment –ConnectionBroker $brokerServerName –WebAccessServer $webAccessServerName –SessionHost $sessionHostFQDN[0]
} catch {
	Write-Log $Error[0] -writeHostError
	exit
}

<#
Write-Log "Restarting the broker, '$brokerServerName'... " 
Restart-Computer -ComputerName $brokerServerName -Force -Wait -For Wmi -ErrorAction Continue 
#>

#Test connection to broker
Do {
	Write-Log "Attempting to reconnect to '$brokerServerName'..."
	Start-Sleep -Seconds 2
} Until (Test-Connection $brokerServerName -Count 1 -ErrorAction SilentlyContinue)

Write-Log "Connection to '$brokerServerName' successful. Continuing deployment..." -writeHostInfo

#Test for RDMS service on broker
Do {
	Write-Log "Identifying the RDMS service has started on '$brokerServerName' before continuing..."
	Start-Sleep -Seconds 10
} Until (Get-Service -ComputerName $brokerServerName | Where-Object {
		$_.Status -eq "Running" -and $_.Name -eq "RDMS"
	})

Write-Log "RDMS Service started on '$brokerServerName'. Continuing deployment..." -writeHostInfo

#Add hosts
if ($sessionHostFQDN.Length -gt 1) {
	forEach ($sesstionHost in $sessionHostFQDN) {
		if ($sessionHostFQDN.IndexOf($sesstionHost) -ne 0) {
			try {
				Write-Log "Attempting to install session host, '$sesstionHost'..." -writeHostInfo
				Add-RDServer -Server $sesstionHost -Role RDS-RD-SERVER -ConnectionBroker $brokerServerName | Out-Null
				Write-Log "Installation of session host '$sesstionHost' sucsessful. Continuing deployment..."
			} catch {
				Write-Log "Installation of the session host, '$sesstionHost' failed with error: $($Error[0])" -infoType "ERROR"
			}
		}
	}
}

#Add licensing server if FQDN Specified
if ($licenseServerName) {
	try {
		Write-Log "Attempting to install license server, '$licenseServerName'..." -writeHostInfo
		Add-RDServer -Server $licenseServerName -Role RDS-LICENSING -ConnectionBroker $brokerServerName | Out-Null
		Write-Log "Installation of license server '$licenseServerName' sucsessful. Continuing deployment..."
	} catch {
		Write-Log "Installation of license server, '$licenseServerName' failed with error: $($Error[0])" -infoType "ERROR"
	}
	
	
	#Set License Config
	Write-Log "Setting License Server configuration on $licenseServerName..."
	Try {
		Set-RDLicenseConfiguration -LicenseServer $licenseServerName -Mode PerUser -ConnectionBroker $brokerServerName -Force
		Write-Log "Setting License Server configuration on $licenseServerName complete"
	} catch {
		Write-Log "Setting License Server configuration on $licenseServerName failed with error: $($Error[0])" -infoType "ERROR"
	}
}

#Add Gateway server
try {
	Write-Log "Attempting to install gateway server, '$gatewayServerName'..."
	Add-RDServer -Server $gatewayServerName -GatewayExternalFqdn $gatewayExternalFQDN -Role RDS-GATEWAY -ConnectionBroker $brokerServerName | Out-Null
	Set-RDDeploymentGatewayConfiguration -GatewayMode Custom -LogonMethod Password -GatewayExternalFqdn $gatewayExternalFQDN -UseCachedCredentials $true -BypassLocal $false -ConnectionBroker $brokerServerName -Force
	Write-Log "Installation of gateway server '$gatewayServerName' sucsessful. Continuing deployment..."
} catch {
	Write-Log "Installation of gateway server '$gatewayServerName' failed with error: $($Error[0])" -infoType "ERROR"
}

Start-Sleep -Seconds 5

#Configure Gateway Settings
Write-Log "Attempting to configure Gateway settings..."
$gatewaySession = New-PSSession -ComputerName $gatewayServerName
$remoteCommand = Invoke-Command -Session $gatewaySession -ScriptBlock {
	
	$broker = $args[0]
	$sessionHost = $args[1]
	$computerList = $broker + " " + $sessionHost
	$computerList = $computerList -split (" ")
	
	#import the module
	Import-Module RemoteDesktopServices
	
	#check the gateway is ready for modification
	Do {
		Write-Output "Checking Gateway is ready for modification. "
		Start-Sleep -Seconds 1
	} Until (Test-Path "RDS:\GatewayServer\CAP\RDG_CAP_AllUsers")
	
	#configure CAP
	Write-Output "Configuring CAP. "
	cd RDS:\GatewayServer\CAP\RDG_CAP_AllUsers
	Set-Item IdleTimeout -value 120
	Set-Item SessionTimeout -value 480 -SessionTimeoutAction 0
	cd .\DeviceRedirection
	Set-Item DiskDrives -value 0
	Set-Item Printers -value 0
	Set-Item SerialPorts -value 0
	Set-Item Clipboard -value 0
	Set-Item PlugAndPlayDevices -value 0
	
	#configure RAP
	Write-Output "Configuring RAP."
	cd ..\..\..\
	cd .\GatewayManagedComputerGroups
	New-Item -Name "ResourceAccessGroup" -Computers $computerList -Description "Lists the resources users will have access to when connecting though the Gateway"
	cd ..\
	cd .\RAP\RDG_AllDomainComputers\
	Set-Item ComputerGroupType -Value 0 -ComputerGroup "ResourceAccessGroup"
} -ArgumentList $brokerServerName, $sessionHostFQDN

Write-Log $remoteCommand

Remove-PSSession $gatewaySession.Id


if ($installCerts -eq $true) {
	
	$farmServers = @($brokerServerName, $gatewayServerName, $webAccessServerName)
	
	forEach ($serv in $farmServers) {
		
		#Request-Certificate -CN $serv -CAName $CAName -Export
		
        <#$certStore = "$scriptDir\Certificates"

            Invoke-Command -ComputerName $serv -ScriptBlock {
                #Generate self-signed certificates
                $a = $args[0]
                $b = $args[1]
                $c = $args[2]
                $cert = New-SelfSignedCertificate -DnsName $a -CertStoreLocation Cert:\LocalMachine\My
                $certPath = 'cert:\localMachine\my\' + $cert.Thumbprint
                Export-PfxCertificate -Cert $certPath -FilePath "C:\$a.pfx" -Password $b
                } -ArgumentList $serv, $certPassword, $certStore
            
            If (!(Test-Path $certStore)) {
            Write-Log "Creating Certificate directory"
            New-Item -Path $certStore -ItemType Directory
            }

            $from = "\\" + $serv + "\C$\$serv.pfx"
            $to = "$certStore\$serv.pfx"
            Write-Log "Moving cert '$serv.pfx' to Cert directory" 
            Move-Item $from $to -Force
            #>
		
		#Install Certificates
		Write-Host "Setting certificates..."
		$certLocation = "$scriptDir\Certificates\$serv.pfx"
		try {
			if ($serv -eq $brokerServerName) {
				Write-Log "Installing $serv certificate on Broker"
				Set-RDCertificate -Role RDRedirector -ImportPath $certLocation -ConnectionBroker $brokerServerName -Password $certPassword -Force
				Set-RDCertificate -Role RDPublishing -ImportPath $certLocation -ConnectionBroker $brokerServerName -Password $certPassword -Force
				Write-Log "Setting Broker certificates complete"
			} elseIf ($serv -eq $gatewayServerName) {
				Write-Log "Installing $serv certificate on Gateway server"
				Set-RDCertificate -Role RDGateway -ImportPath $certLocation -ConnectionBroker $brokerServerName -Password $certPassword -Force
				Write-Log "Setting Gateway certificate complete"
			} elseIf ($serv -eq $webAccessServerName) {
				Write-Log "Installing $serv certificate on WebAccess server"
				Set-RDCertificate -Role RDWebAccess -ImportPath $certLocation -ConnectionBroker $brokerServerName -Password $certPassword -Force
				Write-Log "Setting WebAccess certificates complete"
			}
		} catch {
			Write-Log "There was an error setting a certificate. $($Error[0])" -infoType "ERROR"
		}
		
		#Remove exported certificates from C:\Windows\System32
		#Remove-Item -Path "C:\Windows\System32\$serv.pfx" -Force       
	}
	
}

#Install programs and create sessions if a CSV is found
if ($installApps -eq $True) {
	
	#Append '$' to the install disk value
	$installDisk = "$installDisk$"
	
	If (Test-Path "$scriptDir\$csvName") {
		$CSVImport = Import-CSV "$scriptDir\$csvName"
		
		forEach ($line in $CSVImport) {
			$displayName = $line.displayName
			$collectionName = $line.collectionName
			$cmdLine = $line.cmdLine
			$folderName = $line.folderName
			$filePath = $line.filePath
			$iconPath = $line.iconPath
			$iconIndex = $line.iconIndex
			if ($line.installHost) {
				$installHost = $line.installHost.Split(" ")
			}
			$appName = $line.sourceName
			$installCommand = $line.installCommand
			$poshCmd = $line.powerShellCommand
			
			Write-Log " "
			if ($displayName) {
				Write-Log "=====Beginning install and publishing for '$displayName'=====" -writeHostInfo
			} else {
				Write-Log "=====Beginning install of command '$poshCmd'=====" -writeHostInfo
			}
			
			
			#Copy and Install Apps on sessions hosts if required
			if ($installHost) {
				#Copy files that need installed
				forEach ($server in $installHost) {
					$sourceFilePath = "$scriptDir\Software\*"
					$destSourcePath = "\\$server\$installDisk\Sources\"
					if (!(Test-Path $destSourcePath)) {
						New-Item -Path $destSourcePath -ItemType Directory | Out-Null
						Write-Log "New directory created: '$destSourcePath'"
						
						#copy the file to the $destSourcePath
						try {
							Write-Log "Trying copy '$sourceFilePath' to '$destSourcePath'"
							Copy-item $sourceFilePath $destSourcePath -Recurse -Force
							Write-Log "Item '$sourceFilePath' copied to '$destSourcePath'"
						} catch {
							Write-Log "Failed trying to copy item '$sourceFilePath' to '$destSourcePath': $($Error[0])" -infoType "ERROR"
						}
					} else {
						Write-Log "Source folder $destSourcePath already exists on $server. Copy not required. Skipping task..."
					}
					
					#Start Install if install command is provided i.e. there's an install to run
					if ($installCommand) {
						Write-Log "Starting install of $appName on $server..." -writeHostInfo
						Invoke-Command -ComputerName $server -ScriptBlock {
							$a = $args[0]
							$b = $args[1]
							$c = $args[2]
							
							#Modify the destination install path to create a version for deploying locally on a server
							$a = $a.TrimStart("\\")
							$a = $a.Replace("$\", ":\")
							$a = $a.Split("\")
							$searchFolder = $a[1] + "\" + $a[2] + "\"
							
							$fullInstallPath = Get-ChildItem $searchFolder -Recurse -Filter $c | Select-Object FullName -First 1
							$fullInstallPath = $fullInstallPath.FullName
							
							change user /install | Out-Null
							Start-Process -FilePath $fullInstallPath -ArgumentList $b -Wait
							change user /execute | Out-Null
						} -ArgumentList $destSourcePath, $installCommand, $appName
					}
					
					if ($poshCmd) {
						Write-Log "Running PowerShell Command '$poshCmd' on '$server'" -writeHostInfo
						Invoke-Command -ComputerName $server -ScriptBlock {
							$a = $args[0]
							change user /install | Out-Null
							powershell.exe $a | Out-Null
							change user /execute | Out-Null
						} -ArgumentList $poshCmd
						
					}
				}
			}
			
			#Create collection if necessary if an install host value exists (Install host must exist to create a collection)
			if ($installHost -and $displayName) {
				Write-Log "Checking if Session Collection '$collectionName' already exists"
				
				#check if collection already exists
				$isRDCollectionCreated = Get-RDSessionCollection -ConnectionBroker $brokerServerName | Where-Object CollectionName -eq $collectionName
				if (!($isRDCollectionCreated)) {
					
					#add FQDN to each hostname
					$hostArray = @()
					forEach ($RDhost in $InstallHost) {
						$hostArray += $RDhost + "." + $FQDN
					}
					
					try {
						Write-Log "Attempting to install collection '$collectionName'..."
						New-RDSessionCollection –CollectionName $collectionName –SessionHost $hostArray –ConnectionBroker $brokerServerName | Out-Null
						Write-Log "Installation of collection sucsessful. Continuing deployment..."
					} catch {
						Write-Log "Installation of collection failed. Continuing deployment... Error: $($Error[0])" -infoType "ERROR"
					}
				} else {
					Write-Log "Session Collection '$collectionName' already exists, skipping..."
				}
			}
			
			#Set the command line setting
			if ($cmdLine) {
				$cmdLineSetting = "Require"
			} else {
				$cmdLineSetting = "DoNotAllow"
			}
			
			if ($displayName) {
				#Attempt remote app publish
				Write-Log "Attempting publishing of RemoteApp '$displayName' in collection '$collectionName'..."
				try {
					if ($iconPath) {
						New-RDRemoteApp -DisplayName $displayName -FilePath $filePath -ShowInWebAccess 1 -CollectionName $collectionName -CommandLineSetting $cmdLineSetting -FolderName $folderName -RequiredCommandLine $cmdLine -ConnectionBroker $brokerServerName -IconPath $iconPath -iconIndex $iconIndex | Out-Null
					} else {
						New-RDRemoteApp -DisplayName $displayName -FilePath $filePath -ShowInWebAccess 1 -CollectionName $collectionName -CommandLineSetting $cmdLineSetting -FolderName $folderName -RequiredCommandLine $cmdLine -ConnectionBroker $brokerServerName | Out-Null
					}
					Write-Log "Succesfully published RemoteApp '$displayName' in collection '$collectionName' to the Broker '$brokerServerName'"
				} catch {
					Write-Log "There was an error publishing RemoteApp '$displayName' to collection '$collectionName' to Broker '$brokerServerName'. App will not be published! $($Error[0])" -infoType "ERROR"
				}
			}
			
			Write-Log "=====Ending install and publishing for '$displayName'=====" -writeHostInfo
			
			#Null Values
			$displayName = $null
			$collectionName = $null
			$cmdLine = $null
			$folderName = $null
			$filePath = $null
			$broker = $null
			$iconPath = $null
			$iconIndex = $null
			$installHost = $null
			$appName = $null
			$installCommand = $null
			$isRDCollectionCreated = $null
		}
	} else {
		Write-Log "CSV could not be found. No apps will be installed"
	}
	
} else {
	Write-Log "The 'InstallApps' switch was not specified. Apps will not be installed"
}

Write-Log "RDS Farm Deployment Complete using broker $brokerServerName" -writeHostInfo

Validate-RDSDeployment $collectionName
