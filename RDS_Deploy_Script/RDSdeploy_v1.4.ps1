<#
.SYNOPSIS
This PowerShell script is used for the deployment of a Windows Server 2012/16 Remote Desktop Farm. It also includes the ability to install applications on specific hosts if the corresponding apps.csv file is completed

.DESCRIPTION
Complete the associated parameters and apps.csv file to deploy a Remote Desktop Farm. This script will create a broker, sessions hosts, install applications on session hosts, create and configure gateway, add web access and a license server. It will then publish required applications to collections.

Script should be ran external to the computers the farm is being deployed on but if not possible can be run from a Gateway, License or Web Access servers as these servers are not restarted as part of the deployment process

.PARAMETER InstallApps
	Switch to determine if applications should be installed (requires the apps.csv file to be populated)

.PARAMETER InstallCerts
	Swtich to determine if certificates should be installed. Certificates should be named as per their corresponding servers. (E.g. broker01.domain.local.pfx) and placed in the Certificates folder

.PARAMETER FQDN
	The fully qualified domain name of the deployment

.PARAMETER sessionHost
	The hostname of the servers that are to be session hosts within the deployment. Multipe hosts should be seperated by a comma (,).

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
		./REDdeploy_v1.0.ps1 -installApps -FQDN domain.local -sessionHost host011, host012 -webAccessServerName webaccess01 -brokerServerName broker01 -licenseServerName license01 -gatewayServerName gateway01 -gatewayExternalFQDN gateway01.domain.local -csvName apps.csv -installDisk D 
		
		Deploy a RDS farm, install applications but no certificates
.EXAMPLE
		./REDdeploy_v1.0.ps1 -FQDN domain.local -sessionHost host011, host012 -webAccessServerName webaccess01 -brokerServerName broker01 -licenseServerName license01 -gatewayServerName gateway01 -gatewayExternalFQDN gateway01.domain.local

		Deploy a RDS farm only and no applications
.EXAMPLE		
		./REDdeploy_v1.0.ps1 -installApps -installCerts -FQDN domain.local -sessionHost host011, host012 -webAccessServerName webaccess01 -brokerServerName broker01 -licenseServerName license01 -gatewayServerName gateway01 -gatewayExternalFQDN gateway01.domain.local -csvName apps.csv -installDisk D 
	
		Deploy a RDS farm with applications and certificates

.NOTES
Author: Michael Sanderson
Date: 11OCT2017
Updated: 10JAN2017
UpdNote: Added help
UpdNote: Added validation to ensure host values in CSV match those given as parameters before continuing script
UpdNote: Added check that certificates exist before deployment starts
UpdNote: Cleaned up script for some better error checking. Added jobs for the installs on hosts so the script deploys quicker
UpdNote: Added a function that will unblock all files within the RDS Deploy folder due to an issue with windows believing they have been downloaded from the Internet
#>

[CmdletBinding()]
param
(
	[switch]$installCerts,
	[switch]$installApps,
	[string]$FQDN = "magicmike.com",
	[array]$sessionHost = @("magicmikexyz1", "magicmikexyz2"),
	[string]$webAccessServerName = "magicmike4",
	[string]$brokerServerName = "magicmike1",
	[string]$licenseServerName = "magicmike5",
	[string]$gatewayServerName = "magicmike6",
	[string]$gatewayExternalFQDN = "magicmike6.magicmike.com",
	[string]$csvName = "apps.csv",
	[string]$installDisk = "D",
    [string]$certLevel = "Trusted"
)

#Write log function
function Write-Log {
	Param (
		[string]$logString,
		[String]$infoType = "INFO",
		[Switch]$writeHostInfo,
		[Switch]$writeHostError,
		[Switch]$writeHostGeneral,
		[Switch]$writeHostYellow,
		[String]$Colour
	)
	
	$logDateTime = Get-Date -Format f
	Add-Content $logFile -Value (($logDateTime + ": " + $infoType + ": ") + ($logString))
	if ($writeHostInfo) {
		Write-Host $logString -ForegroundColor Cyan -BackgroundColor Black
	} ElseIf ($writeHostError) {
		Write-Host $logString -ForegroundColor Red -BackgroundColor Black
	} ElseIf ($writeHostGeneral) {
		Write-Host $logString -ForegroundColor Green -BackgroundColor Black
	} ElseIf ($writeHostYellow) {
		Write-Host $logString -ForegroundColor Yellow -BackgroundColor Black
	}
	
}

function Show-Prompt($title, $message, $resultYes, $resultNo) {
	$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", $resultYes
	$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", $resultNo
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
	$result = $host.ui.PromptForChoice($title, $message, $options, 1)
	
	switch ($result) {
		0 {
			Write-Log "Yes has been selected"
		}
		1 {
			exit
		}
	}
}

#CHECK DEPLOYMENT BEFORE DEPLOYING. SHOULD PREVENT MOST ERRORS
function Check-Deployment {
	if ($installApps) {
		#IF CSV FILE CAN BE FOUND
		If (Test-Path "$scriptDir\$csvName") {
			$CSVImport = Import-CSV "$scriptDir\$csvName"
			
			#NULL VALUES
			$incorrectHosts = $null
			$compareCSVHosts = $null
			
			forEach ($line in $CSVImport) {
				if ($line.installHost) {
					$installHost = $line.installHost.Split(" ")
					$compareCSVHosts = Compare-Object $sessionHost $installHost
					
					if ($compareCSVHosts.sideIndicator -eq "=>") {
						$incorrectHosts += @($line.displayName)
					}
				}
			}
			
			if ($incorrectHosts) {
				$incorrectHosts = $incorrectHosts -join "`n"
				$errorMessage = @" 
    Mistmatch between hosts in '$($csvName)' for application(s):-
    $incorrectHosts

    Applications cannot be installed on incorrectly named hosts. Continue?

"@
				Show-Prompt "Mistmatch found" $errorMessage "Continue the deployment" "Exit deployment"
			}
		} else {
			Show-Prompt "CSV not found" "The CSV file, '$($csvName)', could not be found but 'installApp' switch specified. Do you wish to continue?" "Continue deployment (No apps will be installed)" "Exit deployment"
		}
	}
	
	
	if ($installCerts) {
		$certsFolderPath = "$scriptDir\Certificates"
		
		if (Test-Path $certsFolderPath) {
			$serversThatNeedCertsArray = @($webAccessServerName, $brokerServerName, $gatewayServerName)
			forEach ($server in $serversThatNeedCertsArray) {
				if (!(Test-Path "$certsFolderPath\$server.pfx")) {
					Show-Prompt "Certificate not found" "The certificate for server, '$server', could not be found. Ensure it is spelt correctly and of the format 'servername.fqdn.pfx' (e.g. server01.domain.local.pfx). Do you wish to continue? Certificates will not be installed!" "Continue deployment (Certificates will not be installed)" "Exit deployment"
				}
			}
			
		} else {
			Show-Prompt "Folder not found" "The folder 'Certificates' could not be found. Do you wish to continue? Certificates will not be installed!" "Continue deployment (Certificates will not be installed)" "Exit deployment"
		}
		
		
	}
}

#VALIDATE THE DEPLOYMENT AT THE END
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
	
	Write-Log "S T A R T  V A L I D A T I O N" -writeHostGeneral
	$errorFound = 0
	$roleType = "RDS-Connection-Broker"
	Write-Log "Checking $roleType role has been installed on $brokerServerName..." -writeHostYellow
	if (Get-WindowsFeature $roleType -ComputerName $brokerServerName | Where-Object {
			$_.Installed -eq $true
		}) {
		Write-Log "$roleType role was succesfully installed" -writeHostGeneral
	} else {
		Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
		$errorFound++
	}

    forEach ($hostFQDN in $sessionHostFQDN) {
	    $roleType = "RDS-RD-Server"
	    Write-Log "Checking $roleType role has been installed on $hostFQDN..." -writeHostYellow
	    if (Get-WindowsFeature $roleType -ComputerName $hostFQDN | Where-Object {
			    $_.Installed -eq $true
		    }) {
		    Write-Log "$roleType role was succesfully installed" -writeHostGeneral
	    } else {
		    Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
		    $errorFound++
	    }
    }
    
	$roleType = "RDS-Licensing"
	Write-Log "Checking $roleType role has been installed on $licenseServerName..." -writeHostYellow
	if (Get-WindowsFeature $roleType -ComputerName $licenseServerName | Where-Object {
			$_.Installed -eq $true
		}) {
		Write-Log "$roleType role was succesfully installed" -writeHostGeneral
	} else {
		Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
		$errorFound++
	}
	
	$roleType = "RDS-Gateway"
	Write-Log "Checking $roleType role has been installed on $gatewayServerName..." -writeHostYellow
	if (Get-WindowsFeature $roleType -ComputerName $gatewayServerName | Where-Object {
			$_.Installed -eq $true
		}) {
		Write-Log "$roleType role was succesfully installed" -writeHostGeneral
	} else {
		Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
		$errorFound++
	}
	
	$roleType = "RDS-Web-Access"
	Write-Log "Checking $roleType role has been installed on $webAccessServerName..." -writeHostYellow
	if (Get-WindowsFeature $roleType -ComputerName $webAccessServerName | Where-Object {
			$_.Installed -eq $true
		}) {
		Write-Log "$roleType role was succesfully installed" -writeHostGeneral
	} else {
		Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
		$errorFound++
	}

#CHECK CERTIFICATES HAVE BEEN INSTALLED
if ($installCerts){
    #BROKER
	    $CertRoleType = "RDRedirector"
	    Write-Log "Checking $CertRoleType certificate has been installed for $brokerServerName..." -writeHostYellow
	    if (Get-RDCertificate -ConnectionBroker $brokerServerName | Where-Object {
			    $_.role -eq $CertRoleType -and $_.IssuedTo.Remove(0, 3) -eq $brokerServerName -and $_.Level -eq $certLevel
		    }) {
		    Write-Log "$CertRoleType cert is installed" -writeHostGeneral
	    } else {
		    Write-Log "Problem with certificate for $CertRoleType" -infoType "ERROR" -writeHostError
		    $errorFound++
	    }

    #BROKER
	    $CertRoleType = "RDPublishing"
	    Write-Log "Checking $CertRoleType certificate has been installed for $brokerServerName..." -writeHostYellow
	    if (Get-RDCertificate -ConnectionBroker $brokerServerName | Where-Object {
			    $_.role -eq $CertRoleType -and $_.IssuedTo.Remove(0, 3) -eq $brokerServerName -and $_.Level -eq $certLevel
		    }) {
		    Write-Log "$CertRoleType cert is installed" -writeHostGeneral
	    } else {
		    Write-Log "Problem with certificate for $CertRoleType" -infoType "ERROR" -writeHostError
		    $errorFound++
	    }

    #WEBACCESS
        $CertRoleType = "RDWebAccess"
	    Write-Log "Checking $CertRoleType certificate has been installed for $webAccessServerName..." -writeHostYellow
	    if (Get-RDCertificate -ConnectionBroker $brokerServerName | Where-Object {
			    $_.role -eq $CertRoleType -and $_.IssuedTo.Remove(0, 3) -eq $webAccessServerName -and $_.Level -eq $certLevel
		    }) {
		    Write-Log "$CertRoleType cert is installed" -writeHostGeneral
	    } else {
		    Write-Log "Problem with certificate for $CertRoleType" -infoType "ERROR" -writeHostError
		    $errorFound++
	    }

    #GATEWAY
        $CertRoleType = "RDGateway"
	    Write-Log "Checking $CertRoleType certificate has been installed for $gatewayServerName..." -writeHostYellow
	    if (Get-RDCertificate -ConnectionBroker $brokerServerName | Where-Object {
			    $_.role -eq $CertRoleType -and $_.IssuedTo.Remove(0, 3) -eq $gatewayServerName -and $_.Level -eq $certLevel
		    }) {
		    Write-Log "$CertRoleType cert is installed" -writeHostGeneral
	    } else {
		    Write-Log "Problem with certificate for $CertRoleType" -infoType "ERROR" -writeHostError
		    $errorFound++
	    }
}
	
#CHECK APPLICATIONS HAVE BEEN PUBLISHED
	forEach ($line in $CSVImport) {
		$app = $line.displayName
		$collName = $line.collectionName
        $validateShouldInstall = $line.shouldInstall
		if ($app -and $validateShouldInstall -eq "Yes") {
			if (Get-RDSessionCollection -ConnectionBroker $brokerServerName | Where-Object {
					$_.CollectionName -eq $collName
				}) {
				Write-Log "Checking '$app' has been published in collection, '$collName'..." -writeHostYellow
				if (Get-RDRemoteApp -collectionName $collName -connectionBroker $brokerServerName -displayName $app) {
					Write-Log "The RemoteApp, '$app', is published" -writeHostGeneral
				} else {
					Write-Log "The RemoteApp, '$app', could not be found in collection '$collName'. It may be the app is not required for this collection. Check apps.csv for details" -infoType "ERROR" -writeHostError
					$errorFound++
				}
			} else {
				Write-Log "Apps will not be checked as the collection, '$collName', does not exist" -infoType "ERROR" -writeHostError
				$errorFound++
			}
		}
	}
	
	#DISPLAY MESSAGE IF ANY ERRORS FOUND
	if ($errorFound -gt 0) {
		Write-Log "There were errors found when validating deployment. Check log for details." -writeHostError
	} else {
		Write-Log "V A L I D A T I O N   S U C C E S S F U L" -writeHostGeneral
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

#IMPORT REQUIRED MODULES
Import-Module RemoteDesktop

#CREATE A LOG FILE
$logFile = "$PSScriptRoot\RDdeploy.log"

#Catch all errors
$ErrorActionPreference = "Stop" #terminate on all errors

#CHECK THE DEPLOYMENT TO ENSURE VALUES MATCH ETC.
Check-Deployment

#BEGIN LOG
Write-Log "====== STARTING SCRIPT 'RDSdeploy.ps1' ======" -writeHostInfo

#UNBLOCK ALL FILES
Write-Log "Unblocking files"
dir $scriptDir -Recurse | Unblock-File

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
		Write-Log "A connection to $computer could not be established. Script will exit. Error: $($Error[0])" -writeHostError -infoType "ERROR"
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

#START RDS FARM DEPLOYMENT
Write-Log "Starting deployment using broker $brokerServerName" -writeHostInfo
try {
	New-RDSessionDeployment –ConnectionBroker $brokerServerName –WebAccessServer $webAccessServerName –SessionHost $sessionHostFQDN[0]
} catch {
	Write-Log $Error[0] -writeHostError -infoType "ERROR"
	Exit
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
				Write-Log "Installation of the session host, '$sesstionHost' failed with error: $($Error[0])" -infoType "ERROR" -writeHostError
                Exit
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
		Write-Log "Installation of license server, '$licenseServerName' failed with error: $($Error[0])" -infoType "ERROR" -writeHostError
        Exit
	}
	
	
	#Set License Config
	Write-Log "Setting License Server configuration on $licenseServerName..." -writeHostInfo
	Try {
		Set-RDLicenseConfiguration -LicenseServer $licenseServerName -Mode PerUser -ConnectionBroker $brokerServerName -Force
		Write-Log "Setting License Server configuration on $licenseServerName complete"
	} catch {
		Write-Log "Setting License Server configuration on $licenseServerName failed with error: $($Error[0])" -infoType "ERROR" -writeHostError
        Exit
	}
}

#Add Gateway server
try {
	Write-Log "Attempting to install gateway server, '$gatewayServerName'..." -writeHostInfo
	Add-RDServer -Server $gatewayServerName -GatewayExternalFqdn $gatewayExternalFQDN -Role RDS-GATEWAY -ConnectionBroker $brokerServerName | Out-Null
	Set-RDDeploymentGatewayConfiguration -GatewayMode Custom -LogonMethod Password -GatewayExternalFqdn $gatewayExternalFQDN -UseCachedCredentials $true -BypassLocal $false -ConnectionBroker $brokerServerName -Force
	Write-Log "Installation of gateway server '$gatewayServerName' sucsessful. Continuing deployment..."
} catch {
	Write-Log "Installation of gateway server '$gatewayServerName' failed with error: $($Error[0])" -infoType "ERROR" -writeHostError
    exit
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
		Write-Log "Setting certificates..." -writeHostInfo
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
			$shouldInstall = $line.shouldINstall
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
			$appName = $line.appName
			$directPath = $line.directPath
			$installCommand = $line.installCommand
			$poshCmd = $line.powerShellCommand
			$userGroups = $line.userGroups
			
			if ($shouldInstall -eq "Yes") {
				if ($displayName) {
					Write-Log "=====Beginning install and publishing for '$displayName'=====" -writeHostInfo
				} elseIf ($poshCmd) {
					Write-Log "=====Beginning install of PowerShell command '$poshCmd'=====" -writeHostInfo
				} elseIf ($appName) {
					Write-Log "=====Beginning install of app '$appName'=====" -writeHostInfo
				} elseIf ($directPath) {
					Write-Log "=====Beginning install of direct command '$directPath'=====" -writeHostInfo
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
						
						#BEGIN INSTALLS
						#FIND THE INSTALL FILE NAME (appName) AND RUN A COMMAND AGAINST IT
						if ($appName) {
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

                                if ($b){
								    Start-Process $fullInstallPath $b -Wait
                                } else {
                                    Start-Process $fullInstallPath -Wait
                                }
								change user /execute | Out-Null
							} -ArgumentList $destSourcePath, $installCommand, $appName -AsJob -JobName $("job_" + $displayname + "_" + $server) | Out-Null
							
							#OR RUN A COMMAND AGAINST A DIRECT PATH WITH ARGUMENTS
						} ElseIf ($directPath) {
							Write-Log "Running '$directPath' on '$server'" -writeHostInfo
							Invoke-Command -ComputerName $server -ScriptBlock {
								$directPath = $args[0]
								$commandToRun = $args[1]
								
								change user /install | Out-Null
								Start-Process $directPath $commandToRun -Wait
								change user /execute | Out-Null
							} -ArgumentList $directPath, $installCommand -AsJob -JobName $("job_" + $directPath + "_" + $server) | Out-Null
							
							#OR MIGHT WANT TO RUN A POWERSHELL COMMAND INSTEAD
						} ElseIf ($poshCmd) {
							Write-Log "Running PowerShell Command '$poshCmd' on '$server'" -writeHostInfo
							Invoke-Command -ComputerName $server -ScriptBlock {
								$a = $args[0]
								change user /install | Out-Null
								PowerShell.exe $a | Out-Null
								change user /execute | Out-Null
							} -ArgumentList $poshCmd -AsJob -JobName $("job_" + $poshCmd + "_" + $server) | Out-Null
							
						}
					}
					#CHECK JOBS HAVE SUCCESFULLY COMPLETED BEFORE MOVING TO NEXT LINE IN THE CSV
					Write-Log "Checking jobs have completed..."
					Get-Job | Wait-Job | Receive-Job -ErrorAction Continue
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
				
				#SET THE COMMAND SETTING 
				if ($cmdLine) {
					$cmdLineSetting = "Require"
				} else {
					$cmdLineSetting = "DoNotAllow"
				}
				
				if ($displayName) {
					#Attempt remote app publish
					Write-Log "Attempting publishing of RemoteApp '$displayName' in collection '$collectionName'..." -writeHostInfo
					try {
						if ($iconPath) {
							New-RDRemoteApp -DisplayName $displayName -FilePath $filePath -ShowInWebAccess 1 -CollectionName $collectionName -CommandLineSetting $cmdLineSetting -FolderName $folderName -RequiredCommandLine $cmdLine -ConnectionBroker $brokerServerName -IconPath $iconPath -iconIndex $iconIndex | Out-Null
						} else {
							New-RDRemoteApp -DisplayName $displayName -FilePath $filePath -ShowInWebAccess 1 -CollectionName $collectionName -CommandLineSetting $cmdLineSetting -FolderName $folderName -RequiredCommandLine $cmdLine -ConnectionBroker $brokerServerName | Out-Null
						}
						Write-Log "Succesfully published RemoteApp '$displayName' in collection '$collectionName' to the Broker '$brokerServerName'" -writeHostInfo
					} catch {
						Write-Log "There was an error publishing RemoteApp '$displayName' to collection '$collectionName' to Broker '$brokerServerName'. App will not be published! $($Error[0])" -infoType "ERROR"
					}
				}
				
				if ($displayName) {
					Write-Log "=====Ending install and publishing for '$displayName'===== `r`n" -writeHostInfo
				} elseIf ($poshCmd) {
					Write-Log "=====Ending install of PowerShell command '$poshCmd'===== `r`n" -writeHostInfo
				} elseIf ($appName) {
					Write-Log "=====Ending install of app '$appName'===== `r`n" -writeHostInfo
				} elseIf ($directPath) {
					Write-Log "=====Ending install of direct command '$directPath'===== `r`n" -writeHostInfo
				}
				
				#NULL VALUES
				$displayName = $NULL
				$collectionName = $NULL
				$cmdLine = $NULL
				$directPath = $NULL
				$folderName = $NULL
				$filePath = $NULL
				$broker = $NULL
				$iconPath = $NULL
				$iconIndex = $NULL
				$installHost = $NULL
				$appName = $NULL
				$installCommand = $NULL
				$isRDCollectionCreated = $NULL
				$poshCmd = $NULL
				
			} else {
				Write-Log "The 'shouldInstall' flag was set to 'No'. App $displayName will not be installed"
			}
			
		}
	} else {
		Write-Log "CSV could not be found. No apps will be installed"
	}
	
} else {
	Write-Log "The 'InstallApps' switch was not specified. Apps will not be installed"
}

Write-Log "RDS Farm Deployment Complete using broker $brokerServerName" -writeHostInfo

Validate-RDSDeployment $collectionName


