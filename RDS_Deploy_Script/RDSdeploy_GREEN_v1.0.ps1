<#
Script should be ran external to the computers the farm is being deployed on but if not possible can be run from
a Gateway, License or Web Access as these servers are not restarted as part of the deployment process
#>

<#
Author: Michael Sanderson
Version: 1.0
#>

[CmdletBinding()] 
Param( 
    [switch]$installCerts,
    [switch]$installApps,
    [switch]$validateDeployment,
    #[Parameter(Mandatory=$True)]
    $FQDN = "magicmike.com",
    #[Parameter(Mandatory=$True)]
    $sessionHost = @("magicmike02", "magicmike03"),
    #[Parameter(Mandatory=$True)]
    [string]$webAccessServerName = "magicmike04",
    #[Parameter(Mandatory=$True)]
    [string]$brokerServerName = "magicmike01",
    [string]$licenseServerName = "magicmike05",
    [string]$gatewayServerName = "magicmike06",
    [string]$gatewayExternalFQDN = "magicmike06.magicmike.com",
    [string]$csvName = "apps.csv",
    [string]$installDisk = "D",
    [string]$certNameBroker,
    [string]$certNameGateway,
    [string]$certNameWeb,
    [string]$CAName = "MSDC01.MAGICMIKE.LOCAL\MAGICMIKE-MSDC01-CA"
) 

#Write log function
function Write-Log {
	Param (
    [string]$logString,
    [String]$infoType = "INFO",
    [Switch]$writeHostInfo,
    [Switch]$writeHostError,
    [Switch]$writeHostGeneral,
    [Switch]$writeHostYellow
    )
	
	$logDateTime = Get-Date -Format f
	Add-Content $logFile -Value (($logDateTime + ": " + $infoType + " ") + ($logString))
    if ($writeHostInfo) {Write-Host $logString -ForegroundColor Green -BackgroundColor Black}
    ElseIf ($writeHostError) {Write-Host $logString -ForegroundColor Red -BackgroundColor Black}
    ElseIf ($writeHostGeneral) {Write-Host $logString -ForegroundColor White -BackgroundColor Black}
    ElseIf ($writeHostYellow) {Write-Host $logString -ForegroundColor Yellow -BackgroundColor Black}

}

function Validate-RDSDeployment ($collName) {

If (Test-Path "$scriptDir\$csvName") {
    $CSVImport = Import-CSV "$scriptDir\$csvName"

        forEach ($line in $CSVImport) {
            $displayName += @($line.displayName)
            $collectionName += @($line.collectionName)
    }
    }

$displayName = $displayName | Select -Unique
$collectionName = $collectionName | ? {$_} | Select -Unique

Write-Log "S T A R T  V A L I D A T I O N" -writeHostInfo
$errorFound = 0
    $roleType = "RDS-Connection-Broker"
        Write-Log "Checking $roleType role has been installed on $brokerServerName..." -writeHostYellow
            if (Get-WindowsFeature $roleType -ComputerName $brokerServerName | Where-Object {$_.Installed -eq $true}) {
            Write-Log "$roleType role was succesfully installed" -writeHostInfo
            }
            else {
            Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
            $errorFound++
            
        }

    $roleType = "RDS-Licensing"
        Write-Log "Checking $roleType role has been installed on $licenseServerName..." -writeHostYellow
            if (Get-WindowsFeature $roleType -ComputerName $licenseServerName | Where-Object {$_.Installed -eq $true}) {
                Write-Log "$roleType role was succesfully installed" -writeHostInfo
                }
                else {
                Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
                $errorFound++
        }

    $roleType = "RDS-Gateway"
        Write-Log "Checking $roleType role has been installed on $gatewayServerName..." -writeHostYellow
            if (Get-WindowsFeature $roleType -ComputerName $gatewayServerName | Where-Object {$_.Installed -eq $true}) {
                Write-Log "$roleType role was succesfully installed" -writeHostInfo
                }
                else {
                Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
                $errorFound++
            }

    $roleType = "RDS-Web-Access"
        Write-Log "Checking $roleType role has been installed on $webAccessServerName..." -writeHostYellow
            if (Get-WindowsFeature $roleType -ComputerName $webAccessServerName | Where-Object {$_.Installed -eq $true}) {
                Write-Log "$roleType role was succesfully installed" -writeHostInfo
                }
                else {
                Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
                $errorFound++
            }

    forEach ($sessionHost in $sessionHostFQDN) {
        $roleType = "RDS-RD-Server"
        Write-Log "Checking $roleType role has been installed on $sessionHost..." -writeHostYellow
            if (Get-WindowsFeature $roleType -ComputerName $sessionHost | Where-Object {$_.Installed -eq $true}) {
            Write-Log "$roleType role was succesfully installed" -writeHostInfo
            }
            else {
            Write-Log "$roleType role NOT installed" -infoType "ERROR" -writeHostError
            $errorFound++
            }
    }

    Write-Log "Checking collection has been created..." -writeHostYellow
    forEach ($collName in $collectionName){
    if (Get-RDSessionCollection -ConnectionBroker $brokerServerName | Where-Object {$_.CollectionName -eq $collName}) {
        Write-Log "Collection name, '$collName', succesfully found" -writeHostInfo
        }
        else {
        Write-Log "Collection name, '$collName', NOT found" -infoType "ERROR" -writeHostError
        $errorFound++
    }
    }

    forEach ($collName in $collectionName){
    if (Get-RDSessionCollection -ConnectionBroker $brokerServerName | Where-Object {$_.CollectionName -eq $collName}) {
        $appNames = $displayName
        forEach ($app in $appNames) {
            Write-Log "Checking '$app' has been published in collection, '$collName'..." -writeHostYellow
                if (Get-RDRemoteApp -collectionName $collName -connectionBroker $brokerServerName -displayName $app) {
                    Write-Log "The RemoteApp, '$app', is published" -writeHostInfo
                    } 
                    else {
                    Write-Log "The RemoteApp, '$app', could not be found in collection '$collName'. It may be the app is not required for this collection. Check apps.csv for details" -infoType "ERROR" -writeHostError
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

#Append FQDN to each value
$sessionHostFQDN = @()
ForEach ($arrayItem in $sessionHost) {$sessionHostFQDN += "$arrayItem.$FQDN"}

$webAccessServerName = "$webAccessServerName.$FQDN"
$brokerServerName = "$brokerServerName.$FQDN"

if ($licenseServerName) {$licenseServerName = "$licenseServerName.$FQDN"}

$gatewayServerName = "$gatewayServerName.$FQDN"

#The location of where the script is ran from
$scriptDir = $PSScriptRoot

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

if ($installCerts -eq $True) {
$certPassword = Read-Host -AsSecureString "Please enter the password for the RDS Farm certificates"
}


$allServersArray = @($webAccessServerName, $brokerServerName, $licenseServerName, $gatewayServerName)
forEach ($hostFQDN in $sessionHostFQDN) {$allServersArray += $hostFQDN}
$allServersArray = $allServersArray | ? {$_} #Remove any blank entries in the array

#Import module Get-Pending Reboot
."$scriptDir\Get-PendingReboot.ps1"
#."$scriptDir\Request-Certificate.ps1"

#START SCRIPT

#TEST CONNECTIONS TO EACH SERVER
ForEach ($computer in $allServersArray){
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
    if ($isRebootRequired.RebootPending -eq $true){
        Write-Log "Reboot pending on $server... Restarting server" 
            try {
            Restart-Computer -ComputerName $server -Force -Wait -For Wmi -ErrorAction SilentlyContinue
            Write-Log "Reboot complete on $server"
            }
            catch {
            Write-Log "$server could not be restarted but will continue to attempt deployment..." -infoType "WARNING"
            }
        }
        elseIf ($isRebootRequired.RebootPending -eq $false){
                Write-Log "No reboot required on $server" 
                }
                        else {
                            Write-Log "Information on reboots could not be found on $server... Restarting server" 
                                try {
                                Restart-Computer -ComputerName $server -Force -Wait -For Wmi -ErrorAction SilentlyContinue
                                Write-Log "Reboot complete on $server"
                                }
                                catch {
                                Write-Log "Reboot failed on '$server':  $($Error[0])" -infoType "ERROR"
                                }
                    }

}

Write-Log "Starting deployment using broker $brokerServerName" -writeHostInfo

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
} Until (Get-Service -ComputerName $brokerServerName | Where-Object {$_.Status -eq "Running" -and $_.Name -eq "RDMS"})

Write-Log "RDMS Service started on '$brokerServerName'. Continuing deployment..." -writeHostInfo

#Add hosts
if ($sessionHostFQDN.Length -gt 1) {
    forEach ($sesstionHost in $sessionHostFQDN){
        if ($sessionHostFQDN.IndexOf($sesstionHost) -ne 0){
            try {
            Write-Log "Attempting to install '$sesstionHost'..." -writeHostInfo
            Add-RDServer -Server $sesstionHost -Role RDS-RD-SERVER -ConnectionBroker $brokerServerName | Out-Null 
            Write-Log "Installation of host '$sesstionHost' sucsessful. Continuing deployment..."   
            } catch {
            Write-Log "Installation of the host, '$sesstionHost' failed with error: $($Error[0])" -infoType "ERROR"
            }
        }
    }
}

#Add licensing server if FQDN Specified
if ($licenseServerName){
    try {
    Write-Log "Attempting to install '$licenseServerName'..." -writeHostInfo
    Add-RDServer -Server $licenseServerName -Role RDS-LICENSING -ConnectionBroker $brokerServerName | Out-Null
    Write-Log "Installation of license server '$licenseServerName' sucsessful. Continuing deployment..."   
    } catch {
    Write-Log "Installation of license server, '$licenseServerName' failed with error: $($Error[0])" -infoType "ERROR" 
    }


    #Set License Config
    Write-Log "Setting License Server configuration on $licenseServerName" 
    Try {
    Set-RDLicenseConfiguration -LicenseServer $licenseServerName -Mode PerUser -ConnectionBroker $brokerServerName -Force
    Write-Log "Setting License Server configuration on $licenseServerName complete" 
    }
    catch {
    Write-Log "Setting License Server configuration on $licenseServerName failed with error: $($Error[0])" -infoType "ERROR"  
    }
}

#Add Gateway server
try {
Write-Log "Attempting to install '$gatewayServerName'..."   
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


if ($installCerts -eq $true){

$farmServers = @($brokerServerName,$gatewayServerName,$webAccessServerName)

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
                    } 
                    elseIf ($serv -eq $gatewayServerName) {
                    Write-Log "Installing $serv certificate on Gateway server"
                    Set-RDCertificate -Role RDGateway -ImportPath $certLocation -ConnectionBroker $brokerServerName -Password $certPassword -Force
                    Write-Log "Setting Gateway certificate complete"
                    }
                    elseIf ($serv -eq $webAccessServerName) {
                    Write-Log "Installing $serv certificate on WebAccess server"
                    Set-RDCertificate -Role RDWebAccess -ImportPath $certLocation -ConnectionBroker $brokerServerName -Password $certPassword -Force
                    Write-Log "Setting WebAccess certificates complete"
                    }          
                }
                catch {
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
            if ($line.installHost) {$installHost = $line.installHost.Split(" ")}
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
                            } catch{
                                Write-Log "Failed trying to copy item '$sourceFilePath' to '$destSourcePath': $($Error[0])" -infoType "ERROR"
                            }
                            } else {
                                Write-Log "Source folder $destSourcePath already exists on $server. Copy not required. Skipping task..."
                            }

                #Start Install if install command is provided i.e. there's an install to run
		        if ($installCommand){
                    Write-Log "Starting install of $appName on $server..." -writeHostInfo             
                    Invoke-Command -ComputerName $server -ScriptBlock {
                        $a = $args[0]
                        $b = $args[1]
                        $c = $args[2]

                        #Modify the destination install path to create a version for deploying locally on a server
                        $a = $a.TrimStart("\\")
                        $a = $a.Replace("$\",":\")
                        $a = $a.Split("\")
                        $searchFolder = $a[1]+ "\" + $a[2] + "\"
                
                        $fullInstallPath = Get-ChildItem $searchFolder -Recurse -Filter $c | Select-Object FullName -First 1
                        $fullInstallPath = $fullInstallPath.FullName

                        change user /install | Out-Null
                        Start-Process -FilePath $fullInstallPath -ArgumentList $b -Wait
                    } -ArgumentList $destSourcePath, $installCommand, $appName
                }

                if ($poshCmd){
                Write-Log "Running PowerShell Command '$poshCmd' on '$server'" 
                    Invoke-Command -ComputerName $server -ScriptBlock {
                        $a = $args[0]
                        change user /install | Out-Null
                        powershell.exe $a
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
                    forEach ($RDhost in $InstallHost) {$hostArray += $RDhost + "." + $FQDN}

                    try {
                       Write-Log "Attempting to install collection '$collectionName'..."   
                       New-RDSessionCollection –CollectionName $collectionName –SessionHost $hostArray –ConnectionBroker $brokerServerName | Out-Null
                       Write-Log "Installation of collection sucsessful. Continuing deployment..." 
                    } catch {
                       Write-Log "Installation of collection failed. Continuing deployment... Error: $($Error[0])" -infoType "ERROR"
                    }
                }
                else {
                Write-Log "Session Collection '$collectionName' already exists, skipping..."
                }
            }

            #Set the command line setting
            if ($cmdLine) {
            $cmdLineSetting = "Require"
            }
            else {
            $cmdLineSetting = "DoNotAllow"
            }

            if ($displayName) {
                #Attempt remote app publish
                Write-Log "Attempting publishing of RemoteApp '$displayName' in collection '$collectionName'..." 
                try {
                if ($iconPath) {
                New-RDRemoteApp -DisplayName $displayName -FilePath $filePath -ShowInWebAccess 1 -CollectionName $collectionName -CommandLineSetting $cmdLineSetting -FolderName $folderName -RequiredCommandLine $cmdLine -ConnectionBroker $brokerServerName -IconPath $iconPath | Out-Null
                }
                else {
                New-RDRemoteApp -DisplayName $displayName -FilePath $filePath -ShowInWebAccess 1 -CollectionName $collectionName -CommandLineSetting $cmdLineSetting -FolderName $folderName -RequiredCommandLine $cmdLine -ConnectionBroker $brokerServerName | Out-Null
                }
                Write-Log "Succesfully published RemoteApp '$displayName' in collection '$collectionName' to the Broker '$brokerServerName'" 
                }
                catch{
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