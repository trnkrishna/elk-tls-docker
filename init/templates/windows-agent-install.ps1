#########################################################
#  Elastic Agent Windows Powershell Install Script
#		by David Walden (Rainiur)
#  This script will download the certificate from the server via scp
#       (This script will register a self-signed cert if you are using a 3rd party signed cert
#       delete --insecure from the elastic-agent install)
#  Install the certificate into the LocalMachine Root
#  Download the agent from elastic.co 
#  And run the install to register it to your Fleet manager
#
#  You will need the following
#		- ssh credentials, filename and IP for the server with your cert 
#			(best to copy the cert to the root directory of the user)
#		- IP address of your Fleet Server
#		- Token for the policy to apply to the system
#
#########################################################

## Import the cert into the Root of the LocalMachine
Import-Certificate -FilePath ca.crt  -CertStoreLocation 'Cert:\LocalMachine\Root' -Verbose

## Verify the cert is installed
Get-ChildItem Cert:\LocalMachine\Root\ | Where-Object { $_.Subject -like '*Elastic*'}

## Download the agent
$filename = "elastic-agent-7.16.1-windows-x86_64.zip"
$ProgressPreference = 'SilentlyContinue'
$url = "https://artifacts.elastic.co/downloads/beats/elastic-agent/" + $filename
Invoke-WebRequest $url -OutFile $filename
$ProgressPreference = 'Continue'

## Unzip the agent
Expand-Archive $filename

## Change into agent directory and install (Don't know why is creates 2 subdirectories to store the files)
Set-Location $filename.Replace(".zip","")
Set-Location $filename.Replace(".zip","")
./elastic-agent install -f --url=https://FLEET_SERVER_IP:8220 --insecure --enrollment-token=ENROLL_TOKEN

## Cleanup
Set-Location ../..
Remove-Item -Recurse -Force $filename.Replace(".zip","")
Remove-Item $filename


