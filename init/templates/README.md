# Checks
Make sure that Elasticstack is accessible
```sh
ping FLEET_SERVER_IP
```

# Linux
Open bash/terminal and execute below commands
```sh
unzip agent-setups.sh
cd agent-setups.sh
sudo bash ./linux-agent-install.sh
```

# Windows
Open powershell as administrator and execute below commands
```sh
Set-ExecutionPolicy Unrestricted CurrentUser
# Unzip agent-setups.zip from Explorer
cd agent-setups
.\windows-agent-install.ps1
```