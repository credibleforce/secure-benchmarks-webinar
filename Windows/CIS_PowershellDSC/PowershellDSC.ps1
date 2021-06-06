# download configuration
iwr -UseBasicParsing https://github.com/NVISOsecurity/posh-dsc-windows-hardening/archive/refs/heads/master.zip -OutFile c:\temp\master.zip
extract-archive c:\temp\master.zip

# install required powershell modules
install-module AuditPolicyDSC
install-module ComputerManagementDsc
install-module SecurityPolicyDsc

# update max envelope size
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048

# compile
.\CIS_WindowsServer2019_v110.ps1

# test
Test-DscConfiguration -Path .\CIS_WindowsServer2019_v110 | ConvertTo-Json

# run
#Start-DscConfiguration -Path .\CIS_WindowsServer2019_v110  -Force -Verbose -Wait