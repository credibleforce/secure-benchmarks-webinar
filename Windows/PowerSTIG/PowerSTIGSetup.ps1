Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048
Install-PackageProvider -Name Nuget -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted 
install-module powerstig -scope CurrentUser

(Get-Module PowerStig -ListAvailable).RequiredModules | % {
    $PSItem | Install-Module -Force
}

# fixed list to allow for forced version of windowsdefenderdsc
install-module AuditPolicyDsc -Force
install-module AuditSystemDsc -Force
install-module AccessControlDsc -MaximumVersion 1.4.1 -Force
install-module ComputerManagementDsc -Force
install-module FileContentDsc -Force
install-module GPRegistryPolicyDsc -Force
install-module PSDscResources -Force
install-module SecurityPolicyDsc -Force
install-module SqlServerDsc -Force
install-module WindowsDefenderDsc -MaximumVersion 2.1.0 -Force
install-module xDnsServer -Force
install-module xWebAdministration -Force
install-module CertificateDsc -Force
install-module nx -Force