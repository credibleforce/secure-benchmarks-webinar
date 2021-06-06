$splunk_server = "splk-sh1"
$splunk_port = "8088"
$splunk_token = "44089d53-fbe1-4881-b3aa-341e525a8bea"
$scan_id= [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
$sourcetype = "powerstig:json"
$computer_name = $env:COMPUTERNAME

# only required if Splunk is using self-signed or untrusted certificate
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
}

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
[ServerCertificateValidationCallback]::Ignore()

function hec_log($logLine){
    $url = "https://${splunk_server}:${splunk_port}/services/collector/event"
    $header = @{Authorization = "Splunk ${splunk_token}"}
    
    # for array we split and send each
    if($logLine -is [array]){
        $logLine | % {
            $event = @{ 
                source = $sourcetype
                sourcetype = $sourcetype
                event = $_ 
            } | ConvertTo-Json -Compress
            $result = Invoke-RestMethod -Method Post -Uri $url -Headers $header -Body $event
        }
    }else{
        $event = @{ 
            source = $sourcetype
            sourcetype = $sourcetype
            event = $logLine 
        } | ConvertTo-Json -Compress
        $event
        $result = Invoke-RestMethod -Method Post -Uri $url -Headers $header -Body $event
    }
}

$result = $(Test-DscConfiguration -ComputerName $computer_name -ReferenceConfiguration "C:\Remediation\localhost.mof")
$total_reviewed = ($result.ResourcesInDesiredState.Count + $result.ResourcesNotInDesiredState.Count)
$score  = [Math]::Round(($result.ResourcesInDesiredState.Count/$total_reviewed)*100)

$result.ResourcesNotInDesiredState | %{
    $_.InstanceName -match '(V-\d+)(\.([a-z]))*'
    $RuleID = ""
    $RuleIdSubset = ""
    $Severity = ""
    if($Matches[1] -ne $null){
        $RuleId = $Matches[1]
    }
    if($Matches[3] -ne $null){
        $RuleIdSubset = $Matches[3]    
    }
    $_.InstanceName -match '\[(low|medium|high)\]'
    if($Matches[1] -ne $null){
        $Severity = $Matches[1]
    }
    $obj = @{
        "ScanID" = $scan_id
        "Score" = $score
        "ComputerName" = $computer_Name
        "Name" = $_.ConfigurationName
        #"InitialState" = $_.InitialState
        #"FinalState" = $_.FinalState
        "InDesiredState" = $_.InDesiredState
        "InstanceName"  = $_.InstanceName
        "VulnNum" = $RuleId
        "VulnNumSubset" = $RuleIdSubset
        "Severity" = $Severity
    }
    hec_log ($obj)
    
}

$result.ResourcesInDesiredState | %{
    $_.InstanceName -match '(V-\d+)(\.([a-z]))*'
    $RuleID = ""
    $RuleIdSubset = ""
    $Severity = ""
    if($Matches[1] -ne $null){
        $RuleId = $Matches[1]
    }
    if($Matches[3] -ne $null){
        $RuleIdSubset = $Matches[3]    
    }
    $_.InstanceName -match '\[(low|medium|high)\]'
    if($Matches[1] -ne $null){
        $Severity = $Matches[1]
    }
    $obj = @{
        "ScanID" = $scan_id
        "Score" = $score
        "ComputerName" = $computer_Name
        "Name" = $_.ConfigurationName
        #"InitialState" = $_.InitialState
        #"FinalState" = $_.FinalState
        "InDesiredState" = $_.InDesiredState
        "InstanceName"  = $_.InstanceName
        "VulnNum" = $RuleId
        "VulnNumSubset" = $RuleIdSubset
        "Severity" = $Severity
    }
    hec_log ($obj)
    
}