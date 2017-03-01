# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

Import-Module JujuHelper
Import-Module JujuWindowsUtils
Import-Module JujuUtils
Import-Module JujuHooks
Import-Module JujuLogging


function Confirm-IsInDomain {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$WantedDomain
    )

    $currentDomain = (Get-ManagementObject -Class Win32_ComputerSystem).Domain.ToLower()
    $comparedDomain = ($WantedDomain).ToLower()
    $inDomain = $currentDomain.Equals($comparedDomain)

    return $inDomain
}

function Grant-PrivilegesOnDomainUser {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Username
    )

    $administratorsGroupSID = "S-1-5-32-544"
    Add-UserToLocalGroup -Username $Username -GroupSID $administratorsGroupSID

    Grant-Privilege $Username SeServiceLogonRight
}

function Get-NewCimSession {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$Nodes
    )

    foreach ($node in $nodes) {
        try {
            Write-JujuWarning "Creating new CIM session on node $node"
            $session = New-CimSession -ComputerName $node
            return $session
        } catch {
            Write-JujuWarning "Failed to get CIM session on $node`: $_"
            continue
        }
    }
    Throw "Failed to get a CIM session on any of the provided nodes: $Nodes"
}

function Get-MyADCredentials {
    Param(
        [Parameter(Mandatory=$false)]
        [System.Object]$Credentials,
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )

    if (!$Credentials) {
        return $null
    }
    if(!$Domain) {
        $Domain = "."
    }
    $obj = Get-UnmarshaledObject $Credentials
    $creds = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    foreach($i in $obj.Keys) {
        $usr = $Domain + "\" + $i
        $clearPasswd = $obj[$i]
        if(!$clearPasswd) {
            continue
        }
        $encPasswd = ConvertTo-SecureString -AsPlainText -Force $clearPasswd
        $pscreds = [System.Management.Automation.PSCredential](New-Object System.Management.Automation.PSCredential($usr, $encPasswd))
        $c = @{
            "pscredentials" = $pscreds
            "password" = $clearPasswd
            "username" = $usr
        }
        $creds.Add($c)
    }
    return $creds
}

function Get-ActiveDirectoryContext {
    if($global:JUJU_AD_RELATION_CONTEXT) {
        return $global:JUJU_AD_RELATION_CONTEXT
    }
    $blobKey = ("djoin-" + $env:COMPUTERNAME)
    $requiredCtx = @{
        "already-joined-${env:COMPUTERNAME}" = $null
        "address" = $null
        "username" = $null
        "password" = $null
        "domainName" = $null
        "netbiosname" = $null
    }

    $optionalContext = @{
        $blobKey = $null
        "adcredentials" = $null
    }
    $ctx = Get-JujuRelationContext -Relation "ad-join" -RequiredContext $requiredCtx -OptionalContext $optionalContext

    # Required context not found
    if(!$ctx.Count) {
        return @{}
    }
    # A node may be added to an active directory domain outside of Juju, or it may be added by another charm colocated.
    # If another charm adds the computer to AD, we still get back a djoin_blob, but if we manually add a computer, the
    # djoin blob will be empty. That is the reason we make the djoin blob optional.
    if(($ctx["already-joined-${env:COMPUTERNAME}"] -eq $false) -and !$ctx[$blobKey]) {
        return @{}
    }

    # replace the djoin data key with something less dynamic
    $djoinData = $ctx[$blobKey]
    $ctx.Remove($blobKey)
    [string]$ctx["djoin_blob"] = $djoinData

    # Deserialize credential info
    if($ctx["adcredentials"]) {
        $creds = Get-MyADCredentials -Credentials $ctx["adcredentials"] -Domain $ctx["netbiosname"]
        if($creds) {
            [array]$ctx["adcredentials"] = $creds
        } else {
            $ctx["adcredentials"] = $null
        }
    }
    Set-Variable -Name "JUJU_AD_RELATION_CONTEXT" -Value $ctx -Scope Global -Option ReadOnly
    return $ctx
}

function Invoke-DJoin {
    Param(
        [Parameter(Mandatory=$true)]
        [String]$DCAddress,
        [Parameter(Mandatory=$true)]
        [String]$DJoinBlob,
        [Parameter(Mandatory=$true)]
        [String]$DomainSuffix
    )

    Write-JujuWarning "Started join domain"

    Set-DnsClientServerAddress -InterfaceAlias * -ServerAddresses $DCAddress
    Set-DnsClientGlobalSetting -SuffixSearchList @($DomainSuffix)
    $cmd = @("ipconfig", "/flushdns")
    Invoke-JujuCommand -Command $cmd

    $blobFile = Join-Path $env:TMP "djoin-blob.txt"
    Write-FileFromBase64 -File $blobFile -Content $DJoinBlob
    $cmd = @("djoin.exe", "/requestODJ", "/loadfile", $blobFile, "/windowspath", $env:SystemRoot, "/localos")
    Invoke-JujuCommand -Command $cmd
    Invoke-JujuReboot -Now
}

function Get-DomainJoinPendingReboot {
    $netlogon = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon"
    # Query Netlogon from the registry. These keys are present if there is a
    # pending reboot from a domain join operation.
    if((Test-Path "$netlogon\JoinDomain") -or (Test-Path "$netlogon\AvoidSpnSet")) {
        return $true
    }
    return $false
}

function Start-JoinDomain {
    $pendingReboot = Get-DomainJoinPendingReboot
    if($pendingReboot) {
        Invoke-JujuReboot -Now
    }
    $adCtxt = Get-ActiveDirectoryContext
    if (!$adCtxt.Count) {
        Write-JujuWarning "ad-join relation context is empty"
        return $false
    }
    if (!(Confirm-IsInDomain $adCtxt['domainName'])) {
        if (!$adCtxt["djoin_blob"] -and $adCtxt["already-joined-${env:COMPUTERNAME}"]) {
            Throw "The domain controller reports that a computer with the same hostname as this unit is already added to the domain, and we did not get any domain join information."
        }
        Invoke-DJoin -DCAddress $adCtxt['address'] -DJoinBlob $adCtxt['djoin_blob'] -DomainSuffix $adCtxt['domainName']
    }
    return $true
}

function Rename-JujuUnit {
    <#
    .SYNOPSIS
     Allows Windows instances from the OpenStack provider to have unique hostnames.
     Function returns a boolean to indicate that a reboot is needed in case
     the hostname was changed.
    #>

    $cfg = Get-JujuCharmConfig
    if(!$cfg['change-hostname']) {
        return $false
    }

    $changedHostname = Get-CharmState -Namespace "Common" -Key "ChangedHostname"
    $computerName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName").ComputerName
    if($changedHostname) {
        $activeComputerName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName").ComputerName
        if($computerName -ne $activeComputerName) {
            Write-JujuWarning "Hostname changed but the computer was not yet rebooted"
            return $true
        }
        return $false
    }

    $newName = Convert-JujuUnitNameToNetbios
    if ($newName -ne $computerName) {
        Write-JujuWarning ("Changing computername from {0} to {1}" -f @($computerName, $newName))
        Rename-Computer -NewName $newName | Out-Null
        Set-CharmState -Namespace "Common" -Key "ChangedHostname" -Value $newName
        return $true
    }

    return $false
}

function Invoke-CommandAsDifferentUser {
    Param(
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory=$true)]
        [String]$User,
        [Parameter(Mandatory=$true)]
        [String]$Password,
        [Parameter(Mandatory=$false)]
        [String]$Domain='.',
        [Parameter(Mandatory=$false)]
        [Array]$ArgumentList
    )

    Grant-Privilege -User $User -Grant "SeServiceLogonRight"

    $domainUser = "{0}\{1}" -f @($Domain, $User)
    $securePass = ConvertTo-SecureString $Password -AsPlainText -Force
    $domainCredential = New-Object System.Management.Automation.PSCredential($domainUser, $securePass)

    $processArgs = @("-Command", $ScriptBlock)
    if($ArgumentList) {
        $processArgs += @("-Args", $ArgumentList)
    }
    $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" -Arguments $processArgs `
                                    -Credential $domainCredential -LoadUserProfile $false
    if($exitCode) {
        Throw "Failed to execute command as $User user. Exit code: $exitCode"
    }
}

Export-ModuleMember -Function @(
    'Confirm-IsInDomain',
    'Grant-PrivilegesOnDomainUser',
    'Get-NewCimSession',
    'Get-ActiveDirectoryContext',
    'Rename-JujuUnit',
    'Start-JoinDomain',
    'Invoke-CommandAsDifferentUser'
)
