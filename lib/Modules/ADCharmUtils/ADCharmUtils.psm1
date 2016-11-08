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


$COMPUTERNAME = [System.Net.Dns]::GetHostName()


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
    $blobKey = ("djoin-" + $COMPUTERNAME)
    $requiredCtx = @{
        "already-joined-$COMPUTERNAME" = $null
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
    if(($ctx["already-joined-$COMPUTERNAME"] -eq $false) -and !$ctx[$blobKey]) {
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
    return $ctx
}

function Invoke-DJoin {
    Param(
        [Parameter(Mandatory=$true)]
        [String]$DCAddress,
        [Parameter(Mandatory=$true)]
        [String]$DJoinBlob
    )

    Write-JujuWarning "Started join domain"

    $networkName = (Get-MainNetadapter)
    Set-DnsClientServerAddress -InterfaceAlias $networkName -ServerAddresses $DCAddress
    $cmd = @("ipconfig", "/flushdns")
    Invoke-JujuCommand -Command $cmd

    $blobFile = Join-Path $env:TMP "djoin-blob.txt"
    Write-FileFromBase64 -File $blobFile -Content $Params["djoin_blob"]
    $cmd = @("djoin.exe", "/requestODJ", "/loadfile", $blobFile, "/windowspath", $env:SystemRoot, "/localos")
    Invoke-JujuCommand -Command $cmd
    Invoke-JujuReboot -Now
}

function Start-JoinDomain {
    $adCtxt = Get-ActiveDirectoryContext
    if (!$adCtxt.Count) {
        Write-JujuWarning "ad-join relation context is empty"
        return $false
    }

    $fqdn = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain.ToLower()
    if($fqdn -ne $adCtxt["domainName"]){
        Throw ("We appear to be part of the wrong domain. " +
               "Expected: {0}, We are in domain: {1}" -f @($adCtxt["domainName"], $fqdn))
    }

    if (!(Confirm-IsInDomain $adCtxt['domainName'])) {
        if (!$adCtxt["djoin_blob"] -and $adCtxt["already-joined-$COMPUTERNAME"]) {
            Throw "The domain controller reports that a computer with the same hostname as this unit is already added to the domain, and we did not get any domain join information."
        }
        Invoke-DJoin -DCAddress $adCtxt['address'] -DJoinBlob $adCtxt['djoin_blob']
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
    $newName = Convert-JujuUnitNameToNetbios
    $hostnameChanged = Get-CharmState -Namespace "Common" -Key "HostnameChanged"
    $renameReboot = $false

    if ($cfg['change-hostname'] -and !$hostnameChanged -and ($COMPUTERNAME -ne $newName)) {
        Write-JujuWarning ("Changing computername from {0} to {1}" -f @($COMPUTERNAME, $newName))

        Rename-Computer -NewName $newName | Out-Null
        Set-CharmState -Namespace "Common" -Key "HostnameChanged" -Value $true
        $renameReboot = $true
    }

    return $renameReboot
}

function Invoke-CommandAsADUser {
    Param(
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory=$true)]
        [String]$Domain,
        [Parameter(Mandatory=$true)]
        [String]$User,
        [Parameter(Mandatory=$true)]
        [String]$Password
    )

    Grant-Privilege -User $User -Grant "SeServiceLogonRight"

    $domainUser = "{0}\{1}" -f @($Domain, $User)
    $securePass = ConvertTo-SecureString $Password -AsPlainText -Force
    $domainCredential = New-Object System.Management.Automation.PSCredential($domainUser, $securePass)

    $exitCode = Start-ProcessAsUser -Command "$PShome\powershell.exe" -Arguments @("-Command", $ScriptBlock) `
                                    -Credential $domainCredential -LoadUserProfile $false
    if($exitCode) {
        Throw "Failed to execute command as AD user. Exit code: $exitCode"
    }
}
