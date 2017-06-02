# Copyright 2014-2016 Cloudbase Solutions Srl
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
#

Import-Module JujuLogging
Import-Module JujuHooks
Import-Module JujuUtils
Import-Module JujuWindowsUtils

$COMPUTER_NAME = [System.Net.Dns]::GetHostName()
$DJOIN_BLOBS_DIR = Join-Path $env:TEMP "blobs"


function Save-DefaultResolvers {
    <#
    .SYNOPSIS
    This function is really only useful if run as the first thing during install.
    It saves the nameservers set on the default interface to the registry.
    #>

    $nameservers = Get-CharmState -Namespace "AD" -Key "nameservers"
    if($nameservers) {
        return
    }

    $nameservers = Get-PrimaryAdapterDNSServers
    if($nameservers) {
        Set-CharmState -Namespace "AD" -Key "nameservers" -Value $nameservers
    }
}

function Restore-DefaultResolvers {
    $nameservers = Get-CharmState -Namespace "AD" -Key "nameservers"
    if ($nameservers) {
        $netadapter = Get-MainNetadapter
        Set-DnsClientServerAddress -InterfaceAlias $netadapter -ServerAddresses "127.0.0.1"
        Add-DNSForwarders -Forwarders $nameservers
    }
}

function Get-ActiveDirectoryFirewallContext {
    # https://technet.microsoft.com/en-us/library/dd772723(v=ws.10).aspx
    $basePorts = @{
        "TCP" = @(389, 636, 88, 53, 464, 5985, 5986, 3389)
        "UDP" = @(389, 88, 53, 464, 3389)
    }

    $openAllPorts = Get-JujuCharmConfig -Scope "open-all-active-directory-ports"
    if (!$openAllPorts) {
        return $basePorts
    }
    $basePorts["TCP"] += @(3269, 3268, 445, 25, 135, 5722, 9389, 139)
    $basePorts["UDP"] += @(445, 123, 138, 137)
    return $basePorts
}

function Add-DNSForwarders {
    Param(
        [Parameter(Mandatory=$false)]
        [System.Array]$Forwarders
    )

    if(!$Forwarders) {
        Write-JujuWarning "No forwarders to add."
    }

    # Reset DNS server forwarders
    $cmd = @("dnscmd.exe", $COMPUTER_NAME, "/resetforwarders")
    Invoke-JujuCommand -Command $cmd | Out-Null

    Import-Module DnsServer

    foreach($i in $Forwarders) {
        if($i -eq "127.0.0.1") {
            continue
        }
        Add-DnsServerForwarder -ComputerName $COMPUTER_NAME -IPAddress $i
    }
}

function Open-ADDCPorts {
    $firewallContext = Get-ActiveDirectoryFirewallContext
    foreach ($protocol in $firewallContext.Keys) {
        foreach ($port in $firewallContext[$protocol]) {
            Open-JujuPort "$port/$protocol"
            $firewallRules = @(
                @{'name' = "Allow Outbound Port $port/$protocol"
                  'direction' = "Outbound"
                  'port' = $port
                  'protocol' = $protocol
                  'action' = 'Allow'},
                @{'name' = "Allow Inbound Port $port/$protocol"
                  'direction' = "Inbound"
                  'port' = $port
                  'protocol' = $protocol
                  'action' = 'Allow'}
            )
            foreach($rule in $firewallRules) {
                $firewallRule = Get-NetFirewallRule -Name $rule['name'] -ErrorAction SilentlyContinue
                if($firewallRule) {
                    continue
                }
                New-NetFirewallRule -DisplayName $rule['name'] -Name $rule['name'] `
                    -Direction $rule['direction'] -LocalPort $rule['port'] `
                    -Protocol $rule['protocol'] -Action $rule['action'] | Out-Null
            }
        }
    }
}

function Close-ADDCPorts {
    $firewallContext = Get-ActiveDirectoryFirewallContext
    foreach ($protocol in $firewallContext.Keys) {
        foreach ($port in $firewallContext[$protocol]) {
            Close-JujuPort "$port/$protocol"
            $firewallRules = @(
                @{'name' = "Allow Outbound Port $port/$protocol"
                  'direction' = "Outbound"
                  'port' = $port
                  'protocol' = $protocol
                  'action' = 'Allow'},
                @{'name' = "Allow Inbound Port $port/$protocol"
                  'direction' = "Inbound"
                  'port' = $port
                  'protocol' = $protocol
                  'action' = 'Allow'}
            )
            foreach($rule in $firewallRules) {
                $firewallRule = Get-NetFirewallRule -Name $rule['name'] -ErrorAction SilentlyContinue
                if($firewallRule) {
                    Remove-NetFirewallRule -Name $rule['name'] | Out-Null
                }
            }
        }
    }
}

function Get-CharmDomain {
    <#
    .SYNOPSIS
    Returns the fully qualified domain name for this active directory deployment.
    #>
    $cfg = Get-JujuCharmConfig

    if(!$cfg['domain-name']) {
        Throw "Domain name config option cannot be empty"
    }

    return $cfg['domain-name']
}

function Grant-DomainAdminPrivileges {
    <#
    .SYNOPSIS
    Adds an user to all the domain administrator groups, granting him
    super user privileges.
    .PARAMETER User
    Name of the user
    .PARAMETER DomainCredential
    PSCredential object with the domain credentials of a domain administrator.
    This is needed to execute the PowerShell commands as domain user.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$User,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$DomainCredential
    )

    $domainSID = (Get-ADDomain -Credential $DomainCredential -Identity (Get-CharmDomain)).DomainSid.Value

    # "Administrators", "Domain Admin", "Schema admin", "Enterprise admin" group SID
    $sids = @("S-1-5-32-544", "$domainSID-512", "$domainSID-518", "$domainSID-519")
    foreach ($sid in $sids) {
        $domainGroupName = Get-GroupNameFromSID -SID $sid
        $groupMember = Get-ADGroupMember -Identity $domainGroupName | Where-Object { $_.SamAccountName -eq $User }
        if(!$groupMember) {
            Add-ADGroupMember -Members $User -Identity $domainGroupName -Credential $DomainCredential
        }
    }
}

function Get-DomainCredential {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$UserName,
        [Parameter(Mandatory=$true)]
        [System.String]$Password
    )

    $domain = Get-CharmDomain
    $domainUser = "{0}\{1}" -f @($domain, $UserName)
    $securePass = ConvertTo-SecureString $Password -AsPlainText -Force
    $domainCredential = New-Object System.Management.Automation.PSCredential($domainUser, $securePass)

    return $domainCredential
}

function Get-DomainAdminCredentials {
    $charmDomain = Get-CharmDomain
    if ((Confirm-IsInDomain $charmDomain) -eq $false) {
        return $false
    }
    # The function returns the SID of the domain administrator. After the reboot when
    # the AD forest is installed, it takes a while until AD is initialized. The following
    # function will give 404 until AD is ready, thus a retry is needed.
    [array]$adminNames = Start-ExecuteWithRetry -ScriptBlock { Get-AdministratorAccount } `
                                               -MaxRetryCount 30 -RetryInterval 10 `
                                               -RetryMessage "Failed to get Administrator account name. Probably AD is loading after reboot. Retrying..."
    $cfg = Get-JujuCharmConfig
    Add-WindowsUser $adminNames[0] $cfg['administrator-password']

    $domainCreds = Get-DomainCredential -UserName $adminNames[0] -Password $cfg['administrator-password']
    return $domainCreds
}

function Install-ADForest {
    Write-JujuWarning "Installing AD Forest"

    # The function returns the SID of the domain administrator. After the reboot when
    # the AD forest is installed, it takes a while until AD is initialized. The following
    # function will give 404 until AD is ready, thus a retry is needed.
    $adminName = Start-ExecuteWithRetry -ScriptBlock { Get-AdministratorAccount } `
                                        -MaxRetryCount 30 -RetryInterval 10 `
                                        -RetryMessage "Failed to get Administrator account name. Probably AD is loading after reboot. Retrying..."

    $cfg = Get-JujuCharmConfig
    $charmDomain = Get-CharmDomain
    if (Confirm-IsInDomain $charmDomain) {
        Write-JujuWarning ("AD forest is already installed. Adding default domain user {0} to domain admin groups" -f @($cfg['domain-user']))
        $domainCreds = Get-DomainCredential -UserName $adminName -Password $cfg['administrator-password']
        Grant-DomainAdminPrivileges -User $cfg['domain-user'] -DomainCredential $domainCreds
        return
    }

    Write-JujuLog "Setting default administrator password"
    Add-WindowsUser $adminName $cfg['administrator-password']

    Write-JujuWarning ("Creating local admin for default domain user: {0}" -f @($cfg['domain-user']))
    New-LocalAdmin -Username $cfg['domain-user'] -Password $cfg['domain-user-password']

    $safeModeSecurePass = ConvertTo-SecureString -String $cfg['safe-mode-password'] -AsPlainText -Force

    $netbiosName = $charmDomain.Split('.')[0]
    $stat = Install-ADDSForest -DomainName $charmDomain -DomainNetbiosName $netbiosName `
                               -SafeModeAdministratorPassword $safeModeSecurePass `
                               -InstallDns -NoRebootOnCompletion -Confirm:$false -Force
    if($stat.Status -ne "Success") {
        Throw "Failed to install the domain forest"
    }

    if($stat.RebootRequired) {
        Invoke-JujuReboot -Now
    }
}

function New-ADRelationOU {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$OUName,
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ContainerOU
    )

    Write-JujuWarning "Creating relation AD organizational unit: $OUName"

    $ou = Get-ADOrganizationalUnit -Filter {Name -eq $OUName}
    if (!$ou) {
        $parameters = @{
            'Name' = $OUName
            'PassThru' = $true
        }
        if($ContainerOU) {
            $parameters['Path'] = $ContainerOU.DistinguishedName
        }
        return (New-ADOrganizationalUnit @parameters)
    }

    return $ou
}

function New-ADRelationUser {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$UserName,
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ContainerOU
    )

    Write-JujuWarning "Creating relation AD user: $UserName"

    $user = Get-ADUser -Filter {Name -eq $UserName}
    $keyName = ("ad-user-pass-" + $UserName)
    if ($user) {
        $cachedPass = Get-LeaderData -Attribute $keyName
        if(!$cachedPass){
            Throw "Failed to get cached password for AD user $UserName"
        }
        return @($user, $cachedPass)
    }

    $pass = Get-RandomString -Weak
    $parameters = @{
        'SamAccountName' = $UserName
        'Name' = $UserName
        'AccountPassword' = ConvertTo-SecureString -AsPlainText $pass -Force
        'Enabled' = $true
        'PasswordNeverExpires' = $true
        'PassThru' = $true
    }
    if($ContainerOU) {
        $parameters['Path'] = $ContainerOU.DistinguishedName
    }
    $user = New-ADUser @parameters
    Set-LeaderData -Settings @{$keyName = $pass}

    return @($user, $pass)
}

function New-ADRelationGroup {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$GroupName,
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ContainerOU
    )

    $group = Get-ADGroup -Filter {Name -eq $GroupName}
    if($group) {
        return $group
    }

    Write-JujuWarning "Creating relation AD group: $GroupName"

    $parameters = @{
        'Name' = $GroupName
        'GroupScope' = 'Global'
        'GroupCategory' = 'Security'
        'PassThru' = $true
    }
    if($ContainerOU) {
        $parameters['Path'] = $ContainerOU.DistinguishedName
    }

    return (New-ADGroup @parameters)
}

function New-ADRelationUsers {
    Param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]$RelationUsers,
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ContainerOU
    )

    Write-JujuWarning ("AD users to be created: {0}" -f @($RelationUsers.Keys -join ", "))

    $usersCreds = @{}
    foreach($userName in $RelationUsers.Keys) {
        $creds = New-ADRelationUser $userName -ContainerOU $ContainerOU
        $user = $creds[0] # ADUser Object
        $usersCreds[$userName] = $creds[1] # User password

        $groups = $RelationUsers[$userName]
        if(!$groups) {
            continue
        }
        foreach ($group in $groups) {
            $grp = New-ADRelationGroup -GroupName $group -ContainerOU $ContainerOU
            if(!$grp){
                Throw "Failed to create AD group: $group"
            }

            Write-JujuWarning ("Assigning AD user {0} to AD group {1}" -f @($user.Name, $group))
            $groupMember = Get-ADGroupMember -Identity $grp | Where-Object { $_.SamAccountName -eq $user.SamAccountName }
            if(!$groupMember) {
                Add-ADGroupMember -Identity $grp -Members $user
            }
        }
    }

    return $usersCreds
}

function Add-ComputerToADGroup {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$Computer,
        [Parameter(Mandatory=$true)]
        [System.String]$GroupName,
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$GroupContainerOU
    )

    $grp = New-ADRelationGroup -GroupName $GroupName -ContainerOU $GroupContainerOU
    if(!$grp){
        Throw "Failed to create AD group: $GroupName"
    }

    Write-JujuWarning "Adding AD computer $Computer to AD group $GroupName"

    $adComputer = Get-ADComputer -Filter {Name -eq $Computer}
    $groupMember = Get-ADGroupMember -Identity $grp | Where-Object { $_.SamAccountName -eq $adComputer.SamAccountName }
    if(!$groupMember) {
        Add-ADGroupMember -Identity $grp -Members $adComputer
    }
}

function New-DJoinData {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$Computer,
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ContainerOU
    )

    Write-JujuWarning "Creating domain join data for: $Computer"

    $blobName = ("djoin-" + $Computer)
    $blob = Get-LeaderData -Attribute $blobName
    if($blob){
        return $blob
    }

    if(!(Test-Path $DJOIN_BLOBS_DIR)) {
        New-Item -ItemType Directory -Path $DJOIN_BLOBS_DIR | Out-Null
    }

    $blobFile = Join-Path $DJOIN_BLOBS_DIR ($Computer + ".txt")

    if(Test-Path $blobFile) {
        $blob = Convert-FileToBase64 $blobFile
        Set-LeaderData -Settings @{$blobName = $blob}
        return $blob
    }

    $domain = Get-CharmDomain
    $cmd = @("djoin.exe", "/provision", "/domain", $domain, "/machine", $Computer, "/savefile", $blobFile)
    if($ContainerOU) {
        $cmd += @("/machineou", $ContainerOU.DistinguishedName)
    }

    try {
        Invoke-JujuCommand -Command $cmd | Out-Null
        $blob = Convert-FileToBase64 $blobFile
        Set-LeaderData -Settings @{$blobName = $blob}
    } catch {
        Write-JujuWarning ("Failed to create djoin data: {0}" -f $_.Exception.Message)
        Throw $_
    } finally {
        if(Test-Path $blobFile) {
            Remove-Item -Force $blobFile | Out-Null
        }
    }

    return $blob
}

function New-ADRelationServiceAccount {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$Name,
        [Parameter(Mandatory=$true)]
        [System.String[]]$AllowedPrincipals,
        [Parameter(Mandatory=$true)]
        [System.String[]]$Groups,
        [Parameter(Mandatory=$true)]
        [System.String]$Computer
    )

    $service = Get-ADServiceAccount -Filter * | Where-Object { $_.Name -eq $Name }
    if(!$service) {
        $domain = Get-CharmDomain
        New-ADServiceAccount -Name $Name -Enabled $true -DNSHostName "${Name}.${domain}" `
                             -PrincipalsAllowedToRetrieveManagedPassword $AllowedPrincipals
    }
    Add-ADComputerServiceAccount -Identity $Computer -ServiceAccount "${Name}$"
    foreach($group in $Groups) {
        $groupMember = Get-ADGroupMember -Identity $group | Where-Object { $_.SamAccountName -eq "${Name}$" }
        if(!$groupMember) {
            Add-ADGroupMember -Identity $group -Members "${Name}$"
        }
    }
}

function Get-RelationDjoin {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$Computer
    )

    $ret = @{}

    $adComputer = Get-ADComputer -Filter {Name -eq $Computer}
    $djoinKey = ("djoin-" + $Computer)
    if($adComputer) {
        $ret["already-joined-$Computer"] = $true
        $blob = Get-LeaderData -Attribute $djoinKey
        if($blob){
            # Blob was already generated, we sent it again
            $ret[$djoinKey] = $blob
        }
        return $ret
    }

    $ret["already-joined-$Computer"] = $false
    $blob = New-DJoinData -Computer $Computer -ContainerOU $ou
    if(!$blob){
        Throw "Failed to generate domain join information for: $Computer"
    }
    $ret[$djoinKey] = $blob

    return $ret
}

function New-ADRelationServiceAccounts {
    Param(
        [Parameter(Mandatory=$true)]
        [String[]]$ServiceAccounts,
        [Parameter(Mandatory=$true)]
        [String]$Computer
    )

    $kdsScriptBlock = {
        if(!(Get-KdsRootKey)) {
            Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
        }
    }
    $adminName = Get-AdministratorAccount
    $charmDomain = Get-CharmDomain
    Invoke-CommandAsADUser -ScriptBlock $kdsScriptBlock -Domain $charmDomain `
                           -User $adminName -Password $cfg['administrator-password']

    foreach($service in $ServiceAccounts.Keys) {
        $properties = $ServiceAccounts[$service]
        New-ADRelationServiceAccount -Name $service -AllowedPrincipals $properties['allowed-principals'] `
                                     -Groups $properties['groups'] -Computer $Computer
    }
}

function New-ADJoinRelationData {
    <#
    .SYNOPSIS
     This method is meant to be used in relation-changed hook for 'ad-join' relation.
     It returns a HashTable with the relation settings that need to be set.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$RelationId,
        [Parameter(Mandatory=$true)]
        [System.String]$Unit
    )

    $cfg = Get-JujuCharmConfig
    $domainInfo = Get-ADDomain
    $relationSettings = @{
        'address' = Get-JujuUnitPrivateIP
        'hostname' = $COMPUTER_NAME
        'username' = $cfg['domain-user']
        'password' = $cfg['domain-user-password']
        'domainName' = $domainInfo.Forest
        'suffix' = $domainInfo.DistinguishedName
        'netbiosname' = $domainInfo.NetBIOSName
        'ca-certificate-name' = $cfg['ca-common-name']
    }

    $relationData = Get-JujuRelation -RelationId $RelationId -Unit $Unit
    $ou = $null
    if($relationData['ou-name']) {
        $ou = New-ADRelationOU -OUName $relationData['ou-name']
    }

    if($relationData['users']) {
        $adUsers = Get-UnmarshaledObject $relationData['users']
        $creds = New-ADRelationUsers -RelationUsers $adUsers -ContainerOU $ou
        $relationSettings["adcredentials"] = Get-MarshaledObject $creds
    } else {
        # NOTE(ibalutoiu): Use deprecated 'adusers' relation variable
        $adUsersEncoded = Get-JujuRelation -Attribute "adusers" -RelationId $RelationId -Unit $Unit
        if($adUsersEncoded) {
            $adUsers = Get-UnmarshaledObject $adUsersEncoded
            $creds = New-ADRelationUsersDeprecated -RelationUsers $adUsers
            $relationSettings["adcredentials"] = Get-MarshaledObject $creds
        }
    }

    $compName = $relationData['computername']
    if(!$compName) {
        return $relationSettings
    }

    $djoinData = Get-RelationDjoin -Computer $compName
    $relationSettings["already-joined-$compName"] = $djoinData["already-joined-$compName"]
    $djoinKey = "djoin-" + $compName
    if($djoinData[$djoinKey]) {
        $relationSettings[$djoinKey] = $djoinData[$djoinKey]
    }

    if($relationData['computer-group']) {
        Add-ComputerToADGroup -Computer $compName -GroupName $relationData['computer-group'] -GroupContainerOU $ou | Out-Null
    } else {
        # NOTE(ibalutoiu): Use deprecated 'computerGroup' relation variable
        $computerGroupEncoded = Get-JujuRelation -Attribute "computerGroup" -RelationId $RelationId -Unit $Unit
        if ($computerGroupEncoded) {
            $computerGroup = ConvertFrom-Base64 $computerGroupEncoded
            Add-ComputerToADGroupDeprecated -Computer $compName -Group $computerGroup | Out-Null
        }
    }

    if($relationData['service-accounts']) {
        $serviceAccounts = Get-UnmarshaledObject $relationData['service-accounts']
        New-ADRelationServiceAccounts -ServiceAccounts $serviceAccounts -Computer $compName
        $relationSettings['service-accounts'] = Get-MarshaledObject $serviceAccounts.Keys
    }

    return $relationSettings
}

function Get-ActiveDirectoryPeerContext {
    $requiredCtxt = @{
        "forest-installed" = $null
    }
    $ctxt = Get-JujuRelationContext -Relation "ad-peer" -RequiredContext $requiredCtxt
    if(!$ctxt.Count) {
        return @{}
    }
    return $ctxt
}

function Set-DNSToMainDomainController {
    $mainDCAddress = Get-LeaderData -Attribute 'main-domain-controller'
    Set-DnsClientServerAddress -InterfaceAlias (Get-MainNetadapter) -ServerAddresses $mainDCAddress
    Invoke-JujuCommand -Command @("ipconfig", "/flushdns")
}

function Join-Domain {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$Domain,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$LocalCredential,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$DomainCredential
    )

    Set-DNSToMainDomainController

    Write-JujuWarning "Started Domain Join"

    if (Confirm-IsInDomain $Domain) {
        Write-JujuWarning "Domain $Domain is already joined"
        return
    }

    Start-ExecuteWithRetry -ScriptBlock { Add-Computer -LocalCredential $LocalCredential -Credential $DomainCredential -Domain $Domain } `
                           -RetryMessage "Failed to join domain $Domain. Retrying"

    Invoke-JujuReboot -Now
}

function Set-ComputerSPN {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$AccountName,
        [Parameter(Mandatory=$true)]
        [System.String]$Computer
    )

    $output = Invoke-JujuCommand -Command @('setspn.exe', '-Q', $AccountName)

    Write-JujuWarning "setspn query accountname = $AccountName, output = $output"

    for($i=0; $i -lt $output.Count; $i++) {
        if($output[$i].EndsWith($AccountName, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-JujuWarning "Record for $AccountName is found, and skip adding"
            return
        }
    }

    $output = Invoke-JujuCommand -Command @('setspn.exe', '-S', $AccountName, $Computer)

    Write-JujuWarning "setspn accountname = $AccountName, output = $output"
}

function New-DNSRecords {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$ZoneName,
        [Parameter(Mandatory=$true)]
        [System.String]$Name,
        [Parameter(Mandatory=$true)]
        [System.String]$Type,
        [Parameter(Mandatory=$true)]
        [System.Array]$Values
    )


    Write-JujuWarning ("Adding DNS record {0} of type {1} with values {2} in zone {3}" -f
                       @($Name, $Type, ($Values -join ', '), $ZoneName))

    $records = Get-DnsServerResourceRecord -ZoneName $ZoneName | Where-Object {
        $_.HostName -eq $Name -and $_.RecordType -eq $Type
    }

    $registered = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")

    # TODO: Add support for the other types of record as well.
    switch($Type) {
        'A' {
            $addresses = @()
            if($records) {
                $addresses = $records.RecordData.IPv4Address
            }
            $addresses | ForEach-Object { $registered.Add([string]$_) }
            foreach($ip in $Values) {
                if($ip -in $addresses) {
                    continue
                }
                $registered.Add($ip)
                Add-DnsServerResourceRecord -A -Name $Name -ZoneName $ZoneName -IPv4Address $ip | Out-Null
            }
        }
        'AAAA' {
            $ipv6Addresses = @()
            if($records) {
                $ipv6Addresses = $records.RecordData.IPv6Address
            }
            $ipv6Addresses | ForEach-Object { $registered.Add([string]$_) }
            foreach($ip in $Values) {
                if($ip -in $ipv6Addresses) {
                    continue
                }
                $registered.Add($ip)
                Add-DnsServerResourceRecord -AAAA -Name $Name -ZoneName $ZoneName -IPv6Address $ip | Out-Null
            }
        }
        'CNAME' {
            $hostnameAliases = @()
            if($records) {
                $hostnameAliases = $records.RecordData.HostNameAlias
            }
            $aliases = $hostnameAliases | ForEach-Object { $_.Trim('.') }
            $aliases | ForEach-Object { $registered.Add($_) }
            foreach($h in $Values) {
                if($h -in $aliases) {
                    continue
                }
                $registered.Add($h)
                Add-DnsServerResourceRecord -CName -Name $Name -ZoneName $ZoneName -HostNameAlias $h | Out-Null
            }
        }
        default {
            Write-JujuWarning ("Record of type {0} is not supported" -f @($Type))
            continue
        }
    }

    return $registered
}

function Get-IsAnotherCharmCollocated {
    <#
    .SYNOPSIS
    Checks if there is any other charm joined to 'ad-join' relation with the
    same computer name as the current one. If that's the case, then we have a
    collocated charm. This function is useful in the 'ad-join' relation
    departed hook in order to skip removing the AD computer for a remote
    charm, if the same machine is used by another charm joined to AD.
    .PARAMETER CurrentComputerName
    The computer name to check when iterating over 'ad-join' relation ids.
    .PARAMETER CurrentADRelationId
    Used to pass the current relation id when the function is called from
    the context of an 'ad-join' relation hook, in order to skip the current
    relation id.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [String]$CurrentComputerName,
        [Parameter(Mandatory=$false)]
        [String]$CurrentADRelationId
    )

    $rids = Get-JujuRelationIds -Relation 'ad-join'
    foreach($rid in $rids) {
        if ($CurrentADRelationId -and ($rid -eq $CurrentADRelationId)) {
            continue
        }
        $units = Get-JujuRelatedUnits -RelationId $rid
        foreach($unit in $units) {
            $d = Get-JujuRelation -RelationId $rid -Unit $unit
            $unitCompName = $d["computername"]
            if ($CurrentComputerName -eq $unitCompName) {
                return $true
            }
        }
    }

    return $false
}

function Get-IsDomainController {
    $domain = Get-CharmDomain
    if (!(Confirm-IsInDomain $domain)) {
        return $false
    }

    # TODO(ibalutoiu): Create separate functions to get domain administrator account name or local administrator account name.
    #                  Sometimes, function 'Get-AdministratorAccount' may return an array with both the names for local administrator and domain administrator.
    [array]$adminNames = Start-ExecuteWithRetry -ScriptBlock { Get-AdministratorAccount } -MaxRetryCount 30 -RetryInterval 10 `
                                                -RetryMessage "Failed to get Administrator account name. Probably AD is loading after reboot. Retrying..."
    $adminName = $adminNames[0]
    $cfg = Get-JujuCharmConfig
    $domainCreds = Get-DomainCredential -UserName $adminName -Password $cfg['administrator-password']

    $domainControllers = Start-ExecuteWithRetry {
        (Get-ADDomainController -Credential $domainCreds -Filter {Enabled -eq $true}).Name
    } -MaxRetryCount 30 -RetryInterval 10 `
      -RetryMessage "Failed to get AD domain controllers. Probably domain controller rebooted and is not yet initialized. Retrying..."
    if($COMPUTER_NAME -notin $domainControllers) {
        return $false
    }

    return $true
}

function Start-DomainControllerPromotion {
    if(Get-IsDomainController) {
        Write-JujuWarning "$COMPUTER_NAME is already a domain controller"
        return
    }

    $cfg = Get-JujuCharmConfig
    # After the reboot when the AD forest is installed, it takes a while until AD is initialized.
    # The following function will give 404 until AD is ready, thus a retry is needed.
    $adminName = Start-ExecuteWithRetry -ScriptBlock { Get-AdministratorAccount } -MaxRetryCount 30 -RetryInterval 10 `
                                        -RetryMessage "Failed to get Administrator account name. Probably AD is loading after reboot. Retrying..."

    Write-JujuWarning "Setting local administrator password."
    Add-WindowsUser $adminName $cfg['administrator-password']

    $secureLocalPass = ConvertTo-SecureString $cfg['administrator-password'] -AsPlainText -Force
    $localCredential = New-Object PSCredential($adminName, $secureLocalPass)
    $domainCreds = Get-DomainCredential -UserName $adminName -Password $cfg['administrator-password']

    $charmDomain = Get-CharmDomain
    Join-Domain -Domain $charmDomain -LocalCredential $localCredential -DomainCredential $domainCreds

    Write-JujuWarning "Promoting $COMPUTER_NAME to Domain Controller"

    $netbiosName = $charmDomain.Split('.')[0]
    $safeModeSecurePass = ConvertTo-SecureString $cfg['safe-mode-password'] -AsPlainText -Force
    $stat = Start-ExecuteWithRetry {
        $stat = Install-ADDSDomainController -InstallDns -CriticalReplicationOnly:$false `
            -DomainName $netbiosName -SafeModeAdministratorPassword $safeModeSecurePass `
            -NoRebootOnCompletion -Credential $domainCreds -Confirm:$false -Force
        if($stat.Status -ne "Success") {
            Throw "Failed to promote $COMPUTER_NAME to domain controller"
        }
        return $stat
    } -RetryMessage "Failed to add new domain controller. Retrying"

    $domainUser = "{0}\{1}" -f @($netbiosName, $adminName)
    Grant-Privilege -User $domainUser -Grant "SeServiceLogonRight"
    Grant-Privilege -User $domainUser -Grant "SeAssignPrimaryTokenPrivilege"

    # Change all the Juju services to run under AD administrator, otherwise they
    # won't start after reboot.
    $jujuServices = (Get-Service -Name "jujud-*").Name
    Set-ServiceLogon -Services $jujuServices -UserName $domainUser -Password $cfg['administrator-password']

    if($stat.RebootRequired) {
        Invoke-JujuReboot -Now
    }
}

function New-RelationDNSReconds {
    Param(
        [Parameter(Mandatory=$true)]
        [String]$RelationId,
        [Parameter(Mandatory=$true)]
        [String]$Unit
    )

    $registered = @{}
    $dnsRecordsEnc = Get-JujuRelation -Attribute 'dns-records' -RelationId $RelationId -Unit $Unit
    if(!$dnsRecordsEnc) {
        return $registered
    }
    $dnsRecords = Get-UnmarshaledObject $dnsRecordsEnc
    $dnsZones = $dnsRecords.Keys
    if(!$dnsZones) {
        Write-JujuWarning "No DNS zones requested"
        return $registered
    }

    Import-Module DnsServer

    foreach($dnsZone in $dnsZones) {
        $zone = Get-DnsServerZone -ZoneName $dnsZone -ErrorAction SilentlyContinue
        if(!$zone) {
            Add-DnsServerPrimaryZone -ZoneName $dnsZone -ReplicationScope Forest -Confirm:$false
        }
        $records = $dnsRecords[$dnsZone].Keys
        if(!$records) {
            Write-JujuWarning "No DNS records requested in zone $dnsZone"
            continue
        }
        $registered[$dnsZone] = @{}
        foreach($record in $records) {
            $recordTypes = $dnsRecords[$dnsZone][$record].Keys
            if(!$recordTypes) {
                Write-JujuWarning "No DNS records for $record requested in zone $dnsZone"
                continue
            }
            $registered[$dnsZone][$record] = @{}
            foreach($type in $recordTypes) {
                $values = $dnsRecords[$dnsZone][$record][$type]
                if(!$values) {
                    Write-JujuWarning "No DNS records of type $type for $record requested in zone $dnsZone"
                    continue
                }
                $registeredRecords = New-DNSRecords -ZoneName $dnsZone -Name $record -Type $type -Values $values
                if($registeredRecords.Count) {
                    $registered[$dnsZone][$record][$type] = $registeredRecords
                }
            }
        }
    }

    return $registered
}

function Uninstall-ADDC {
    Write-JujuWarning "Destroying AD domain controller $COMPUTER_NAME"

    $cfg = Get-JujuCharmConfig
    $adminName = Get-AdministratorAccount
    $domainCredential = Get-DomainCredential -UserName $adminName -Password $cfg['administrator-password']
    $uninstallSecurePass = ConvertTo-SecureString $cfg['administrator-password'] -AsPlainText -Force

    $parameters = @{
        'Credential' = $domainCredential
        'LocalAdministratorPassword' = $uninstallSecurePass
        'RemoveApplicationPartitions' = $true
        'NoRebootOnCompletion' = $true
        'Confirm' = $false
        'Force' = $true
    }

    $domainControllers = Start-ExecuteWithRetry {
        (Get-ADDomainController -Credential $domainCredential -Filter {Enabled -eq $true}).Name
    } -RetryMessage "Failed to get the domain controllers. Retrying"

    if ($domainControllers.Count -eq 1) {
        $parameters['LastDomainControllerInDomain'] = $true
        $parameters['IgnoreLastDNSServerForZone'] = $true
    } else {
        # Synchronize the current domain controller with all of its replication partners.
        $cmd = @("repadmin.exe", "/syncall")
        Invoke-JujuCommand -Command $cmd | Out-Null
    }

    # Set juju services under LocalSystem user, otherwise they won't start
    # after the reboot.
    $jujuServices = (Get-Service -Name "jujud-*").Name
    Set-ServiceLogon -Services $jujuServices -Username "LocalSystem"

    $stat = Start-ExecuteWithRetry {
        $stat = Uninstall-ADDSDomainController @parameters
        if($stat.Status -ne "Success") {
            Throw "Failed to uninstall domain controller $COMPUTER_NAME"
        }
        return $stat
    } -RetryMessage "Failed to uninstall the AD domain controller $COMPUTER_NAME"

    Close-ADDCPorts

    if($stat.RebootRequired) {
        Invoke-JujuReboot -Now
    }
}

function Remove-UnitFromDomain {
    # Restore default DNS nameservers
    $nameservers = Get-CharmState -Namespace "AD" -Key "nameservers"
    if ($nameservers) {
        $dnsAddresses = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
        foreach($i in $nameservers) {
            if($i -ne "127.0.0.1") {
                $dnsAddresses.Add($i)
            }
        }
        $netadapter = Get-MainNetadapter
        Set-DnsClientServerAddress -InterfaceAlias $netadapter -ServerAddresses $dnsAddresses | Out-Null
        Remove-CharmState -Namespace "AD" -Key "nameservers" | Out-Null
    }

    $cfg = Get-JujuCharmConfig
    $adminName = Get-AdministratorAccount
    $localAdmin = "{0}\{1}" -f @($COMPUTER_NAME, $adminName)
    $adminSecurePass = ConvertTo-SecureString $cfg['administrator-password'] -AsPlainText -Force
    $localCreds = New-Object PSCredential($localAdmin, $adminSecurePass)

    # Join the default WORKGROUP
    Remove-Computer -Credential $localCreds -WorkgroupName "WORKGROUP" -ComputerName $COMPUTER_NAME -Force -Confirm:$false | Out-Null
}

# TODO: Move to another module or create subordiante charm
function Get-ADCertificationAuthority {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$CAName
    )

    $rootStore = "Cert:LocalMachine\Root"
    $existingCAs = Get-ChildItem $rootStore | Where-Object { $_.Subject.StartsWith("CN=${CAName}") }
    if($existingCAs) {
        return $existingCAs
    }
    return $null
}

# TODO: Move to another module or create subordiante charm
function Install-ADCertificationAuthority {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$CAName
    )

    $existingCAs = Get-ADCertificationAuthority -CAName $CAName
    if($existingCAs) {
        Write-JujuWarning "$CAName was already generated"
        return $existingCAs
    }

    Write-JujuWarning "Installing Enterprise root CA: $CAName"

    $adminName = Get-AdministratorAccount
    $cfg = Get-JujuCharmConfig
    $domainCredential = Get-DomainCredential -UserName $adminName -Password $cfg['administrator-password']

    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -Credential $domainCredential -CACommonName $CAName -Confirm:$false -Force | Out-Null

    if($cfg['enable-san-certificates']) {
        Write-JujuWarning "Enabling SAN certificates"
        $cmd = @("certutil.exe", "-setreg", "policy\EditFlags", "+EDITF_ATTRIBUTESUBJECTALTNAME2")
        Invoke-JujuCommand -Command $cmd | Out-Null
    }

    Write-JujuWarning "Restarting the ADCS service"
    Restart-Service "CertSvc" -Force

    return (Get-ADCertificationAuthority -CAName $CAName)
}

# NOTE(ibalutoiu): This function is deprecated and it will be removed in the future.
#                  Backwards comparability is the only reason why it's still here.
function New-ADRelationGroupDeprecated {
    [Obsolete("The function 'New-ADRelationGroupDeprecated' is obsolete. It will be removed in the future. Please use 'New-ADRelationGroup'")]
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$Group
    )

    # Sanitize the group name, in case there are extra " in it
    $Group = $Group.Replace('"', "")

    $ou = $null
    $groupSplit = $Group.Split(",")
    [array]::Reverse($groupSplit)

    foreach ($i in $groupSplit){
        $item = $i.Split("=")
        $adType = $item[0].Replace('"', "")
        $adTypeValue = $item[1].Replace('"', "")
        if ($adType -eq "OU") {
            $ou = New-ADRelationOU -OUName $adTypeValue
        } elseif ($adType -eq "CN") {
            $groupName = $adTypeValue
        }
    }

    if(!$groupName){
        return $false
    }

    Write-JujuInfo "Looking for AD group '$groupName'"
    try {
        return (Get-ADGroup -Identity $groupName)
    } catch {
        Write-JujuWarning "AD Group '$groupName' does not exist."
    }

    Write-JujuInfo "Creating new AD group '$groupName'"

    $containerDn = $domainDN
    if ($ou) {
        $containerDN = $ou
    }

    $group = New-ADGroup -Name $groupName -Path $containerDn `
                         -GroupScope Global -GroupCategory Security -PassThru
    return $group
}

# NOTE(ibalutoiu): This function is deprecated and it will be removed in the future.
#                  Backwards comparability is the only reason why it's still here.
function New-ADRelationUsersDeprecated {
    [Obsolete("The function 'New-ADRelationUsersDeprecated' is obsolete. It will be removed in the future. Please use 'New-ADRelationUsers'")]
    Param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]$RelationUsers
    )

    Write-JujuInfo ("AD users to be created: {0}" -f @($RelationUsers.Keys -join ", "))
    $usersCreds = @{}
    foreach($userName in $RelationUsers.Keys) {
        $creds = New-ADRelationUser $userName
        $user = $creds[0]
        $usersCreds[$userName] = $creds[1] # User password
        $groups = $RelationUsers[$userName]
        if($groups.Length -eq 0) {
            continue
        }
        foreach ($group in $groups) {
            $grp = New-ADRelationGroupDeprecated -Group $group
            if(!$grp){
                Throw "Failed to create AD group '$group'"
            }
            Write-JujuInfo ("Assigning AD user '{0}' to AD group '{1}'" -f @($user.Name, $group))
            $groupMember = Get-ADGroupMember -Identity $grp | Where-Object { $_.SamAccountName -eq $user.SamAccountName }
            if(!$groupMember) {
                Add-ADGroupMember -Identity $grp -Members $user
            }
        }
    }
    return $usersCreds
}

# NOTE(ibalutoiu): This function is deprecated and it will be removed in the future.
#                  Backwards comparability is the only reason why it's still here.
function Add-ComputerToADGroupDeprecated {
    [Obsolete("The function 'Add-ComputerToADGroupDeprecated' is obsolete. It will be removed in the future. Please use 'Add-ComputerToADGroup'")]
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$Computer,
        [Parameter(Mandatory=$true)]
        [System.String]$Group
    )

    $grp = New-ADRelationGroupDeprecated -Group $Group
    if(!$grp){
        Throw "Failed to create AD group '$Group'"
    }
    Write-JujuInfo "Adding AD computer '$Computer' to AD group '$Group'"
    $adComputer = Get-ADComputer -Filter {Name -eq $Computer}
    $groupMember = Get-ADGroupMember -Identity $grp | Where-Object { $_.SamAccountName -eq $adComputer.SamAccountName }
    if(!$groupMember) {
        Add-ADGroupMember -Identity $grp -Members $adComputer
    }
}

function Get-FSMORoles {
    <#
    .SYNOPSIS
    Retrieves the FSMO role holders from one or more Active Directory domains and forests.
    .DESCRIPTION
    Get-FSMORoles uses the Get-ADDomain and Get-ADForest Active Directory cmdlets to determine
    which domain controller currently holds each of the Active Directory FSMO roles.
    .PARAMETER DomainName
    One or more Active Directory domain names.
    .EXAMPLE
    Get-Content domainnames.txt | Get-FSMORoles
    .EXAMPLE
    Get-FSMORoles -DomainName domain1, domain2
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string[]]$DomainName = $env:USERDOMAIN
    )
    BEGIN {
        Import-Module ActiveDirectory -Cmdlet Get-ADDomain, Get-ADForest -ErrorAction SilentlyContinue
    }
    PROCESS {
        $details = Get-CimInstance Win32_ComputerSystem

        if(-not $details.PartOfDomain){
            return
        }

        foreach ($domain in $DomainName) {
            Write-JujuInfo "Querying $domain"
            $addomain = Get-ADDomain -Identity $domain -ErrorAction Stop
            $adforest = Get-ADForest -Identity (($addomain).forest)

            return @{
                InfrastructureMaster = $addomain.InfrastructureMaster
                PDCEmulator = $addomain.PDCEmulator
                RIDMaster = $addomain.RIDMaster
                DomainNamingMaster = $adforest.DomainNamingMaster
                SchemaMaster = $adforest.SchemaMaster
            }
        }
    }
}

function Remove-ADComputerFromADForest {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Computer
    )

    if($Computer -eq ""){
        Write-JujuWarning "You need to specify a name to delete"
        return
    }

    $adminName = Get-AdministratorAccount
    $cfg = Get-JujuCharmConfig
    $domainCredential = Get-DomainCredential -UserName $adminName -Password $cfg['administrator-password']

    $computerObject = Get-ADComputer -Identity $Computer
    if($computerObject) {
        Write-JujuWarning "Removing $Computer from AD domain"
        $computerObject | Remove-ADObject -Recursive -Confirm:$false -Credential $domainCredential -ErrorAction SilentlyContinue | Out-Null
    }

    $ZoneName = Get-CharmDomain
    $DNSResources = $null
    $DNSResources = Get-DnsServerResourceRecord -ZoneName $ZoneName -Node $Computer -ErrorAction SilentlyContinue
    if($DNSResources -ne $null){
        $DNSResources | ForEach-Object { Remove-DnsServerResourceRecord -ZoneName $ZoneName -InputObject $_ -Force -ErrorAction Stop }
    }
}

function Start-TransferFSMORoles {
    $leaderCheck = Confirm-Leader
    if(-not $leaderCheck){
        Write-JujuWarning "Unit is not leader. Skipping the rest of the hook"
        return
    }

    $currentMachineName = [System.Net.Dns]::GetHostName()
    $cfg = Get-JujuCharmConfig
    Write-JujuWarning 'Transferring FSMO roles to leader'
    Move-ADDirectoryServerOperationMasterRole -Identity $currentMachineName -OperationMasterRole 0,1,2,3,4 -Force -Confirm:$false -ErrorAction Stop
    Write-JujuWarning 'FSMO roles transferred'
}

function Set-ConstraintsDelegation {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$TrustedComputer,
        [Parameter(Mandatory=$true)]
        [string]$TrustingComputer,
        [Parameter(Mandatory=$true)]
        [string]$ServiceType,
        [ValidateSet("Add", "Replace", "Remove")]
        [string]$Action
    )

    $params = @{
        $Action = @{
            "msDS-AllowedToDelegateTo" = @("$ServiceType/$TrustingComputer","$ServiceType/$TrustingComputer.$env:UserDnsDomain")
        }
    }
    Get-ADComputer $TrustedComputer | Set-ADObject @params
}

function Set-UnitsConstraintsDelegations {
    Param(
        [Parameter(Mandatory=$true)]
        [String]$RelationId,
        [Parameter(Mandatory=$true)]
        [String[]]$Units
    )

    $marshaledConstraints = $null
    $unitsComputerNames = @{}
    foreach($unit in $Units) {
        $data = Get-JujuRelation -RelationId $RelationId -Unit $unit
        $marshaledConstraints = $data["constraints"]
        $compName = $data["computername"]
        if($compName) {
            $unitsComputerNames[$unit] = $compName
        }
    }
    if(!$marshaledConstraints) {
        Write-JujuWarning "Remote charm didn't set any constraints delegations to be set by AD"
        return
    }
    if(!$unitsComputerNames.Count) {
        Write-JujuWarning "No computers names set for the relation: $RelationId"
        return
    }
    $constraints = Get-UnmarshaledObject $marshaledConstraints
    $leaderData = Get-LeaderData
    $unitsWithConstraints = @{}
    $unitsToSetConstraints = @{}
    foreach($unit in $Units) {
        $compName = $leaderData["constraints-${RelationId}-${unit}"]
        if($compName) {
            $unitsWithConstraints[$unit] = $compName
            continue
        }
        if($unitsComputerNames[$unit]) {
            $unitsToSetConstraints[$unit] = $unitsComputerNames[$unit]
        }
    }
    try {
        $leaderSettings = @{}
        foreach($unit in $unitsToSetConstraints.Keys) {
            $compName = $unitsToSetConstraints[$unit]
            [array]$computerNamesWithConstraints = $unitsWithConstraints.Values
            $msg = "Setting constraints delegations {0} between computer {1} and computers {1}" -f @(($constraints -join ', '),
                                                                                                     $compName,
                                                                                                     ($computerNamesWithConstraints -join ', '))
            Write-JujuWarning $msg
            foreach($c in $computerNamesWithConstraints) {
                foreach($constraint in $constraints) {
                    Set-ConstraintsDelegation -TrustedComputer $c -TrustingComputer $compName -ServiceType $constraint -Action "Add"
                    Set-ConstraintsDelegation -TrustedComputer $compName -TrustingComputer $c -ServiceType $constraint -Action "Add"
                }
            }
            $unitsWithConstraints[$unit] = $compName
            $leaderSettings["constraints-${RelationId}-${unit}"] = $compName
        }
    } finally {
        if($leaderSettings.Count) {
            Set-LeaderData -Settings $leaderSettings
        }
    }
}

function Clear-ComputerConstraintsDelegations {
    Param(
        [Parameter(Mandatory=$true)]
        [String]$RelationId,
        [Parameter(Mandatory=$true)]
        [string]$RemoteUnit,
        [Parameter(Mandatory=$true)]
        [string]$CompName,
        [Parameter(Mandatory=$true)]
        [string[]]$Constraints
    )

    $leaderData = Get-LeaderData
    $unitsWithConstraints = @{}
    $units = Get-JujuRelatedUnits -RelationId $RelationId
    foreach($unit in $units) {
        $name = $leaderData["constraints-${RelationId}-${unit}"]
        if($name) {
            $unitsWithConstraints[$unit] = $name
        }
    }
    [array]$computerNamesWithConstraints = $unitsWithConstraints.Values
    foreach($c in $computerNamesWithConstraints) {
        foreach($constraint in $Constraints) {
            Set-ConstraintsDelegation -TrustedComputer $CompName -TrustingComputer $c -ServiceType $constraint -Action "Remove"
            Set-ConstraintsDelegation -TrustedComputer $c -TrustingComputer $CompName -ServiceType $constraint -Action "Remove"
        }
    }
    Set-LeaderData -Settings @{"constraints-${RelationId}-${RemoteUnit}" = $null}
}


# HOOKS METHODS

function Invoke-InstallHook {
    Write-JujuWarning "Running install hook"

    $isLeader = Confirm-Leader
    $mainDCIP = Get-LeaderData -Attribute 'main-domain-controller'
    if(!$mainDCIP -and $isLeader) {
        Set-LeaderData -Settings @{
            'main-domain-controller' = Get-JujuUnitPrivateIP
        }
    }

    try {
        Set-MpPreference -DisableRealtimeMonitoring $true
    } catch {
        # No need to error out the hook if this fails.
        Write-JujuWarning "Failed to disable monitoring."
    }

    # Set machine to use high performance settings.
    try {
        Set-PowerProfile -PowerProfile Performance
    } catch {
        # No need to error out the hook if this fails.
        Write-JujuWarning "Failed to set performance power scheme."
    }

    Start-TimeResync
    Save-DefaultResolvers

    $renameReboot = Rename-JujuUnit
    if($renameReboot) {
        Invoke-JujuReboot -Now
    }

    Write-JujuWarning "Installing Windows Features"
    Install-WindowsFeatures -Features @(
        'AD-Domain-Services', 'RSAT-AD-Tools', 'RSAT-AD-Powershell',
        'RSAT-ADDS', 'RSAT-ADDS-Tools', 'RSAT-AD-AdminCenter',
        'DNS', 'RSAT-DNS-Server', 'GPMC'
    )

    $mainDCIP = Get-LeaderData -Attribute 'main-domain-controller'
    $privateIP = Get-JujuUnitPrivateIP
    if($mainDCIP -ne $privateIP) {
        Write-JujuWarning "Current unit is not the main domain controller unit"
        return
    }

    Install-ADForest
    Restore-DefaultResolvers
    Open-ADDCPorts

    Set-JujuStatus -Status "active" -Message "Unit is ready"
}

function Invoke-LeaderElectedHook {
    $domain = Get-CharmDomain
    if (!(Confirm-IsInDomain $domain)) {
        Write-JujuWarning "AD forest is not yet installed. Skipping the rest of the hook"
        return
    }

    $isLeader = Confirm-Leader
    $isDomainController = Get-IsDomainController
    if($isLeader -and $isDomainController) {
        Set-LeaderData -Settings @{
            'main-domain-controller' = Get-JujuUnitPrivateIP
        }
        $relationSettings = @{
            "forest-installed" = $true
        }
        $rids = Get-JujuRelationIds -Relation 'ad-peer'
        foreach($rid in $rids) {
            Set-JujuRelation -RelationId $rid -Settings $relationSettings
        }
    }
}

function Invoke-StopHook {
    $domain = Get-CharmDomain
    if (!(Confirm-IsInDomain $domain)) {
        Write-JujuWarning "This machine is not part of the domain"
        return
    }

    Set-DNSToMainDomainController

    if(Get-IsDomainController) {
        Uninstall-ADDC
    }

    $isCollocatedCharm = Get-IsAnotherCharmCollocated -CurrentComputerName $COMPUTER_NAME
    if($isCollocatedCharm) {
        Write-JujuWarning "Machine still needs to be joined to AD"
        return
    }

    # TODO(ibalutoiu): This must be done by other peer units in order to have
    #                  the computer deleted from AD even when the current
    #                  unit is brutally killed.
    $computerObject = Get-ADComputer -Filter {Name -eq $COMPUTER_NAME}
    if($computerObject) {
        # TODO(ibalutoiu): Create separate functions to get domain administrator account name or local administrator account name.
        #                  Sometimes, function 'Get-AdministratorAccount' may return an array with both the names for local administrator and domain administrator.
        [array]$adminNames = Get-AdministratorAccount
        $adminName = $adminNames[0]
        $cfg = Get-JujuCharmConfig
        $domainCredential = Get-DomainCredential -UserName $adminName -Password $cfg['administrator-password']

        Write-JujuWarning "Removing $COMPUTER_NAME from AD domain"
        Remove-ADObject -Identity $computerObject -Recursive -Confirm:$false -Credential $domainCredential | Out-Null
    }

    Remove-UnitFromDomain
}

function Invoke-ADJoinRelationChangedHook {
    $domain = Get-CharmDomain
    if (!(Confirm-IsInDomain $domain)) {
        Write-JujuWarning "AD forest is not yet installed. Skipping the rest of the hook"
        return
    }

    if (!(Confirm-Leader)) {
        Write-JujuWarning "Unit is not leader. Skipping the rest of the hook"
        return
    }

    $rids = Get-JujuRelationIds -Relation 'ad-join'
    foreach($rid in $rids) {
        [array]$units = Get-JujuRelatedUnits -RelationId $rid
        if(!$units.Count) {
            continue
        }
        foreach($unit in $units) {
            $relationSettings = New-ADJoinRelationData -RelationId $rid -Unit $unit
            Set-JujuRelation -RelationId $rid -Settings $relationSettings
        }
        Set-UnitsConstraintsDelegations -RelationId $rid -Units $units
    }
}

function Invoke-ADJoinRelationDepartedHook {
    $domain = Get-CharmDomain
    if (!(Confirm-IsInDomain $domain)) {
        Write-JujuWarning "AD forest is not yet installed. Skipping the rest of the hook"
        return
    }
    if (!(Confirm-Leader)) {
        Write-JujuWarning "Unit is not leader. Skipping the rest of the hook"
        return
    }
    $relationData = Get-JujuRelation
    $compName = $relationData['computername']
    if (!$compName) {
        Write-JujuWarning "Remote unit didn't set computername"
        return
    }
    # Remove computer from the AD domain
    $blobName = ("djoin-" + $compName)
    $blob = Get-LeaderData -Attribute $blobName
    if(!$blob) {
        return
    }
    # Check if there is another collocated charm joined to the AD domain. If
    # so, we don't need to remove the machine from AD.
    $currentRelationId = Get-JujuRelationId
    $isCollocatedCharm = Get-IsAnotherCharmCollocated -CurrentADRelationId $currentRelationId `
                                                      -CurrentComputerName $compName
    if($isCollocatedCharm) {
        Write-JujuWarning "Computer $CurrentComputerName needs to be joined to AD"
        return
    }
    if($relationData['service-accounts']) {
        $serviceAccounts = Get-UnmarshaledObject $relationData['service-accounts']
        foreach($service in $serviceAccounts.Keys) {
            $svcAccount = Get-ADServiceAccount -Filter * | Where-Object { $_.Name -eq $service }
            if($svcAccount) {
                Remove-ADServiceAccount -Identity "${service}$" -Confirm:$false
            }
        }
    }
    $computerObject = Get-ADComputer -Filter {Name -eq $compName}
    if($computerObject) {
        $marshaledConstraints = Get-JujuRelation -Attribute "constraints"
        if($marshaledConstraints) {
            $remoteUnit = Get-JujuRemoteUnit
            $constraints = Get-UnmarshaledObject $marshaledConstraints
            Clear-ComputerConstraintsDelegations -RelationId $currentRelationId -RemoteUnit $remoteUnit `
                                                 -CompName $compName -Constraints $constraints
        }
        Write-JujuWarning "Removing $compName form AD domain"
        $computerObject | Remove-ADObject -Recursive -Confirm:$false
    }
    Set-LeaderData -Settings @{$blobName = $null}
    $blobFile = Join-Path $DJOIN_BLOBS_DIR ($compName + ".txt")
    if(Test-Path $blobFile) {
        Remove-Item -Force $blobFile
    }
}

function Invoke-ADPeerRelationChangedHook {
    Write-JujuWarning "Running ad-peer relation changed hook"

    $mainDCAddress = Get-LeaderData -Attribute 'main-domain-controller'
    $privateIP = Get-JujuUnitPrivateIP
    if($mainDCAddress -eq $privateIP) {
        $rids = Get-JujuRelationIds -Relation 'ad-peer'
        foreach($rid in $rids) {
            Set-JujuRelation -RelationId $rid -Settings @{
                "forest-installed" = $true
            }
        }
        return
    }

    $peerCtxt = Get-ActiveDirectoryPeerContext
    if (!$peerCtxt['forest-installed']) {
        Write-JujuWarning "AD forest was not yet initialized"
        return
    }

    Start-DomainControllerPromotion
    Restore-DefaultResolvers
    Open-ADDCPorts

    Set-JujuStatus -Status "active" -Message "Unit is ready"
}

function Invoke-ADDNSRelationChangedHook {
    $domain = Get-CharmDomain
    if (!(Confirm-IsInDomain $domain)) {
        Write-JujuWarning "AD forest is not yet installed. Skipping the rest of the hook"
        return
    }

    if (!(Confirm-Leader)) {
        Write-JujuWarning "Unit is not leader. Skipping the rest of the hook"
        return
    }

    $domainInfo = Get-ADDomain
    $relationSettings = @{
        'address' = Get-JujuUnitPrivateIP
        'dns-root' = $domainInfo.DNSRoot
    }

    $rids = Get-JujuRelationIds -Relation 'ad-dns'
    foreach($rid in $rids) {
        $units = Get-JujuRelatedUnits -RelationId $rid
        foreach($unit in $units) {
            $registeredRecords = New-RelationDNSReconds -RelationId $rid -Unit $unit
            if(!$registeredRecords.Count) {
                continue
            }
            $relationSettings['registered-records'] = Get-MarshaledObject $registeredRecords
            Set-JujuRelation -RelationId $rid -Settings $relationSettings
        }
    }
}

function Invoke-ADSPNRelationChangedHook {
    $domain = Get-CharmDomain
    if (!(Confirm-IsInDomain $domain)) {
        Write-JujuWarning "AD forest is not yet installed. Skipping the rest of the hook"
        return
    }

    if (!(Confirm-Leader)) {
        Write-JujuWarning "Unit is not leader. Skipping the rest of the hook"
        return
    }

    $rids = Get-JujuRelationIds -Relation 'ad-spn'
    foreach($rid in $rids) {
        $units = Get-JujuRelatedUnits -RelationId $rid
        foreach($unit in $units) {
            $relationData = Get-JujuRelation
            $compName = $relationData['computername']
            if(!$relationData['services'] -or !$compName) {
                Write-JujuWarning "Relation variables are not set"
                continue
            }
            $services = Get-UnmarshaledObject $relationData['services']
            foreach($svc in $services) {
                Set-ComputerSPN -AccountName $svc -Computer $compName
            }
        }
    }
}

function Invoke-UpdateStatusHook {
    $leaderCheck = Confirm-Leader
    if(-not $leaderCheck){
        Write-JujuWarning "Unit is not leader. Skipping the rest of the hook"
        return
    }
    $domainCreds = Get-DomainAdminCredentials
    $rids = Get-JujuRelationIds -Relation 'ad-peer'

    $computerNames = @(
        $COMPUTER_NAME)
    foreach($rid in $rids) {
        $units = Get-JujuRelatedUnits -RelationId $rid
        foreach($unit in $units) {
            $computerAddress = Get-JujuRelation -RelationId $rid -Unit $unit -Attribute 'private-address'
            $computer = [System.Net.Dns]::GetHostByAddress([string]$computerAddress).HostName
            if($computer -and ($computer -notIn $computerNames)) {
                $computerNames += $computer
            }
        }
    }

    [array]$ADDomainControllers = Start-ExecuteWithRetry { Get-ADDomainController -Credential $domainCreds } -MaxRetryCount 30 -RetryInterval 10 `
                                        -RetryMessage "Failed to get AD domain controllers. Probably domain controller is not yet initialized. Retrying..."
    [array]$FSMOComputers = (Get-FSMORoles).Values
    $ADDomain = Get-CharmDomain
    $FSMOTransferNeeded = $false
    $ComputersToRemove = @()

    foreach ($ADComputer in $ADDomainControllers){
        $FQDNComputer = "{0}.{1}" -f @($ADComputer, $ADDomain)
        if($ADComputer -notIn $computerNames){
            $ComputersToRemove += $ADComputer
            Write-JujuWarning "Machine $ADComputer is not in the cluster anymore. Queuing for removal..."
            if ($FQDNComputer -in $FSMOComputers){
                $FSMOTransferNeeded = $true
            }
        }
    }

    if($FSMOTransferNeeded){
        Start-TransferFSMORoles
    }

    foreach($computer in $ComputersToRemove){
        Remove-ADComputerFromADForest -Computer $computer
    }
}
