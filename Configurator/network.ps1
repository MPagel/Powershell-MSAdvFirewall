####################################################################################################################################
##   Network adapter management  
####################################################################################################################################

Function Get-NetworkAdapter
{#  .ExternalHelp   Maml-Network.XML
    Param ( [String]$Name="%" , [String]$Server=”.”, [switch]$Formatted )
 
    $name=$name.replace(“*”,”%”) 
    $nic=Get-WmiObject –computername $Server -nameSpace Root\cimv2 -Query "Select * from Win32_Networkadapter where name like '$name' " | sort-object –property name
    if ($formatted) {format-table -autosize -wrap -inputObject $nic `
                                 -property  Name,  MACAddress , @{Label=$lstr_Speed ; Expression={if ($_.Speed -eq $null) {$lstr_Disconnected} Else {$_.Speed} }} }
    else            {$nic}
}


Function Select-NetworkAdapter
{#  .ExternalHelp   Maml-Network.XML  
    param ( [string]$Server=".")
   
    Get-wmiobject -ComputerName $Server -Query "Select * from Win32_NetworkAdapterconfiguration where IPEnabled=True" |  
        foreach {Get-WmiObject -ComputerName $_.__SERVER -Query "ASSOCIATORS OF {$_} Where ResultClass=Win32_NetworkAdapter"} | 
            select-list -prop name,macaddress
}


Function Get-IpConfig
{#  .ExternalHelp   Maml-Network.XML  
    Param ( [parameter(ValueFromPipeline=$true)]$nic="%" , 
            $server=“.” ,  $List, $Table,  [Switch]$all
          )
    Process {
       if ($all) {$list="*"} 
       If ($Nic –is [String]) {$Nic=(Get-NetworkAdapter $nic)}
       If ($nic –is [Array] ) {$nic| forEach-Object {get-ipconfig –nic $_ -Server $server -list:$list -Table:$Table} }
       If ($nic –is [System.Management.ManagementObject]){
         $config=Get-wmiObject –computerName $nic.__server -query "associators of {$nic} where AssocClass=Win32_NetworkAdapterSetting” | Where {$_.IPEnabled}
         If ($list)  {If ($list = "ALL")  
                            {format-list -inputobject $config –property Description, ServiceName, MACAddress, IPAddress, DefaultIPGateway , 
                                                                        IPSubnet, DHCPEnabled , DHCPServer,
                                                                        @{Label=”LeaseObtained”; expression={$_.convertToDateTime($_.DHCPLeaseObtained)}},
                                                                        @{Label=”LeaseExpires”; expression={$_.convertToDateTime($_.DHCPLeaseExpires)}}, 
                                                                        DNSHostName , DNSDomain , DNSServerSearchOrder, DNSDomainSuffixSearchOrder , 
                                                                        DNSEnabledForWINSResolution, WINSPrimaryServer, WINSSecondaryServer, 
                                                                        WINSEnableLMHostsLookup, WINSScopeID
                      }     
                      else  {format-list  -inputobject $config -property $list}
                     } 
         Else        {if ($Table)  {format-table -inputobject $config –property $table –autosize  }
                      Else         {$Config}
       }
     }
   }
}


Function Set-IpConfig
{#  .ExternalHelp   Maml-Network.XML  
    [CmdletBinding(SupportsShouldProcess=$True)]
    param ( [parameter(Mandatory=$true, ValueFromPipeline=$true)]$nic , 
            [String[]]$IPAddress,            [String[]]$SubnetMask,         [String[]]$Gateway,
            [String]$WINSPrimaryServer,      [String]$WINSSecondaryServer ,  
            [String[]]$DNSServerSearchOrder, [string]$server="." ,          [Switch]$EnableDHCP
          )
    Process {
        If ($Nic –is [String]) {$Nic=(Get-NetworkAdapter -name $nic -server $server )}
        If ($nic –is [System.Management.ManagementObject]){
            $config=Get-wmiObject –computerName $nic.__server -query "associators of {$nic} where AssocClass=Win32_NetworkAdapterSetting” | Where {$_.IPEnabled} 
            if ($IPaddress -and $SubnetMask) {If ($psCmdlet.shouldProcess($nic.name , "Set IP Address $ipaddress mask $subnetMask")) {
                                                  $result=$config.EnableStatic($IPAddress,$SubnetMask) 
                                                  if ($result.returnValue -eq 0) {Write-verbose  $lstr_Success} else {write-Warning $lStr_IpConfigErrors[[int]$result.returnValue]}
                                             } 
            }
            elseif ($EnableDhcp)             {If ($psCmdlet.shouldProcess($nic.name , $lstr_IpConfigEnableDhcp )) {
                                                  $result=$config.enableDhcp()
                                                  if ($result.returnValue -eq 0) {Write-verbose $lstr_Success} else {write-Warning $lStr_IpConfigErrors[[int]$result.returnValue]}
                                                  $result=$config.SetDNSServerSearchOrder(@())
                                                  $result=$config.SetGateways(@())
                                             }
            }
            if ($Gateway)                    {If ($psCmdlet.shouldProcess($nic.name , ($lstr_IpConfigSetGateway -f $gateway) )) {
                                                  $result=$config.SetGateways($Gateway)
                                                  if ($result.returnValue-eq 0) {Write-verbose $lstr_Success} else {write-Warning $ipconfigErrors[[int]$result.returnValue]}
                                             }
            }
            if ($DNSServerSearchOrder )      {If ($psCmdlet.shouldProcess($nic.name , ($lstr_IpConfigSetDNS -f $DNSServerSearchOrder) )) {
						  $result=$config.SetDNSServerSearchOrder($DNSServerSearchOrder) 
                                                  if ($result.returnValue -eq 0) {Write-verbose $lstr_Success} else {write-Warning $ipconfigErrors[[int]$result.returnValue]}
                                             }
            }
            if ($WINSPrimaryServer)          {If ($psCmdlet.shouldProcess($nic.name , ($lstr_IpConfigSetWINS -f $WinsPrimaryServer, $WinsSecondaryServer) )) {
						  $result=$config.SetWinsServer($WINSPrimaryServer,$WINSSecondaryServer) 
                                                  if ($result.returnValue -eq 0) {Write-verbose $lstr_Success} else {write-Warning $ipconfigErrors[[int]$result.returnValue]}
                                             }
            }
         }
       get-IpConfig $nic -all 
       write-warning $lstr_IpConfigDhcpWarning 
   }
}


Function New-IpConfig 
{#  .ExternalHelp   Maml-Network.XML 
    [CmdletBinding(SupportsShouldProcess=$True)]
    param ([parameter(ValueFromPipeline=$true)] $nic="%" )
    process { 
        If ($Nic –is [String]) {$Nic=(Get-NetworkAdapter $nic)}
        if ($nic -is [array])   {$nic | foreach-object {New-ipconfig -nic $_} }
        If ($nic –is [System.Management.ManagementObject]) {
            $config=Get-wmiObject –computerName $nic.__server -namespace root\cimV2 -query "associators of {$nic} where AssocClass=Win32_NetworkAdapterSetting” | Where {$_.IPEnabled} 
            if ($psCmdlet.shouldProcess($nic.name , $lstr_IpConfigRenewDHCPSuccess )) {
                $result=$Config.RenewDHCPLease()
                if ($result -eq 0) {Write-verbose $lstr_Success} else {write-Warning $ipconfigErrors[$result]}
            }
        }
   }
}


Function Remove-IpConfig 
{#  .ExternalHelp   Maml-Network.XML 
    [CmdletBinding(SupportsShouldProcess=$True)]
    param ([parameter(Mandatory=$true, ValueFromPipeline=$true)] $nic )
    Process {   
        If ($Nic –is [String]) {$Nic=(Get-NetworkAdapter $nic)}
        if ($nic -is [array])   {$nic | foreach-object {Remove-ipconfig -nic $_} }
        If ($nic –is [System.Management.ManagementObject]) {
            $config=Get-wmiObject –computerName $nic.__server -query "associators of {$nic} where AssocClass=Win32_NetworkAdapterSetting” | Where {$_.IPEnabled} 
            if ($psCmdlet.shouldProcess($nic.name , $lstr_IpConfigReleaseDHCPSuccess)) {
               $result=$Config.ReleaseDHCPLease()
               if ($result -eq 0) {Write-verbose $lstr_Success } else {write-Warning $ipconfigErrors[$result]}
            }
       }      
    }
}
