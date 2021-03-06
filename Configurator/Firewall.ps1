####################################################################################################################################
##   Firewall management  
####################################################################################################################################



Function Get-FirewallProfile 
{#  .ExternalHelp  Maml-FireWall.XML
 Expand-EnumType FwProfileType (New-object –comObject HNetCfg.FwPolicy2).currentProfileTypes 
}


Function Get-FirewallConfig
{#  .ExternalHelp  Maml-FireWall.XML
   $fw=New-object –comObject HNetCfg.FwPolicy2
   @(1,2,4) | select-Object @{Name=“Network_Type”     ;expression={[FwProfileType]$_}},
                            @{Name=“Firewall_Enabled” ;expression={$fw.FireWallEnabled($_)}},
                            @{Name=“Block_All_Inbound”;expression={$fw.BlockAllInboundTraffic($_)}},
                            @{name=“Default_In”       ;expression={[FwAction]$fw.DefaultInboundAction($_)}},
                            @{Name=“Default_Out”      ;expression={[FwAction]$fw.DefaultOutboundAction($_)}}
}


Function Set-FirewallConfig
{#  .ExternalHelp  Maml-FireWall.XML
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param ([parameter(Mandatory=$true)][FwProfileType]$profile, 
           [Boolean]$Enabled,
           [Boolean]$Block,
           [FwAction]$InBoundAction,
           [FwAction]$OutBoundAction
          )
    $fw=New-object –comObject HNetCfg.FwPolicy2
    If ($enable –ne $null)         {if ($psCmdlet.shouldProcess(($lStr_FirewallProfile -f $Profile)  , ($lstr_FirewallSetEnabled -f $enable) )) {
                                      $fw.firewallEnabled($profile) = $enable}
                                  }
    If ($Block –ne $null)          {if ($psCmdlet.shouldProcess(($lStr_FirewallProfile -f $Profile)  , ($lstr_FirewallSetBlockAllInboud  -f $block))) {
                                      $fw.BlockAllInboundTraffic($profile) = $Block}
                                  }
    If ($InBoundAction –ne $null)  {if ($psCmdlet.shouldProcess(($lStr_FirewallProfile -f $Profile)  , ($lstr_FirewallSetDefaultInbound -f $InboundAction) )) {
                                       $fw.DefaultInboundAction($profile) = $InBoundAction}
                                  }
   If ($OutBoundAction –ne $null) {if ($psCmdlet.shouldProcess(($lStr_FirewallProfile -f $Profile)  , ($lstr_FirewallSetDefaultOutBound  -f $OutboundAction) )) {
                                      $fw.DefaultOutboundAction($profile) = $OutBoundAction}
                                  }
}


Function Get-FireWallRule
{#  .ExternalHelp  Maml-FireWall.XML
    Param ([String]$Name="*", 
           [fwdirection]$Direction,  
           [fwProtocol]$Protocol, 
           [fwProfileType]$profile,  
           [fwAction]$action, 
           $grouping="*", 
           [switch]$Disabled
          )
    (New-Object –comObject HNetCfg.FwPolicy2).rules | Where-Object {
            ($_.Name      -like $name)      -and 
            ($_.Grouping  -like $Grouping)  -and
            ($_.Enabled   -ne   $Disabled)  -and        
           (($_.direction -eq   $direction) -or ($direction -eq $null)) -and            
           (($_.Protocol  -eq   $protocol)  -or ($protocol  -eq $null)) -and
           (($_.Action    -eq   $action  )  -or ($action    -eq $null)) -and
           (($_.Profiles  -bAnd $profile )  -or ($profile   -eq $null))           
   }
}

Function ChgGrp-FireWallRule
{#  .ExternalHelp  Maml-FireWall.XML
    Param ([String]$Name="*", 
           [fwdirection]$Direction,  
           [fwProtocol]$Protocol, 
           [fwProfileType]$profile,  
           [fwAction]$action,
           [parameter(Mandatory=$true)][String]$NewGrp, #@%windir%\system32\inetsrv\iisres.dll,-30505
           $grouping="*",
           [switch]$Disabled
          )
    $fwPolicy = New-Object -ComObject "HNetCfg.FwPolicy2"
    $OldRules = (New-Object –comObject HNetCfg.FwPolicy2).rules | Where-Object {
            ($_.Name      -like $name)      -and 
            ($_.Grouping  -like $Grouping)  -and
            ($_.Enabled   -ne   $Disabled)  -and        
           (($_.direction -eq   $direction) -or ($direction -eq $null)) -and            
           (($_.Protocol  -eq   $protocol)  -or ($protocol  -eq $null)) -and
           (($_.Action    -eq   $action  )  -or ($action    -eq $null)) -and
           (($_.Profiles  -bAnd $profile )  -or ($profile   -eq $null))           
   }
    foreach ($OldRule in $OldRules) {
        $OldRule.Grouping = $NewGrp
#        $OldRule.put_Grouping($NewGrp)
    }
}

Function ChgNm-FireWallRule
{#  .ExternalHelp  Maml-FireWall.XML
    Param ([String]$Name="*", 
           [fwdirection]$Direction,  
           [fwProtocol]$Protocol, 
           [fwProfileType]$profile,  
           [fwAction]$action,
           [parameter(Mandatory=$true)][String]$NewName, #@%windir%\system32\inetsrv\iisres.dll,-30505
           $grouping="*",
           [switch]$Disabled
          )
    $fwPolicy = New-Object -ComObject "HNetCfg.FwPolicy2"
    $OldRules = (New-Object –comObject HNetCfg.FwPolicy2).rules | Where-Object {
            ($_.Name      -like $name)      -and 
            ($_.Grouping  -like $Grouping)  -and
            ($_.Enabled   -ne   $Disabled)  -and        
           (($_.direction -eq   $direction) -or ($direction -eq $null)) -and            
           (($_.Protocol  -eq   $protocol)  -or ($protocol  -eq $null)) -and
           (($_.Action    -eq   $action  )  -or ($action    -eq $null)) -and
           (($_.Profiles  -bAnd $profile )  -or ($profile   -eq $null))           
   }
    foreach ($OldRule in $OldRules) {
        $OldRule.Name = $NewName
#        $OldRule.put_Grouping($NewGrp)
    }
}

Function New-FirewallRule
{
param ([parameter(Mandatory=$true)][String]$name ,
                                   [String]$Description, 
                                   [string]$Grouping,
                                   [String]$application,  
                                   [string]$Service , 
                              [fwDirection]$direction       ="Inbound", 
   [parameter(Mandatory=$true)][fwprotocol]$Protocol,  
                                   [String]$Localports      ="*", 
                                   [String]$remotePorts     ="*", 
                                   [String]$LocalAddresses  ="*"  , 
                                   [String]$remoteAddressess="*" , 
                                 [fwAction]$action          ="Allow" ,
                                      [int]$profiles        =2147483647,  
                                   [switch]$Disabled)

$fwPolicy                = New-Object -ComObject "HNetCfg.FwPolicy2"
$NewRule                 = New-Object -ComObject "HNetCfg.FWRule"
$NewRule.Name            = $Name
$NewRule.Direction       = $direction
$NewRule.Protocol        = $protocol
$NewRule.LocalPorts      = $Localports
$NewRule.RemotePorts     = $RemotePorts
$NewRule.LocalAddresses  = $LocalAddresses
$NewRule.RemoteAddresses = $remoteAddressess 
$NewRule.Action          = $action
$NewRule.Profiles        = $profiles
$NewRule.Enabled         = -not $Disabled


if ($description)  {$NewRule.Description     = $Description}
if ($grouping)     {$NewRule.Grouping        = $Grouping   }
if ($ervice)       {$NewRule.ServiceName     = $Service    }
if ($application)  {$NewRule.Applicationname = $application}

$newrule
$fwPolicy.Rules.Add($NewRule )
}
