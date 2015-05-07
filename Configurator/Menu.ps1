
####################################################################################################################################
##   system Configuration menu  
####################################################################################################################################

Function Show-menu
{ if ((get-command tzutil.exe -ErrorAction silentlyContinue) -ne $null) {
  $global:OldWindowTitle        = $Host.UI.RawUI.WindowTitle 
  $Global:Tz                    = "( $(tzutil.exe /g) )"}
  $Global:wuConfig              = Get-WindowsUpdateConfig

  $Global:RemoteDesktop         = Get-RemoteDesktopConfig
  $Global:WinRmConfig           = Get-WinRmConfig
  $Global:FailOverClusterConfig = $(if (Get-module -Name FailoverClusters -listavailable) {"Enabled"} else {"Disabled"} )
  $Global:PageFile              = get-pageFile
  $Global:ComputerName          = (Get-WmiObject win32_computerSystem).Caption
  $Global:Domain                = (Get-WmiObject win32_computerSystem).domain
  $Global:Domain                = if ((Get-WmiObject win32_computerSystem).partofdomain) {"Domain: $Domain"} else {"Workgroup: $domain"}
  $Global:localAdminsGroupGroup = get-wmiObject -query "Select * From Win32_Group Where domain='$computerName' and SID = 'S-1-5-32-544'"
  get-wmiobject -query "Associators of  {$Global:localAdminsGroupGroup} where assocclass=Win32_GroupUser"  |
                 ForEach-Object -begin   {$global:adminUsers  = ''} `
                                -process {$global:adminUsers += ($_.caption +", ")} `
                                -end     {$global:adminUsers  = ($global:adminUsers  -replace "\,\s$","")} 

  get-ipconfig | ForEach-Object -begin   {$global:addr ='Address(es): '} `
                                -process {$_.ipaddress | forEach-Object {if ($_ -gt "") {$global:addr += ($_ +", ") }}} `
                                -end     {$global:addr =($global:addr -replace "\,\s$","")}
  $t                            = "Configuring $((get-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName) "
     $Host.UI.RawUI.WindowTitle = "PowerShell Configurator"
  $w=$host.ui.RawUI.WindowSize.width
 
  do { Clear-host
       Write-host @"
$('-' * ($w-1))
$($t.padleft($w/2+$t.length/2))
$('=' * ($w-1))
[ 1] Workgroup / Domain Membership  [ $global:Domain]    
[ 2] Computer Name                  [ $global:ComputerName ]
[ 3] Local Administrators           [ $global:adminUsers ]
[ 4] Network Settings               [ $global:addr ]
[ 5] Firewall features 
[ 6] Firewall Rules              `n
[ 7] Windows Update Settings        [ $($wuConfig.levelText) ]
[ 8] Install Updates             `n    
[ 9] Remote Desktop Settings        [ $RemoteDesktop ]
[10] Remote Manangement Settings    [ $WinRMConfig ]`n
[11] Enable/Disable Roles/Features  [ Clustering: $FailOverClusterConfig ]
[12] iSCSI Settings               `n
[13] Shutdown Event tracker         [ $(Get-shutdownTracker) ]
[14] Page file settings             [ $pageFile ]`n
[15] Language & Regional settings   [ $((get-culture).displayname) ]
[16] Time and date settings         [ $(get-date -Format 'dddd d MMMM yyyy HH:mm:ss ''GMT''z') ]
                                      $tz
[17] System Environment variables
[18] Shell and Startup programs
[19] Activate Windows              `n
[20] Log Off
[21] Reboot Server                                                          
[22] Shut Down Server              `n
[99] Exit this Menu                `n
"@ 
      $selection= [int](read-host("Enter a selection")) 
      if ($?) {switch ($selection) {
           1 { #### Workgroup or Domain ####
               $InWorkgroup  = $( if ($domain -match "^Workgroup") {1} else {0} )
               Switch (Select-item -Caption "Computer confiuration" -Message "Computer is curerently a member of a $domain. Should it be" -Text "in a &Domain","in a &Workgroup", "&Cancel" -default $InWorkgroup) {
                    1 { $Name = Read-Host "Enter the new workgroup name"
                        if ($name -NE "" ) { 
                            if (-not $inworkgroup) {
                               $credential=$Host.ui.PromptForCredential("","Enter an account to remove the machine from the domain","","")
                               ADD-Computer -confirm -workgroupname $name -credential $credential
                            }
                            else {ADD-Computer -confirm -workgroupname $name }
                            $null = read-host "Changes will only take effect after the computer is rebooted. Press [enter] to continue"   
                        }
                      }
                    0 { $Name = Read-Host "Enter the new Domain name"
                        if ($name -NE "") { 
                            $credential=$Host.ui.PromptForCredential("","Enter an account to add the machine to the domain","$env:userName","")
                            ADD-Computer -confirm -DomainName $name -credential $credential
                            $null = read-host "Changes will only take effect after the computer is rebooted. Press [enter] to continue"   
                        }
                      }
                }   
               $Global:Domain =    (Get-WmiObject win32_computerSystem).domain
               $Global:Domain = if ((Get-WmiObject win32_computerSystem).partofdomain) {"Domain: $Domain"} else {"Workgroup: $domain"}
             }
           2 { #### Computer Name ####
               $Name = read-host "The computer name is currently $ComputerName .Enter the new name (or leave blank to cancel)"
               if ($name -NE "") {rename-computer -confirm -name $Name }
             }
           3 { #### Members of Local Admins  
               Write-host "Configuring the $($localAdminsGroupGroup.name) group, which already has the following members:" 
               Get-wmiobject -Query "Associators of {$localAdminsGroupGroup} where role=groupComponent"  | Foreach-Object {write-host $_.CAPTION}  
               switch (select-item  -caption "" -Message "Do you need to create the a local user account first ?" -Text "&No","&Yes","&Cancel" ) {
                             1 {  $name=read-host "Enter the name of a local user to create and add to the $($localAdminsGroupGroup.name) group" 
                                  if ($name -ne "") {
                                      write-host "Creating local user"
                                      net.exe user $name /add
                                   }    
                               }
                    0          {  $name=read-host "Enter the name of a user to add to the $($localAdminsGroupGroup.name) group" }
                    {$_ -lt 2} {  if ($name -ne "") {
                                      write-host "`nAdding $name user to local group $($localAdminsGroupGroup.name)"
                                      net.exe LocalGroup $localAdminsGroupGroup.Name /add $name
                                      get-wmiobject -query "Associators of  {$localAdminsGroupGroup} where assocclass=Win32_GroupUser"  |
                                         ForEach-Object -begin   {$global:adminUsers  = ''} `
                                                        -process {$global:adminUsers += ($_.caption +", ")} `
                                                        -end     {$global:adminUsers  = ($global:adminUsers  -replace "\,\s$","")} 
                                      write-host "Members of the group a are now `n$global:adminUsers" 
                                      $null = read-host "Press [Enter] to continue"  
                                  }
                               }
               }          
             }
           4 { ### Configure Network ###
                $nic = Select-NetworkAdapter
                if ($nic) {
                    Switch  (select-item -Caption "Configuring $($nic.Name)" -Message "Do you want to use DHCP" -Text "&No","&Yes","&Cancel" -default 1 ) {
                        1  {Set-IpConfig -confirm -nic $nic -enableDHCP 
                            $null = read-host "Press [Enter] to continue"                
                           }
                        0  { $Address   =  @()  + (Read-host "Please enter one or more IP v4 or IPV6 addresses, seperated by commas").split(",") 
                             $Subnet    =  @()  + (Read-host "Please enter the same number of subnet masks, seperated by commas (use dotted Decimal for IPv4 and number of bits for IPV6").split(",")  
                             $Gateway   =  @()  + (Read-host "(Optional) enter one or more gateways, seperated by commas").split(",")
                             $DNSOrder  =  @()  + (Read-host "(Optional) enter one or more DNS servers, seperated by Commas").split(",")
                             $Wins1     =          Read-host "If using WINS please enter the PRIMARY WINS Server "
                             if ($wins1) {$wins2 = Read-host "(Optional) enter the SECONDARY WINS Server "} 
                             else        {$wins2 = "" }
                             Set-IpConfig -confirm -nic $nic -IPAddress $Address -SubnetMask $Subnet -Gateway $Gateway -WINSPrimaryServer $WINS1 -WINSSecondaryServer -WINS2 -DNSServerSearchOrder $DNSOrder
                             $null = read-host "Press [Enter] to continue"    
                             get-ipconfig | ForEach-Object -begin   {$global:addr ='IP address(es): '} `
                                                           -process {$_.ipaddress | forEach-Object {$global:addr += ($_ +" , ") }} `
                                                           -end     {$global:addr =(($global:addr -replace " ,  , "," , ") -replace "\s\,\s$","")}
            
                           }
                    }
                }
             }
           5 {  ### Firewall features ####
                "The computer is currently using the following network profile(s) : $(get-firewallProfile). `nPlease select the profiles to configure..."
                $p =  Get-FirewallConfig | Select-list -property * -multi
                if ($P) {
		         $enable  = [Boolean](select-item -Caption "Configuring firewall " -Message "Do you want to " -Text "&Disable Firewall","&Enable Firewall" -default 1 )
                         $BlockIn = [Boolean](select-item -Caption "" -Message "Should inbound traffic be:" -Text "&Allowed according to rules","&Blocked" -default 0 )
                         Write-host "`nWhat should the default behavior for inbound traffic to be (default is block) "
			 $inbound = (Select-EnumType fwaction) ; if (-not $inbound) {$inbound=[fwaction]::block}
                         Write-host "`nWhat should the default behavior for outbound traffic to be (default is Allow) "
			 $Outbound = (Select-EnumType fwaction) ; if (-not $Outbound) {$Outbound=[fwaction]::Allow}
                         $P | foreach-object {Set-FirewallConfig -confirm -profile $_.network_Type -enable $enable -Block $blockin -Inbound $inbound -OutBound $outbound}
                         Get-FirewallConfig | format-table -autosize                        
			 $null = read-host "Press [Enter] to continue" 
                        }

             }
           6 {  #### Firewall rules #### 
                Switch (select-item -Caption "Configuring firewall rules" -Message "Do you want to " -Text "&Disable rules","&Enable Rules","&Cancel" -default 1 ){
                     0          {$Enable=$False}
                     1          {$Enable=$true}  
                     {$_ -lt 2} {$Direction=$(if   (select-item -caption "`n" -Message "which network traffic direction does the rule apply to " -Text "&Outbound","&Inbound" -default 1 ) 
                                                   {[FWDirection]::inbound}
                                              else {[FWDirection]::outbound}
                                             )
                                 Get-firewallRule -Direction inbound -disable:$Enable | sort name | select-list -multi -Property name,
                                                      @{Label="Action";    expression={[Fwaction]$_.action}},      
                                                      @{label="Profile(s)"; expression={Expand-EnumType fwprofiletype $_.profiles  }} | 
                                         foreach {$_.enabled = $enable}
                                }
               } 
             }
           7 {  #### Configure Windows Update service ####
                write-host "Windows update notification level is currently $($wuConfig.leveltext), select the new notficiation level"
                $level = Select-EnumType AutoUpdateNotificationLevel -default $wuConfig.LevelID
                write-host "currently, Windows updates are applied on $($wuConfig.DayText), select when updates are to be installed"
                $day = Select-EnumType autoupdateDay -default $wuConfig.DayID
                $hour=  Read-host "Updates are applied at $($wuConfig.Updatehour):00 Enter the hour ONLY  for installation to run (3 for 3AM, 22 for 10PM, etc) "
                if (-not $hour ) {$hour= $wuConfig.Updatehour}
                $inclusive= [boolean](select-item -Caption "" -Message "Should recommended updates be" -Text  "&Excluded", "Automatically &included" -default 1) 
                Set-WindowsUpdateConfig -confirm  -NotificationLevel $Level -Day $day -hour $hour -IncludeRecommended $inclusive
                $Global:wuConfig = Get-WindowsUpdateConfig
	     }   
           8 {  #### Manually install updates from Windows update #### 
                switch (select-item -Caption "Applying Windows updates" -Message "Do you want to:" -Text  "&Update without reboot", 
                                                                                                            "&Automatically reboot if needed",
                                                                                                            "&Shutdown after update",
                                                                                                            "&Cancel update" -default 1) {
                     0 {Add-WindowsUpdate -Criteria "IsInstalled=0 and IsHidden=0" -choose}
                     1 {Add-WindowsUpdate -Criteria "IsInstalled=0 and IsHidden=0" -choose -autoRestart}
                     2 {Add-WindowsUpdate -Criteria "IsInstalled=0 and IsHidden=0" -choose -ShutdownAfterUpdate} 
                }
                $null = Read-Host "Press [Enter] to Continue"
             }
           9 {  #### Enable / Disable remote desktop ####
		Switch (select-item -Caption "Configuring RemoteDesktop" -Message "Do you want to: " -Text "&Disable Remote Desktop",
                                                                                                             "&Enable Remote Desktop",
                                                                                                             "&Cancel"  -default 1 ) {
                     1 { if (select-item -Caption "Configuring RemoteDesktop" -Message "Do you want to: " "&Only Allow connections from clients with network level authentication", 
                                                                                                          "&Allow connections from any client (less secure)"  -default 0) 
                               { Set-RemoteDesktop -confirm -LowSecurity } 
                         else  { Set-RemoteDesktop -confirm } 
                       }
                     0 { Set-RemoteDesktop  -confirm -Disable } 
               }
               $Global:RemoteDesktop = Get-RemoteDesktopConfig
               $null = Read-Host "Press [Enter] to Continue"
             }
          10 {  #### Endable / Disable WinRM #### 
                Switch  (select-item -Caption "Configuring WinRM" -Message "Do you want to " -Text "&Disable WinRM","&Enable WinRM","&Cancel" -default 1 ) {
                    1  {  Set-WSManQuickConfig -verbose
                          Read-Host "Press [Enter] to Continue" }
                    0  { Disable-WinRm  
                         Read-Host "Press [Enter] to Continue"  }
                }
                $Global:WinRmConfig = Get-WinRmConfig
             }
          11 {  #### Add and remove Windows Features #### 
                Write-host "Configuring Windows roles and features : items currently enabled are:" 
                $winBits = (Get-WindowsFeature | select-object -property name, Installed | sort-object -property installed,name)
                $winbits  | foreach-object {if ($_.Installed ) {Write-host $_.name} }
                switch (select-item -Caption "`n" -Message "Do you want to " -Text "&Disable roles/features","&Enable Roles/Features","&Cancel"  -default 1 ) { 
                     1 { Select-List -multi -InputObject ($winbits | where {-not $_.Installed} ) -property Name,Installed | 
                             foreach-object {Add-WindowsFeature -Name $_.name -confirm}
                       }         
                     0 { Select-List -multi -InputObject ($winbits | where {$_.Installed} ) -property Name,Installed | 
                             foreach-object {Remove-WindowsFeature -Name $_.name -confirm}
                       }
                }
             } 
          12 { Set-IscsiConfig}
          13 { switch (select-item -Caption "`n" -Message "Do you want to " -Text "&Disable the Shutdown Event tracker","&Enable the Shutdown Event tracker","&Cancel"  -default 0 ) { 
                     1 { Set-ShutDownTracker           }         
                     0 { Set-ShutDownTracker -Disabled }
               } 
             }
          14 {  #### Enable / Disable automated page file settings ####
                switch  (select-item -Caption "Configuring Paging file" -Message "Do you want to " -Text "&Disable Automatic paging","&Enable Automatic Paging","&Cancel"  -default 1 ) { 
                    1  { Set-AutoPageFile  -confirm          }
                    0  { Set-AutoPageFile  -confirm -Disabled}
               }
               $Global:PageFile=get-pageFile
             }              
          15 { Set-RegionalConfig
               Read-Host "A change to the settings may not be visibile until PowerShell is restarted. `n Press [Enter] to Continue" 
             }
          16 { Set-DateConfig
               Read-Host "A change to the settings may not be visibile until PowerShell is restarted. `n Press [Enter] to Continue"
             }
          17 { $Global:count=-1
               $regpath= "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
               $propnames = (get-item -Path $regPath).property
               $props=(get-itemproperty -Path $regPath)
               $itemlist=$props | Get-member | where {$propnames -contains $_.name}
               $itemlist | format-table -autosize -property @{name="id"; expression={($global:count ++)}}, name, @{name="Value";expression={ $props.($_.name) }}
               Switch (select-item -caption "" -Message "What changes would you like to make" -TextChoices "&No Changes", "&Add a new item", "&Replace an existing item", "&Delete an existing item") {
                 {($_ -eq 2) -or ($_ -eq 3)}  { $response = Read-Host "Enter the ID number of the affected variable"
					        if ($response) {$propName  = $itemlist[[int]$response].name } else {$propname=$null}
                                              }
                 {($_ -eq 1)               }  {$propName  = Read-host "Enter the name of the new system Environment Variable" }
                 {($_ -eq 2) -or ($_ -eq 1)}  {$propValue = Read-host "Enter the Value to store in the Variable" }  
                 {($_ -eq 1) -and $propname}  {New-ItemProperty    -Confirm -ErrorAction silentlyContinue -Path $regPath -Name $propName -Value $propValue | out-Null }
                 {($_ -eq 2) -and $propname}  {Set-ItemProperty    -Confirm -ErrorAction silentlyContinue -Path $regPath -Name $propName -Value $propValue | out-Null }
                 {($_ -eq 3) -and $propname}  {Remove-ItemProperty -Confirm -ErrorAction silentlyContinue -Path $regPath -Name $propName                   | out-Null }
               }
               
             }
          18 {  $regPath = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\winlogon"
		$shell=(get-itemproperty -Path $regPath).shell
                # Don't want people changing the shell on full install Server or Windows client
		if ($shell -ne 'explorer.exe') {
                    switch (select-item -Caption ("The Shell is currently set to  `n{0}`n "-f $shell ) `
                                        -Message "Select a Windows Shell" `
                                        -Text "Do &Not Change" ,"&PowerShell in its default state", "Powershell with this &menu", "&CMD.EXE ") { 
		       1  { set-itemproperty -Confirm  -Path $regPath -Name Shell -Value 'PowerShell.exe' }                
                       2  { set-itemproperty -Confirm  -Path $regPath -Name Shell -Value 'PowerShell.exe -noExit -Command "Import-Module Configurator ; menu "  '   }
                       3  { set-itemproperty -Confirm  -Path $regPath -Name Shell -Value 'cmd.exe /c "cd /d "%USERPROFILE%" & start cmd.exe /k runonce.exe /AlternateShellStartup" '  }
                    }
		} 
                $regpath = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\"
                $count=0
                $props=(get-itemproperty -Path $regPath)
                $itemList = $(foreach ($p in (get-item -Path $regPath).property ) {select-object -inputObject "" -prop @{name="ID"; expression={($Global:count++)}}, @{Name="PropertyName"; expression={$p}}, @{name="Value"; expression={$props.$p}}  }  )
                if ($itemList -ne $Null) {
                    if ($itemlist -is [array]) {Write-host "The following programs are run at logon ..." 
                                                $itemlist | format-table -autosize
                                                $response = Read-Host "Enter the ID(s) of any you would like to remove (press [Enter] to keep them all)."
                                                $itemlist[[int[]]$response.split(",")] | foreach { Remove-ItemProperty -Confirm -Path $regpath -name $_.PropertyName -ErrorAction silentlyContinue }
  
                    }
                    else {if (Select-item -Caption ("One program is run at logon: `n{0} = {1} `n" -f $itemList.PropertyName, $ItemList.value ) `
                                          -Message "Would you like to remove this startup program"   `
                                          -Text "&No","&Yes") {Remove-ItemProperty -Confirm -Path $regpath -name $itemlist.PropertyName -errorAction SilentlyContinue}
                    }
                }        
             }
          19 { switch (select-item -Caption (Get-Registration) -Message "Do you want to " -Text "&Activate Windows with the current product key","&Enter a product Key and then Activate","&Cancel"  -default 0 ) { 
                     1 { Register-Computer -confirm -Productkey $(Read-host "Please enter the 25 digit product key in the form 12AB3-CD45E-6FGH7-IJK8L-9MNOP`n" )
                         $null = Read-Host "Press [Enter] to Continue"                         
                       }         
                     0 { Register-Computer -Confirm 
                         $null = Read-Host "Press [Enter] to Continue"
                       }
               } 
             }  
          20 { if (select-item -Caption "OK To Log off ?" -Message "" -Text "&No","&Yes") {logoff.exe} }
          21 { restart-computer -confirm }
          22 {    Stop-Computer -confirm }
      }}       
    } until ($selection -gt 30)
  $Host.UI.RawUI.WindowTitle  = $global:OldWindowTitle  
}

set-alias -Name menu -Value show-menu


