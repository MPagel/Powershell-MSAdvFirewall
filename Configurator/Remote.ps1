####################################################################################################################################
##   Management of the configuration of Remote system-management
####################################################################################################################################

Function Get-RemoteDesktopConfig
{#  .ExternalHelp  Maml-Remote.XML
    if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 1) { $lstr_RemoteDesktopForbidden }
    elseif ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -eq 1) {$lstr_RemoteDesktopSecureOnly} 
    else {$lstr_RemoteDesktopAllowAll}
}


Function Set-RemoteDesktop
{#  .ExternalHelp  Maml-Remote.XML
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param([switch]$LowSecurity ,
          [Switch]$Disable )
    if ($Disable) {
           if ($pscmdlet.shouldProcess("$ComputerName", $lstr_RemoteDesktopConfiguring)) {
               set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 1 -erroraction silentlycontinue -Confirm:$false 
               if (-not $?) {new-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 1 -PropertyType dword  -Confirm:$false }
               set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 -erroraction silentlycontinue  -Confirm:$false 
               if (-not $?) {new-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 -PropertyType dword -Confirm:$false}  
               (get-firewallRule -name $lstr_RemoteDesktopFirewallRule) | foreach-object {$_.enabled=$False}
           }
    }
    else {
           if ($pscmdlet.shouldProcess("$ComputerName", $lstr_RemoteDesktopConfiguring)) {
               set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0 -erroraction silentlycontinue  -Confirm:$false
               if (-not $? )     {new-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0 -PropertyType dword  -Confirm:$false }
               if ($LowSecurity) {
                  set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 0 -erroraction silentlycontinue -Confirm:$false
                  if (-not $?) {new-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 0 -PropertyType dword -Confirm:$false} 
               }
               (get-firewallRule -name $lstr_RemoteDesktopFirewallRule -disabled) | foreach-object {$_.enabled=$true}
           } 
    }         
}


Function Get-WinRMConfig 
{#  .ExternalHelp  Maml-Remote.XML
    if ((get-service winrm).status -eq $Ltsr_WindowsServiceRunning ) {
       if ((winrm enumerate winrm/config/listener) -ne $null) {"Listener enabled"} else {$Ltsr_WinRMDisabled} }
     else {$Ltsr_WinRMStopped}
}



Function Disable-WinRm
{   winrm "invoke" "Restore" "winrm/Config" "@{}"
    Netsh.exe "advfirewall" "firewall" "set" "rule" "group=remote administration" "new" "enable=no"
}
