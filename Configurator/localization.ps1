
Add-type @"
public enum FwProfileType {
                           Public   = 4,
                           Domain   = 1,
                           Private  = 2,
                           All      = 1073741824
                          } 

public enum FwAction {
                             Allow                  = 1,
                             Block                  = 0
                           }
  
public enum FwProtocol {
                             IPv6Frag               = 44,
                             IPv6Route              = 43,
                             IPv6                   = 41,
                             UDP                    = 17,
                             IPv6Opts               = 60,
                             IPv6NoNxt              = 59,
                             ICMPv6                 = 58,
                             VRRP                   = 112,
                             TCP                    = 6,
                             GRE                    = 47,
                             PGM                    = 113,
                             IGMP                   = 2,
                             ICMPv4                 = 1,
                             L2TP                   = 115
                         }

public enum FwDirection {
                             Outbound               = 2,
                             Inbound                = 1
                           } 

public enum AutoUpdateDay {
                             Saturday               = 7,
                             Friday                 = 6,
                             Thursday               = 5,
                             Wednesday              = 4,
                             Tuesday                = 3,
                             Monday                 = 2,
                             Sunday                 = 1,
                             Every_Day              = 0
                           }

public enum AutoUpdateNotificationLevel {
                             Scheduled_installation = 4,
                             Before_installation    = 3,
                             Before_download        = 2,
                             Disabled               = 1,
                             Not_set                = 0
                           }
"@


$lStr_IpConfigErrors=@{0="Successful completion, no reboot required."; 1="Successful completion, reboot required." ; 64="Method not supported on this platform." ; 
65="Unknown failure." ; 66="Invalid subnet mask."; 67="An error occurred while processing an instance that was returned."; 
68="Invalid input parameter."; 69="More than five gateways specified."; 70="Invalid IP address."; 71="Invalid gateway IP address.";
72="An error occurred while accessing the registry for the requested information." ; 73="Invalid domain name."; 74="Invalid host name." ; 
75="No primary or secondary WINS server defined."; 76="Invalid file."; 77="Invalid system path." ; 78="File copy failed."; 
79="Invalid security parameter."; 80="Unable to configure TCP/IP service."; 81="Unable to configure DHCP service."
82="Unable to renew DHCP lease." ; 83="Unable to release DHCP lease."; 84="IP not enabled on adapter." ; 85="IPX not enabled on adapter." ; 
86="Frame or network number bounds error."; 87="Invalid frame type."; 88="Invalid network number."; 89="Duplicate network number."; 
90="Parameter out of bounds."; 91="Access denied."; 92="Out of memory."; 93="Already exists." ; 94="Path, file, or object not found."; 
95="Unable to notify service."; 96="Unable to notify DNS service."; 97="Interface not configurable."; 
98="Not all DHCP leases could be released or renewed."; 100="DHCP not enabled on the adapter."}

$lStr_licenseStatus               = @{0="Unlicensed"; 1="Licensed"; 2="OOBGrace"; 3="OOTGrace"; 4="NonGenuineGrace"; 5="Notification"; 6="ExtendedGrace"}

$lstr_WUresultcode                = @{0="Not started"; 1="In progress"; 2="Succeeded"; 3="Succeeded with errors"; 4="Failed" ; 5="Aborted" } 

$lstr_WaitingToReboot             = "Waiting to reboot."
$lstr_Automatic                   = "Automatic"
$lstr_NotSet                      = "Not set"
$lstr_Displayed                   = "Displayed"
$lstr_NotDisplayed                = "Not displayed"
$lstr_LocalComputer               = "Local computer"
$lStr_TestAdmin                   = "Session elevated: {0}" 
$lStr_NoFreeDrives                = "No free drive letters found"
$lStr_Checking                    = "Checking ..."
$lstr_Speed                       = "Speed"
$lstr_Disconnected                = "Disconnected"
$lstr_Success                     = "Success"
$Ltsr_WindowsServiceRunning       = "running"
$lstr_Included                    = "Included" 
$lstr_Excluded                    = "Excluded"
$lstr_Updating                    = 'Updating'
$lstr_WUDownLoading               = "Downloading {0} update(s)"
$lstr_WUChecking                  = "Checking available updates"
$lstr_WUApplyUpdates              = "Apply update(s)"
$lstr_WUSet                       = "Set Windows-Update; notification level:{0}, day:{1} , hour:{2}, recommended updates:{3} "
$lstr_wuInstalling                = "Installing {0} update(s)" 
$lStr_DriverAdd                   = "Install driver"
$lStr_ProductAdd                  = "Install product"
$lStr_ProductRemove               = "Remove installed product"
$lStr_HotFixAdd                   = "Install hot-fix"
$lstr_RemoteDesktopForbidden      = "Connections not allowed"
$lstr_RemoteDesktopSecureOnly     = "Only secure connections allowed"
$lstr_RemoteDesktopAllowAll       = "All connections allowed"
$lstr_RemoteDesktopEnabling       = "Enabling remote desktop on local computer {0}."
$lstr_RemoteDesktopConfiguring    = "Configuring remote desktop."
$lstr_RemoteDesktopFirewallRule   = "Remote Desktop (TCP-In)"
$Ltsr_WinRMEnabled                = "Listener enabled"
$Ltsr_WinRMDisabled               = "No listener"
$Ltsr_WinRMStopped                = "No service"    
$lstr_IpConfigDhcpWarning         = "The new configuration may not appear at once and may need a reboot."
$lstr_IpConfigEnableDhcp          = "Enable DHCP"
$lstr_IpConfigSetGateway          = "Set gateway {0}"
$lstr_IpConfigSetDNS              = "Set DNS Server(s) {0}" 
$lstr_IpConfigSetWINS             = "Set WINS Server(s) {0} {1}"
$lstr_IpConfigRenewDHCPSuccess    = "Renew DHCP Lease"
$lstr_IpConfigReleaseDHCPSuccess  = "Release DHCP Lease"
$lStr_FirewallProfile             = "{0} firewall" 
$lstr_FirewallSetEnabled          = "Set firewall enabled to {0}" 
$lstr_FirewallSetBlockAllInboud   = "Set block all inbound traffic to {0}" 
$lstr_FirewallSetDefaultInbound   = "Set default inbound action to {0}"
$lstr_FirewallSetDefaultOutBound  = "Set default Outbound action to {0}"
$lstr_PageFileDisableAuto         = "Disable automatic page file"
$lstr_PageFileEnableAuto          = "Enable automatic page file"
$lstr_PageFileManual              = "Min={1}, Max={2} File={0}"
$lstr_RenameComputerAndReboot     = "Rename commputer to '{0}' and reboot."
$lstr_RenameComputerComplete      = "Machine renamed." 
$lStr_RegistrationInfo            = "Product: {0} --- Licensing status: {1}"
$lStr_RegistrationInfoGettingInfo = "Getting registration information" 
$lStr_RegistrationSetKey          = "Set licensing key"
$lStr_RegistrationActivate        = "Activate product"
$lStr_RegistrationSuccess         = "Product activated successfully."
$lStr_RegistrationFailure         = "Activation failed, and the license state is '{0}'"
$lStr_RegistrationState           = "The license state is '{0}' " 
$lStr_FeatureGet                  = "Getting Windows Feature information"
$LStr_FeatureAdd                  = "Adding Windows Feature"
$LStr_FeatureRemove               = "Removing Windows Feature"

