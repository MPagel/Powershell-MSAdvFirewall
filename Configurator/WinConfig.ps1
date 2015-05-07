######################################################di
#####    Management of windows configuration     #####  
######################################################

Function Set-RegionalConfig    
{# .ExternalHelp  MAML-WinConfig.xml
    control.exe "intl.cpl"
}

		
Function Set-DateConfig        
{# .ExternalHelp  MAML-WinConfig.xml
    control.exe "timedate.cpl"
}


Function Set-iSCSIConfig
{# .ExternalHelp  MAML-WinConfig.xml
    Iscsicpl.exe
}


Function Set-AutoPageFile
{# .ExternalHelp  MAML-WinConfig.xml
    [CmdletBinding(SupportsShouldProcess=$True)]
    param([Switch]$Disabled)

    If ($disabled) {
        $pc=Get-WmiObject -class win32_computerSystem -Impersonation 3 -EnableAllPrivileges
        $pc.AutomaticManagedPagefile=$false
        If ($psCmdlet.shouldProcess($lstr_LocalComputer , $lstr_PageFileDisableAuto )) { $pc.Put() | out-null }
    }
    else {
        $pc=Get-WmiObject -class win32_computerSystem -Impersonation 3 -EnableAllPrivileges
        $pc.AutomaticManagedPagefile=$True 
        If ($psCmdlet.shouldProcess($lstr_LocalComputer , $lstr_PageFileEnableAuto)) { $pc.Put() | Out-Null }
    } 
}


Function Get-PageFile 
{# .ExternalHelp  MAML-WinConfig.xml

    $pf=get-wmiObject -NameSpace "root\cimv2" -class win32_pageFileSetting 
    if     ($pf.count -gt 1) {"Multiple Page files"}
    elseif ((Get-WmiObject -NameSpace "root\cimv2"  -class win32_computerSystem).AutomaticManagedPagefile) {$lstr_Automatic}
        else { ($lstr_PageFileManual -f $pf.name,$pf.initialsize,$pf.maximumSize)}
}


Function Set-ShutDownTracker
{# .ExternalHelp  MAML-WinConfig.xml
    [CmdletBinding(SupportsShouldProcess=$True)]
    param([Switch]$Disabled)

    $RegKey="Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT"
    if (-not(test-path -path "$RegKey\Reliability")) {New-Item -path $regKey -name "Reliability" -type "RegistryKey"}
    if ($Disabled) { Set-ItemProperty -path "$RegKey\Reliability" -name ShutDownReasonOn -Value 0 -ErrorAction "silentlyContinue"}
    else           { Set-ItemProperty -path "$Regkey\Reliability" -name ShutDownReasonOn -Value 1
                     Set-ItemProperty -path "$RegKey\Reliability" -name ShutdownReasonUI -value 1
    }
}


Function Get-ShutDownTracker 
{# .ExternalHelp  MAML-WinConfig.xml
    $RegKey="Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT"
    if (test-path "$RegKey\Reliability") {
          if ([int](get-ItemProperty -path "$RegKey\Reliability" ).shutdownReasonOn) {$lstr_Displayed} else {$lstr_NotDisplayed} 
    }
    else {$lstr_NotSet}
}
