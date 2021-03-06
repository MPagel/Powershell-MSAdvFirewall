#######################################################################################################################
#####    Management of Other software component (non windows features: drivers, MSI based applications, hotfixes) #####
#######################################################################################################################

Function Add-Driver 
{#  .ExternalHelp  Maml-Software.XML
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param ( [Parameter(Mandatory=$true  ,valueFromPipeline=$true )]
            [ValidateScript({Test-path $_ })]
            [String]$Path) 

    Process {
        $infFile=(Resolve-Path $path).path
        If ($psCmdlet.shouldProcess($infFile , $lStr_DriverAdd)) { pnputil.exe -i -a $InfFile }
    }
}


Function Get-Driver
{#  .ExternalHelp  Maml-Software.XML
    Param ([string]$Filter, [String]$Server="." ) 
    Get-wmiObject -ComputerName $Server -NameSpace "root\cimv2" -class "win32_SystemDriver" -Filter $Filter
}  


Function Get-InstalledProduct 
{#  .ExternalHelp  Maml-Software.XML
    Param ([string]$Filter, [String]$Server="." )
    Get-wmiObject -ComputerName $Server  -NameSpace "root\cimv2" -class "win32_Product" -Filter $Filter
} 


Function Add-InstalledProduct 
{#  .ExternalHelp  Maml-Software.XML
    [CmdletBinding(SupportsShouldProcess=$True)]
     Param ( [Parameter(Mandatory=$true  ,valueFromPipeline=$true )]
             [ValidateScript({Test-path $_ })]
             [String]$Path) 

    Process {
        $MSIFile=(Resolve-Path $path).path
        If ($psCmdlet.shouldProcess($MsiFile , $lStr_ProductAdd)) { Msiexec.exe "/i" $MSIFile }
    }
} 


Function Remove-InstalledProduct 
{#  .ExternalHelp  Maml-Software.XML
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param ([Parameter(Mandatory=$true)][String]$Name)

    If ($psCmdlet.shouldProcess($Name , $lStr_ProductRemove)) { (Get-InstalledProduct -Filter "Name='$name'").Uninstall() }
} 


Function Add-HotFix 
{#  .ExternalHelp  Maml-Software.XML
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param ( [Parameter(Mandatory=$true  ,valueFromPipeline=$true )]
            [ValidateScript({Test-path $_ } )]
            [String]$Path, 
            [switch]$NoReboot)

    Process {
        $HotFixFile=(Resolve-Path $path).path
        If ($psCmdlet.shouldProcess($HotFixFile , $lStr_HotFixAdd)) {
  
            if ($NoReboot) {Wusa.exe $HotFixFile  "/quiet" "/NoReboot"}
            else           {Wusa.exe $HotFixFile "/quiet" }
        }
    }
}

#Don't need to write Get-Hotfix - it is a standard cmdlet in PowerShell 2.0
