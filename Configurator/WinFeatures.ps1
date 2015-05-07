####################################################################################################################################
##   Windows Feature management  Conditionally defined if ServerManager Module is not loaded 
####################################################################################################################################

import-module ServerManager -ErrorAction silentlyContinue
if (-not (get-module -name ServerManager))  {

    Function Get-WindowsFeature 
    {#  .ExternalHelp  Maml-WinFeatures.xml
         Write-Progress -Activity $lStr_FeatureGet -Status $lStr_Checking
         DISM.exe "/online" "/get-features" /format:table | where {$_ -like "*able*" } | 
              foreach { $name      = $_.split("|")[0].trim(" ")
                        $Installed = ($_.split("|")[1].trim(" ") -eq "Enabled")
                        New-Object -TypeName System.Object | Add-Member NoteProperty -Name "Name" -Value $name -PassThru | Add-Member NoteProperty -Name "Installed" -Value $Installed -PassThru
                      }
         Write-Progress -Activity $lStr_FeatureGet -Status $lStr_Checking -completed 
    }




    Function Add-WindowsFeature
    {#  .ExternalHelp  Maml-WinFeatures.xml
        [CmdletBinding(SupportsShouldProcess=$True)]
        Param   ( [parameter(Mandatory= $true, ValueFromPipeLine= $true)]
                  [validateNotNullOrEmpty()]$Name 
                ) 
        Process { $Name | foreach-object {
                      If ($psCmdlet.shouldProcess($_ , $LStr_FeatureAdd)) { DISM.exe "/online" "/enable-feature" "/featurename:$_"}  
                  }
                }
    }


    Function Remove-WindowsFeature
    {#  .ExternalHelp  Maml-WinFeatures.xml
        [CmdletBinding(SupportsShouldProcess=$True)]
        Param   ( [parameter(Mandatory= $true, ValueFromPipeLine= $true)]
                  [validateNotNullOrEmpty()]$Name 
                ) 
        Process { $Name | foreach-object{
		              If ($psCmdlet.shouldProcess($_ , $LStr_FeatureRemove)) {DISM.exe "/online" "/disable-feature" "/featurename:$_"}  
                  }
                }
    }

} #end of conditional definitions

    Function Select-WindowsFeature  
    {#  .ExternalHelp  Maml-WinFeatures.xml
         get-windowsFeature |sort-object -property Installed,name  | select-list  -property Name,Installed -multiple | foreach {$_.name}
    }
