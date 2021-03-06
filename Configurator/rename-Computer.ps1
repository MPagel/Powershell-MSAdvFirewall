####################################################################################################################################
##   Rename-Computer
##   This was a cmdlet in the CTP of Powershell 2.0 and but had gone from the 7100 builds.
####################################################################################################################################

Function Rename-Computer 
{# .ExternalHelp  MAML-Rename-Computer.xml
  [CmdletBinding(SupportsShouldProcess=$True)]
   param ([parameter(Mandatory= $true, ValueFromPipeLine= $true)]
          [validateNotNullOrEmpty()]
          [String]$Name
         )
   
   $Config = (Get-WmiObject -class win32_computersystem -namespace root\cimv2)
   If ($psCmdlet.shouldProcess($lstr_LocalComputer , ($lstr_RenameComputerAndReboot -f $name))) { 
       $result=$config.rename($Name,$Null, $null)
       if ($result.ReturnValue -eq 0) {
             10..1 |  foreach {Write-Progress -Activity $lstr_RenameComputerComplete -Status $lstr_WaitingToReboot -SecondsRemaining $_  ; sleep 1}
            restart-computer -Confirm:$false
       }
   } 
}
