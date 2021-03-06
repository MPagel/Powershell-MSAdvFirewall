####################################################################################################################################
##   Licencsing and activation management
####################################################################################################################################

Function Get-Registration
{#  .ExternalHelp  Maml-Licensing.XML 
    Param ($server="." )
    Write-Progress -Activity $lStr_RegistrationInfoGettingInfo -Status $lStr_Checking
    get-wmiObject -query  "SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey <> null
                                          AND ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f'
                                          AND LicenseIsAddon=False" -Computername $server |
        foreach {$lStr_RegistrationInfo  -f $_.name , $lStr_licenseStatus[[int]$_.LicenseStatus] }
    Write-Progress -Activity $lStr_RegistrationInfoGettingInfo -Status $lStr_Checking -completed
}


Function Register-Computer
{#  .ExternalHelp  Maml-Licensing.XML 
    [CmdletBinding(SupportsShouldProcess=$True)]
    param ([parameter()]
           [ValidateScript({ $_ -match "^\S{5}-\S{5}-\S{5}-\S{5}-\S{5}$"})]
           [String]$Productkey , 
           [String] $Server="."
          )
    
    $objService = get-wmiObject -query "select * from SoftwareLicensingService" -computername $server
    if ($ProductKey) { If ($psCmdlet.shouldProcess($Server , $lStr_RegistrationSetKey)) {
                           $objService.InstallProductKey($ProductKey) | out-null  
                           $objService.RefreshLicenseStatus() | out-null
                       }
    }
    get-wmiObject -query  "SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey <> null 
                                                                  AND ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' 
                                                                  AND LicenseIsAddon=False" -Computername $server |     foreach-object {
              If ($psCmdlet.shouldProcess($_.name , $lStr_RegistrationActivate )) {
                          $_.Activate()                      | out-null 
                           $objService.RefreshLicenseStatus() | out-null
                           $_.get()
                           If     ($_.LicenseStatus -eq 1) {write-verbose $lStr_RegistrationSuccess }
                           Else   {write-error ($lStr_RegistrationFailure -f $lStr_licenseStatus[[int]$_.LicenseStatus] ) }
                           If     (-not $_.LicenseIsAddon) { return }
              }
              else { write-Host ($lStr_RegistrationState -f $lStr_licenseStatus[[int]$_.LicenseStatus]) }
    }
}
