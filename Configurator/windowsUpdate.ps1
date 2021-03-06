####################################################################################################################################
##   Windows update management
####################################################################################################################################
 
Function Add-WindowsUpdate
{#  .ExternalHelp  Maml-WindowsUpdate.XML
    [CmdletBinding(SupportsShouldProcess=$True)]
    param ([String]$Criteria="IsInstalled=0 and Type='Software' and IsHidden=0 and AutoSelectOnWebSites=1" , 
           [switch]$AutoRestart, 
           [Switch]$ShutdownAfterUpdate, 
           [Switch]$Choose)
 
    write-progress -Activity $lstr_Updating -Status $lstr_WUChecking
    $updateSession = new-object -com "Microsoft.Update.Session"  
    $updates=$updateSession.CreateupdateSearcher().Search($criteria).Updates
    if   ($choose -and ($Updates.Count -gt 0)) {
          $UpdatesToDownload = New-object -com "Microsoft.Update.UpdateColl"
          select-list -InputObject (0..($updates.count-1) | foreach-object {$updates.item($_)} ) -property title, supportUrl -multiple |
          foreach-Object {$UpdatesToDownload.add($_) | out-null}
    }
    Else {$UpdatesToDownload = $updates.Copy()} 
  
    if   ($UpdatesToDownload.Count -eq 0)  
         { "There are no applicable updates."}   
    else {$downloader = $updateSession.CreateUpdateDownloader()                   
          $downloader.Updates = $UpdatesToDownload 
          write-progress -Activity $lstr_Updating -Status ($lstr_WUDownLoading -f $downloader.Updates.count)
          $result=$downloader.Download()      #  .Hresult 0 = OK , resultCode maps to $lstr_WUresultcode 
          if (($result.hresult -eq 0) -and (($result.resultcode -eq 2) -or ($result.resultcode -eq 3))) {
              $updatesToInstall   = New-object -com "Microsoft.Update.UpdateColl"
              $UpdatesToDownload  | where-Object {$_.isdownloaded} | foreach-Object {$updatesToInstall.Add($_) | out-null }
              $installer          = $updateSession.CreateUpdateInstaller()
              $installer.Updates  = $updatesToInstall
              if ($psCmdlet.shouldProcess($lstr_WUApplyUpdates , $lstr_LocalComputer )) {
                  write-progress -Activity $lstr_Updating  -Status ($lstr_wuInstalling -f $Installer.Updates.count)
                  $installationResult = $installer.Install()
                  $Global:counter     = -1 
                  $installer.updates  | Format-Table -autosize -property Title,EulaAccepted,@{label='Result'; 
                                           expression={$lstr_WUresultcode[$installationResult.GetUpdateResult($Global:Counter++).resultCode ] }} 
                  if ($autoRestart -and $installationResult.rebootRequired) { restart-computer }
                  if ($ShutdownAfterUpdate)                                 { Stop-Computer }
              }    
           }
    }
}


Function Get-WindowsUpdateConfig
{#  .ExternalHelp  Maml-WindowsUpdate.XML
    $AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
    $AUObj = New-Object -TypeName System.Object 
    Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "LevelID"            -Value ($AUSettings.NotificationLevel)
    Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "DayID"              -Value ($AUSettings.ScheduledInstallationDay )
    Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "LevelText"          -Value ([AutoUpdateNotificationLevel]$AUSettings.NotificationLevel -replace "_"," ")
    Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "DayText"            -Value ([autoUpdateDay]$AUSettings.ScheduledInstallationDay -replace "_"," " )
    Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "UpdateHour"         -Value $AUSettings.ScheduledInstallationTime 
    Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "Recommendedupdates" -Value $(IF ($AUSettings.IncludeRecommendedUpdates) {"Included"}  else {"Excluded"})
    $AuObj
}


Function Set-WindowsUpdateConfig
{#  .ExternalHelp  Maml-WindowsUpdate.XML
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param ([AutoupdateNotificationLevel]$NotificationLevel ,  [AutoupdateDay]$Day , [Int]$hour , [boolean]$IncludeRecommended )
    
   $AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
   if ($NotificationLevel)  {$AUSettings.NotificationLevel        =$NotificationLevel}
   if ($Day)                {$AUSettings.ScheduledInstallationDay =$Day}
   if ($hour)               {$AUSettings.ScheduledInstallationTime=$hour}
   if ($IncludeRecommended) {$AUSettings.IncludeRecommendedUpdates=$IncludeRecommended}

   If ($psCmdlet.shouldProcess("Local computer ($computerName)" , ($lstr_WUSet -f `
                                                       ([AutoUpdateNotificationLevel]$AUSettings.NotificationLevel -replace "_"," "),
                                                       ([autoUpdateDay]$AUSettings.ScheduledInstallationDay -replace "_"," " ),
                                                       $AUSettings.ScheduledInstallationTime, 
                                                       $(IF ($AUSettings.IncludeRecommendedUpdates) {$lstr_Included}  else {$lstr_Excluded})
       ))) { $AUSettings.Save() }
}
