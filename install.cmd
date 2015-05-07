@echo off
cls
echo      Installing PowerShell configurator
echo   ========================================
echo.
echo Ensuring that .Net Framework 2 and Windows PowerShell are installed
Echo Press [ctrl][c] to abort or
pause
dism /online /enable-feature  /featurename:NetFx2-ServerCore
dism /online /enable-feature /featurename:MicrosoftWindowsPowerShell

echo.
echo About to create folder and copy Powershell module.
Echo Press [ctrl][c] to abort or
pause

md "%ProgramFiles%\modules\configurator"
copy %0\..\configurator\*.* "%ProgramFiles%\modules\configurator"

echo.
echo About to set registry entries for PowerShell script execution, module path and console settings 
Echo Press [ctrl][c] to abort or
pause

start /w regedit %0\..\PS_Console.REG

echo.
echo About to Launch the PowerShell configurator
Echo Press [ctrl][c] to abort or
pause

start %windir%\System32\WindowsPowerShell\v1.0\powershell.exe -noExit -Command "Import-Module '%ProgramFiles%\modules\configurator' ; menu "