#region Module manifest creation
$params = @{
  Path              = "$PSScriptRoot\automateADInstall.psd1"
  RootModule        = "automateADInstall.psm1"
  Author            = "Olamide Olaleye"
  CompanyName       = "Fountview Enterprise Solutions"
  Description       = "Automate ADDS Forest Deployment; Adding additional domain controller to the forest with logging and Pester validation"
  ModuleVersion     = "1.0.0"
  PowerShellVersion = '5.1'
  RequireModules    = @('ActiveDirectory', 'Pester')
}
New-ModuleManifest @params
#endregion