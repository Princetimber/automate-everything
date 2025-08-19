#region Main Script Execution (Example)
try {
  $StoragePoolFriendlyName = "LUN2" # Example storage pool name
  $VirtualHardDiskFriendlyName = "VHD2" # Example virtual hard disk name
  $FileSystemLabel = "NTDS" # Example file system label
  $DirectoryName = "NTDS" # Example directory name

  Invoke-StorageCreation -StoragePoolFriendlyName $StoragePoolFriendlyName -VirtualHardDiskFriendlyName $VirtualHardDiskFriendlyName -FileSystemLabel $FileSystemLabel -DirectoryName $DirectoryName -CreateNTDS
  Write-Log "Script executed successfully." 'INFO'
  Write-Host "Storage creation process completed successfully!" -ForegroundColor Green
  Write-Host "Log file created at: $Global:LogFile" -ForegroundColor Magenta
  Write-Host "You can view the log file for details." -ForegroundColor DarkCyan
  Write-Host "Please ensure you have the necessary permissions to create storage and directories." -ForegroundColor DarkCyan
  Write-Host "If you encounter any issues, check the log file for more information." -ForegroundColor DarkCyan
  Write-Host "You can now proceed with the next steps in your deployment process." -ForegroundColor DarkCyan
  Write-Host "Thank you for using this script!" -ForegroundColor DarkMagenta
  Write-Host "If you have any feedback or suggestions, please let us know." -ForegroundColor DarkCyan
  Write-Host "Have a great day!" -ForegroundColor DarkCyan
  Write-Host "For any issues, please refer to the log file or contact support." -ForegroundColor DarkCyan
  Write-Host "You can also check the documentation for more information." -ForegroundColor DarkCyan
  Write-Host "Thank you for using the storage creation script!" -ForegroundColor DarkCyan
}
catch {
  Write-Log "An error occurred during script execution: $_" 'ERROR'
  throw $_
}
#endregion