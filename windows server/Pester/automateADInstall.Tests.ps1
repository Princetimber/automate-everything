#region Pester Tests
Import-Module "$PSScriptRoot\..\Modules\Logging.psm1" -Force
Import-Module "$PSScriptRoot\..\Modules\automateADInstall.psm1" -Force

Describe "Logging Functionality" {
    It "Should write an INFO entry to the log file" {
        $message = "Test info message"
        Write-Log $message 'INFO'
        $logFile = Get-LogFilePath
        $log = Get-Content $logFile | Select-String $message
        $log | Should -Not -BeNullOrEmpty
        $log.ToString() | Should -Match "\[INFO\] $message"
    }
    It "Should write an ERROR entry to the log file" {
        $message = "Test error message"
        Write-Log $message 'ERROR' -ErrorAction SilentlyContinue
        $logFile = Get-LogFilePath
        $log = Get-Content $logFile | Select-String $message
        $log | Should -Not -BeNullOrEmpty
        $log.ToString() | Should -Match "\[ERROR\] $message"
    }
}

Describe "New-EnvPath" {
    It "Should join a path and child path correctly" {
        $result = New-EnvPath -Path "C:\Base" -ChildPath "Sub"
        $result | Should -Be "C:\Base\Sub"
    }
}

Describe "Test-Paths" {
    It "Should throw error if path does not exist" {
        $nonExistentPath = "C:\DefinitelyNotARealPath"
        { Test-Paths -Paths @($nonExistentPath) } | Should -Throw
    }
}

Describe "Invoke-PSModules" {
    It "Should not throw error if module is already installed" {
        { Invoke-PSModules -Name "Microsoft.PowerShell.Management" } | Should -Not -Throw
    }
}

Describe "Invoke-ADModule" {
    It "Should not throw error for already installed feature" {
        { Invoke-ADModule -Name "AD-Domain-Services" } | Should -Not -Throw
    }
}

Context "AD Forest Functions" {
    It "New-ADDSForest should accept parameters and call Install-ADDSForest" {
        Mock Install-ADDSForest {}
        $params = @{
            DomainName = "testdomain.local"
            DomainNetBiosName = "TESTDOMAIN"
            DatabasePath = "C:\Windows"
            LogPath = "C:\Windows\NTDS"
            SYSVOLPath = "C:\Windows"
            Force = $true
        }
        New-ADDSForest @params
        Assert-MockCalled Install-ADDSForest -Exactly 1 -Scope It
    }
    It "Invoke-ADDSForest should call New-ADDSForest" {
        Mock New-ADDSForest {}
        Invoke-ADDSForest -DomainName "testdomain.local"
        Assert-MockCalled New-ADDSForest -Exactly 1 -Scope It
    }
}

Context "AD Domain Controller Functions" {
    It "New-ADDSDomainController should accept parameters and call Install-ADDSDomainController" {
        Mock Install-ADDSDomainController {}
        $params = @{
            DomainName = "testdomain.local"
            SiteName = "Default-First-Site-Name"
            DomainAdministrator = "admin@testdomain.local"
            SafeModeAdministratorPassword = ConvertTo-SecureString "pass" -AsPlainText -Force
            DatabasePath = "C:\Windows"
            LogPath = "C:\Windows\NTDS"
            SysvolPath = "C:\Windows"
            Force = $true
        }
        # Mock Read-Host for password input
        Mock Read-Host { ConvertTo-SecureString "pass" -AsPlainText -Force }
        New-ADDSDomainController @params
        Assert-MockCalled Install-ADDSDomainController -Exactly 1 -Scope It
    }
    It "Invoke-ADDSDomainController should call New-ADDSDomainController" {
        Mock New-ADDSDomainController {}
        Invoke-ADDSDomainController -DomainName "testdomain.local"
        Assert-MockCalled New-ADDSDomainController -Exactly 1 -Scope It
    }
}
#endregion
