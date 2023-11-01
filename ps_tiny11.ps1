# this script is based on https://github.com/ntdevlabs/tiny11builder
# and i never would've created this without prior work by ntdevlabs
using namespace System.Text.RegularExpressions
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList "-File `"$($PSCommandPath)`""
    Exit
}
# substring match on PackageName, case-insensitive
$pkgs = @{ 
    'InternetExplorer'              = 0; 
    'Kernel-LA57'                   = 0;
    'LanguageFeatures-Handwriting'  = 0;
    'LanguageFeatures-OCR'          = 0;
    'LanguageFeatures-Speech'       = 0;
    'LanguageFeatures-TextToSpeech' = 0;
    'MediaPlayer'                   = 0;
    'TabletPCMath'                  = 0;
    'Wallpaper'                     = 0;
}
# substring match on DisplayName, case-insensitive
$apps = @{ 
    'Clipchamp.Clipchamp'                    = 0;
    # cortana
    '549981'                                 = 0;
    'Microsoft.BingNews'                     = 0;
    'Microsoft.BingWeather'                  = 0;
    'Microsoft.GamingApp'                    = 0;
    'Microsoft.GetHelp'                      = 0;
    'Microsoft.Getstarted'                   = 0;
    'Microsoft.MicrosoftOfficeHub'           = 0;
    'Microsoft.MicrosoftSolitaireCollection' = 0;
    'Microsoft.MicrosoftStickyNotes'         = 0;
    'Microsoft.Paint'                        = 0;
    'Microsoft.People'                       = 0;
    'Microsoft.PowerAutomateDesktop'         = 0;
    'Microsoft.Todos'                        = 0;
    'Microsoft.WindowsAlarms'                = 0;
    'microsoft.windowscommunicationsapps'    = 0;
    'Microsoft.WindowsFeedbackHub'           = 0;
    'Microsoft.WindowsMaps'                  = 0;
    'Microsoft.WindowsSoundRecorder'         = 0;
    'Microsoft.Xbox.TCUI'                    = 0;
    'Microsoft.XboxGameOverlay'              = 0;
    'Microsoft.XboxGamingOverlay'            = 0;
    'Microsoft.XboxSpeechToTextOverlay'      = 0;
    'Microsoft.YourPhone'                    = 0;
    'Microsoft.ZuneMusic'                    = 0;
    'Microsoft.ZuneVideo'                    = 0;
    'MicrosoftCorporationII.MicrosoftFamily' = 0;
    'MicrosoftCorporationII.QuickAssist'     = 0;
    #'MicrosoftWindows.Client.WebExperience'  = 0;
    # not actually in my image, so this is a guess
    'MicrosoftTeams'                         = 0;
}
# must end with *
$folders = @(
    "\Windows\SystemApps\Microsoft.MicrosoftEdge_*",
    "\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_*",
    "\ProgramData\Microsoft\Windows\AppRepository\Microsoft.MicrosoftEdge_*",
    "\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.MicrosoftEdge*",
    "\Program Files\Internet Explorer*",
    "\Program Files (x86)\Internet Explorer*",
    "\Program Files\WindowsApps\MicrosoftTeams_*",
    "\Program Files (x86)\Microsoft\Edge*",
    "\Program Files (x86)\Microsoft\EdgeUpdate*"
    )
$files = @(
    "\Windows\System32\OneDriveSetup.exe"
    )
$yes = (cmd /c "choice <nul 2>nul")[1]
$tempdir = 'C:\ps_tiny11'
$mntdir = 'C:\tiny11mnt'
$output = Join-Path $PSScriptRoot 'ps_tiny11.iso'
$isomaker = Join-Path $PSScriptRoot 'oscdimg.exe'
$unattend = Join-Path $PSScriptRoot 'autounattend.xml'
$install_reg = Join-Path $PSScriptRoot 'installwim_patches.reg'
$boot_reg = Join-Path $PSScriptRoot 'bootwim_patches.reg'
$isocommand = $isomaker + ' -m -o -u2 -udfver102 -bootdata:2#p0,e,b' + "${tempdir}\boot\etfsboot.com" + '#pEF,e,b' + "${tempdir}\efi\microsoft\boot\efisys.bin" + " ${tempdir}" + " ${output}"
function DoExit {
    Write-Host 'Finished.  Press Enter to continue...'
    $null = $Host.UI.ReadLine()
    Exit
}
function Cleanup {
    if (Test-Path $tempdir) {
        Write-Host "Removing: ${tempdir} ..."
        Remove-Item -path $tempdir -Recurse -Force
    }
    if (Test-Path $mntdir) {
        Write-Host "Removing: ${mntdir} ..."
        Remove-Item -path $mntdir -Recurse -Force
    }
    $Error.Clear()
}
function Dismount {
    if (Test-Path $mntdir) {
        Write-Host "Dismounting image and discarding changes..." -ForegroundColor yellow
        Dismount-WindowsImage -Path $mntdir -Discard -LogLevel 1 | Out-Null
        $Error.Clear()
    }
}
function AbortOnError {
    if ($Error.Count -ne 0) {
        Write-Host 'Something is proper fucked, try again I guess.' -ForegroundColor red
        Dismount
        Cleanup
        DoExit
    }
}
function CheckAbort {
    $errors = $Error.Count
    if ($errors -ne 0) {
        $choice = Read-Host "${errors} error(s) occurred, continue? (Y/n)"
        if ($choice -eq 'n') {
            Dismount
            Cleanup
            DoExit
        }
        $Error.Clear()
    }
}
function CrapRemoval {
    foreach ($f in $folders) {
        # takeown won't match * on directories for me, so i do this instead ...
        $items = Get-ChildItem -Path "${mntdir}${f}" -Force
        foreach ($i in $items) {
            Write-Host "Removing ${i} ..."
            takeown /f $i.FullName /r /d $yes | Out-Null
            icacls $i.FullName /grant ("$env:username"+":F") /T /C | Out-Null
            Remove-Item -Path $i.FullName -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    foreach ($f in $files) {
        Write-Host "Removing ${mntdir}${f} ..."
        takeown /f "${mntdir}${f}" | Out-Null
        icacls "${mntdir}${f}" /grant ("$env:username"+":F") /T /C | Out-Null
        Remove-Item "${mntdir}${f}" -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $Error.Clear()
}
# shamelessly ripped from https://github.com/ianis58/tiny11builder/tree/main
function InstallRegistryShit {
    Write-Host 'Loading install registry ...'
    reg load HKLM\installwim_DEFAULT "${mntdir}\Windows\System32\config\default" | Out-Null
    reg load HKLM\installwim_NTUSER "${mntdir}\Users\Default\ntuser.dat" | Out-Null
    reg load HKLM\installwim_SOFTWARE "${mntdir}\Windows\System32\config\SOFTWARE" | Out-Null
    reg load HKLM\installwim_SYSTEM "${mntdir}\Windows\System32\config\SYSTEM" | Out-Null
    Write-Host 'Modifying registry ...'
    regedit /s $install_reg | Out-Null
    Write-Host 'Unloading install registry ...'
    reg unload HKLM\installwim_DEFAULT | Out-Null
	reg unload HKLM\installwim_NTUSER | Out-Null
	reg unload HKLM\installwim_SOFTWARE | Out-Null
	reg unload HKLM\installwim_SYSTEM | Out-Null
}
# shamelessly ripped from https://github.com/ianis58/tiny11builder/tree/main
function BootRegistryShit {
    Write-Host 'Loading boot registry ...'
    reg load HKLM\bootwim_DEFAULT "${mntdir}\Windows\System32\config\default" | Out-Null
	reg load HKLM\bootwim_NTUSER "${mntdir}\Users\Default\ntuser.dat" | Out-Null
	reg load HKLM\bootwim_SYSTEM "${mntdir}\Windows\System32\config\SYSTEM" | Out-Null
    Write-Host 'Modifying registry ...'
    regedit /s $boot_reg | Out-Null
    Write-Host 'Unloading boot registry ...'
    reg unload HKLM\bootwim_DEFAULT | Out-Null
	reg unload HKLM\bootwim_NTUSER | Out-Null
	reg unload HKLM\bootwim_SYSTEM | Out-Null
}
Dismount
Cleanup
if (Test-Path $output) {
    $choice = Read-Host "${output} already exists, delete it and continue? (Y/n)"
    if ($choice -eq 'n') {
        DoExit
    }
    Remove-Item -Path $output -Force
    AbortOnError # file is in use
}
$drives = Get-Volume | Select-Object -Property DriveLetter -ExpandProperty DriveLetter
$drive = $null
foreach ($d in $drives) {
    if ((Test-Path "${d}:\sources\install.wim") -and (Test-Path "${d}:\sources\boot.wim")) {
        $choice = Read-Host "Windows setup found on drive ${d}, use it? (y/N)"
        if ($choice -eq 'y') {
            $wim = 'install.wim'
            $drive = $d
            break
        }
    }
    #elseif ((Test-Path "${d}:\sources\install.esd") -and (Test-Path "${d}:\sources\boot.wim")) {
    #     $choice = Read-Host "Windows setup found on drive ${d}, use it? (y/N)"
    #     if ($choice -eq 'y') {
    #         $wim = 'install.esd'
    #         $drive = $d
    #         break
    #     }
    #}
}
if ($null -eq $drive) {
    Write-Host 'Windows setup not found, please mount the ISO and try again...' -ForegroundColor red
    DoExit
}
Write-Host "Copying installation media to ${tempdir}..."
New-Item -Path $tempdir -ItemType Directory -Force | Out-Null
Copy-Item "${drive}:\*" $tempdir -Recurse -Force | Out-Null
Write-Host "Copying complete."
Set-ItemProperty -Path "${tempdir}\sources\${wim}" -Name IsReadOnly -Value $false
$image_info = Get-WindowsImage -ImagePath "${tempdir}\sources\${wim}"
# if there's only one image, select it automatically. probably always 1? fuck if i know
if ($image_info.Count -eq 1) {
    $index = $image_info[0].ImageIndex
}
else {
    foreach ($i in $image_info) {
        $num = $i.ImageIndex
        $name = $i.ImageName
        $size = ($i.ImageSize -as [float]) / 1073741824.0
        Write-Host "ImageIndex ${num} = ${name}, size = ${size} GiB"
    }
    $index = Read-Host 'Enter ImageIndex to process'
}
# well this shit didn't work
#if ($wim -eq 'install.esd') {
#    Write-Host "Converting ESD to WIM ..."
#    Export-WindowsImage -SourceImagePath "${tempdir}\sources\install.esd" -DestinationImagePath "${tempdir}\sources\install.wim" -SourceIndex $index -CheckIntegrity | Out-Null
#    AbortOnError
#    $index = 1
#}
Write-Host 'Mounting image...'
New-Item -Path $mntdir -ItemType Directory -Force | Out-Null
Mount-WindowsImage -Path $mntdir -ImagePath "${tempdir}\sources\install.wim" -Index $index -LogLevel 1 | Out-Null
$app_info = Get-AppxProvisionedPackage -Path $mntdir -LogLevel 1
foreach ($x in $app_info) {
    foreach ($k in $apps.Keys.Clone()) {
        if ($x.DisplayName.ToLower().Contains($k.ToLower())) {
            $pkg = $x.PackageName
            # count how many times we find each entry
            $apps[$k] += 1
            Write-Host "Removing app: ${pkg} ..."
            Remove-AppxProvisionedPackage -Path $mntdir -PackageName $pkg -LogLevel 1 | Out-Null
            CheckAbort
        }
    }
}
foreach ($kv in $apps.GetEnumerator()) {
    if ($kv.Value -eq 0) {
        $key = $kv.Key
        Write-Host "No matching application found for this search pattern: ${key}" -ForegroundColor yellow
    }
}
$pkg_info = Get-WindowsPackage -Path $mntdir -LogLevel 1
Write-Host 'Removing packages, a few errors in this section is normal ...'
foreach ($x in $pkg_info) {
    foreach ($k in $pkgs.Keys.Clone()) {
        if ($x.PackageName.ToLower().Contains($k.ToLower())) {
            $pkg = $x.PackageName
            $pkgs[$k] += 1
            Write-Host "Removing Windows package: ${pkg}"
            Remove-WindowsPackage -Path $mntdir -PackageName $pkg -ErrorAction SilentlyContinue -LogLevel 1 | Out-Null
        }
    }
}
$Error.Clear()
foreach ($kv in $pkgs.GetEnumerator()) {
    if ($kv.Value -eq 0) {
        $key = $kv.Key
        Write-Host "No matching package found for this search pattern: ${key}" -ForegroundColor yellow
    }
}
CrapRemoval
Copy-Item $unattend "${mntdir}\Windows\System32\Sysprep\autounattend.xml"
InstallRegistryShit
CheckAbort
Write-Host 'Dismounting image ...'
Dismount-WindowsImage -Path $mntdir -Save -CheckIntegrity -LogLevel 1 | Out-Null
Write-Host 'Exporting image ...'
Export-WindowsImage -SourceImagePath "${tempdir}\sources\${wim}" -DestinationImagePath "${tempdir}\sources\${wim}.new" -SourceIndex $index -CompressionType 'max' -LogLevel 1 | Out-Null
AbortOnError
Remove-Item -Path "${tempdir}\sources\${wim}"
Rename-Item -Path "${tempdir}\sources\${wim}.new" -NewName "${tempdir}\sources\${wim}"
Write-Host "${wim} completed. Continuing with boot.wim ..."
Set-ItemProperty -Path "${tempdir}\sources\boot.wim" -Name IsReadOnly -Value $false
Mount-WindowsImage -Path $mntdir -ImagePath "${tempdir}\sources\boot.wim" -Index 2 -LogLevel 1 | Out-Null
AbortOnError
BootRegistryShit
Write-Host 'Dismounting image ...'
Dismount-WindowsImage -Path $mntdir -Save -CheckIntegrity -LogLevel 1 | Out-Null
Copy-Item $unattend "${tempdir}\autounattend.xml"
Write-Host "Creating ISO at ${output} ..."
Invoke-Expression $isocommand
Cleanup
DoExit