# this script is based on https://github.com/ntdevlabs/tiny11builder
# and i never would've created this without prior work by ntdevlabs
using namespace System.Text.RegularExpressions
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
    # https://github.com/ntdevlabs/tiny11builder/issues/56
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
    # https://github.com/ntdevlabs/tiny11builder/issues/93
    'MicrosoftWindows.Client.WebExperience'  = 0;
    # not actually in my image, so this is a guess
    'MicrosoftTeams'                         = 0;
}
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList "-File `"$($PSCommandPath)`""
    Exit
}
$Error.Clear()
# source: https://github.com/AveYo/LeanAndMean/blob/main/RunAsTI.ps1
# this is MIT licensed by AveYo, see 'RunAsTI_LICENSE' for more information
function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
} # lean & mean snippet by AveYo, 2022.01.28
function DoExit {
    Write-Host 'Finished.  Press Enter to continue...'
    $null = $Host.UI.ReadLine()
    Exit
}
function Cleanup {
    Write-Host "Removing: ${tempdir} ..."
    Remove-Item -path $tempdir -Recurse -Force
    Write-Host "Removing: ${mntdir} ..."
    Remove-Item -path $mntdir -Recurse -Force
}
function Dismount {
    Write-Host "Dismounting image and discarding changes..." -ForegroundColor yellow
    Dismount-WindowsImage -Path $mntdir -Discard -LogLevel 1 | Out-Null
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
    if (Test-Path "${mntdir}\Program Files (x86)\Microsoft\Edge") {
        Write-Host 'Removing Edge ...'
        Remove-Item -path "${mntdir}\Program Files (x86)\Microsoft\Edge" -Recurse -Force
        Remove-Item -path "${mntdir}\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force
    }
    if (Test-Path "${mntdir}\Windows\System32\OneDriveSetup.exe") {
        Write-Host 'Removing OneDrive ...'
        #takeown /f "${mntdir}\Windows\System32\OneDriveSetup.exe"
        #icacls "${mntdir}\Windows\System32\OneDriveSetup.exe" /grant Administrators:F /T /C
        #Remove-Item -Path "${mntdir}\Windows\System32\OneDriveSetup.exe" -Force
        RunAsTI powershell "Remove-Item -Path ${mntdir}\Windows\System32\OneDriveSetup.exe -Force"
    }
    CheckAbort
}
# shamelessly ripped from https://github.com/ntdevlabs/tiny11builder
function WinRegistryShit {
    Write-Host 'Loading registry ...'
    reg load HKLM\zCOMPONENTS "${mntdir}\Windows\System32\config\COMPONENTS" | Out-Null
    reg load HKLM\zDEFAULT "${mntdir}\Windows\System32\config\default" | Out-Null
    reg load HKLM\zNTUSER "${mntdir}\Users\Default\ntuser.dat" | Out-Null
    reg load HKLM\zSOFTWARE "${mntdir}\Windows\System32\config\SOFTWARE" | Out-Null
    reg load HKLM\zSYSTEM "${mntdir}\Windows\System32\config\SYSTEM" | Out-Null
    Write-Host 'Bypassing system requirements(on the system image) ...'
    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d "1" /f | Out-Null
    Write-Host 'Disabling Teams (maybe)...'
    # this should work, i think?  but it doesn't seem to be...
    RunAsTI reg 'add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d "0"'
    Write-Host 'Disabling Sponsored Apps ...'
    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f | Out-Null
    reg add 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' /v 'ConfigureStartPins' /t REG_SZ /d '{"pinnedList": [{}]}' /f | Out-Null
    Write-Host 'Enabling Local Accounts on OOBE ...'
    reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d "1" /f | Out-Null
    Copy-Item $unattend "${mntdir}\Windows\System32\Sysprep\autounattend.xml"
    Write-Host 'Disabling Reserved Storage ...'
    reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f | Out-Null
    Write-Host 'Disabling Chat icon ...'
    reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d "3" /f | Out-Null
    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f | Out-Null
    # tweaks below here are added by me (0xDEADFED5), so if they suck it's my fault
    # source: https://winaero.com/how-to-disable-ads-in-windows-11/
    Write-Host 'Disabling Explorer ads ...'
    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f | Out-Null
    Write-Host 'Disabling ads on lockscreen ...'
    reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f | Out-Null
    Write-Host 'Disabling tips ...'
    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f | Out-Null
    Write-Host 'Tweaking complete!'
    Write-Host 'Unloading registry ...'
    reg unload HKLM\zCOMPONENTS | Out-Null
    #reg unload HKLM\zDRIVERS | Out-Null
    reg unload HKLM\zDEFAULT | Out-Null
    reg unload HKLM\zNTUSER | Out-Null
    #reg unload HKLM\zSCHEMA | Out-Null
    reg unload HKLM\zSOFTWARE | Out-Null
    reg unload HKLM\zSYSTEM | Out-Null
}
# shamelessly ripped from https://github.com/ntdevlabs/tiny11builder
function BootRegistryShit {
    Write-Host 'Loading registry ...'
    reg load HKLM\zCOMPONENTS "${mntdir}\Windows\System32\config\COMPONENTS" | Out-Null
    reg load HKLM\zDEFAULT "${mntdir}\Windows\System32\config\default" | Out-Null
    reg load HKLM\zNTUSER "${mntdir}\Users\Default\ntuser.dat" | Out-Null
    reg load HKLM\zSOFTWARE "${mntdir}\Windows\System32\config\SOFTWARE" | Out-Null
    reg load HKLM\zSYSTEM "${mntdir}\Windows\System32\config\SYSTEM" | Out-Null
    Write-Host 'Bypassing system requirements (on the setup image) ...'
    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d "1" /f | Out-Null
    reg add "HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d "1" /f | Out-Null
    Write-Host 'Tweaking complete!'
    Write-Host 'Unloading registry ...'
    reg unload HKLM\zCOMPONENTS | Out-Null
    #reg unload HKLM\zDRIVERS | Out-Null
    reg unload HKLM\zDEFAULT | Out-Null
    reg unload HKLM\zNTUSER | Out-Null
    #reg unload HKLM\zSCHEMA | Out-Null
    reg unload HKLM\zSOFTWARE | Out-Null
    reg unload HKLM\zSYSTEM | Out-Null
}
$tempdir = 'C:\ps_tiny11'
$mntdir = 'C:\tiny11mnt'
$output = Join-Path $PSScriptRoot 'ps_tiny11.iso'
$isomaker = Join-Path $PSScriptRoot 'oscdimg.exe'
$unattend = Join-Path $PSScriptRoot 'autounattend.xml'
$isocommand = $isomaker + ' -m -o -u2 -udfver102 -bootdata:2#p0,e,b' + "${tempdir}\boot\etfsboot.com" + '#pEF,e,b' + "${tempdir}\efi\microsoft\boot\efisys.bin" + " ${tempdir}" + " ${output}"
if (Test-Path $mntdir) {
    Write-Host 'Previous image is possibly still mounted.' -ForegroundColor yellow
    Dismount
    Remove-Item -Path $mntdir -Recurse -Force
    $Error.Clear()
}
if (Test-Path $tempdir) {
    Write-Host "Cleaning up temp files..."  -ForegroundColor yellow
    Remove-Item -Path $tempdir -Recurse -Force
}
if (Test-Path $output) {
    $choice = Read-Host "${output} already exists, delete it and continue? (Y/n)"
    if ($choice -eq 'n') {
        DoExit
    }
    Remove-Item -Path $output -Force
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
CheckAbort
$app_info = Get-AppxProvisionedPackage -Path $mntdir -LogLevel 1 | Select-Object -Property DisplayName, PackageName
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
$pkg_info = Get-WindowsPackage -Path $mntdir -LogLevel 1 | Select-Object PackageName
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
WinRegistryShit
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