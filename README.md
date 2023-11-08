# ps_tiny11

A PowerShell version of [tiny11builder](https://github.com/ntdevlabs/tiny11builder).

This is a script to automate the build of a streamlined Windows 11 image ***or modify currently running Windows 11***.  Many privacy related and other tweaks are applied as well, please read this entire document before use.

#### Changes from tiny11builder:

- Items to remove are searched for by case-insensitive substring.  If an item name is adjusted slightly in a new build this script should hopefully still find it.  For instance, instead of "Microsoft-Windows-InternetExplorer-Optional-Package\~31bf3856ad364e35\~amd64\~\~11.0.22621.1702", this script searches for "InternetExplorer" in the setup image and gets the full package name from there.
- ps_tiny11 will tell you about items it doesn't find in the setup image
- ps_tiny11 will search drives for a Windows setup image and prompt for confirmation
- If no Windows installer found, prompt to modify running Windows
- If there's only one ImageIndex in the install.wim, it will automatically be selected
- Various sanity checks
- Many additional tweaks
- Modify hosts file to block telemetry servers

Like tiny11builder, oscdimg.exe is included for creating the ISO.

Also included is an unattended answer file, which is used to bypass the MS account on OOBE and apply HKCU registry tweaks.

I've tried to improve privacy a fair bit, but it only scratches the surface.  I recommend using [O&O ShutUp10++](https://www.oo-software.com/en/shutup10) to do a better job.

Tested on Windows 11 version 22H2 (22621.2428) amd64 and (22621.1702).  Other builds should mostly work.

#### Instructions to build ISO:

1. Download Windows 11 from [UUPDump](https://uupdump.net/) (don't use ESD compression) or from the Microsoft website (<https://www.microsoft.com/software-download/windows11>).
2. Mount the downloaded ISO image using Windows Explorer (double-click it)
3. Right-click ps_tiny11.ps1 and select 'Run with PowerShell'.  It will ask for Admin privileges.
4. Select the drive letter where the image is mounted
5. If installation image contains more than one version of Windows 11, select which one to process
6. Chill for a bit, yah?
7. After it's done, if shit didn't break, you will have ps_tiny11.iso

#### Instructions to modify currently running Windows 11:

1. Right-click ps_tiny11.ps1 and select 'Run with PowerShell'.  It will ask for Admin privileges.  Explorer will be restarted to apply changes.

#### What is removed:

Clipchamp,  
News,  
Weather,  
Xbox (although Xbox Identity provider is still here, so it should be possible to be reinstalled with no issues),  
GetHelp,  
GetStarted,  
Office Hub,  
Solitaire,  
PeopleApp,  
PowerAutomate,  
ToDo,  
Alarms,  
Mail and Calendar,  
Feedback Hub,  
Maps,  
Sound Recorder,  
Your Phone,  
Media Player,  
QuickAssist,  
Internet Explorer,  
LA57 support,  
OCR,  
Speech support,  
TTS,  
Media Player Legacy,  
Tablet PC Math,  
Wallpapers,  
Edge,  
OneDrive 

#### Tweaks applied:

Remove Windows 11 hardware requirements,  
Disable Teams,  
Disable Sponsored apps,  
Enable local accounts,  
Disable reserved storage,  
Disable chat icon,  
Disable new right click context menu,  
Disable Search icon in taskbar,  
Disable Windows tips,  
Disable Explorer ads,  
Disable lockscreen ads,  
Disable Windows Platform Binary Table (untested)([source](https://www.powershellgallery.com/packages/Disable-WpbtExecution/1.0.5)),  
Dark mode  

#### Group Policy tweaks([source](https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.CloudContent::DisableWindowsConsumerFeatures)):

#### Changes to default security options are ***emphasized***, Windows Defender real-time protection etc. is still on by default

***Disable Windows Defender SmartScreen***,  
***Disable Windows Defender cloud protection***,  
***Turn off routine remediation (ask user what to do when malware is found)***,  
Turn off cloud consumer account state content,  
Turn off Automatic Download and Update of Map Data,    
Turn off cloud optimized content,  
Turn off Microsoft consumer experiences,  
Lowest telemetry setting,  
Do not allow sending intranet or internet history,  
Limit Diagnostic Log Collection,  
Limit Dump Collection,  
Turn off desktop gadgets,  
Turn off collection of InPrivate Filtering data,  
Disallow Microsoft Edge to pre-launch at Windows startup, when the system is idle, and each time Microsoft Edge is closed,  
Disallow Microsoft Edge to start and load the Start and New Tab page at Windows startup and each time Microsoft Edge is closed,  
Disable news and interests on the taskbar,  
Disable Cloud Search,  
Disable Cortana,  
Don't search the web or display web results in Search,  
Disable Cortana above lock screen,  
No auto-restart with logged on users for scheduled automatic updates installations,  
Disable widgets,  
Disable "Improve inking and typing recognition" AKA text input data collection,  
Don't launch privacy settings experience on user logon,  
Disable Windows Error Reporting  

#### Hostnames added to hosts file ([source](https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints)):

business.bing.com,  
c.bing.com,  
th.bing.com,  
c-ring.msedge.net,  
fp.msedge.net,  
I-ring.msedge.net,  
s-ring.msedge.net,  
dual-s-ring.msedge.net,  
creativecdn.com,  
edgeassetservice.azureedge.net,  
r.bing.com,  
a-ring-fallback.msedge.net,  
fp-afd-nocache-ccp.azureedge.net,  
prod-azurecdn-akamai-iris.azureedge.net,  
widgetcdn.azureedge.net,  
widgetservice.azurefd.net,  
dmd.metaservices.microsoft.com,  
functional.events.data.microsoft.com,  
browser.events.data.msn.com,  
self.events.data.microsoft.com,  
v10.events.data.microsoft.com,  
telecommand.telemetry.microsoft.com,  
www.telecommandsvc.microsoft.com,  
checkappexec.microsoft.com,  
ping-edge.smartscreen.microsoft.com,  
data-edge.smartscreen.microsoft.com,  
nav-edge.smartscreen.microsoft.com,  
edge.microsoft.com,  
windows.msn.com,  
iecvlist.microsoft.com,  
msedge.api.cdp.microsoft.com,  
manage.devcenter.microsoft.com,  
config.teams.microsoft.com,  
teams.live.com,  
teams.events.data.microsoft.com,  
statics.teams.cdn.live.net,  
arc.msn.com,  
ris.api.iris.microsoft.com,  
api.msn.com,  
c.msn.com,  
ntp.msn.com,  
srtb.msn.com,  
fd.api.iris.microsoft.com,  
staticview.msn.com

#### How to Modify:

Top of ps_tiny11.ps1 contains apps, packages, files and folders to remove, and hostnames to be blocked.  Comment out lines that you want to skip with '#'.  

installwim_patches.reg contains the tweaks, comment out unwanted ones by adding ';' in front of them, they're labeled.

#### Known issues:

I'm not 100% sure, still testing.  I've tested offline/online on hardware and many times in VM, nothing seems to be broken.  Disabling Windows Platform Binary Table may or may not work.

I have code in there that should convert install.esd to install.wim, but it doesn't seem to do shit, so it's commented out.  Don't use ESD compression if you want to use this script.  

#### Changelog:

31-10-2023:  

- Updated registry tweaks and file/folder removal to be like this project, and added some tweaks from there: (<https://github.com/ianis58/tiny11builder/tree/main/tools>)  
- Removed the RunAsTI snippet and the failed attempt at the Teams registry tweak.   
- Replaced autoattend.xml with the one from (<https://github.com/bravomail/tinier11/blob/main/autounattend.xml>), thanks bravomail!
- WebExperience is no longer removed

07-11-2023:

- Reorganize code a bit, can now modify currently running Windows
- Group Policy tweaks added ([source](https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.CloudContent::DisableWindowsConsumerFeatures))
- autounattend.xml now modifies registry to enable old context menu (do i need to add other tweaks there?)
- Modify hosts file to block telemetry servers ([source](https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints))