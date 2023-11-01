# ps_tiny11

A PowerShell version of [tiny11builder](https://github.com/ntdevlabs/tiny11builder).

This is literally the first PowerShell script I've ever written.

Changes from tiny11builder:

- Items to remove are searched for by substring.  
If an item name is adjusted slightly in a new build this script should hopefully still find it.  For instance, instead of "Microsoft-Windows-InternetExplorer-Optional-Package\~31bf3856ad364e35\~amd64\~\~11.0.22621.1702", this script searches for "InternetExplorer" in the setup image and gets the full package name from there.
- ps_tiny11 will tell you about items it doesn't find on the setup image
- Explorer ads, lockscreen ads, and Windows tips are disabled.  Info source: (<https://winaero.com/how-to-disable-ads-in-windows-11/>)
- Additional tweaks that I found here: (<https://github.com/ianis58/tiny11builder/tree/main/tools>)
- ps_tiny11 will search drives for a Windows setup image and prompt for confirmation
- If there's only one ImageIndex in the install.wim, it will automatically be selected
- Various sanity checks
- I discovered (<https://github.com/ianis58/tiny11builder>) after I wrote my version, and liked their registry technique (I almost did it that way too when I added some), so I updated mine

This is a script to automate the build of a streamlined Windows 11 image.

Like tiny11builder, oscdimg.exe is included for creating the ISO.

Also included is an unattended answer file, which is used to bypass the MS account on OOBE and to deploy the image with the /compact flag.

Tested on Windows 11, version 22H2 (22621.2428) amd64, and (22621.1702).  Other builds should mostly work.

Instructions:

1. Download Windows 11 from [UUPDump](https://uupdump.net/) (don't use ESD compression) or from the Microsoft website (<https://www.microsoft.com/software-download/windows11>).
2. Mount the downloaded ISO image using Windows Explorer (double-click it)
3. Right-click ps_tiny11.ps1 and select 'Run with PowerShell'.  It will ask for Admin privileges.
4. Select the drive letter where the image is mounted
5. If installation image contains more than one version of Windows 11, select which one to process
6. Chill for a bit, yah?
7. After it's done, if shit didn't break, you will have ps_tiny11.iso

What is removed:

Windows 11 hardware requirements,  
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
OneDrive,  
WebExperience  

Known issues:

I'm not 100% sure, I've tested a few installations in VM to confirm registry changes, but I haven't tested further.  I'll be testing on hardware later this week.  
I have code in there that should convert install.esd to install.wim, but it doesn't seem to do shit, so it's commented out.  Don't use ESD compression if you want to use this script.  

Changelog:

31-10-2023:  

- Updated registry tweaks and file/folder removal to be like this project, and added some tweaks from there: (<https://github.com/ianis58/tiny11builder/tree/main/tools>)  
- I removed the RunAsTI snippet and the failed attempt at the Teams registry tweak.  
- Removed unnecessary reg loads/unloads  
- Replaced autoattend.xml with the one from (<https://github.com/bravomail/tinier11/blob/main/autounattend.xml>), thanks bravomail!
- WebExperience is no longer removed

