#ifndef AppSource
  #error AppSource must be supplied by Build-AndShip.ps1
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by Build-AndShip.ps1
#endif
#ifndef AppVersion
  #define AppVersion "9.0.0"
#endif
#ifndef GitShort
  #error GitShort must be supplied by Build-AndShip.ps1
#endif
#ifndef PublisherName
  #error PublisherName must be supplied by Build-AndShip.ps1
#endif

[Setup]
AppId={{6D05062C-1C0E-4C39-A906-FAD7D5CC65F2}
AppName=DefenseTracker
AppVersion={#AppVersion}
AppVerName=DefenseTracker V9 ({#GitShort})
AppPublisher={#PublisherName}
DefaultDirName={localappdata}\Programs\DefenseTracker
DefaultGroupName=DefenseTracker
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=DefenseTracker-Setup-{#GitShort}
UninstallDisplayIcon={app}\DefenseTracker.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
VersionInfoVersion=9.0.0.0
VersionInfoCompany={#PublisherName}
VersionInfoDescription=DefenseTracker V9 installer
VersionInfoProductName=DefenseTracker
VersionInfoProductVersion={#AppVersion}

[Files]
Source: "{#AppSource}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\DefenseTracker"; Filename: "{app}\DefenseTracker.exe"; WorkingDir: "{app}"

[Run]
Filename: "{app}\DefenseTracker.exe"; Description: "Launch DefenseTracker"; Flags: nowait postinstall skipifsilent unchecked
