; Inno Setup script for Tesseract Crypt (Windows x64).
;
; Built by .github/workflows/release.yml.  Expects a staging directory
; ("stage" at the repository root) containing the built binaries, the
; LICENSE file and any required runtime DLLs (e.g. libsodium.dll).
;
; The application version can be overridden from the command line:
;     iscc "/DAppVersion=1.2.3" packaging\windows\tesseract-crypt.iss

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

#define AppName "Tesseract Crypt"
#define AppPublisher "adyoi"
#define AppURL "https://github.com/adyoi/tesseract-crypt"
#define AppExeName "tesseract-crypt.exe"

[Setup]
AppId={{9E5B6C3A-2F47-4D9E-8C1A-7B3F2A6D5E10}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\..\stage\LICENSE
OutputDir=..\..\dist
OutputBaseFilename=tesseract-crypt-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
UninstallDisplayName={#AppName} {#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add {#AppName} to the system &PATH"; \
    GroupDescription: "Integration:"; Flags: checkedonce

[Files]
Source: "..\..\stage\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\stage\tscrypt.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\stage\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\stage\*.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
    ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}'); \
    Tasks: addtopath

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  { Look for the path surrounded by semicolons, including start/end. }
  Result := Pos(';' + Uppercase(Param) + ';',
                ';' + Uppercase(OrigPath) + ';') = 0;
end;
