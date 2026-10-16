; Inno Setup script for Tesseract Crypt (Windows x64 and x86).
;
; Built by .github/workflows/release.yml.  Expects a staging directory
; ("stage" at the repository root) containing the built binaries, the
; LICENSE file and any required runtime DLLs (e.g. libsodium.dll).
;
; Command line overrides:
;     iscc "/DAppVersion=1.2.3" packaging\windows\tesseract-crypt.iss   (x64)
;     iscc "/DAppVersion=1.2.3" "/DArchX86" packaging\windows\tesseract-crypt.iss
; Define ArchX86 for the 32-bit build; omit it for x64.

#ifndef AppVersion
  #define AppVersion "1.0.3"
#endif

#ifdef ArchX86
  #define ArchTag "x86"
  #define ArchAllowed "x86compatible"
  #define ArchAppId "{{7C4D2E9B-8A31-4F52-B6D0-1E5A9C3F7B24}"
#else
  #define ArchTag "x64"
  #define ArchAllowed "x64compatible"
  #define ArchAppId "{{9E5B6C3A-2F47-4D9E-8C1A-7B3F2A6D5E10}"
#endif

#define AppName "Tesseract Crypt"
#define AppPublisher "adyoi"
#define AppURL "https://github.com/adyoi/tesseract-crypt"
#define AppExeName "tesseract-crypt.exe"

[Setup]
AppId={#ArchAppId}
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
OutputBaseFilename=tesseract-crypt-{#AppVersion}-windows-{#ArchTag}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed={#ArchAllowed}
#ifndef ArchX86
ArchitecturesInstallIn64BitMode=x64compatible
#endif
; Per-user install: no UAC, and HKCU PATH is definitely the invoking user's.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline
ChangesEnvironment=yes
UninstallDisplayName={#AppName} {#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add {#AppName} to &PATH (recommended)"; \
    GroupDescription: "Command line:"; Flags: checkedonce

[Files]
Source: "..\..\stage\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\stage\tscrypt.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\stage\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\stage\*.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Registry]
; Append {app} to the per-user PATH (only when the task is selected and the
; entry is not already present).  ChangesEnvironment=yes makes Setup broadcast
; WM_SETTINGCHANGE so newly launched programs see the update.
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
    ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}'); \
    Tasks: addtopath

[Code]
{ True when Param is not already one of the ';'-separated PATH entries. }
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';',
                ';' + Uppercase(OrigPath) + ';') = 0;
end;

{ Remove a single entry from the per-user PATH, leaving the rest intact. }
procedure RemovePathEntry(const Entry: string);
var
  Path: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Path) then
    exit;
  StringChangeEx(Path, ';' + Entry, '', False);
  StringChangeEx(Path, Entry + ';', '', False);
  if Uppercase(Path) = Uppercase(Entry) then
    Path := '';
  RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Path);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemovePathEntry(ExpandConstant('{app}'));
end;

{ Tell the user why the command is not visible in an already-open shell. }
procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
    WizardForm.FinishedLabel.Caption := WizardForm.FinishedLabel.Caption +
      Chr(13) + Chr(10) + Chr(13) + Chr(10) +
      'Open a new terminal so that "tesseract-crypt" and "tscrypt" are ' +
      'available on PATH.';
end;
