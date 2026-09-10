#define MyAppName "SuperWall Kids"
#define MyAppVersion "0.2.0"
#define MyPublisher "Bendemen Studios"
#define MyExeName "SuperWall.Agent.exe"

[Setup]
AppId={{9C6F5B93-A4C4-4A3E-9B2E-5D1A8E2A4B7C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyPublisher}
DefaultDirName={autopf}\SuperWall Kids
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\publish\installer
OutputBaseFilename=SuperWall-Kids-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
Uninstallable=no

[Files]
Source: "..\publish\agent\SuperWall.Agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\SuperWall"

[Code]
var
  DashboardPage: TInputQueryWizardPage;
  EnrollmentPage: TInputQueryWizardPage;

function IsValidHttpsUrl(const Value: string): Boolean;
begin
  Result := (Pos('https://', LowerCase(Value)) = 1) and (Length(Value) > 8);
end;

procedure InitializeWizard;
begin
  DashboardPage := CreateInputQueryPage(wpWelcome,
    'SuperWall Kids koppelen',
    'Centrale dashboard-server',
    'Vul de HTTPS-adres van het SuperWall dashboard in.');
  DashboardPage.Add('Dashboard URL:', False);
  DashboardPage.Values[0] := 'https://';

  EnrollmentPage := CreateInputQueryPage(DashboardPage.ID,
    'Apparaat registreren',
    'Enrollment key',
    'Deze bootstrap-key koppelt deze Windows-pc aan je SuperWall-installatie.');
  EnrollmentPage.Add('Enrollment key:', True);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = DashboardPage.ID then
  begin
    if not IsValidHttpsUrl(DashboardPage.Values[0]) then
    begin
      MsgBox('Gebruik een geldige HTTPS dashboard URL.', mbError, MB_OK);
      Result := False;
    end;
  end
  else if CurPageID = EnrollmentPage.ID then
  begin
    if Length(Trim(EnrollmentPage.Values[0])) < 16 then
    begin
      MsgBox('De enrollment key lijkt ongeldig.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  DashboardUrl, EnrollmentKey, AgentPath: string;
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then Exit;

  DashboardUrl := DashboardPage.Values[0];
  EnrollmentKey := EnrollmentPage.Values[0];
  AgentPath := ExpandConstant('{app}\{#MyExeName}');

  RegWriteStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'SUPERWALL_DASHBOARD', DashboardUrl);
  RegWriteStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'SUPERWALL_ENROLLMENT_KEY', EnrollmentKey);

  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'delete SuperWallAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'create SuperWallAgent binPath= "' + AgentPath + '" start= auto obj= LocalSystem DisplayName= "SuperWall Kids"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'description SuperWallAgent "SuperWall Kids offline-first parental control service"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'failure SuperWallAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'start SuperWallAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;
