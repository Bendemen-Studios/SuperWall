#define MyAppName "SuperWall Kids"
#define MyAppVersion "0.4.1"
#define MyPublisher "Bendemen Studios"
#define MyExeName "SuperWall.Agent.exe"
#define ServiceSddl "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCRP;;;AU)"

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

function IsUpgrade: Boolean;
begin
  Result := WizardSilent and (CompareText(ExpandConstant('{param:UPGRADE|}'), '1') = 0);
end;

function IsValidHttpsUrl(const Value: string): Boolean;
begin
  Result := (Pos('https://', LowerCase(Value)) = 1) and (Length(Value) > 8);
end;

function RunHidden(const FileName, Params: string): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure InitializeWizard;
begin
  DashboardPage := CreateInputQueryPage(wpWelcome,
    'SuperWall Kids koppelen',
    'Centrale dashboard-server',
    'Vul het HTTPS-adres van het SuperWall dashboard in.');
  DashboardPage.Add('Dashboard URL:', False);
  DashboardPage.Values[0] := 'https://superwall.hvmc.nl';

  EnrollmentPage := CreateInputQueryPage(DashboardPage.ID,
    'Apparaat registreren',
    'Enrollment key',
    'Deze eenmalige bootstrap-key koppelt deze Windows-pc aan je SuperWall-installatie.');
  EnrollmentPage.Add('Enrollment key:', True);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := IsUpgrade and ((PageID = DashboardPage.ID) or (PageID = EnrollmentPage.ID));
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
  DashboardUrl, EnrollmentKey, AgentPath, EnrollmentFile, DashboardFile, AppDir, CommonDir: string;
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then Exit;

  AgentPath := ExpandConstant('{app}\{#MyExeName}');
  AppDir := ExpandConstant('{app}');
  CommonDir := ExpandConstant('{commonappdata}\SuperWall');
  EnrollmentFile := CommonDir + '\enrollment.key';
  DashboardFile := CommonDir + '\dashboard.url';

  if not DirExists(CommonDir) then
    ForceDirectories(CommonDir);

  if not IsUpgrade then
  begin
    DashboardUrl := DashboardPage.Values[0];
    EnrollmentKey := Trim(EnrollmentPage.Values[0]);
    SaveStringToFile(DashboardFile, DashboardUrl, False);
    SaveStringToFile(EnrollmentFile, EnrollmentKey, False);
    RegWriteStringValue(HKEY_LOCAL_MACHINE,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'SUPERWALL_DASHBOARD', DashboardUrl);
  end;

  RunHidden(ExpandConstant('{sysnative}\icacls.exe'),
    '"' + CommonDir + '" /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" "Users:(OI)(CI)(RX)" /deny "Users:(OI)(CI)(W,DC,WDAC,WEA)"');
  if FileExists(EnrollmentFile) then
    RunHidden(ExpandConstant('{sysnative}\icacls.exe'),
      '"' + EnrollmentFile + '" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"');
  if FileExists(DashboardFile) then
    RunHidden(ExpandConstant('{sysnative}\icacls.exe'),
      '"' + DashboardFile + '" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"');
  RunHidden(ExpandConstant('{sysnative}\icacls.exe'),
    '"' + AppDir + '" /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" "Users:(OI)(CI)(RX)" /deny "Users:(OI)(CI)(W,DC,WDAC,WEA)"');

  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'stop SuperWallAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'delete SuperWallAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'create SuperWallAgent binPath= "' + AgentPath + '" start= auto obj= LocalSystem DisplayName= "SuperWall Kids"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'description SuperWallAgent "SuperWall Kids offline-first parental control service"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'sdset SuperWallAgent {#ServiceSddl}',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'failure SuperWallAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'failureflag SuperWallAgent 1', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'start SuperWallAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if not IsUpgrade then
    MsgBox('SuperWall Kids is geïnstalleerd. De pc wordt automatisch met het dashboard gekoppeld zodra de enrollment key is geaccepteerd.', mbInformation, MB_OK);
end;
