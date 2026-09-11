#define MyAppName "SuperWall Kids"
#define MyAppVersion "0.4.6"
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
  DashboardUrl, EnrollmentKey, AgentPath, EnrollmentFile, DashboardFile, TargetUserFile, AppDir, CommonDir, TargetUser: string;
  ResultCode: Integer;
begin
  if CurStep <> ssInstall then Exit;

  { Stop the existing service before Inno replaces SuperWall.Agent.exe.
    This is required for reliable upgrades when the previous agent still has
    the executable open. }
  if IsUpgrade then
  begin
    RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'stop SuperWallAgent');
    Sleep(1500);
  end;

  if CurStep <> ssPostInstall then Exit;

  AgentPath := ExpandConstant('{app}\{#MyExeName}');
  AppDir := ExpandConstant('{app}');
  CommonDir := ExpandConstant('{commonappdata}\SuperWall');
  EnrollmentFile := CommonDir + '\enrollment.key';
  DashboardFile := CommonDir + '\dashboard.url';
  TargetUserFile := CommonDir + '\target-user.txt';

  if not DirExists(CommonDir) then
    ForceDirectories(CommonDir);

  if not IsUpgrade then
  begin
    DashboardUrl := DashboardPage.Values[0];
    EnrollmentKey := Trim(EnrollmentPage.Values[0]);
    SaveStringToFile(DashboardFile, DashboardUrl, False);
    SaveStringToFile(EnrollmentFile, EnrollmentKey, False);

    { The bootstrapper records the interactive account before UAC elevation.
      Prefer that value over the elevated installer username. }
    TargetUser := GetEnv('SUPERWALL_TARGET_USER');
    if Trim(TargetUser) = '' then
      TargetUser := ExpandConstant('{username}');
    SaveStringToFile(TargetUserFile, TargetUser, False);

    RegWriteStringValue(HKEY_LOCAL_MACHINE,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'SUPERWALL_DASHBOARD', DashboardUrl);
  end
  else if not FileExists(TargetUserFile) then
  begin
    TargetUser := GetEnv('SUPERWALL_TARGET_USER');
    if Trim(TargetUser) = '' then
      TargetUser := ExpandConstant('{username}');
    SaveStringToFile(TargetUserFile, TargetUser, False);
  end;

  { Remove machine-wide policies written by older SuperWall Kids versions. }
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ProxyMode /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ProxyServer /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DnsOverHttpsMode /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v QuicAllowed /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v BackgroundModeEnabled /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ExtensionInstallBlocklist /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DownloadRestrictions /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v URLBlocklist /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v ProxyMode /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v ProxyServer /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v DnsOverHttpsMode /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v QuicAllowed /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v BackgroundModeEnabled /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v ExtensionInstallBlocklist /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v DownloadRestrictions /f');
  RunHidden(ExpandConstant('{sysnative}\reg.exe'), 'delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v URLBlocklist /f');

  RunHidden(ExpandConstant('{sysnative}\icacls.exe'),
    '"' + CommonDir + '" /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" "Users:(OI)(CI)(RX)" /deny "Users:(OI)(CI)(W,DC,WDAC,WEA)"');
  if FileExists(EnrollmentFile) then
    RunHidden(ExpandConstant('{sysnative}\icacls.exe'),
      '"' + EnrollmentFile + '" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"');
  if FileExists(DashboardFile) then
    RunHidden(ExpandConstant('{sysnative}\icacls.exe'),
      '"' + DashboardFile + '" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"');
  if FileExists(TargetUserFile) then
    RunHidden(ExpandConstant('{sysnative}\icacls.exe'),
      '"' + TargetUserFile + '" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"');

  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'stop SuperWallAgent');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'delete SuperWallAgent');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'create SuperWallAgent binPath= "' + AgentPath + '" start= auto obj= LocalSystem');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'description SuperWallAgent "SuperWall Kids enforcement agent"');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'sdset SuperWallAgent "{#ServiceSddl}"');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'start SuperWallAgent');
end;