#define MyAppName "SuperWall Kids"
#define MyAppVersion "0.5.16"
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
  ExistingInstallation: Boolean;

function IsUpgrade: Boolean;
begin
  Result := ExistingInstallation;
end;

function IsAlreadyEnrolled: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonappdata}\SuperWall\agent-token.bin')) and
    not FileExists(ExpandConstant('{commonappdata}\SuperWall\enrollment.key'));
end;

function IsValidHttpsUrl(const Value: string): Boolean;
begin
  Result := (Pos('https://', LowerCase(Trim(Value))) = 1) and (Length(Trim(Value)) > 8);
end;

function RunHidden(const FileName, Params: string): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure InitializeWizard;
begin
  ExistingInstallation := FileExists(ExpandConstant('{autopf}\SuperWall Kids\{#MyExeName}'));

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
  Result := IsUpgrade and IsAlreadyEnrolled and
    ((PageID = DashboardPage.ID) or (PageID = EnrollmentPage.ID));
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

function GetInstallerTargetUser: string;
begin
  Result := ExpandConstant('{param:SUPERWALL_TARGET_USER|}');
  if Trim(Result) = '' then
    Result := GetEnv('SUPERWALL_TARGET_USER');
end;

function GetInstallerTargetSid: string;
begin
  Result := ExpandConstant('{param:SUPERWALL_TARGET_SID|}');
  if Trim(Result) = '' then
    Result := GetEnv('SUPERWALL_TARGET_USER_SID');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  DashboardUrl, EnrollmentKey, AgentPath, EnrollmentFile, DashboardFile, TargetUserFile, TargetSidFile, CommonDir, TargetUser, TargetSid, RecoveryScript, RecoveryScriptQ: string;
  WaitCount: Integer;
  WriteOk: Boolean;
begin
  if (CurStep = ssInstall) and IsUpgrade then
  begin
    RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'stop SuperWallAgent');
    WaitCount := 0;
    while WaitCount < 50 do
    begin
      Sleep(200);
      Inc(WaitCount);
    end;
  end;

  if CurStep <> ssPostInstall then Exit;

  AgentPath := ExpandConstant('{app}\{#MyExeName}');
  CommonDir := ExpandConstant('{commonappdata}\SuperWall');
  EnrollmentFile := CommonDir + '\enrollment.key';
  DashboardFile := CommonDir + '\dashboard.url';
  TargetUserFile := CommonDir + '\target-user.txt';
  TargetSidFile := CommonDir + '\target-user.sid';

  if not DirExists(CommonDir) then
    ForceDirectories(CommonDir);

  TargetUser := GetInstallerTargetUser();
  TargetSid := GetInstallerTargetSid();

  if not IsUpgrade then
  begin
    DashboardUrl := Trim(DashboardPage.Values[0]);
    EnrollmentKey := Trim(EnrollmentPage.Values[0]);

    WriteOk := SaveStringToFile(DashboardFile, DashboardUrl, False);
    if (not WriteOk) or (not FileExists(DashboardFile)) then
    begin
      MsgBox('SuperWall kon de dashboard URL niet opslaan. De installatie is afgebroken.', mbError, MB_OK);
      Exit;
    end;

    WriteOk := SaveStringToFile(EnrollmentFile, EnrollmentKey, False);
    if (not WriteOk) or (not FileExists(EnrollmentFile)) then
    begin
      MsgBox('SuperWall kon de enrollment key niet opslaan. De installatie is afgebroken.', mbError, MB_OK);
      Exit;
    end;
  end;

  if Trim(TargetUser) = '' then
  begin
    MsgBox('SuperWall kon de oorspronkelijke Windows-gebruiker niet veilig bepalen. Start de Kids installer vanuit het kindaccount.', mbError, MB_OK);
    Exit;
  end;

  if Trim(TargetSid) = '' then
  begin
    MsgBox('SuperWall kon de beveiligde Windows-gebruikers-ID niet vastleggen. Start de Kids installer opnieuw vanuit het kindaccount.', mbError, MB_OK);
    Exit;
  end;

  WriteOk := SaveStringToFile(TargetUserFile, TargetUser, False);
  if (not WriteOk) or (not FileExists(TargetUserFile)) then
  begin
    MsgBox('SuperWall kon de doelgebruiker niet opslaan. De installatie is afgebroken.', mbError, MB_OK);
    Exit;
  end;

  WriteOk := SaveStringToFile(TargetSidFile, TargetSid, False);
  if (not WriteOk) or (not FileExists(TargetSidFile)) then
  begin
    MsgBox('SuperWall kon de beveiligde gebruikers-ID niet opslaan. De installatie is afgebroken.', mbError, MB_OK);
    Exit;
  end;

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
    '"' + CommonDir + '" /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" "Users:(OI)(CI)(RX)" /deny "Users:(OI)(CI,WDAC,WEA)"');
  if FileExists(EnrollmentFile) then
    RunHidden(ExpandConstant('{sysnative}\icacls.exe'), '"' + EnrollmentFile + '" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"');
  if FileExists(DashboardFile) then
    RunHidden(ExpandConstant('{sysnative}\icacls.exe'), '"' + DashboardFile + '" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"');
  if FileExists(TargetUserFile) then
    RunHidden(ExpandConstant('{sysnative}\icacls.exe'), '"' + TargetUserFile + '" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"');
  if FileExists(TargetSidFile) then
    RunHidden(ExpandConstant('{sysnative}\icacls.exe'), '"' + TargetSidFile + '" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"');

  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'stop SuperWallAgent');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'delete SuperWallAgent');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'create SuperWallAgent binPath= "' + AgentPath + '" start= auto obj= LocalSystem');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'description SuperWallAgent "SuperWall Kids enforcement agent"');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'sdset SuperWallAgent "{#ServiceSddl}"');
  RunHidden(ExpandConstant('{sysnative}\sc.exe'), 'start SuperWallAgent');

  RecoveryScript := CommonDir + '\configure-recovery.cmd';
  RecoveryScriptQ := '"' + RecoveryScript + '"';
  SaveStringToFile(RecoveryScript,
    '@echo off' + #13#10 +
    'setlocal' + #13#10 +
    'timeout /t 12 /nobreak >nul' + #13#10 +
    'sc.exe query SuperWallAgent | findstr /i "RUNNING" >nul' + #13#10 +
    'if errorlevel 1 exit /b 0' + #13#10 +
    'sc.exe failure SuperWallAgent reset= 86400 actions= restart/60000/restart/120000/""/180000 >nul 2>&1' + #13#10 +
    'del /f /q ' + RecoveryScriptQ + ' >nul 2>&1' + #13#10 +
    'exit /b 0' + #13#10, False);
  Exec(ExpandConstant('{sysnative}\cmd.exe'), '/d /c ' + RecoveryScriptQ, '', SW_HIDE, ewNoWait, WaitCount);
end;
