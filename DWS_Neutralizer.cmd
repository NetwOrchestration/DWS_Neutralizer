@echo off
cd /d "%~dp0"
rem #Create and Start Deleted Services...
sc create DiagTrack type= own start= auto error= normal binPath= "%%SystemRoot%%\System32\svchost.exe -k utcsvc" tag= no depend= RpcSs obj= LocalSystem DisplayName= "Diagnostics Tracking Service"
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Description" /t REG_SZ /d @%%SystemRoot%%\system32\diagtrack.dll,-3002 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "DisplayName" /t REG_SZ /d @%%SystemRoot%%\system32\diagtrack.dll,-3001 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "FailureActions" /t REG_BINARY /d 8051010000000000000000000300000014000000010000003075000001000000307500000000000000000000 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "RequiredPrivileges" /t REG_MULTI_SZ /d SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeAssignPrimaryTokenPrivilege\0SeImpersonatePrivilege\0SeSystemProfilePrivilege\0SeTcbPrivilege\0SeDebugPrivilege /f
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "ServiceSidType" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d %%SystemRoot%%\system32\diagtrack.dll /f
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack\Parameters" /v "ServiceMain" /t REG_SZ /d ServiceMain /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Description" /t REG_SZ /d @%%SystemRoot%%\system32\diagtrack.dll,-3002 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "DisplayName" /t REG_SZ /d @%%SystemRoot%%\system32\diagtrack.dll,-3001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "FailureActions" /t REG_BINARY /d 8051010000000000000000000300000014000000010000003075000001000000307500000000000000000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "RequiredPrivileges" /t REG_MULTI_SZ /d SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeAssignPrimaryTokenPrivilege\0SeImpersonatePrivilege\0SeSystemProfilePrivilege\0SeTcbPrivilege\0SeDebugPrivilege /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "ServiceSidType" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d %%SystemRoot%%\system32\diagtrack.dll /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" /v "ServiceMain" /t REG_SZ /d ServiceMain /f
sc create diagnosticshub.standardcollector.service type= own start= demand error= normal binPath= "%%SystemRoot%%\System32\DiagSvcsdiagnosticshub.standardcollector.service.exe" tag= no obj= LocalSystem DisplayName= "Microsoft (R) Diagnostics Hub Standard Collector Service"
reg add "HKLM\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service" /v "Description" /t REG_SZ /d @%%SystemRoot%%\system32\DiagSvcs\DiagnosticsHub.StandardCollector.ServiceRes.dll,-1001 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service" /v "DisplayName" /t REG_SZ /d @%%SystemRoot%%\system32\DiagSvcs\DiagnosticsHub.StandardCollector.ServiceRes.dll,-1000 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service" /v "RequiredPrivileges" /t REG_MULTI_SZ /d SeImpersonatePrivilege\0SeSystemProfilePrivilege\0SeDebugPrivilege /f
reg add "HKLM\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service" /v "ServiceSidType" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Description" /t REG_SZ /d @%%SystemRoot%%\system32\DiagSvcs\DiagnosticsHub.StandardCollector.ServiceRes.dll,-1001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "DisplayName" /t REG_SZ /d @%%SystemRoot%%\system32\DiagSvcs\DiagnosticsHub.StandardCollector.ServiceRes.dll,-1000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "RequiredPrivileges" /t REG_MULTI_SZ /d SeImpersonatePrivilege\0SeSystemProfilePrivilege\0SeDebugPrivilege /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "ServiceSidType" /t REG_DWORD /d 1 /f
sc create dmwappushservice type= share start= auto error= normal binPath= "%%SystemRoot%%\System32\svchost.exe -k netsvcs" tag= no depend= rpcss obj= LocalSystem DisplayName= "dmwappushsvc"
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DisplayName" /t REG_SZ /d @%%SystemRoot%%\system32\dmwappushsvc.dll,-200 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "ServiceSidType" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "RequiredPrivileges" /t REG_MULTI_SZ /d SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeImpersonatePrivilege\0SeIncreaseWorkingSetPrivilege /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "FailureActions" /t REG_BINARY /d 80510100000000000000000004000000140000000100000010270000010000001027000001000000102700000000000010270000 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\Parameters" /v "IdleTimeout(sec)" /t REG_DWORD /d 78 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d %%SystemRoot%%\system32\dmwappushsvc.dll /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\Parameters" /v "ServiceMain" /t REG_SZ /d ServiceMain /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\Security" /v "Security" /t REG_BINARY /d 01000480B0000000BC000000000000001400000002009C0007000000000014008D010200010100000000000504000000000014008D01020001010000000000050600000000001400FF010F0001010000000000051200000000001800FF010F00010200000000000520000000200200000000180014000000010200000000000F02000000010000000000140014000000010100000000000504000000000014001400000001010000000000050B000000010100000000000512000000010100000000000512000000 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\0" /v "Type" /t REG_DWORD /d 6 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\0" /v "Action" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\0" /v "GUID" /t REG_BINARY /d 67D190BC70943941A9BABE0BBBF5B74D /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\0" /v "Data0" /t REG_BINARY /d 370039003500420036004200460039002D0039003700420036002D0034004600380039002D0042004400380044002D003200460034003200420042004200450039003900360045000000 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\0" /v "DataType0" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\1" /v "Type" /t REG_DWORD /d 6 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\1" /v "Action" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\1" /v "GUID" /t REG_BINARY /d 67D190BC70943941A9BABE0BBBF5B74D /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\1" /v "Data0" /t REG_BINARY /d 390034003500360039003300630034002D0033003600340038002D0034003900360036002D0062003200610061002D003300370064003600360065003200340034003900350066000000 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\1" /v "DataType0" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\2" /v "Type" /t REG_DWORD /d 7 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\2" /v "Action" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\2" /v "GUID" /t REG_BINARY /d 16287A2D5E0CFC459CE7570E5ECDE9C9 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\2" /v "Data0" /t REG_BINARY /d 7590BCA328009213 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice\TriggerInfo\2" /v "DataType0" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "DisplayName" /t REG_SZ /d @%%SystemRoot%%\system32\dmwappushsvc.dll,-200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "ServiceSidType" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "RequiredPrivileges" /t REG_MULTI_SZ /d SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeImpersonatePrivilege\0SeIncreaseWorkingSetPrivilege /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "DelayedAutoStart" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "FailureActions" /t REG_BINARY /d 80510100000000000000000004000000140000000100000010270000010000001027000001000000102700000000000010270000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\Parameters" /v "IdleTimeout(sec)" /t REG_DWORD /d 78 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d %%SystemRoot%%\system32\dmwappushsvc.dll /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\Parameters" /v "ServiceMain" /t REG_SZ /d ServiceMain /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\Security" /v "Security" /t REG_BINARY /d 01000480B0000000BC000000000000001400000002009C0007000000000014008D010200010100000000000504000000000014008D01020001010000000000050600000000001400FF010F0001010000000000051200000000001800FF010F00010200000000000520000000200200000000180014000000010200000000000F02000000010000000000140014000000010100000000000504000000000014001400000001010000000000050B000000010100000000000512000000010100000000000512000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\0" /v "Type" /t REG_DWORD /d 6 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\0" /v "Action" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\0" /v "GUID" /t REG_BINARY /d 67D190BC70943941A9BABE0BBBF5B74D /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\0" /v "Data0" /t REG_BINARY /d 370039003500420036004200460039002D0039003700420036002D0034004600380039002D0042004400380044002D003200460034003200420042004200450039003900360045000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\0" /v "DataType0" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\1" /v "Type" /t REG_DWORD /d 6 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\1" /v "Action" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\1" /v "GUID" /t REG_BINARY /d 67D190BC70943941A9BABE0BBBF5B74D /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\1" /v "Data0" /t REG_BINARY /d 390034003500360039003300630034002D0033003600340038002D0034003900360036002D0062003200610061002D003300370064003600360065003200340034003900350066000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\1" /v "DataType0" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\2" /v "Type" /t REG_DWORD /d 7 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\2" /v "Action" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\2" /v "GUID" /t REG_BINARY /d 16287A2D5E0CFC459CE7570E5ECDE9C9 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\2" /v "Data0" /t REG_BINARY /d 7590BCA328009213 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice\TriggerInfo\2" /v "DataType0" /t REG_DWORD /d 1 /f
sc create WMPNetworkSvc type= own start= demand error= normal binPath= "%%PROGRAMFILES%%\Windows Media Player\wmpnetwk.exe" tag= no depend= http/WSearch obj= "NT AUTHORITY\NetworkService" DisplayName= "Windows Media Player Network Sharing Service"
reg add "HKLM\SYSTEM\ControlSet001\Services\WMPNetworkSvc" /v "DisplayName" /t REG_SZ /d "@%%PROGRAMFILES%%\Windows Media Player\wmpnetwk.exe,-101" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\WMPNetworkSvc" /v "Description" /t REG_SZ /d "@%PROGRAMFILES%\Windows Media Player\wmpnetwk.exe,-102" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\WMPNetworkSvc" /v "ServiceSidType" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\WMPNetworkSvc" /v "RequiredPrivileges" /t REG_MULTI_SZ /d SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeImpersonatePrivilege /f
reg add "HKLM\SYSTEM\ControlSet001\Services\WMPNetworkSvc" /v "FailureActions" /t REG_BINARY /d 8051010000000000000000000300000014000000010000003075000001000000307500000000000000000000 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\WMPNetworkSvc\Security" /v "Security" /t REG_BINARY /d 010014808C00000098000000140000003000000002001C000100000002801400FF010F0001010000000000010000000002005C000400000000001400FD01020001010000000000051200000000001800FF010F0001020000000000052000000020020000000014009D010200010100000000000504000000000014008D010200010100000000000506000000010100000000000512000000010100000000000512000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "DisplayName" /t REG_SZ /d "@%%PROGRAMFILES%%\Windows Media Player\wmpnetwk.exe,-101" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Description" /t REG_SZ /d "@%PROGRAMFILES%\Windows Media Player\wmpnetwk.exe,-102" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "ServiceSidType" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "RequiredPrivileges" /t REG_MULTI_SZ /d SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeImpersonatePrivilege /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "FailureActions" /t REG_BINARY /d 8051010000000000000000000300000014000000010000003075000001000000307500000000000000000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc\Security" /v "Security" /t REG_BINARY /d 010014808C00000098000000140000003000000002001C000100000002801400FF010F0001010000000000010000000002005C000400000000001400FD01020001010000000000051200000000001800FF010F0001020000000000052000000020020000000014009D010200010100000000000504000000000014008D010200010100000000000506000000010100000000000512000000010100000000000512000000 /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 1 /f
sc start DiagTrack
sc start diagnosticshub.standardcollector.service
sc start dmwappushservice
sc start WMPNetworkSvc

rem #Restore Registry keys to default values...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /f

reg delete "HKCU\SOFTWARE\Microsoft\Input" /f
reg delete "HKCU\SOFTWARE\Microsoft\Siuf" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /f
reg delete "HKCU\SOFTWARE\Microsoft\InputPersonalization" /f
reg delete "HKCU\Software\Classes\.ico" /v "(Default)" /f
reg delete "HKCU\Software\Classes\.tiff" /v "(Default)" /f
reg delete "HKCU\Software\Classes\.bmp" /v "(Default)" /f
reg delete "HKCU\Software\Classes\.png" /v "(Default)" /f
reg delete "HKCU\Software\Classes\.gif" /v "(Default)" /f
reg delete "HKCU\Software\Classes\.jpeg" /v "(Default)" /f
reg delete "HKCU\Software\Classes\.jpg" /v "(Default)" /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d RequireAdmin /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 3 /f

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9D9E0118-1807-4F2E-96E4-2CE57142E196}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{B19F89AF-E3EB-444B-8DEA-202575A71599}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E83AF229-8640-4D18-A213-E22675EBB2C3}" /v "Value" /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d Allow /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 1 /f


rem #Cleaning hosts file...
attrib -r "%WinDir%\System32\drivers\etc\hosts"
type nul>"%CD%\DWS"
echo statsfe2.update.microsoft.com.akadns.net>>"%CD%\DWS"
echo fe2.update.microsoft.com.akadns.net>>"%CD%\DWS"
echo s0.2mdn.net>>"%CD%\DWS"
echo survey.watson.microsoft.com>>"%CD%\DWS"
echo view.atdmt.com>>"%CD%\DWS"
echo watson.microsoft.com>>"%CD%\DWS"
echo watson.ppe.telemetry.microsoft.com>>"%CD%\DWS"
echo vortex.data.microsoft.com>>"%CD%\DWS"
echo vortex-win.data.microsoft.com>>"%CD%\DWS"
echo telecommand.telemetry.microsoft.com>>"%CD%\DWS"
echo telecommand.telemetry.microsoft.com.nsatc.net>>"%CD%\DWS"
echo oca.telemetry.microsoft.com>>"%CD%\DWS"
echo sqm.telemetry.microsoft.com>>"%CD%\DWS"
echo sqm.telemetry.microsoft.com.nsatc.net>>"%CD%\DWS"
echo watson.telemetry.microsoft.com>>"%CD%\DWS"
echo watson.telemetry.microsoft.com.nsatc.net>>"%CD%\DWS"
echo redir.metaservices.microsoft.com>>"%CD%\DWS"
echo choice.microsoft.com>>"%CD%\DWS"
echo choice.microsoft.com.nsatc.net>>"%CD%\DWS"
echo wes.df.telemetry.microsoft.com>>"%CD%\DWS"
echo services.wes.df.telemetry.microsoft.com>>"%CD%\DWS"
echo sqm.df.telemetry.microsoft.com>>"%CD%\DWS"
echo telemetry.microsoft.com>>"%CD%\DWS"
echo telemetry.appex.bing.net>>"%CD%\DWS"
echo telemetry.urs.microsoft.com>>"%CD%\DWS"
echo settings-sandbox.data.microsoft.com>>"%CD%\DWS"
echo watson.live.com>>"%CD%\DWS"
echo statsfe2.ws.microsoft.com>>"%CD%\DWS"
echo corpext.msitadfs.glbdns2.microsoft.com>>"%CD%\DWS"
echo compatexchange.cloudapp.net>>"%CD%\DWS"
echo a-0001.a-msedge.net>>"%CD%\DWS"
echo sls.update.microsoft.com.akadns.net>>"%CD%\DWS"
echo diagnostics.support.microsoft.com>>"%CD%\DWS"
echo corp.sts.microsoft.com>>"%CD%\DWS"
echo statsfe1.ws.microsoft.com>>"%CD%\DWS"
echo feedback.windows.com>>"%CD%\DWS"
echo feedback.microsoft-hohm.com>>"%CD%\DWS"
echo feedback.search.microsoft.com>>"%CD%\DWS"
echo rad.msn.com>>"%CD%\DWS"
echo preview.msn.com>>"%CD%\DWS"
echo ad.doubleclick.net>>"%CD%\DWS"
echo ads.msn.com>>"%CD%\DWS"
echo ads1.msads.net>>"%CD%\DWS"
echo ads1.msn.com>>"%CD%\DWS"
echo a.ads1.msn.com>>"%CD%\DWS"
echo a.ads2.msn.com>>"%CD%\DWS"
echo adnexus.net>>"%CD%\DWS"
echo adnxs.com>>"%CD%\DWS"
echo az361816.vo.msecnd.net>>"%CD%\DWS"
echo az512334.vo.msecnd.net>>"%CD%\DWS"
echo ssw.live.com>>"%CD%\DWS"
echo ca.telemetry.microsoft.com>>"%CD%\DWS"
echo i1.services.social.microsoft.com>>"%CD%\DWS"
echo df.telemetry.microsoft.com>>"%CD%\DWS"
echo reports.wes.df.telemetry.microsoft.com>>"%CD%\DWS"
echo cs1.wpc.v0cdn.net>>"%CD%\DWS"
echo vortex-sandbox.data.microsoft.com>>"%CD%\DWS"
echo oca.telemetry.microsoft.com.nsatc.net>>"%CD%\DWS"
echo pre.footprintpredict.com>>"%CD%\DWS"
echo spynet2.microsoft.com>>"%CD%\DWS"
echo spynetalt.microsoft.com>>"%CD%\DWS"
echo fe3.delivery.dsp.mp.microsoft.com.nsatc.net>>"%CD%\DWS"
echo cache.datamart.windows.com>>"%CD%\DWS"
echo db3wns2011111.wns.windows.com>>"%CD%\DWS"
echo settings-win.data.microsoft.com>>"%CD%\DWS"
echo v10.vortex-win.data.microsoft.com>>"%CD%\DWS"
echo win10.ipv6.microsoft.com>>"%CD%\DWS"
echo ca.telemetry.microsoft.com>>"%CD%\DWS"
echo i1.services.social.microsoft.com.nsatc.net>>"%CD%\DWS"
echo msnbot-207-46-194-33.search.msn.com>>"%CD%\DWS"
echo settings.data.microsof.com>>"%CD%\DWS"
echo telecommand.telemetry.microsoft.com.nsat­c.net>>"%CD%\DWS"
type "%WinDir%\System32\drivers\etc\hosts">"%CD%\hosts"
for /f "tokens=1 delims= " %%a in ('type "%CD%\DWS"') do (
    type "%CD%\hosts">"%CD%\Temp"
    type "%CD%\Temp" | find /v /i "%%a">"%CD%\hosts"
)
type "%CD%\hosts">"%WinDir%\System32\drivers\etc\hosts"
attrib +r "%WinDir%\System32\drivers\etc\hosts"
del /f /q "%CD%\hosts"
del /f /q "%CD%\DWS"
del /f /q "%CD%\Temp"

rem #Cleaning firewall rules...
netsh advfirewall firewall delete rule name="104.96.147.3_Block"
netsh advfirewall firewall delete rule name="111.221.29.177_Block"
netsh advfirewall firewall delete rule name="111.221.29.253_Block"
netsh advfirewall firewall delete rule name="111.221.64.0-111.221.127.255_Block"
netsh advfirewall firewall delete rule name="131.253.40.37_Block"
netsh advfirewall firewall delete rule name="134.170.115.60_Block"
netsh advfirewall firewall delete rule name="134.170.165.248_Block"
netsh advfirewall firewall delete rule name="134.170.165.253_Block"
netsh advfirewall firewall delete rule name="134.170.185.70_Block"
netsh advfirewall firewall delete rule name="134.170.30.202_Block"
netsh advfirewall firewall delete rule name="137.116.81.24_Block"
netsh advfirewall firewall delete rule name="137.117.235.16_Block"
netsh advfirewall firewall delete rule name="157.55.129.21_Block"
netsh advfirewall firewall delete rule name="157.55.130.0-157.55.130.255_Block"
netsh advfirewall firewall delete rule name="157.55.133.204_Block"
netsh advfirewall firewall delete rule name="157.55.235.0-157.55.235.255_Block"
netsh advfirewall firewall delete rule name="157.55.236.0-157.55.236.255_Block"
netsh advfirewall firewall delete rule name="157.55.240.220_Block"
netsh advfirewall firewall delete rule name="157.55.52.0-157.55.52.255_Block"
netsh advfirewall firewall delete rule name="157.55.56.0-157.55.56.255_Block"
netsh advfirewall firewall delete rule name="157.56.106.189_Block"
netsh advfirewall firewall delete rule name="157.56.121.89_Block"
netsh advfirewall firewall delete rule name="157.56.124.87_Block"
netsh advfirewall firewall delete rule name="157.56.91.77_Block"
netsh advfirewall firewall delete rule name="157.56.96.54_Block"
netsh advfirewall firewall delete rule name="168.63.108.233_Block"
netsh advfirewall firewall delete rule name="191.232.139.2_Block"
netsh advfirewall firewall delete rule name="191.232.139.254_Block"
netsh advfirewall firewall delete rule name="191.232.80.58_Block"
netsh advfirewall firewall delete rule name="191.232.80.62_Block"
netsh advfirewall firewall delete rule name="191.237.208.126_Block"
netsh advfirewall firewall delete rule name="195.138.255.0-195.138.255.255_Block"
netsh advfirewall firewall delete rule name="2.22.61.43_Block"
netsh advfirewall firewall delete rule name="2.22.61.66_Block"
netsh advfirewall firewall delete rule name="204.79.197.200_Block"
netsh advfirewall firewall delete rule name="207.46.101.29_Block"
netsh advfirewall firewall delete rule name="207.46.114.58_Block"
netsh advfirewall firewall delete rule name="207.46.223.94_Block"
netsh advfirewall firewall delete rule name="207.68.166.254_Block"
netsh advfirewall firewall delete rule name="212.30.134.204_Block"
netsh advfirewall firewall delete rule name="212.30.134.205_Block"
netsh advfirewall firewall delete rule name="213.199.179.0-213.199.179.255_Block"
netsh advfirewall firewall delete rule name="23.102.21.4_Block"
netsh advfirewall firewall delete rule name="23.218.212.69_Block"
netsh advfirewall firewall delete rule name="23.223.20.82_Block"
netsh advfirewall firewall delete rule name="23.57.101.163_Block"
netsh advfirewall firewall delete rule name="23.57.107.163_Block"
netsh advfirewall firewall delete rule name="23.57.107.27_Block"
netsh advfirewall firewall delete rule name="23.99.10.11_Block"
netsh advfirewall firewall delete rule name="64.4.23.0-64.4.23.255_Block"
netsh advfirewall firewall delete rule name="64.4.54.22_Block"
netsh advfirewall firewall delete rule name="64.4.54.32_Block"
netsh advfirewall firewall delete rule name="64.4.6.100_Block"
netsh advfirewall firewall delete rule name="65.39.117.230_Block"
netsh advfirewall firewall delete rule name="65.39.117.230_Block"
netsh advfirewall firewall delete rule name="65.52.100.11_Block"
netsh advfirewall firewall delete rule name="65.52.100.7_Block"
netsh advfirewall firewall delete rule name="65.52.100.9_Block"
netsh advfirewall firewall delete rule name="65.52.100.91_Block"
netsh advfirewall firewall delete rule name="65.52.100.92_Block"
netsh advfirewall firewall delete rule name="65.52.100.93_Block"
netsh advfirewall firewall delete rule name="65.52.100.94_Block"
netsh advfirewall firewall delete rule name="65.52.108.29_Block"
netsh advfirewall firewall delete rule name="65.52.108.33_Block"
netsh advfirewall firewall delete rule name="65.55.108.23_Block"
netsh advfirewall firewall delete rule name="65.55.138.114_Block"
netsh advfirewall firewall delete rule name="65.55.138.126_Block"
netsh advfirewall firewall delete rule name="65.55.138.186_Block"
netsh advfirewall firewall delete rule name="65.55.223.0-65.55.223.255_Block"
netsh advfirewall firewall delete rule name="65.55.252.63_Block"
netsh advfirewall firewall delete rule name="65.55.252.71_Block"
netsh advfirewall firewall delete rule name="65.55.252.92_Block"
netsh advfirewall firewall delete rule name="65.55.252.93_Block"
netsh advfirewall firewall delete rule name="65.55.29.238_Block"
netsh advfirewall firewall delete rule name="65.55.39.10_Block"
netsh advfirewall firewall delete rule name="77.67.29.176_Block"
netsh advfirewall firewall delete rule name="Explorer.EXE_BLOCK"
netsh advfirewall firewall delete rule name="WSearch_Block"

rem #Cleaning routing table...
route delete 104.96.147.3
route delete 111.221.29.177
route delete 111.221.29.253
route delete 111.221.64.0
route delete 131.253.40.37
route delete 134.170.115.60
route delete 134.170.165.248
route delete 134.170.165.253
route delete 134.170.185.70
route delete 134.170.30.202
route delete 137.116.81.24
route delete 137.117.235.16
route delete 157.55.129.21
route delete 157.55.130.0
route delete 157.55.133.204
route delete 157.55.235.0
route delete 157.55.236.0
route delete 157.55.240.220
route delete 157.55.52.0
route delete 157.55.56.0
route delete 157.56.106.189
route delete 157.56.121.89
route delete 157.56.124.87
route delete 157.56.91.77
route delete 157.56.96.54
route delete 168.63.108.233
route delete 191.232.139.2
route delete 191.232.139.254
route delete 191.232.80.58
route delete 191.232.80.62
route delete 191.237.208.126
route delete 195.138.255.0
route delete 2.22.61.43
route delete 2.22.61.66
route delete 204.79.197.200
route delete 207.46.101.29
route delete 207.46.114.58
route delete 207.46.223.94
route delete 207.68.166.254
route delete 212.30.134.204
route delete 212.30.134.205
route delete 213.199.179.0
route delete 23.102.21.4
route delete 23.218.212.69
route delete 23.223.20.82
route delete 23.57.101.163
route delete 23.57.107.163
route delete 23.57.107.27
route delete 23.99.10.11
route delete 64.4.23.0
route delete 64.4.54.22
route delete 64.4.54.32
route delete 64.4.6.100
route delete 65.39.117.230
route delete 65.39.117.230
route delete 65.52.100.11
route delete 65.52.100.7
route delete 65.52.100.9
route delete 65.52.100.91
route delete 65.52.100.92
route delete 65.52.100.93
route delete 65.52.100.94
route delete 65.52.108.29
route delete 65.52.108.33
route delete 65.55.108.23
route delete 65.55.138.114
route delete 65.55.138.126
route delete 65.55.138.186
route delete 65.55.223.0
route delete 65.55.252.63
route delete 65.55.252.71
route delete 65.55.252.92
route delete 65.55.252.93
route delete 65.55.29.238
route delete 65.55.39.10
route delete 77.67.29.176

rem #Restoring disabled tasks...
schtasks /Change /TN "Microsoft\Office\Office ClickToRun Service Monitor" /enable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /enable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /enable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /enable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /enable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /enable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /enable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetry\AgentFallBack2016" /enable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /enable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /enable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\ActivateWindowsSearch" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\ConfigureInternetTimeService" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\DispatchRecoveryTasks" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\ehDRMInit" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\InstallPlayReady" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\mcupdate" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\MediaCenterRecoveryTask" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\ObjectStoreRecoveryTask" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\OCURActivate" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\OCURDiscovery" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\PBDADiscovery" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\PBDADiscoveryW1" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\PBDADiscoveryW2" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\PvrRecoveryTask" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\PvrScheduleTask" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\RegisterSearch" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\ReindexSearchRoot" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\SqlLiteRecoveryTask" /enable
schtasks /Change /TN "Microsoft\Windows\Media Center\UpdateRecordPath" /enable