@echo off

rem 
rem .........................................................
rem by XFang
rem xDefender Version 1.0
rem .........................................................
rem 
Title xDefender Version 1.0

%1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c ""%~s0"" ::","","runas",1)(window.close)&&exit
chcp 936
Pushd %~dp0
CD /D "%~dp0"

set ServiceName=WinDefend

for /f "tokens=3" %%a in ('sc query "%ServiceName%" ^| findstr /C:"STATE"') do (
    set "ServiceStatus=%%a"
)

if defined ServiceStatus (
    if %ServiceStatus% equ 1 set Windows_Defender=on
    if %ServiceStatus% equ 4 set Windows_Defender=off
) else (
    cls
    echo .........................................................
    echo .
    echo .  服务 %ServiceName% 不存在，可能未安装 WindowsDefender.
    echo .
    echo .  3秒后 退出脚本.
    echo .
    echo .........................................................
    timeout /t 3
    exit 
)

reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" /v OptionValue >nul 2>&1
if %errorlevel% equ 0 (
    goto %Windows_Defender%
) else (
    cls
    echo .........................................................
    echo .
    if %ServiceStatus% equ 4 echo .   3秒后 [ 关闭 ] WindowsDefender.
    if %ServiceStatus% equ 1 echo .   3秒后 [ 打开 ] WindowsDefender.
    echo .
    echo .   请无视蓝屏...
    echo .
    echo .........................................................
    timeout /t 3
    NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\system32\userinit.exe,%~f0," /f
    NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\WinDefend_off" /ve /t REG_SZ /d "Service" /f
    bcdedit /set {default} safeboot network
    shutdown -r -f -t 4
    exit
)

:off
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
NSudoLG.exe -U:S Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /v "ServiceStartStates" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "LastMAPSSuccessTime" /t REG_BINARY /d "a2a6f1bbd01bdb01" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Reporting" /v "LastRtpTurnedOffTime" /t REG_BINARY /d "66acf1bbd01bdb01" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Reporting" /v "LastRtpHeartbeatReportTime" /t REG_BINARY /d "27a5f1bbd01bdb01" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "4" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Diagnostics" /v "CloudBadListVersion" /t REG_BINARY /d "0500000000000000" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /t REG_BINARY /d "070000000093bfc8defad901" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
goto end

:on
NSudoLG.exe -U:S Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f
NSudoLG.exe -U:S Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /v "ServiceStartStates" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "2" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "1" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "LastMAPSSuccessTime" /t REG_BINARY /d "a2a6f1bbd01bdb01" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Reporting" /v "LastRtpTurnedOffTime" /t REG_BINARY /d "66acf1bbd01bdb01" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Reporting" /v "LastRtpHeartbeatReportTime" /t REG_BINARY /d "27a5f1bbd01bdb01" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "0" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "5" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Diagnostics" /v "CloudBadListVersion" /t REG_BINARY /d "0500000000000000" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /t REG_BINARY /d "060000000093bfc8defad901" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "3" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "0" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "0" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "3" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "3" /f
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "2" /f
goto end

:end
NSudoLG.exe -U:S Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\system32\userinit.exe," /f
NSudoLG.exe -U:S Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\WinDefend_off" /f
bcdedit /deletevalue {default} safeboot
shutdown -r -f -t 4
exit
