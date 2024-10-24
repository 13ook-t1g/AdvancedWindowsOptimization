@echo off
:Windows
cls
echo Are you on Windows 10 or 11?
echo Windows 10 = 1 
echo Windows 11 = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Windows10
if '%choice%'=='2' goto Windows11
goto Windows

:Windows10
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "0" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
timeout /t 2 /nobreak > NUL
goto Finished1

:Windows11
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "0" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;" /f
timeout /t 2 /nobreak > NUL
goto Finished1

:Finished1
cls
pause

@echo off

cls
:MPO
cls
echo MultiPlane-Overlay (MPO)?
echo Enable = 1 
echo Disable = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Enable1
if '%choice%'=='2' goto Disable1
goto MPO

:Enable1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /f
timeout /t 2 /nobreak > NUL
goto Finished2

:Disable1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "5" /f
timeout /t 2 /nobreak > NUL
goto Finished2

:Finished2
cls
pause
:VRR
cls
echo Enable or Disable Variable Refresh Rate?
echo Useful if you have g-sync or freesync
echo Enable = 1 
echo Disable = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Enable
if '%choice%'=='2' goto Disable
goto VRR

:Enable
reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;" /f
timeout /t 2 /nobreak > NUL
goto Finished

:Disable
reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;" /f
timeout /t 2 /nobreak > NUL
goto Finished

:Finished
cls
pause