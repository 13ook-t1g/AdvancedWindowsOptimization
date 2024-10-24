@echo off
:start
cls
echo Basic Network Optimization
echo Apply  = 1 
echo Reset  = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :start1
if '%choice%'=='2' goto :RestoreBasic
goto :start

:start1
echo Tcp Optimizer
netsh int tcp set global autotuninglevel=Disabled
netsh int tcp set heuristics disabled

cls
:congestionprovider
cls
echo CongestionProvider
echo Windows 10 = 1 
echo Windows 11 = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :W10
if '%choice%'=='2' goto :W11
goto :congestionprovider

:W10
netsh int tcp set supplemental Internet congestionprovider=ctcp
powershell Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CTCP
cls
goto :RSS

:W11
netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2
netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2
netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2
cls
goto :RSS

:RSS
cls
echo Receive-Side Scaling State
echo Your Network Adapter support RSS?
echo Go check in Advanced Network Driver settings
echo Yes = 1 
echo No  = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :enableRSS
if '%choice%'=='2' goto :disableRSS
goto :RSS

:disableRSS
cls
netsh int tcp set global rss=disabled
goto :GeneralTCPoptimizer

:enableRSS
cls
netsh int tcp set global rss=enabled
goto :RGeneralTCPoptimizer

:GeneralTCPoptimizer
netsh int tcp set global rsc=disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
powershell Disable-NetAdapterLso -Name *
netsh int tcp set global timestamps=disabled
netsh int tcp set global chimney=disabled
cls
powershell Disable-NetAdapterChecksumOffload -Name *
powershell Disable-NetAdapterBinding -Name * -ComponentID ms_tcpip6
cls
:ecnmain
echo ECN Capability
echo Your router support ECN Capability?
echo Ask ISP or Check by yourself
echo Yes = 1 
echo No  = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :ecn1
if '%choice%'=='2' goto :ecn2
cls
goto :ecnmain

:ecn1
netsh int tcp set global ecncapability=enabled
goto :MTU

:ecn2
netsh int tcp set global ecncapability=disabled
goto :MTU

:MTU
cls
echo Maximum Transmission Unit (MTU)
echo IPOE or PPPOE
echo Ask ISP or Check by yourself
echo IPOE  = 1 
echo PPPOE = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :IPOE
if '%choice%'=='2' goto :PPPOE
cls
goto :MTU

:IPOE
netsh int ipv4 show subinterface
pause
netsh int ipv4 set subinterface "Wi-Fi" mtu=1500 store=persistent
netsh int ipv4 set subinterface "Ethernet" mtu=1500 store=persistent
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s ^|findstr /i /l "ServiceName"') do (
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t Reg_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t Reg_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t Reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpInitialRTT" /d "300" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "UseZeroBroadcast" /d "0" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "DeadGWDetectDefault" /d "1" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "MTU" /d "1500" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "InterfaceMetric" /d "1" /t REG_DWORD /f
)
cls
goto :TcpipTweaks

:PPPOE
cls
netsh int ipv4 show subinterface
pause
netsh int ipv4 set subinterface "Wi-Fi" mtu=1492 store=persistent
netsh int ipv4 set subinterface "Ethernet" mtu=1492 store=persistent
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s ^|findstr /i /l "ServiceName"') do (
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t Reg_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t Reg_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t Reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpInitialRTT" /d "300" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "UseZeroBroadcast" /d "0" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "DeadGWDetectDefault" /d "1" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "MTU" /d "1492" /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "InterfaceMetric" /d "1" /t REG_DWORD /f
)
cls
goto :TcpipTweaks

:TcpipTweaks
netsh int ipv4 show subinterface
pause
cls
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t Reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global initialRto=3000
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER"  /v "explorer.exe" /t REG_DWORD /d "10" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER"  /v "explorer.exe" /t REG_DWORD /d "10" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f
cls

:PriorityUpdate
echo Set Highest Priority
echo Yes = 1 
echo No  = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :PriorityUpdate1
if '%choice%'=='2' goto :basicnetwork
cls
goto :PriorityUpdate

:PriorityUpdate1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "Class" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "1" /f
:basicnetwork
cls
echo Completed Basic Network Optimization
pause

:AdvancedOptimization
cls
echo Advanced Optimization
echo apply = 1
echo reset = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :continue
if '%choice%'=='2' goto :RestoreAdvanced
goto :AdvancedOptimization

:exit
exit

:continue
cls
echo DSCP Value
pause
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "Start" /t Reg_DWORD /d "1" /f
sc start Psched

for %%i in (csgo VALORANT-Win64-Shipping javaw FortniteClient-Win64-Shipping ModernWarfare r5apex) do (
reg query "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" || (
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Application Name" /t Reg_SZ /d "VALORANT-Win64-Shipping.exe" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Version" /t Reg_SZ /d "1.0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Protocol" /t Reg_SZ /d "*" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Local Port" /t Reg_SZ /d "*" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Local IP" /t Reg_SZ /d "*" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Local IP Prefix Length" /t Reg_SZ /d "*" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Remote Port" /t Reg_SZ /d "*" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Remote IP" /t Reg_SZ /d "*" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Remote IP Prefix Length" /t Reg_SZ /d "*" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "DSCP Value" /t Reg_SZ /d "46" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\VALORANT-Win64-Shipping" /v "Throttle Rate" /t Reg_SZ /d "-1" /f
		)
	)

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "46" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "56" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "46" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "56" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "5" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "7" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "65000" /f
cls
echo TCP and UDP Optimization
pause
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
netsh int ip set global neighborcachelimit=4096
netsh int udp set global uro=disabled
powershell "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue"
cls
echo Reduce Interrupt Delay
pause
for /f %%n in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /v "*WakeOnMagicPacket" /s ^| findstr  "HKEY"') do (
reg add "%%n" /v "TxIntDelay" /t REG_SZ /d "0" /f
reg add "%%n" /v "TxAbsIntDelay" /t REG_SZ /d "0" /f
reg add "%%n" /v "RxIntDelay" /t REG_SZ /d "0" /f
reg add "%%n" /v "RxAbsIntDelay" /t REG_SZ /d "0" /f
)
cls
echo DelayedAck and MultihopSets
pause
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckFrequency" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckTicks" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "CongestionAlgorithm" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MultihopSets" /t REG_DWORD /d "15" /f
cls

:EthernetWireless
cls
echo Network Adapter Optimization
echo Ethernet = 1
echo Wireless = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :ethernet
if '%choice%'=='2' goto :Wireless
goto :EthernetWireless

:ethernet
for /f %%n in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (
reg add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
reg add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f
reg add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f
reg add "%%n" /v "DisableDelayedPowerUp" /t REG_SZ /d "2" /f
reg add "%%n" /v "*EEE" /t REG_SZ /d "0" /f
reg add "%%n" /v "EEE" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f
reg add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f
reg add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f
reg add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f
reg add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f
reg add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f
reg add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
reg add "%%n" /v "SmartPowerDownEnable" /t REG_SZ /d "0" /f
reg add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
reg add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f
reg add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f
reg add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f
reg add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
reg add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
reg add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f
reg add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f
reg add "%%n" /v "JumboPacket" /t REG_SZ /d "1514" /f
reg add "%%n" /v "TransmitBuffers" /t REG_SZ /d "4096" /f
reg add "%%n" /v "ReceiveBuffers" /t REG_SZ /d "512" /f 
reg add "%%n" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f
reg add "%%n" /v "LsoV1IPv4" /t REG_SZ /d "0" /f
reg add "%%n" /v "LsoV2IPv4" /t REG_SZ /d "0" /f
reg add "%%n" /v "LsoV2IPv6" /t REG_SZ /d "0" /f
reg add "%%n" /v "PMARPOffload" /t REG_SZ /d "0" /f
reg add "%%n" /v "PMNSOffload" /t REG_SZ /d "0" /f
reg add "%%n" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f
reg add "%%n" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f
reg add "%%n" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f
reg add "%%n" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f
reg add "%%n" /v "RSS" /t REG_SZ /d "1" /f
reg add "%%n" /v "*NumRssQueues" /t REG_SZ /d "2" /f
reg add "%%n" /v "RSSProfile" /t REG_SZ /d "3" /f
reg add "%%n" /v "*FlowControl" /t REG_SZ /d "0" /f
reg add "%%n" /v "FlowControlCap" /t REG_SZ /d "0" /f
reg add "%%n" /v "*InterruptModeration" /t REG_SZ /d "0" /f
cls
goto :AFD

:Wireless
cls
goto :AFD

:AFD
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaxActiveTransmitFileCount" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaxFastCopyTransmit" /t REG_DWORD /d "4096" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaxFastTransmit" /t REG_DWORD /d "32768" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "PriorityBoost" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNICBuffers" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "TransmitWorker" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d "33170" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d "33170" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableAddressSharing" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "LargeBufferSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "IRPStackSize" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableRawSecurity" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableDirectAcceptEx" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableChainedReceive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "4096" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "BufferMultiplier" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DefaultPnPCapabilities" /t REG_DWORD /d "36" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "DisableSmartNameResolution" /t REG_DWORD /d "1" /f
cls
Echo DNS Service Parameters
pause
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "DisableSmartNameResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableIdnMapping" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "RegistrationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "PreferLocalOverLowerBindingDNS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "DisableSmartProtocolReordering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "64000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "301" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "DisableParallelAandAAAA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "14400" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaximumUdpPacketSize" /t REG_DWORD /d "4864" /f
cls
Echo DNS Service Parameters (Updated)
pause
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "172800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "600" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "172800" /f
cls
:MaximumUdpPacketSize
Echo Maximum Udp Packet Size
Echo IPOE or PPPOE
echo IPOE = 1
echo PPPOE = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :1472
if '%choice%'=='2' goto :1464
goto :MaximumUdpPacketSize

:1472
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaximumUdpPacketSize" /t REG_DWORD /d "1472" /f
goto :customtcpip

:1464
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaximumUdpPacketSize" /t REG_DWORD /d "1464" /f
goto :customtcpip

:customtcpip
echo Custom TCP/IP Optimization
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableAuthenticateUserSharing" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "enablesecuritysignature" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "restrictnullsessaccess" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" /v "ExitOnMSICW" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "AutoDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\Security" /v "SecureDSCommunication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "QueryIpMatching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" /v "ExitOnMSICW" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UDP\Parameters" /v "EnableUDPFastSend" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_DWORD /d "0" /f
cls
:rssuser
Echo Network Adapter support RSS?
echo Yes = 1
echo No = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto :rssuser1
if '%choice%'=='2' goto :nonrssuser
goto :rssuser

:rssuser1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "RssBaseCpu" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "MaxNumRssCpus" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "TrackNblOwner" /t REG_DWORD /d "0" /f
goto :TcpWindowSize

:nonrssuser
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "RssBaseCpu" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "MaxNumRssCpus" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableRss" /t REG_DWORD /d "1" /f
goto :TcpWindowSize


:TcpWindowSize
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DeadGWDetectDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWaitDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpUseRFC1122UrgentPointe" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxSendFree" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectResponseRetransmissions" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ForwardBufferMemory" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxForwardBufferMemory" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NumForwardPackets" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxNumForwardPackets" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "AllowUnqualifiedQuery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableMediaSenseEventLog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTcpChimneyOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DnsOutstandingQueriesCount" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableAddrMaskReply" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableHeuristics" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableIPAutoConfigurationLimits" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveTime" /t REG_DWORD /d "15000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "QualifyingDestinationThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpAlwaysSourceRoute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpCacheLife" /t REG_DWORD /d "600" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpCacheMinReferencedLife" /t REG_DWORD /d "160" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpCacheSize" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTWTcbs" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableFastRouteLookup" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NumTcbTablePartitions" /t REG_DWORD /d "34" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
cls
Echo Custom TCP/IP Optimization (Updated)
pause
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /t REG_DWORD /d "1" /f
cls
:caculator
cls
echo TcpWindowSize ForwardBufferMemory NumForwardPackets
echo Your MTU is 1500 or 1492
echo Type Value
set choice=
set /p choice=

if not '%choice%'=='' (
    set choice=%choice:~0,4%
    if '%choice%'=='1500' goto :1500
    if '%choice%'=='1492' goto :1492
)

echo Invalid choice, please try again.
pause
goto :caculator

:1500
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "64240" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "64240" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ForwardBufferMemory" /t REG_DWORD /d "149760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxForwardBufferMemory" /t REG_DWORD /d "149760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NumForwardPackets" /t REG_DWORD /d "585" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxNumForwardPackets" /t REG_DWORD /d "585" /f
goto :finishedXD

:1492
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "65340" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "65340" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ForwardBufferMemory" /t REG_DWORD /d "148992" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxForwardBufferMemory" /t REG_DWORD /d "148992" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NumForwardPackets" /t REG_DWORD /d "582" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxNumForwardPackets" /t REG_DWORD /d "582" /f
goto :finishedXD


:finishedXD
cls
Echo Router Optimization
pause
echo Completed
start https://youtu.be/JAvYxek2zvc?si=uZqARQeNaNEXIcLZ
exit

:RestoreBasic
cls
netsh int ip reset
Netsh Winsock Reset
netsh int tcp set global autotuninglevel=normal
netsh int tcp set heuristics disabled
netsh int tcp set supplemental Internet congestionprovider=CUBIC
powershell Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CUBIC
netsh int tcp set global rss=enabled
netsh int tcp set global rsc=enabled
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /f
powershell Disable-NetAdapterLso -Name *
netsh int tcp set global timestamps=default
netsh int tcp set global chimney=default
netsh int ipv4 set subinterface "Wi-Fi" mtu=1500 store=persistent
netsh int ipv4 set subinterface "Ethernet" mtu=1500 store=persistent
netsh int tcp set global ecncapability=disabled
powershell Enable-NetAdapterChecksumOffload -Name *
powershell Enable-NetAdapterBinding -Name * -ComponentID ms_tcpip6
powershell Enable-NetAdapterLso -Name *
netsh int tcp set global maxsynretransmissions=4
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global initialRto=1000
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER"  /v "explorer.exe" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER"  /v "explorer.exe" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "499" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "500" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "2000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "2001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "Class" /t REG_DWORD /d "8" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t Reg_DWORD /d "0" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /f
Reg.exe delete "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "20" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER"  /v "explorer.exe" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER"  /v "explorer.exe" /t REG_DWORD /d "2" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "4" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "2" /f

for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s ^|findstr /i /l "ServiceName"') do (
	Reg.exe delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /f
	Reg.exe delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /f
	Reg.exe delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /f
	Reg.exe delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpInitialRTT" /f
	Reg.exe delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "UseZeroBroadcast" /f
	Reg.exe delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "DeadGWDetectDefault" /f
	Reg.exe delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "MTU" /f
	Reg.exe delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "InterfaceMetric" /f
)
cls
echo Restore Completed
pause
goto :AdvancedOptimization
exit

:RestoreAdvanced
cls
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeGuaranteed" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeNetworkControl" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeGuaranteed" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeNetworkControl" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeGuaranteed" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNetworkControl" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /f
netsh int ip set global neighborcachelimit=256
netsh int udp set global uro=enabled
powershell "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Disabled -WeakHostReceive Disabled -ErrorAction SilentlyContinue"
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckFrequency" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckTicks" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "CongestionAlgorithm" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MultihopSets" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaxActiveTransmitFileCount" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaxFastCopyTransmit" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaxFastTransmit" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "PriorityBoost" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNICBuffers" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "TransmitWorker" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableAddressSharing" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "LargeBufferSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "IRPStackSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableRawSecurity" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableDirectAcceptEx" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableChainedReceive" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "BufferMultiplier" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "RssBaseCpu" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "MaxNumRssCpus" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableRss" /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /f
Reg.exe delete "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /f
Reg.exe delete "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider" /v "RestoreConnection" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider" /v "WakeUp" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWaitDelay" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpUseRFC1122UrgentPointe" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxSendFree" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectResponseRetransmissions" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ForwardBufferMemory" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxForwardBufferMemory" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NumForwardPackets" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxNumForwardPackets" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableLargeMtu" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "AllowUnqualifiedQuery" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableMediaSenseEventLog" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableRss" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTcpChimneyOffload" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DnsOutstandingQueriesCount" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DnsQueryTimeouts" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableAddrMaskReply" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableHeuristics" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableIPAutoConfigurationLimits" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveTime" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "QualifyingDestinationThreshold" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastCopyReceiveThreshold" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastSendDatagramThreshold" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpAlwaysSourceRoute" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpCacheLife" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpCacheMinReferencedLife" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpCacheSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTWTcbs" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableFastRouteLookup" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /ve /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NumTcbTablePartitions" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableIPAutoConfigurationLimits" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /f

Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "UseDomainNameDevolution" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SyncDomainWithMembership" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /f


Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DeadGWDetectDefault" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DontAddDefaultGatewayDefault" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ForwardBroadcasts" /f

Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPEnableRouter" /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPEnableRouter" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_DWORD /d "10" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "RssBaseCpu" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "MaxNumRssCpus" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "TrackNblOwner" /t REG_DWORD /d "2" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "DisableCompression" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableAuthenticateUserSharing" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "enablesecuritysignature" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "restrictnullsessaccess" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\Security" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "QueryIpMatching" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoDetect" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\UDP\Parameters" /v "EnableUDPFastSend" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UDP\Parameters" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "ServiceDllUnloadOnStop" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "DisableParallelAandAAAA" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaximumUdpPacketSize" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DefaultPnPCapabilities" /t REG_DWORD /d "16" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "DisableSmartNameResolution" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /f
powershell Enable-NetAdapterChecksumOffload -Name *
powershell Enable-NetAdapterLso -Name *
cls
echo Restore Completed
pause
exit