#NoTrayIcon
#RequireAdmin
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=.\assets\icons\switch.ico
#AutoIt3Wrapper_Outfile=dpSniffer-X86.exe
#AutoIt3Wrapper_Outfile_x64=dpSniffer-X64.exe
#AutoIt3Wrapper_UseUpx=y
#AutoIt3Wrapper_Compile_Both=y
#AutoIt3Wrapper_UseX64=y
#AutoIt3Wrapper_Res_Description=Cisco, Extreme, Link Layer - Discovery Protocol Sniffer
#AutoIt3Wrapper_Res_Fileversion=0.7.0.0
#AutoIt3Wrapper_Res_ProductName=dpSniffer
#AutoIt3Wrapper_Res_LegalCopyright=longchihang
#AutoIt3Wrapper_Res_Language=1033
#AutoIt3Wrapper_Run_AU3Check=n
#AutoIt3Wrapper_AU3Check_Parameters=-d -w 1 -w 2 -w 3 -w 4 -w 5 -w 6
#Au3Stripper_Parameters=/MO
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#cs ----------------------------------------------------------------------------
 AutoIt Version: 3.3.14.5
 Author:         longchihang
 Program Name:   CDP/EDP/LLDP Sniffer (Using WinPcap driver)
#ce ----------------------------------------------------------------------------
#include <Array.au3>
#include <Debug.au3>
#include <File.au3>
#include "Winpcap.au3" ; http://opensource.grisambre.net/pcapau3/
#include "Services.au3" ; https://github.com/xwxbug/autoit-cn/blob/master/UserInclude/Services.au3
; Opt("mustdeclarevars",1)
; ------------------------------------------------------------------------------
#include <ButtonConstants.au3>
#include <ComboConstants.au3>
#include <EditConstants.au3>
#include <GUIConstantsEx.au3>
#include <GUIListView.au3>
#include <GuiStatusBar.au3>
#include <ListViewConstants.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#Region ### START Koda GUI section ### Form=.\assets\frmmain.kxf
$frmMain = GUICreate("CDP/EDP/LLDP Sniffer 0.7", 450, 470, -1, -1, $WS_OVERLAPPEDWINDOW) ;, $WS_SIZEBOX + $WS_SYSMENU)
$lblInterfaces = GUICtrlCreateLabel("Intefaces :", 8, 8, 54, 17)
GUICtrlSetResizing($lblInterfaces, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$cmbInterfaces = GUICtrlCreateCombo("", 96, 8, 337, 25, BitOR($CBS_DROPDOWNLIST,$CBS_AUTOHSCROLL));, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL)
GUICtrlSetResizing($cmbInterfaces, $GUI_DOCKLEFT + $GUI_DOCKRIGHT + $GUI_DOCKTOP + $GUI_DOCKHEIGHT)
$lblNumber0 = GUICtrlCreateLabel("Number :", 8, 40, 47, 17)
GUICtrlSetResizing($lblNumber0, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$lblNumber = GUICtrlCreateLabel("", 96, 40, 80, 20, $WS_BORDER)
GUICtrlSetResizing($lblNumber, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$chkSave = GUICtrlCreateCheckbox("Save pcap", 288, 40, 73, 17)
GUICtrlSetResizing($chkSave, $GUI_DOCKRIGHT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$btnScan = GUICtrlCreateButton("Scan", 368, 40, 65, 25)
GUICtrlSetResizing($btnScan, $GUI_DOCKRIGHT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$lblSlotPort = GUICtrlCreateLabel("Slot/Port :", 8, 72, 52, 17)
GUICtrlSetResizing($lblSlotPort, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$txtSlotPort = GUICtrlCreateInput("", 96, 72, 200, 21)
GUICtrlSetResizing($txtSlotPort, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKHEIGHT)
$lblDeviceName = GUICtrlCreateLabel("Device name :", 8, 104, 73, 17)
GUICtrlSetResizing($lblDeviceName, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$txtDeviceName = GUICtrlCreateInput("", 96, 104, 200, 21)
GUICtrlSetResizing($txtDeviceName, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKHEIGHT)
$lblDeviceMac = GUICtrlCreateLabel("Devic MAC :", 8, 136, 64, 17)
GUICtrlSetResizing($lblDeviceMac, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$txtDeviceMac = GUICtrlCreateInput("", 96, 136, 200, 21)
GUICtrlSetResizing($txtDeviceMac, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKHEIGHT)
$lblDeviceVersion = GUICtrlCreateLabel("Device Version :", 8, 168, 82, 17)
GUICtrlSetResizing($lblDeviceVersion, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$edtDeviceVersion = GUICtrlCreateEdit("", 96, 168, 337, 65)
GUICtrlSetResizing($edtDeviceVersion, $GUI_DOCKLEFT + $GUI_DOCKRIGHT + $GUI_DOCKTOP + $GUI_DOCKHEIGHT)
$btnExport = GUICtrlCreateButton("Export", 8, 210, 40, 25)
GUICtrlSetResizing($btnExport, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$btnClear = GUICtrlCreateButton("Clear", 50, 210, 40, 25)
GUICtrlSetResizing($btnClear, $GUI_DOCKLEFT + $GUI_DOCKTOP + $GUI_DOCKSIZE)
$packetwindow = GUICtrlCreateListView("Number|Time|Len|_DP|Slot/Port|Device name", 8, 240, 433, 201)
GUICtrlSendMsg(-1, $LVM_SETCOLUMNWIDTH, 0, 40)
GUICtrlSendMsg(-1, $LVM_SETCOLUMNWIDTH, 1, 80)
GUICtrlSendMsg(-1, $LVM_SETCOLUMNWIDTH, 2, 40)
GUICtrlSendMsg(-1, $LVM_SETCOLUMNWIDTH, 3, 70)
GUICtrlSendMsg(-1, $LVM_SETCOLUMNWIDTH, 4, 80)
GUICtrlSendMsg(-1, $LVM_SETCOLUMNWIDTH, 5, 120)
_GUICtrlListView_JustifyColumn(GUICtrlGetHandle($packetwindow), 2, 1)
GUICtrlSetResizing($packetwindow, $GUI_DOCKLEFT + $GUI_DOCKRIGHT + $GUI_DOCKTOP + $GUI_DOCKBOTTOM)

$stbMain = _GUICtrlStatusBar_Create($frmMain)
Dim $stbMain_PartsWidth[3] = [150, 300, -1]
_GUICtrlStatusBar_SetParts($stbMain, $stbMain_PartsWidth)
_GUICtrlStatusBar_SetText($stbMain, "Status :", 0)
_GUICtrlStatusBar_SetText($stbMain, "Packets :", 1)
_GUICtrlStatusBar_SetText($stbMain, "Hit _DPs :", 2)
_GUICtrlStatusBar_SetMinHeight($stbMain, 25)

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###
; ------------------------------------------------------------------------------
GUIRegisterMsg($WM_NOTIFY, "WM_NOTIFY")
GUIRegisterMsg($WM_SIZE, "WM_SIZE")

Func OSPath()
	Switch @OSVersion
	Case "WIN_10", "WIN_81", "WIN_8", "WIN_7", "WIN_VISTA", _
			"WIN_2016", "WIN_2012R2", "WIN_2012", "WIN_2008R2", "WIN_2008"
		Return "VISTA"
	Case "WIN_XP", "WIN_XPe", "WIN_2003"
		Return "XP"
	Case "WIN_2000"
		Return "2000"
	Case Else
		Return "VISTA"
	EndSwitch
EndFunc
Global $g_sBinaryPath = @ScriptDir & "\" & @OSArch & "\" & OSPath() & "\drivers\npf.sys"

;Global $g_sBinaryPath = @ScriptDir & "\drivers\npf.sys"
Global $g_sServiceName = GetServiceNameFromBinaryPath($g_sBinaryPath)
; Global $bDebug = True
Global $g_bInstallPcapService = False

Func _Exit()
	If $g_bInstallPcapService Then UnInstallService($g_sServiceName)
	Exit
EndFunc

$g_bInstallPcapService = InstallService($g_sServiceName, $g_sBinaryPath)

$winpcap=_PcapSetup()
If ($winpcap=-1) Then
	MsgBox(16,"Pcap error !","WinPcap not found !")
	_Exit()
EndIf

$pcap_devices=_PcapGetDeviceList()
If ($pcap_devices=-1) Then
	MsgBox(16,"Pcap error !",_PcapGetLastError())
	_Exit()
EndIf

GUICtrlSetData($cmbInterfaces, "Pcap capture file")
For $i = 0 to Ubound($pcap_devices)-1
	GUICtrlSetData($cmbInterfaces, $pcap_devices[$i][1])
Next

Local $fScan = False
Local $sInterface = ""
Local $nPromiscuous = 1
Local $sFilter = "( ether[0:4] = 0x0180c200 and ether[4:2] = 0x000e and ether[12:2] = 0x88cc )" _
	 & " or ( ether[0:4] = 0x01000ccc and ether[4:2] = 0xcccc and ether[14:4] = 0xaaaa0300 and ether[18:4] = 0x000c2000 ) " _
	 & " or ( ether[0:4] = 0x00e02b00 and ether[4:2] = 0x0000 and ether[14:4] = 0xaaaa0300 and ether[18:4] = 0xe02b00bb ) " _
	 & " or ( ether[0:4] = 0x0180c200 and ether[4:2] = 0x000e and ether[14:4] = 0xaaaa0300 and ether[18:4] = 0x000088cc ) "
Local $packet_number=1
Local $pcap=0
Local $packet=0
Local $pcapfile=0
Local $packet_stats
Local $sScanningDot="."
Local $nMsg
Local $timeScanning
Local $packet_received=-1
Local $packet_dp_hits=-1

Local $aValues[0][5]

Local $DP_TYPE[]=["NULL", "CDP", "EDP", "LLDP", "LLDP-EthII"]
 ; _DebugSetup("Debug dpSniffer")
_DebugOut("Start debug !!!!")
While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			ExitLoop
		Case $btnScan
			$fScan = Not $fScan
			If ($fScan) Then
				GUICtrlSetData($btnScan, "Stop")
				GUICtrlSetState ($chkSave, $GUI_DISABLE)
				GUICtrlSetState ($cmbInterfaces, $GUI_DISABLE)

				$timeScanning=TimerInit()
				_GUICtrlStatusBar_SetText($stbMain, "Status : " & "Scanning" & $sScanningDot , 0)
				$sInterface = GetSelectedInterface()
				_DebugOut("$sInterface: " & $sInterface)
				$packet_number=1
				$pcap=_PcapStartCapture($sInterface, $sFilter, $nPromiscuous)
				If ($pcap=-1) Then
					MsgBox(16,"Pcap error !",_PcapGetLastError())
					ContinueLoop
				EndIf
				#cs
				Local $linktype=_PcapGetLinkType($pcap)
				If ($linktype[1]<>"EN10MB") Then
					MsgBox(16,"Pcap error !","This example only works for Ethernet captures")
					ContinueLoop
				Endif
				#ce
				If GUICtrlRead($chkSave)=$GUI_CHECKED Then
					Local $file=FileSaveDialog ( "Pcap file to write to ?", ".", "Pcap (*.pcap)" ,16 )
					If ($file<>"") Then
						;If StringLower(StringRight($file,5))<>".pcap" Then $file&=".pcap"
						$pcapfile=_PcapSaveToFile($pcap,$file)
						If ($pcapfile=0) Then MsgBox(16,"Pcap error !",_PcapGetLastError())
					EndIf
				EndIf
			Else
				If IsPtr($pcapfile) Then
					_PcapStopCaptureFile($pcapfile)
					$pcapfile=0
				EndIf
				If Not IsInt($pcap) Then _PcapStopCapture($pcap)
				$pcap=0
				_GUICtrlStatusBar_SetText($stbMain, "Status : " & "Stop", 0)
				; _GUICtrlStatusBar_SetText($stbMain, "Packets : ", 1)
				; _GUICtrlStatusBar_SetText($stbMain, "Hit _DPs : ", 2)
				GUICtrlSetData($btnScan, "Scan")
				GUICtrlSetState ($cmbInterfaces, $GUI_ENABLE)
				GUICtrlSetState ($chkSave, $GUI_ENABLE)
			EndIf
		Case $btnExport
			Local $tsvfile=FileSaveDialog( "Tsv file to write to ?", ".", "Tsv (*.tsv)" ,16 )
			If ($tsvfile<>"") Then
				;If StringLower(StringRight($tsvfile,4))<>".tsv" Then $file&=".tsv"
				If (Not _GUICtrlListView_SaveCSV($packetwindow,$tsvfile,@TAB,Default)) Then MsgBox(16,"Tsv export error !",_WinAPI_GetLastErrorMessage())
			EndIf
		Case $btnClear
			_GUICtrlListView_DeleteAllItems($packetwindow)
			DeleteAllAndUpdateValues()
	EndSwitch
	If IsPtr($pcap) Then 	; If $pcap is a Ptr, then the capture is Scanning
		If TimerDiff($timeScanning)>1000 Then
			_GUICtrlStatusBar_SetText($stbMain, "Status : " & "Scanning" & $sScanningDot , 0)
			If $sScanningDot="..........." Then
				$sScanningDot="."
			Else
				$sScanningDot=$sScanningDot&"."
			EndIf
			$timeScanning=TimerInit()
		EndIf

		Local $time0=TimerInit()
		While (TimerDiff($time0)<500) ; Retrieve packets from queue for maximum 500ms before returning to main loop, not to "hang" the window for user
			$packet=_PcapGetPacket($pcap)
			$packet_stats=_PcapGetStats($pcap)
			If Not IsInt($packet_stats) Then
				If $packet_received <> $packet_stats[0][0] Then
					_GUICtrlStatusBar_SetText($stbMain, "Packets : " & $packet_stats[0][0], 1)
					$packet_received=$packet_stats[0][0]
				EndIf
				If $packet_dp_hits <> $packet_stats[3][0] Then
					_GUICtrlStatusBar_SetText($stbMain, "Hit _DPs : " & $packet_stats[3][0], 2)
					$packet_dp_hits=$packet_stats[3][0]
				EndIf
			EndIf
			If IsInt($packet) Then ExitLoop
			Local $nXdp = FindXdp($packet[3])
			Local $nXdpSummary
			Switch $nXdp
				Case 1
					$nXdpSummary=CdpHandler($packet[3], 22, $packet[2])
				Case 2
					$nXdpSummary=EdpHandler($packet[3], 22, $packet[2])
				Case 3
					$nXdpSummary=LldpHandler($packet[3], 22, $packet[2])
				Case 4
					$nXdpSummary=LldpHandler($packet[3], 14, $packet[2])
			EndSwitch

			GUICtrlCreateListViewItem($packet_number&"|"&StringTrimRight($packet[0],4)&"|"&$packet[2]&"|"&$DP_TYPE[$nXdp] & "|" & $nXdpSummary, $packetwindow)
			; Local $data=$packet[3]
			_GUICtrlListView_EnsureVisible($packetwindow, $packet_number)
			; GUICtrlSetData($lblNumber, $packet_number)
			$packet_number+=1

			If IsPtr($pcapfile) Then _PcapWriteLastPacket($pcapfile)
		Wend

	EndIf
WEnd
GUIDelete()
If IsPtr($pcapfile) Then _PcapStopCaptureFile($pcapfile)	; A file is still open: close it
if IsPtr($pcap) Then _PcapStopCapture($pcap)	; A capture is still running: close it
_PcapFree()

_Exit()


Func GetSelectedInterface()
	If (GUICtrlRead($cmbInterfaces)="Pcap capture file") Then
		$file=FileOpenDialog ( "Pcap file to open ?", ".", "Pcap (*.pcap)|All files (*.*)" ,1 )
		If $file="" Then Return ""
		Return "file://"&$file
	Else
		For $n = 0 to Ubound($pcap_devices)-1
			If $pcap_devices[$n][1]=GUICtrlRead($cmbInterfaces) Then
				Return $pcap_devices[$n][0]
			EndIf
		Next
	EndIf
	Return ""
EndFunc

; GUICtrlRead($filter)
#cs
REFERENCE:
	https://www.darkoperator.com/blog/2008/9/20/tcpdump-filter-for-cdp.html
	http://www.troliver.com/?p=335

	( destination_mac = 0x01000ccccccc and ethernet_type = CDP )
	or ( destination_mac = 0x00e02b000000 and ethernet_type = EDP )
	or ( destination_mac = 0x0180c200000e and ethernet_type = LLDP )
	or ( LLC / SNAP )

	$sFilter = "( ether[0:4] = 0x01000ccc and ether[4:2] = 0xcccc and ether[20:2] = 0x2000 )" _
	 & " or ( ether[0:4] = 0x00e02b00 and ether[4:2] = 0x0000 and ether[20:2] = 0x00bb )" _
	 & " or ( ether[0:4] = 0x0180c200 and ether[4:2] = 0x000e and ether[12:2] = 0x88cc )" _
	 & " or ( ether[14:2] = 0xaaaa and ether[16:1] = 0x03 )"

	; EthernetII.LLDP, LLC/SNAP.CDP, LLC/SNAP.EDP, LLC/SNAP.LLDP
	$sFilter = "( ether[0:4] = 0x0180c200 and ether[4:2] = 0x000e and ether[12:2] = 0x88cc )" _
	 & " or ( ether[0:4] = 0x01000ccc and ether[4:2] = 0xcccc and ether[14:4] = 0xaaaa0300 and ether[18:4] = 0x000c2000 ) " _
	 & " or ( ether[0:4] = 0x00e02b00 and ether[4:2] = 0x0000 and ether[14:4] = 0xaaaa0300 and ether[18:4] = 0xe02b00bb ) " _
	 & " or ( ether[0:4] = 0x0180c200 and ether[4:2] = 0x000e and ether[14:4] = 0xaaaa0300 and ether[18:4] = 0x000088cc ) "

	 ( ether[0:4] = 0x0180c200 and ether[4:2] = 0x000e and ether[12:2] = 0x88cc ) or ( ether[0:4] = 0x01000ccc and ether[4:2] = 0xcccc and ether[14:4] = 0xaaaa0300 and ether[18:4] = 0x000c2000 ) or ( ether[0:4] = 0x00e02b00 and ether[4:2] = 0x0000 and ether[14:4] = 0xaaaa0300 and ether[18:4] = 0xe02b00bb ) or ( ether[0:4] = 0x0180c200 and ether[4:2] = 0x000e and ether[14:4] = 0xaaaa0300 and ether[18:4] = 0x000088cc )
#ce


Func FindXdp($data)
	;Local $macdst=StringMid ($data,3,2)&":"&StringMid ($data,5,2)&":"&StringMid ($data,7,2)&":"&StringMid ($data,9,2)&":"&StringMid ($data,11,2)&":"&StringMid ($data,13,2)
	;Local $macsrc=StringMid ($data,15,2)&":"&StringMid ($data,17,2)&":"&StringMid ($data,19,2)&":"&StringMid ($data,21,2)&":"&StringMid ($data,23,2)&":"&StringMid ($data,25,2)
	;Local $ethertype=BinaryMid ( $data, 13 ,2 )

	Local $bMacDestination = BinaryMid($data, 1, 6)
	Local $bMacSource = BinaryMid($data, 7, 6)
	Local $bEtherType = BinaryMid($data, 13, 2)
	Local $bEthernetIIType = BinaryMid($data, 13, 2)

	Local $fLlcSnap = False
	Local $nXdp = 0

	If $bMacDestination = "0x01000ccccccc" Then
		; CDP destination, CDP only LLC/SNAP type
		$fLlcSnap = True
		$nXdp = 1
	ElseIf $bMacDestination = "0x00e02b000000" Then
		; EDP destination, EDP only LLC/SNAP type
		$fLlcSnap = True
		$nXdp = 2
	ElseIf $bMacDestination = "0x0180c200000e" Then
		; LLDP destination, LLDP may be EthernetII type or LLC/SNAP type
		If $bEthernetIIType="0x88cc" Then
			; LLDP EthernetII
			$fLlcSnap = False
			$nXdp = 4
		Else
			$fLlcSnap = True
			$nXdp = 3
		EndIf
	EndIf

	If $fLlcSnap Then
		Local $bLlcSnap = BinaryMid($data, 15, 3)
		Local $bLlcSnapOrgCode
		Local $bLlcSnapType
		If $bLlcSnap = "0xaaaa03" Then
			$bLlcSnapOrgCode = BinaryMid($data,  18, 3)
			$bLlcSnapType = BinaryMid($data,  21, 2)

			Switch $nXdp
				Case 1
					If $bLlcSnapOrgCode = "0x00000c" And _
						$bLlcSnapType = "0x2000" Then
						; Cisco CDP
						Return $nXdp
					EndIf
				Case 2
					If $bLlcSnapOrgCode = "0x00e02b" And _
						$bLlcSnapType = "0x00bb" Then
						; Extreme, EDP
						Return $nXdp
					EndIf
				Case 3
					If $bLlcSnapOrgCode = "0x000000" And _
						$bLlcSnapType = "0x88cc" Then
						; IEEE, LLDP
						Return $nXdp
					EndIf
			EndSwitch
			$nXdp = 0
		EndIf
		; Else Unknown
	EndIf

	; LLDP EthernetII Or Unknown 0
	Return $nXdp
EndFunc

Func CdpHandler($data, $cdp_data_offset, $data_len)
	Local $nCurrent=$cdp_data_offset + 1
	Local $nCdpVersion = Number(BinaryMid($data, $nCurrent, 1))
	Local $nCdpTtl = Number(BinaryMid($data, $nCurrent + 1, 1))
	Local $nCdpCheckSum = Number(String(BinaryMid($data, $nCurrent + 2, 1)))
	$nCurrent+=4

	Local $bCdpTlvType
	Local $nCdpTlvLength
	Local $nNextTlv

	Local $sCdpDeviceId
	Local $nCdpNumberOfAddresses
	Local $nCdpAddressProtocolType
	Local $nCdpAddressProtocolLength
	Local $nCdpAddressProtocol
	Local $nCdpAddressLength
	Local $sCdpAddress = ""
	Local $sCdpAddresses = ""
	Local $sCdpPortId = ""
	Local $sCdpPlatform = ""
	Local $sCdpSoftware = ""
	Local $sCdpDeviceMac = ""
	Local $nCdpNativeVlan
	Local $nCdpDuplex
	Local $sCdpDuplex = ""

	_DebugOut("$data: " & $data)
	While $nCurrent < $data_len
		_DebugOut("$data["&$nCurrent&"]: " & BinaryMid($data, $nCurrent, 1))
		$bCdpTlvType = Number(String(BinaryMid($data, $nCurrent, 2)))
		$nCdpTlvLength = Number(String(BinaryMid($data, $nCurrent + 2, 2))) ; Number(String(BinaryMid())) BigEndian, Number(BinaryMid()) LittleEndian
		_DebugOut("$nCurrent: "&$nCurrent)
		_DebugOut("$nCdpTlvLength: "&$nCdpTlvLength)
		$nNextTlv = $nCurrent + $nCdpTlvLength
		_DebugOut("$nNextTlv: "&$nNextTlv)
		$nCurrent+=4
		Switch $bCdpTlvType
			Case "0x00001" ; CDP_TLV_TYPE_DEVICE_ID
				$sCdpDeviceId = BinaryToString(BinaryMid($data, $nCurrent, $nCdpTlvLength - 4)) ; minus 4 bytes of tlv header

			Case "0x00002" ; CDP_TLV_TYPE_ADDRESSES
				$nCdpNumberOfAddresses = Number(String(BinaryMid($data, $nCurrent, 4)))
				$nCurrent += 4
				For $n = 1 To $nCdpNumberOfAddresses
					$nCdpAddressProtocolType = Number(BinaryMid($data, $nCurrent, 1))
					$nCdpAddressProtocolLength = Number(BinaryMid($data, $nCurrent + 1, 1))
					$nCdpAddressProtocol = Number(BinaryMid($data, $nCurrent + 2, 1))
					$nCdpAddressLength = Number(String(BinaryMid($data, $nCurrent + 3, 2)))
					If $nCdpAddressLength <= 4 Then
						For $i = 1 To $nCdpAddressLength
							If $sCdpAddress = "" Then
								$sCdpAddress = Number(BinaryMid($data, $nCurrent + 4 + $i, 1))
							Else
								$sCdpAddress &= "." & Number(BinaryMid($data, $nCurrent + 4 + $i, 1))
							EndIf
						Next
					Else
						For $i = 1 To $nCdpAddressLength Step 2 ; show as ipv6
							If $sCdpAddress = "" Then
								$sCdpAddress = StringMid(BinaryMid($data, $nCurrent + 4 + $i, 2), 3)
							Else
								$sCdpAddress &= ":" & StringMid(BinaryMid($data, $nCurrent + 4 + $i, 2), 3)
							EndIf
						Next
						If Mod($nCdpAddressLength, 2) <> 0 Then ; Is odd, end pair-byte only one byte.
							$sCdpAddress &= ":" & StringMid(BinaryMid($data, $nCurrent + 4 + $nCdpAddressLength, 1), 3)
						EndIf
					EndIf

					If $sCdpAddresses = "" Then
						$sCdpAddresses = $sCdpAddress
					Else
						$sCdpAddresses &= ", " & $sCdpAddress
					EndIf

					$nCurrent += (5 + $nCdpAddressLength)
				Next

			Case "0x00003" ; CDP_TLV_TYPE_PORT_ID
				$sCdpPortId = BinaryToString(BinaryMid($data, $nCurrent, $nCdpTlvLength - 4)) ; minus 4 bytes of tlv header

			Case "0x00004" ; CDP_TLV_TYPE_CAPABILITIES
				; Skip these information

			Case "0x00005" ; CDP_TLV_TYPE_SOFTWARE
				$sCdpSoftware = BinaryToString(BinaryMid($data, $nCurrent, $nCdpTlvLength - 4)) ; minus 4 bytes of tlv header
				$sCdpSoftware = StringReplace($sCdpSoftware, @LF, @CRLF)

			Case "0x00006" ; CDP_TLV_TYPE_PLATFORM
				$sCdpPlatform = BinaryToString(BinaryMid($data, $nCurrent, $nCdpTlvLength - 4)) ; minus 4 bytes of tlv header

			Case "0x00008" ; CDP_TLV_TYPE_PROTOCOL_HELLO
				$sCdpDeviceMac = StringUpper(StringMid(BinaryMid($data, $nCurrent+23, 6),3))

			Case "0x0000a" ; CDP_TLV_TYPE_NATIVE_VLAN
				$nCdpNativeVlan = Number(String(BinaryMid($data, $nCurrent, 2)))

			Case "0x0000b" ; CDP_TLV_TYPE_DUPLEX
				$nCdpDuplex = Number(BinaryMid($data, $nCurrent, 1))
				If $nCdpDuplex = 1 Then
					$sCdpDuplex = "Full"
				Else
					$sCdpDuplex = "Half"
				EndIf

		EndSwitch
		$nCurrent=$nNextTlv
	WEnd

	AddAndUpdateValues($sCdpPortId, $sCdpDeviceId, $sCdpDeviceMac, $sCdpSoftware)
	Return $sCdpPortId & "|" & $sCdpDeviceId
EndFunc

Func EdpHandler($data, $edp_data_offset, $data_len)
	Local $nCurrent=$edp_data_offset + 1
	Local $nEdpVersion = Number(BinaryMid($data, $nCurrent, 1))
	Local $sEdpDeviceMac = StringUpper(StringMid(BinaryMid($data, $nCurrent+10, 6),3))
	$nCurrent+=16
	Local $bEdpTlvType
	Local $nEdpTlvLength
	Local $nNextTlv
	Local $nEdpSlot
	Local $nEdpPort
	Local $sEdpSlotPort = ""
	Local $sEdpDeviceVesion = ""
	Local $sEdpDeviceName = ""
	_DebugOut("$data: " & $data)
	While $nCurrent < $data_len
		_DebugOut("$data["&$nCurrent&"]: " & BinaryMid($data, $nCurrent, 1))
		If BinaryMid($data, $nCurrent, 1) = "0x99" Then ; EDP_TLV_MARKER
			$bEdpTlvType = BinaryMid($data, $nCurrent + 1, 1)
			$nEdpTlvLength = Number(String(BinaryMid($data, $nCurrent + 2, 2))) ; Number(String(BinaryMid())) BigEndian, Number(BinaryMid()) LittleEndian
			_DebugOut("$nCurrent: "&$nCurrent)
			_DebugOut("$nEdpTlvLength: "&$nEdpTlvLength)
			$nNextTlv = $nCurrent + $nEdpTlvLength
			_DebugOut("$nNextTlv: "&$nNextTlv)
			$nCurrent+=4
			Switch $bEdpTlvType
				Case "0x02" ; EDP_TLV_TYPE_INFO
					$sEdpSlotPort = Number(String(BinaryMid($data, $nCurrent, 2))) + 1 & ":" & _
									Number(String(BinaryMid($data, $nCurrent + 2, 2))) + 1 ; BigEndian
					; virt_chassis + reserved, don't want to display
					$nCurrent+=12
					$sEdpDeviceVesion = Number(BinaryMid($data, $nCurrent, 1)) & "." & _
										Number(BinaryMid($data, $nCurrent + 1, 1)) & "." & _
										Number(BinaryMid($data, $nCurrent + 2, 1)) & "." & _
										Number(BinaryMid($data, $nCurrent + 3, 1))
					$nCurrent+=4
				Case "0x01" ; EDP_TLV_TYPE_DISPLAY
					$sEdpDeviceName = BinaryToString(BinaryMid($data, $nCurrent, $nEdpTlvLength - 4)) ; minus 4 bytes of tlv header
					_DebugOut("display: "&BinaryMid($data, $nCurrent, $nEdpTlvLength))
				Case "0x00" ; EDP_TLV_TYPE_NULL
					; The tail of Edp
			EndSwitch
			$nCurrent=$nNextTlv
		Else
			$nCurrent+=1
		EndIf
	WEnd

	AddAndUpdateValues($sEdpSlotPort, $sEdpDeviceName, $sEdpDeviceMac, $sEdpDeviceVesion)
	Return $sEdpSlotPort & "|" & $sEdpDeviceName
EndFunc

Func LldpHandler($data, $lldp_data_offset, $data_len)
	Local $nCurrent=$lldp_data_offset + 1

	Local $bLldpTlvType
	Local $nLldpTlvLength
	Local $nNextTlv

	Local $bLldpTlvSubType
	Local $sLldpPortId = ""
	Local $sLldpDeviceMac = ""
	Local $sLldpPortDesc = ""
	Local $sLldpSystemName = ""
	Local $sLldpSystemDesc = ""

	_DebugOut("$data: " & $data)
	While $nCurrent < $data_len
		_DebugOut("$data["&$nCurrent&"]: " & BinaryMid($data, $nCurrent, 1))
		$bLldpTlvType = BitShift(Number(BinaryMid($data, $nCurrent, 1)),1)
		$nLldpTlvLength = BitOr(BitShift(BitAnd(Number(BinaryMid($data, $nCurrent, 1)), 0x01), -8), _
								Number(BinaryMid($data, $nCurrent + 1, 1)))

		_DebugOut("$nCurrent: "&$nCurrent)
		_DebugOut("$nLldpTlvLength: "&$nLldpTlvLength)
		$nNextTlv = $nCurrent + $nLldpTlvLength + 2 ; $nLldpTlvLength not include tlv header
		_DebugOut("$nNextTlv: "&$nNextTlv)
		$nCurrent+=2
		Switch $bLldpTlvType
			Case "0x01" ; LLDP_TLV_TYPE_CHASSIS
				$bLldpTlvSubType = Number(BinaryMid($data, $nCurrent, 1))
				$nCurrent+=1
				Switch $bLldpTlvSubType
					Case "0x01", "0x02", "0x03"
						; LLDP_TLV_TYPE_CHASSIS_SUBTYPE_CHASSIS_COMPONENT
						; LLDP_TLV_TYPE_CHASSIS_SUBTYPE_INTERFACE_ALIAS
						; LLDP_TLV_TYPE_CHASSIS_SUBTYPE_PORT_COMPONENT
						; Skip
					Case "0x04" ; LLDP_TLV_TYPE_CHASSIS_SUBTYPE_MAC_ADDRESS
						$sLldpDeviceMac = StringUpper(StringMid(BinaryMid($data, $nCurrent, 6),3))
					Case "0x05", "0x06", "0x07"
						; LLDP_TLV_TYPE_CHASSIS_SUBTYPE_NETWORK_ADDRESS
						; LLDP_TLV_TYPE_CHASSIS_SUBTYPE_INTERFACE_NAME:
						; LLDP_TLV_TYPE_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED
						; Skip
				EndSwitch

			Case "0x02" ; LLDP_TLV_TYPE_PORT
				$bLldpTlvSubType = Number(BinaryMid($data, $nCurrent, 1))
				$nCurrent+=1
				Switch $bLldpTlvSubType
					Case "0x01", "0x02", "0x05"
						; LLDP_TLV_TYPE_PORT_SUBTYPE_INTERFACE_ALIAS
						; LLDP_TLV_TYPE_PORT_SUBTYPE_PORT_COMPONENT
						; LLDP_TLV_TYPE_PORT_SUBTYPE_INTERFACE_NAME
						$sLldpPortId = BinaryToString(BinaryMid($data, $nCurrent, $nLldpTlvLength - 1)) ; $nLldpTlvLength not include tlv header but include the LldpTlvSubType 1 byte, so need to minus 1.

					Case "0x03", "0x04", "0x06", "0x07"
						; LLDP_TLV_TYPE_PORT_SUBTYPE_MAC_ADDRESS:
						; LLDP_TLV_TYPE_PORT_SUBTYPE_NETWORK_ADDRESS:
						; LLDP_TLV_TYPE_PORT_SUBTYPE_AGENT_CIRCUIT_ID:
						; LLDP_TLV_TYPE_PORT_SUBTYPE_LOCALLY_ASSIGNED:
						; Skip
				EndSwitch

			Case "0x03" ; LLDP_TLV_TYPE_TTL
				; Skip

			Case "0x04" ; LLDP_TLV_TYPE_PORT_DESCRIPTION
				$sLldpPortDesc = BinaryToString(BinaryMid($data, $nCurrent, $nLldpTlvLength)) ; $nLldpTlvLength not include tlv header

			Case "0x05" ; LLDP_TLV_TYPE_SYSTEM_NAME
				$sLldpSystemName = BinaryToString(BinaryMid($data, $nCurrent, $nLldpTlvLength)) ; $nLldpTlvLength not include tlv header

			Case "0x06" ; LLDP_TLV_TYPE_SYSTEM_DESCRIPTION
				$sLldpSystemDesc = BinaryToString(BinaryMid($data, $nCurrent, $nLldpTlvLength)) ; $nLldpTlvLength not include tlv header

			Case "0x07" ; LLDP_TLV_TYPE_SYSTEM_CAPABILITIES
				; Skip

			Case "0x08" ; LLDP_TLV_TYPE_MANAGEMENT_ADDRESS
				; Skip

		EndSwitch
		$nCurrent=$nNextTlv
	WEnd

	Local $sLldpPort
	If $sLldpPortDesc <> "" Then
		; $sLldpPort = $sLldpPortDesc
		If $sLldpPortId <> "" Then
			$sLldpPort = $sLldpPortId & " (" & $sLldpPortDesc & ")"
		Else
			$sLldpPort = $sLldpPortDesc
		EndIf
	Else
		$sLldpPort = $sLldpPortId
	EndIf

	AddAndUpdateValues($sLldpPort , $sLldpSystemName, $sLldpDeviceMac, $sLldpSystemDesc)
	Return $sLldpPort & "|" & $sLldpSystemName
EndFunc

Func AddAndUpdateValues($sSlotPort, $sDeviceName, $sDeviceMac, $sDeviceVersion)
	Local $aAddValues[][] = [[$packet_number, $sSlotPort, $sDeviceName, $sDeviceMac, $sDeviceVersion]]
	_ArrayAdd($aValues, $aAddValues)
	GUICtrlSetData($lblNumber, $packet_number)
	GUICtrlSetData($txtSlotPort, $sSlotPort)
	GUICtrlSetData($txtDeviceName, $sDeviceName)
	GUICtrlSetData($txtDeviceMac, $sDeviceMac)
	GUICtrlSetData($edtDeviceVersion, $sDeviceVersion)
EndFunc

Func UpdateValues($nIndex)
	_DebugOut("UpdateValues() " & "$nIndex: " & $nIndex & " UBound($aValues, $UBOUND_ROWS): " & UBound($aValues, $UBOUND_ROWS))
	; _ArrayDisplay($aValues)
	If 0 <= $nIndex And $nIndex < UBound($aValues, $UBOUND_ROWS) Then
		_DebugOut("UpdateValues() " & "$lblNumber: " & $aValues[$nIndex][0])
		GUICtrlSetData($lblNumber, $aValues[$nIndex][0])
		GUICtrlSetData($txtSlotPort, $aValues[$nIndex][1])
		GUICtrlSetData($txtDeviceName, $aValues[$nIndex][2])
		GUICtrlSetData($txtDeviceMac, $aValues[$nIndex][3])
		GUICtrlSetData($edtDeviceVersion, $aValues[$nIndex][4])
		;GUICtrlSetData($lblNumber, $nIndex + 1)
	EndIf
EndFunc

Func DeleteAllAndUpdateValues()
	ReDim $aValues[0][5]
	; _ArrayDisplay($aValues)
	GUICtrlSetData($lblNumber, "")
	GUICtrlSetData($txtSlotPort, "")
	GUICtrlSetData($txtDeviceName, "")
	GUICtrlSetData($txtDeviceMac, "")
	GUICtrlSetData($edtDeviceVersion, "")
EndFunc

Func WM_NOTIFY($hWnd, $iMsg, $wParam, $lParam)
	#forceref $hWnd, $iMsg, $wParam
	Local $hWndFrom, $iIDFrom, $iCode, $tNMHDR, $hWndListView, $tInfo
	$hWndListView = $packetwindow
	If Not IsHWnd($packetwindow) Then $hWndListView = GUICtrlGetHandle($packetwindow)

	$tNMHDR = DllStructCreate($tagNMHDR, $lParam)
	$hWndFrom = HWnd(DllStructGetData($tNMHDR, "hWndFrom"))
	$iIDFrom = DllStructGetData($tNMHDR, "IDFrom")
	$iCode = DllStructGetData($tNMHDR, "Code")
	Switch $hWndFrom
		Case $hWndListView
			Switch $iCode
				Case $NM_CLICK ; Sent by a list-view control when the user clicks an item with the left mouse button
					$tInfo = DllStructCreate($tagNMITEMACTIVATE, $lParam)
					_DebugOut("$NM_CLICK" & @CRLF & "--> hWndFrom:" & @TAB & $hWndFrom & @CRLF & _
							"-->IDFrom:" & @TAB & $iIDFrom & @CRLF & _
							"-->Code:" & @TAB & $iCode & @CRLF & _
							"-->Index:" & @TAB & DllStructGetData($tInfo, "Index") & @CRLF & _
							"-->SubItem:" & @TAB & DllStructGetData($tInfo, "SubItem") & @CRLF & _
							"-->NewState:" & @TAB & DllStructGetData($tInfo, "NewState") & @CRLF & _
							"-->OldState:" & @TAB & DllStructGetData($tInfo, "OldState") & @CRLF & _
							"-->Changed:" & @TAB & DllStructGetData($tInfo, "Changed") & @CRLF & _
							"-->ActionX:" & @TAB & DllStructGetData($tInfo, "ActionX") & @CRLF & _
							"-->ActionY:" & @TAB & DllStructGetData($tInfo, "ActionY") & @CRLF & _
							"-->lParam:" & @TAB & DllStructGetData($tInfo, "lParam") & @CRLF & _
							"-->KeyFlags:" & @TAB & DllStructGetData($tInfo, "KeyFlags"))
							UpdateValues(DllStructGetData($tInfo, "Index"))
					; No return value
				Case $NM_DBLCLK ; Sent by a list-view control when the user double-clicks an item with the left mouse button
					$tInfo = DllStructCreate($tagNMITEMACTIVATE, $lParam)
					_DebugOut("$NM_DBLCLK" & @CRLF & "--> hWndFrom:" & @TAB & $hWndFrom & @CRLF & _
							"-->IDFrom:" & @TAB & $iIDFrom & @CRLF & _
							"-->Code:" & @TAB & $iCode & @CRLF & _
							"-->Index:" & @TAB & DllStructGetData($tInfo, "Index") & @CRLF & _
							"-->SubItem:" & @TAB & DllStructGetData($tInfo, "SubItem") & @CRLF & _
							"-->NewState:" & @TAB & DllStructGetData($tInfo, "NewState") & @CRLF & _
							"-->OldState:" & @TAB & DllStructGetData($tInfo, "OldState") & @CRLF & _
							"-->Changed:" & @TAB & DllStructGetData($tInfo, "Changed") & @CRLF & _
							"-->ActionX:" & @TAB & DllStructGetData($tInfo, "ActionX") & @CRLF & _
							"-->ActionY:" & @TAB & DllStructGetData($tInfo, "ActionY") & @CRLF & _
							"-->lParam:" & @TAB & DllStructGetData($tInfo, "lParam") & @CRLF & _
							"-->KeyFlags:" & @TAB & DllStructGetData($tInfo, "KeyFlags"))
					; No return value
				Case $NM_RCLICK ; Sent by a list-view control when the user clicks an item with the right mouse button
					$tInfo = DllStructCreate($tagNMITEMACTIVATE, $lParam)
					_DebugOut("$NM_RCLICK" & @CRLF & "--> hWndFrom:" & @TAB & $hWndFrom & @CRLF & _
							"-->IDFrom:" & @TAB & $iIDFrom & @CRLF & _
							"-->Code:" & @TAB & $iCode & @CRLF & _
							"-->Index:" & @TAB & DllStructGetData($tInfo, "Index") & @CRLF & _
							"-->SubItem:" & @TAB & DllStructGetData($tInfo, "SubItem") & @CRLF & _
							"-->NewState:" & @TAB & DllStructGetData($tInfo, "NewState") & @CRLF & _
							"-->OldState:" & @TAB & DllStructGetData($tInfo, "OldState") & @CRLF & _
							"-->Changed:" & @TAB & DllStructGetData($tInfo, "Changed") & @CRLF & _
							"-->ActionX:" & @TAB & DllStructGetData($tInfo, "ActionX") & @CRLF & _
							"-->ActionY:" & @TAB & DllStructGetData($tInfo, "ActionY") & @CRLF & _
							"-->lParam:" & @TAB & DllStructGetData($tInfo, "lParam") & @CRLF & _
							"-->KeyFlags:" & @TAB & DllStructGetData($tInfo, "KeyFlags"))
					;Return 1 ; not to allow the default processing
					Return 0 ; allow the default processing
				Case $NM_RDBLCLK ; Sent by a list-view control when the user double-clicks an item with the right mouse button
					$tInfo = DllStructCreate($tagNMITEMACTIVATE, $lParam)
					_DebugOut("$NM_RDBLCLK" & @CRLF & "--> hWndFrom:" & @TAB & $hWndFrom & @CRLF & _
							"-->IDFrom:" & @TAB & $iIDFrom & @CRLF & _
							"-->Code:" & @TAB & $iCode & @CRLF & _
							"-->Index:" & @TAB & DllStructGetData($tInfo, "Index") & @CRLF & _
							"-->SubItem:" & @TAB & DllStructGetData($tInfo, "SubItem") & @CRLF & _
							"-->NewState:" & @TAB & DllStructGetData($tInfo, "NewState") & @CRLF & _
							"-->OldState:" & @TAB & DllStructGetData($tInfo, "OldState") & @CRLF & _
							"-->Changed:" & @TAB & DllStructGetData($tInfo, "Changed") & @CRLF & _
							"-->ActionX:" & @TAB & DllStructGetData($tInfo, "ActionX") & @CRLF & _
							"-->ActionY:" & @TAB & DllStructGetData($tInfo, "ActionY") & @CRLF & _
							"-->lParam:" & @TAB & DllStructGetData($tInfo, "lParam") & @CRLF & _
							"-->KeyFlags:" & @TAB & DllStructGetData($tInfo, "KeyFlags"))
					; No return value
			EndSwitch
	EndSwitch
	Return $GUI_RUNDEFMSG
EndFunc   ;==>WM_NOTIFY

; Resize the status bar when GUI size changes
Func WM_SIZE($hWnd, $iMsg, $wParam, $lParam)
	#forceref $hWnd, $iMsg, $wParam, $lParam
	_GUICtrlStatusBar_Resize($stbMain)

	; https://www.autoitscript.com/forum/topic/120893-resize-a-listview/
    ; $iGUIWidth = BitAND($lParam, 0xFFFF)
    ; $iGUIHeight = BitShift($lParam, 16)
    ; Use a suitable formula to get it to resize as you wish - here it is a simple fraction of the GUI size
    ; WinMove($packetwindow, "", 8, 240, $iGUIWidth * 300 / 500, $iGUIHeight * 300 / 500)

	Return $GUI_RUNDEFMSG
EndFunc   ;==>WM_SIZE


Func GetServiceNameFromBinaryPath($sBinaryPath)
	Local $sDrive = "", $sDir = "", $sFileName = "", $sExtension = ""
	Local $aPathSplit = _PathSplit($sBinaryPath, $sDrive, $sDir, $sFileName, $sExtension)
	Local $sServiceName = $sFileName
	Return $sServiceName
EndFunc

Func InstallService($sServiceName, $sBinaryPath) ; Create and Start
	Local $bInstallPcapService = False
	If Not _Service_Exists($sServiceName) Then
		If Not CreateService($sServiceName, $sBinaryPath) Then
			$bInstallPcapService = False
			Return $bInstallPcapService
		Else
			$bInstallPcapService = True
		EndIf
	EndIf

	If Not StartService($sServiceName) Then
		Local $iErrorCode = @error
		Switch $iErrorCode
		Case 2, 1275, 1058
			; 2 系統找不到指定的檔案。 ; 1275 This driver has been blocked from loading
			; 1058 The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
			StopService($sServiceName)
			; MsgBox($MB_SYSTEMMODAL, "", "Try to force delete this service and install again!" & @CRLF)
			DeleteService($sServiceName)
			If CreateService($sServiceName, $sBinaryPath) Then
				$bInstallPcapService = True
				StartService($sServiceName)
			EndIf
		EndSwitch
	EndIf
	Return $bInstallPcapService
EndFunc

Func UnInstallService($sServiceName) ; Stop and Delete
	If _Service_Exists($sServiceName) Then
		If StopService($sServiceName) Then
			Return DeleteService($sServiceName)
		EndIf
	EndIf
	Return False
EndFunc

Func CreateService($sServiceName, $sBinaryPath)
	; MsgBox($MB_SYSTEMMODAL, "", "CreateService("&$sServiceName &"): Creating service, please wait..." & @CRLF)
	;_Service_Create($sServiceName, "Au3Service " & $sServiceName, $SERVICE_WIN32_OWN_PROCESS, $SERVICE_DEMAND_START, $SERVICE_ERROR_SEVERE, '"' & @ScriptFullPath & '"')
	_Service_Create($sServiceName, $sServiceName, $SERVICE_KERNEL_DRIVER, $SERVICE_DEMAND_START, $SERVICE_ERROR_NORMAL, $sBinaryPath)
	Local $sMessage = _WinAPI_GetLastErrorMessage()
	Local $iErrorCode = @error
	Local $bSuccess
	If $iErrorCode Then
		$bSuccess = False
		; MsgBox($MB_SYSTEMMODAL, "", "CreateService("&$sServiceName &"): Problem with error code " & @error & ", " & $sMessage & @CRLF)
	Else
		$bSuccess = True
		; MsgBox($MB_SYSTEMMODAL, "", "CreateService("&$sServiceName &"): Success, " & $sMessage & @CRLF)
	EndIf
	Return SetError($iErrorCode, $sMessage, $bSuccess)
EndFunc   ;==>CreateService

Func StartService($sServiceName)
	; MsgBox($MB_SYSTEMMODAL, "", "StartService("&$sServiceName &"): Starting service, please wait..." & @CRLF)
	_Service_Start($sServiceName)
	Local $sMessage = _WinAPI_GetLastErrorMessage()
	Local $iErrorCode = @error
	Local $bSuccess
	If $iErrorCode Then
		$bSuccess = False
		; MsgBox($MB_SYSTEMMODAL, "", "StartService("&$sServiceName &"): Problem with error code " & @error & ", " & $sMessage & @CRLF)
	Else
		$bSuccess = True
		; MsgBox($MB_SYSTEMMODAL, "", "StartService("&$sServiceName &"): Success, " & $sMessage & @CRLF)
	EndIf
	Return SetError($iErrorCode, $sMessage, $bSuccess)
EndFunc   ;==>StartService

Func StopService($sServiceName)
	; MsgBox($MB_SYSTEMMODAL, "", "StopService("&$sServiceName &"): Stoping service, please wait..." & @CRLF)
	_Service_Stop($sServiceName)
	Local $sMessage = _WinAPI_GetLastErrorMessage()
	Local $iErrorCode = @error
	Local $bSuccess
	If $iErrorCode Then
		$bSuccess = False
		; MsgBox($MB_SYSTEMMODAL, "", "StopService("&$sServiceName &"): Problem with error code " & @error & ", " & $sMessage & @CRLF)
	Else
		$bSuccess = True
		; MsgBox($MB_SYSTEMMODAL, "", "StopService("&$sServiceName &"): Success, " & $sMessage & @CRLF)
	EndIf
	Return SetError($iErrorCode, $sMessage, $bSuccess)
EndFunc   ;==>StopService

Func DeleteService($sServiceName)
	; MsgBox($MB_SYSTEMMODAL, "", "DeleteService("&$sServiceName &"): Deleting service, please wait..." & @CRLF)
	_Service_Delete($sServiceName)
	Local $sMessage = _WinAPI_GetLastErrorMessage()
	Local $iErrorCode = @error
	Local $bSuccess
	If $iErrorCode Then
		$bSuccess = False
		; MsgBox($MB_SYSTEMMODAL, "", "DeleteService("&$sServiceName &"): Problem with error code " & @error & ", " & $sMessage & @CRLF)
	Else
		$bSuccess = True
 		; MsgBox($MB_SYSTEMMODAL, "", "DeleteService("&$sServiceName &"): Success, " & $sMessage & @CRLF)
	EndIf
	Return SetError($iErrorCode, $sMessage, $bSuccess)
EndFunc   ;==>DeleteService

; https://www.autoitscript.com/forum/topic/129250-_guictrllistview_savecsv-exports-the-details-of-a-listview-to-a-csv-file/
Func _GUICtrlListView_SaveCSV($hListView, $sFilePath, $sDelimiter = ',', $sQuote = '"')
    If $sDelimiter = Default Then
        $sDelimiter = ','
    EndIf
    If $sQuote = Default Then
        $sQuote = '"'
    EndIf

	#cs
	; https://www.autoitscript.com/forum/topic/31334-get-header-text-from-a-listview/
	Local $iIndex
	Local $sColumnHeaderText = ""
	Local $aAttibutesOfColumn = _GUICtrlListView_GetColumn($hListView, $iIndex)
	If IsArray($aAttibutesOfColumn) Then
		$sColumnHeaderText = $aAttibutesOfColumn[5]
	EndIf
	Local $sReturn = ''
	$sReturn = $sColumnHeaderText;StringSplit($sColumnHeaderText,"|")
	#ce

    Local Const $iColumnCount = _GUICtrlListView_GetColumnCount($hListView) - 1
    Local Const $iItemCount = _GUICtrlListView_GetItemCount($hListView) - 1
    Local $sReturn = ''
    For $i = 0 To $iItemCount
        For $j = 0 To $iColumnCount
            $sReturn &= $sQuote & StringReplace(_GUICtrlListView_GetItemText($hListView, $i, $j), $sQuote, $sQuote & $sQuote, 0, 1) & $sQuote
            If $j < $iColumnCount Then
                $sReturn &= $sDelimiter
            EndIf
        Next
        $sReturn &= @CRLF
    Next

    Local $hFileOpen = FileOpen($sFilePath, $FO_OVERWRITE)
    If $hFileOpen = -1 Then
        Return SetError(1, 0, False)
    EndIf
    FileWrite($hFileOpen, $sReturn)
    FileClose($hFileOpen)
    Return True
EndFunc   ;==>_GUICtrlListView_SaveCSV