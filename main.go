package main

/*
References:
- https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4
*/

import (
	"flag"
    "fmt"
    "golang.org/x/crypto/md4"
    "golang.org/x/text/encoding/unicode"
    "os"
    "io"
)

func GenerateNtHash(password string) (ntHash string, err error) {
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
    utf16le, err := encoder.String(password)

    if err != nil {
    	fmt.Printf("[!] Error converting password to UTF16-LE: %s\n", err)
        return "", err
    }

    cipher := md4.New()
    _, err = io.WriteString(cipher, utf16le)

    if err != nil {
    	fmt.Printf("[!] Error writing UTF-16LE bytes to Hash object: %s\n", err)
        return "", err
    }

	ntHash = fmt.Sprintf("%x", cipher.Sum(nil))
    return ntHash, nil
}

func main() {
	password := flag.String("password", "", "Input password")
	flag.Parse()

	if *password == "" {
		flag.Usage()
		return
	}

    fmt.Printf("[+] Generating NT hash of the password '%s'\n", *password)

    ntHash, err := GenerateNtHash(*password)
    if err != nil {
    	fmt.Printf("[!] Error generating NT hash: %s\n", err)
    	os.Exit(1)
    }

    fmt.Printf("[+] NT Hash: %s\n", ntHash)
}
