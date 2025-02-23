package config

import (
	"fmt"
	"os"
	"spki/src/pkg/crypto"
)

// encryption encrypts a plain text string from the command line and prints the encrypted result.
func encryption(plain string) {
	fmt.Println(crypto.Encryption(plain))
	os.Exit(0)
}
