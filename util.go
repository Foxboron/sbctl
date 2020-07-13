package sbctl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"log"
)

func PrintGenerateError(msg string, logger *log.Logger) error {
	logger.Println(msg)
	return errors.New(msg)
}

func ChecksumFile(file string) string {
	hasher := sha256.New()
	s, err := ioutil.ReadFile(file)
	hasher.Write(s)
	if err != nil {
		log.Fatal(err)
	}

	return hex.EncodeToString(hasher.Sum(nil))
}
