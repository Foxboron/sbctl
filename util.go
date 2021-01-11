package sbctl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
)

func PrintGenerateError(logger *log.Logger, msg string, args ...interface{}) error {
	msg = fmt.Sprintf(msg, args)
	logger.Println(msg)
	return errors.New(msg)
}

func ChecksumFile(file string) string {
	hasher := sha256.New()
	s, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	hasher.Write(s)

	return hex.EncodeToString(hasher.Sum(nil))
}
