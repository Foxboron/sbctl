package sbctl

import (
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"log"
)

func ChecksumFile(file string) string {
	hasher := sha256.New()
	s, err := ioutil.ReadFile(file)
	hasher.Write(s)
	if err != nil {
		log.Fatal(err)
	}

	return hex.EncodeToString(hasher.Sum(nil))
}
