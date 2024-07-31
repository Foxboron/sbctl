package config

import (
	"fmt"
	"testing"
)

var conf = `
---
keydir: /etc/sbctl/keys
guid: /var/lib/sbctl/GUID
files_db: /var/lib/sbctl/files.db
bundles_db: /var/lib/sbctl/bundles.db
db_additions:
  - microsoft
files:
  - path: /boot/vmlinuz-linux-lts
  - path: /usr/lib/fwupd/efi/fwupdx64.efi
    output: /usr/lib/fwupd/efi/fwupdx64.efi.signed
keys:
  pk:
    privkey: /etc/sbctl/keys/PK/PK.key
    pubkey: /etc/sbctl/keys/PK/PK.pem
    type: file
  kek:
    privkey: /etc/sbctl/keys/KEK/KEK.key
    pubkey: /etc/sbctl/keys/KEK/KEK.pem
    type: file
  db:
    privkey: /etc/sbctl/keys/db/db.key
    pubkey: /etc/sbctl/keys/db/db.pem
    type: file
`

func TestParseConfig(t *testing.T) {
	conf, err := NewConfig([]byte(conf))
	if err != nil {
		t.Fatalf("%v", err)
	}
	fmt.Println(conf.Keys.PK)
}
