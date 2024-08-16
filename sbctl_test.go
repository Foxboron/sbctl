package sbctl

import (
	"testing"
)

func TestGetESP(t *testing.T) {
	for _, c := range []struct {
		lsblk   []byte
		esp     string
		wantErr error
	}{
		{
			lsblk:   []byte(`{"blockdevices":[{"parttype":null,"mountpoint":null,"pttype":"gpt","fstype":"crypto_LUKS","mountpoints":[null],"children":[{"parttype":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b","mountpoint":"/efi","pttype":"gpt","fstype":"vfat","mountpoints":["/efi"]},{"parttype":"4f68bce3-e8cd-4db1-96e7-fbcaf984b709","mountpoint":null,"pttype":"gpt","fstype":"crypto_LUKS","mountpoints":[null],"children":[{"parttype":null,"mountpoint":"/home/.snapshots","pttype":null,"fstype":"btrfs","mountpoints":["/home/.snapshots","/home","/var","/srv","/"]}]}]}]}`),
			esp:     "/efi",
			wantErr: nil,
		},
		{
			lsblk:   []byte(`{"blockdevices":[{"parttype":null,"mountpoint":null,"pttype":"gpt","fstype":"crypto_LUKS","mountpoints":[null],"children":[{"parttype":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b","mountpoint":"/efi","pttype":null,"fstype":"vfat","mountpoints":["/efi"]},{"parttype":"4f68bce3-e8cd-4db1-96e7-fbcaf984b709","mountpoint":null,"pttype":null,"fstype":"crypto_LUKS","mountpoints":[null],"children":[{"parttype":null,"mountpoint":"/home/.snapshots","pttype":null,"fstype":"btrfs","mountpoints":["/home/.snapshots","/home","/var","/srv","/"]}]}]}]}`),
			esp:     "/efi",
			wantErr: nil,
		},
	} {
		esp, err := findESP(c.lsblk)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if esp != c.esp {
			t.Fatalf("wrong esp")
		}
	}
}
