sbctl - Secure Boot Manager
===========================

The goal of the project is to have one consistent UI to manage secure boot keys.

# Features
* Manages secure boot keys
* Live enrollment of secure boot keys
* Signing database to help keep track of files to sign
* Verify ESP of files missing signatures
* EFI stub generation

# Roadmap

* Convert to use [goefi](https://github.com/Foxboron/goefi) instead of relying on `sbsigntools`
* Key rotation
* Customize keys
* Secure the keys

# Usage

```
$ sbctl
Secure Boot key manager

Usage:
  sbctl [command]

Available Commands:
  bundle           Bundle the needed files for an EFI stub image
  create-keys      Create a set of secure boot signing keys
  enroll-keys      Enroll the current keys to EFI
  generate-bundles Generate all EFI stub bundles
  help             Help about any command
  list-bundles     List stored bundles
  list-files       List enrolled files
  remove-bundle    Remove bundle from database
  remove-file      Remove file from database
  sign             Sign a file with secure boot keys
  sign-all         Sign all enrolled files with secure boot keys
  status           Show current boot status
  verify           Find and check if files in the ESP are signed or not

Flags:
  -h, --help   help for sbctl

Use "sbctl [command] --help" for more information about a command.
```

## Key creation and enrollment

```
# sbctl status
==> WARNING: Setup Mode: Enabled
==> WARNING: Secure Boot: Disabled

# sbctl create-keys
==> Creating secure boot keys...
  -> Using UUID d6e9af79-c6b5-4b43-b893-dbb7e6570142...
==> Signing /usr/share/secureboot/keys/PK/PK.der.esl with /usr/share/secureboot/keys/PK/PK.key...
==> Signing /usr/share/secureboot/keys/KEK/KEK.der.esl with /usr/share/secureboot/keys/PK/PK.key...
==> Signing /usr/share/secureboot/keys/db/db.der.esl with /usr/share/secureboot/keys/KEK/KEK.key...

# sbctl enroll-keys
==> Syncing /usr/share/secureboot/keys to EFI variables...
==> Synced keys!

# sbctl status
==> Setup Mode: Disabled
==> WARNING: Secure Boot: Disabled

# Reboot!
# sbctl status
==> Setup Mode: Disabled
==> Secure Boot: Enabled
```


## Signatures
```
# sbctl verify
==> Verifying file database and EFI images in /efi...
  -> WARNING: /boot/vmlinuz-linux is not signed
  -> WARNING: /efi/EFI/BOOT/BOOTX64.EFI is not signed
  -> WARNING: /efi/EFI/BOOT/KeyTool-signed.efi is not signed
  -> WARNING: /efi/EFI/Linux/linux-linux.efi is not signed
  -> WARNING: /efi/EFI/arch/fwupdx64.efi is not signed
  -> WARNING: /efi/EFI/systemd/systemd-bootx64.efi is not signed

# sbctl sign -s /efi/EFI/BOOT/BOOTX64.EFI
==> Signing /efi/EFI/BOOT/BOOTX64.EFI...

# sbctl sign -s /efi/EFI/arch/fwupdx64.efi
==> Signing /efi/EFI/arch/fwupdx64.efi...

# sbctl sign -s /efi/EFI/systemd/systemd-bootx64.efi
==> Signing /efi/EFI/systemd/systemd-bootx64.efi...

# sbctl sign -s /usr/lib/fwupd/efi/fwupdx64.efi -o /usr/lib/fwupd/efi/fwupdx64.efi.signed
==> Signing /usr/lib/fwupd/efi/fwupdx64.efi...

# sbctl verify
==> Verifying file database and EFI images in /efi...
  -> /usr/lib/fwupd/efi/fwupdx64.efi.signed is signed
  -> /efi/EFI/BOOT/BOOTX64.EFI is signed
  -> /efi/EFI/arch/fwupdx64.efi is signed
  -> /efi/EFI/systemd/systemd-bootx64.efi is signed
  -> WARNING: /boot/vmlinuz-linux is not signed
  -> WARNING: /efi/EFI/BOOT/KeyTool-signed.efi is not signed
  -> WARNING: /efi/EFI/Linux/linux-linux.efi is not signed

# sbctl list-files
==> File: /efi/EFI/BOOT/BOOTX64.EFI
==> File: /efi/EFI/arch/fwupdx64.efi
==> File: /efi/EFI/systemd/systemd-bootx64.efi
==> File: /efi/vmlinuz-linux
==> File: /usr/lib/fwupd/efi/fwupdx64.efi
  -> Output: /usr/lib/fwupd/efi/fwupdx64.efi.signed
```

## Generate EFI Stub
```
# sbctl bundle -s -i /boot/intel-ucode.img \
      -l /usr/share/systemd/bootctl/splash-arch.bmp \
      -k /boot/vmlinuz-linux \
      -f /boot/initramfs-linux.img \
      /boot/EFI/Linux/linux-linux.efi
==> Wrote EFI bundle /boot/EFI/Linux/linux-linux.efi
==> Bundle: /boot/EFI/Linux/linux-linux.efi
  -> Intel Microcode: /boot/intel-ucode.img
  -> Kernel Image: /boot/vmlinuz-linux
  -> Initramfs Image: /boot/initramfs-linux.img
  -> Cmdline: /proc/cmdline
  -> OS Release: /usr/lib/os-release
  -> EFI Stub Image: /usr/lib/systemd/boot/efi/linuxx64.efi.stub
  -> ESP Location: /efi
  -> Splash Image: /usr/share/systemd/bootctl/splash-arch.bmp
  -> Output: /boot/EFI/Linux/linux-linux.efi

# sbctl list-bundles
==> Bundle: /boot/EFI/Linux/linux-linux.efi
  -> Intel Microcode: /boot/intel-ucode.img
  -> Kernel Image: /boot/vmlinuz-linux
  -> Initramfs Image: /boot/initramfs-linux.img
  -> Cmdline: /proc/cmdline
  -> OS Release: /usr/lib/os-release
  -> EFI Stub Image: /usr/lib/systemd/boot/efi/linuxx64.efi.stub
  -> ESP Location: /efi
  -> Splash Image: /usr/share/systemd/bootctl/splash-arch.bmp
  -> Output: /boot/EFI/Linux/linux-linux.efi

# sbctl generate-bundles
==> Generating EFI bundles....
==> Wrote EFI bundle /boot/EFI/Linux/linux-linux.efi
```
