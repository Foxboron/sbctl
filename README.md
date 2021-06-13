# sbctl - Secure Boot Manager
[![Build Status](https://github.com/Foxboron/sbctl/workflows/CI/badge.svg)](https://github.com/Foxboron/sbctl/actions)

sbctl intends to be a user-friendly secure boot key manager capable of setting
up secure boot, offer key management capabilities, and keep track of files that
needs to be signed in the boot chain.

It is written top-to-bottom in [Golang](https://golang.org/) using
[go-uefi](https://github.com/Foxboron/go-uefi) for the API layer and doesn't
rely on existing secure boot tooling. It also tries to sport some integration
testing towards towards [tianocore](https://www.tianocore.org/) utilizing
[vmtest](https://github.com/anatol/vmtest).

![](https://pkgbuild.com/~foxboron/sbctl_demo.gif)

## Features
* User-friendly
* Manages secure boot keys
* Live enrollment of keys
* Signing database to help keep track of files to sign
* Verify ESP of files missing signatures
* EFI stub generation
* JSON Output

## Roadmap to 1.0
* Key rotation
* TPM Support
* Hardware Token support
* Configuration Files
* Automatic boot chain signing using the [Boot Loader Interface](https://systemd.io/BOOT_LOADER_INTERFACE/)

## Dependencies
* util-linux (using `lsblk`)
* binutils (using `objcopy`)
* Go >= 1.16

# Support and development channel

Development discussions and support happens in `#sbctl` on the [libera.chat](https://kiwiirc.com/nextclient/irc.libera.chat/#sbctl) IRC network.

# Usage

```
$ sbctl
Secure Boot Key Manager

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
      --json   Output as json

Use "sbctl [command] --help" for more information about a command.
```

## Key creation and enrollment

```
# sbctl status
Installed:	✘ Sbctl is not installed
Setup Mode:	✘ Enabled
Secure Boot:	✘ Disabled

# sbctl create-keys
Created Owner UUID a9fbbdb7-a05f-48d5-b63a-08c5df45ee70
Creating secure boot keys...✔
Secure boot keys created!

# sbctl enroll-keys
Enrolling keys to EFI variables...✔
Enrolled keys to the EFI variables!

# sbctl status
Installed:	✔ Sbctl is installed
Owner GUID:	a9fbbdb7-a05f-48d5-b63a-08c5df45ee70
Setup Mode:	✔ Disabled
Secure Boot:	✘ Disabled

// Reboot!
# sbctl status
Installed:	✔ Sbctl is installed
Owner GUID:	a9fbbdb7-a05f-48d5-b63a-08c5df45ee70
Setup Mode:	✔ Disabled
Secure Boot:	✔ Enabled
```


## Signatures
```
# sbctl verify
Verifying file database and EFI images in /efi...
✘ /boot/vmlinuz-linux is not signed
✘ /efi/EFI/BOOT/BOOTX64.EFI is not signed
✘ /efi/EFI/BOOT/KeyTool-signed.efi is not signed
✘ /efi/EFI/Linux/linux-linux.efi is not signed
✘ /efi/EFI/arch/fwupdx64.efi is not signed
✘ /efi/EFI/systemd/systemd-bootx64.efi is not signed

# sbctl sign -s /efi/EFI/BOOT/BOOTX64.EFI
✔ Signed /efi/EFI/BOOT/BOOTX64.EFI...

# sbctl sign -s /efi/EFI/arch/fwupdx64.efi
✔ Signed /efi/EFI/arch/fwupdx64.efi...

# sbctl sign -s /efi/EFI/systemd/systemd-bootx64.efi
✔ Signed /efi/EFI/systemd/systemd-bootx64.efi...

# sbctl sign -s /usr/lib/fwupd/efi/fwupdx64.efi -o /usr/lib/fwupd/efi/fwupdx64.efi.signed
✔ Signed /usr/lib/fwupd/efi/fwupdx64.efi...

# sbctl verify
Verifying file database and EFI images in /efi...
✔ /usr/lib/fwupd/efi/fwupdx64.efi.signed is signed
✔ /efi/EFI/BOOT/BOOTX64.EFI is signed
✔ /efi/EFI/arch/fwupdx64.efi is signed
✔ /efi/EFI/systemd/systemd-bootx64.efi is signed
✘ /boot/vmlinuz-linux is not signed
✘ /efi/EFI/BOOT/KeyTool-signed.efi is not signed
✘ /efi/EFI/Linux/linux-linux.efi is not signed

# sbctl list-files
/boot/vmlinuz-linux
Signed:		✘ Not Signed

/efi/EFI/BOOT/KeyTool-signed.efi
Signed:		✘ Not Signed

/efi/EFI/Linux/linux-linux.efi
Signed:		✘ Not Signed

/efi/EFI/arch/fwupdx64.efi
Signed:		✔ Signed

/efi/EFI/BOOT/BOOTX64.EFI
Signed:		✔ Signed

/usr/lib/fwupd/efi/fwupdx64.efi
Signed:		✔ Signed
Output File:	/usr/lib/fwupd/efi/fwupdx64.efi.signed

/efi/EFI/systemd/systemd-bootx64.efi
Signed:		✔ Signed
```

## Generate EFI Stub
```
# sbctl bundle -s -i /boot/intel-ucode.img \
      -l /usr/share/systemd/bootctl/splash-arch.bmp \
      -k /boot/vmlinuz-linux \
      -f /boot/initramfs-linux.img \
      /efi/EFI/Linux/linux-linux.efi
Wrote EFI bundle /efi/EFI/Linux/linux-linux.efi

# sbctl list-bundles
Enrolled bundles:

/efi/EFI/Linux/linux-linux.efi
	Signed:		✔ Signed
	ESP Location:	/efi
	Output:		└─/EFI/Linux/linux-linux.efi
	EFI Stub Image:	  └─/usr/lib/systemd/boot/efi/linuxx64.efi.stub
	Splash Image:	    ├─/usr/share/systemd/bootctl/splash-arch.bmp
	Cmdline:	    ├─/etc/kernel/cmdline
	OS Release:	    ├─/usr/lib/os-release
	Kernel Image:	    ├─/boot/vmlinuz-linux
	Initramfs Image:    └─/boot/initramfs-linux.img
	Intel Microcode:      └─/boot/intel-ucode.img


# sbctl generate-bundles
Generating EFI bundles....
Wrote EFI bundle /efi/EFI/Linux/linux-linux.efi
```
