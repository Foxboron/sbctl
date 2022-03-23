#!/bin/bash
dd if=/dev/zero of=rootfs.raw bs=1G count=1
mkfs.ext4 rootfs.raw
sudo losetup -fP rootfs.raw
mkdir rootfs
sudo mount /dev/loop0 rootfs
sudo pacstrap rootfs base openssh terminus-font

echo "[Match]
Name=enp0s3

[Network]
DHCP=yes" | sudo tee rootfs/etc/systemd/network/20-wired.network

sudo sed -i '/^root/ { s/:x:/::/ }' rootfs/etc/passwd
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' rootfs/etc/ssh/sshd_config
sudo sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' rootfs/etc/ssh/sshd_config
echo "shared              	/mnt      	9p        	rw,sync,dirsync,access=client,trans=virtio	0 0" | sudo tee rootfs/etc/fstab
echo "FONT=ter-132n" | sudo tee rootfs/etc/vconsole.conf

sudo arch-chroot rootfs systemctl enable sshd systemd-networkd
sudo rm rootfs/var/cache/pacman/pkg/*
sudo umount rootfs
sudo losetup -d /dev/loop0
rm -r rootfs
qemu-img create -o backing_file=rootfs.raw,backing_fmt=raw -f qcow2 rootfs.cow
