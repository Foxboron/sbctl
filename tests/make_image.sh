#!/bin/bash

# TODO: Move to a pre-built image?
prepareDeps(){
  pacman -Sy
  pacman -S --noconfirm sudo qemu-img arch-install-scripts linux dracut
}

cleanupPreviousRuns() {
  rm -rf "${OUTDIR}/rootfs"
  rm -rf "${OUTDIR}/rootfs.raw"
}

set -ex

export WORKDIR=/workdir
export OUTDIR=$WORKDIR/kernel

prepareDeps
cleanupPreviousRuns

# Copy a kernel file too
find /usr/lib/modules/ -name "vmlinuz" -type f -exec cp {} $OUTDIR/bzImage \; -quit

dd if=/dev/zero of="${OUTDIR}/rootfs.raw" bs=1G count=1
mkfs.ext4 "${OUTDIR}/rootfs.raw"
sudo losetup -fP "${OUTDIR}/rootfs.raw"
mkdir "${OUTDIR}/rootfs"
sudo mount /dev/loop0 "${OUTDIR}/rootfs"
sudo pacstrap "${OUTDIR}/rootfs" base openssh

echo "[Match]
Name=enp0s3

[Network]
DHCP=yes" | sudo tee "${OUTDIR}/rootfs/etc/systemd/network/20-wired.network"

sudo sed -i '/^root/ { s/:x:/::/ }' "${OUTDIR}/rootfs/etc/passwd"
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' "${OUTDIR}/rootfs/etc/ssh/sshd_config"
sudo sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' "${OUTDIR}/rootfs/etc/ssh/sshd_config"

sudo arch-chroot "${OUTDIR}/rootfs" systemctl enable sshd systemd-networkd
sudo rm "${OUTDIR}"/rootfs/var/cache/pacman/pkg/*
sudo umount "${OUTDIR}"/rootfs
sudo losetup -d /dev/loop0
rm -r "${OUTDIR}"/rootfs
qemu-img create -o backing_file=rootfs.raw,backing_fmt=raw -f qcow2 "${OUTDIR}"/rootfs.cow
chmod 777 "${OUTDIR}"/rootfs.*
