# debian_install
posix shell script to install debian in one go

# depends
- /bin/sh
- wget curl tar xz gzip sfdisk mkfs.fat mkfs.ext4 mount blkid perl ar mkfs.btrfs

# supported features
- firmware : BIOS/UEFI
- arch : aarch64/x86_64
- filesystem : ext4/btrfs
- bootloader : grub
- hardware: virtual machine/real hardware
- debian verison: bookworm (tested), testing, unstable

# sane defaults
- dhcp on ethernet
- static dns or via dhcp
- Install-Recommends disabled
- dpkg.conf and ucf.conf force confold
- zram enabled, zswap disabled
- needrestart enabled and set to automode
- enabled locale : en_US.UTF-8 C.UTF-8, default locale C.UTF-8
- sshd : PasswordAuthentication no, do not AcceptEnv , Restart=always
- useradd new user home permission : 700
- limits : nofile set to 5242880, nproc and core set to unlimited
- sysctl.conf : tuned towards performance
- installed fd and bat, symlinked to /usr/local/bin
- netbootxyz in /boot or ESP for recovery purpose
- grub menu color adjusted to red/black (highlight), white/black (normal)
- initramfs set to dep for smaller size, compressed with zstd
- linux-image-cloud kernel for virtual machine for smaller size 
- btrfs-scrub timer enabled

# usage

## edit install_debian.sh
- boot the hardware with any recent linux distro
- adjust parameters between `#### TODO IMPORTANT VARIABLE ####`
- `pw=` and `ssh_pub=` must be changed to yours, read the comments in the script to generate
- adjust other parameters based on your needs
- run the script as root : `./install_debian.sh`