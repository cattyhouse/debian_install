# what is this
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
- debian verison: bookworm (current stable), trixie (current testing)

# sane defaults
- just a base system with common commandline tools. GUI can be installed via apt afterwards
- dhcp on ethernet (with a note on how to set static ip after installation) for simplicity
- static dns or via dhcp
- apt Install-Recommends disabled
- /etc/dpkg.cfg and /etc/ucf.conf set to force confold to minimize interaction
- zram enabled, zswap disabled
- unattended-upgrades enabled
- needrestart enabled and set to automode
- enabled locale : en_US.UTF-8 and C.UTF-8, default locale :  C.UTF-8
- sshd : `PasswordAuthentication` set to `no`, do not `AcceptEnv` , `Restart=always`
- useradd new user home permission : 700
- limits : nofile set to 5242880, nproc and core set to unlimited
- sysctl.conf : tuned towards performance
- installed fd-find and bat, symlinked to /usr/local/bin as fd and bat
- downloaded netbootxyz to /boot(BIOS) or ESP(UEFI) for recovery purpose, read more about how to use it from their official website
- grub menu color adjusted to red/black (highlight), white/black (normal)
- initramfs set to dep for smaller size, compressed with zstd
- linux-image-cloud kernel for virtual machine for smaller size
- btrfs-scrub timer enabled
- btrfs compress with zstd with level 1 for speed

# usage

- boot the hardware with any recent linux distro
- edit `install_debian.sh`, adjust parameters between `#### TODO IMPORTANT VARIABLE ####`
- `pw=` and `ssh_pub=` must be changed to yours, read the comments in the script to generate
- adjust other parameters based on your needs
- run the script as root : `./install_debian.sh`