#!/bin/sh
export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin/:/sbin:/bin"

# set debian mirror , must end with /
deb_mirror="https://deb.debian.org/debian/"
deb_sec_mirror="https://security.debian.org/debian-security/"
deb_comp="main contrib non-free non-free-firmware"

set_var () {
    #### TODO IMPORTANT VARIABLE ####

    is_vm="yes" # set to "yes" will install cloud kernel
    hostname="debian"
    dev="/dev/vda" # which drive to install to, use lsblk to find it
    tcp_bbr="yes" # yes or no. suggest: yes on remote server. no on low performance LAN box
    rootfs="ext4" # btrfs or ext4
    autodns="no" # if yes, then install and enable systemd-resolved. if no, then use 119.29.29.29 for china, 1.1.1.1 for others
    dns="1.1.1.1" # dns to use when autodns=no
    efi_size="64M" # 1) at least 40M 2) 64M is a good enough
    pw='$6$6uBlduKtkwiJw7wY$IaZKonJKpI.cN5/0c.vRuXnztBWPUfI5B9VYYEGddzmrrNMiYsmdVxzu5JzpnsTxEuiEo95JoF3V9c4BccXgI0' # must be in single quote to prevent shell expansion. generate by : echo 'your_password' | mkpasswd -m sha-512 -s
    ssh_pub='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBJLSxzI5IVEHV7NXo7k2arm3fo756ouGNSywQbx1IOk' # generate by ssh-keygen or get existing one from: head -n1 ~/.ssh/authorized_keys
    debian_suite="stable" # one of : stable testing unstable
    timezone="Asia/Shanghai"
    pkgs="ca-certificates cron curl dbus dbus-user-session init initramfs-tools iproute2 iputils-ping less locales logrotate ncurses-term needrestart procps psmisc rsync ssh systemd systemd-sysv systemd-timesyncd tmux vim whiptail zstd" # must have
    pkgs="apt-file bat bc fd-find fdisk file ipset iptables jq man-db manpages manpages-dev ncdu systemd-zram-generator tree wireguard-tools $pkgs" # optional
    mount_point="/mnt/debian_c7bN4b"

    #### TODO IMPORTANT VARIABLE ####
    # arch
    arch=$(uname -m)
    case "$arch" in
        (aarch64) host_arch="arm64" ;;
        (x86_64) host_arch="amd64" ;;
        (*) die "unsupported arch : $arch" ;;
    esac
    
    case "$debian_suite" in
        (unstable|stable|testing) : ;;
        (*) die "debian_suite must be one of : stable testing unstable" ;;
    esac

    # check efi
    is_efi=""
    if [ -d /sys/firmware/efi/efivars ] ; then
        check_cmd mkfs.fat
        is_efi="y"
        pkgs="$pkgs efibootmgr grub-efi dosfstools"
    else
        pkgs="$pkgs grub-pc"
    fi
    
    # get codename
    codename=$(curl -sfL ${deb_mirror}dists/$debian_suite/InRelease | awk '/^Codename:/ {print $2}')
    [ "$codename" ] || die "failed to get codename for debian_suite : $debian_suite"
}

set_mount () {
    case "$rootfs" in
        (ext4)
            check_cmd mkfs.ext4
            mkfs_opt="mkfs.ext4 -qFF"
            mount_opt="-t ext4"
            fstab_opt="ext4 rw,relatime 0 1"
            pkgs="$pkgs e2fsprogs"
        ;;

        (btrfs)
            check_cmd mkfs.btrfs
            modprobe btrfs 2>/dev/null
            mkfs_opt="mkfs.btrfs -qf"
            mount_opt="-t btrfs -o compress=zstd:1"
            fstab_opt="btrfs compress=zstd:1 0 0"
            pkgs="$pkgs btrfs-progs btrfs-compsize"
        ;;
        
        (*)
            die "unsupported rootfs : $rootfs"
        ;;
    esac

    # fix mount: (hint) your fstab has been modified, but systemd still uses the old version; use 'systemctl daemon-reload' to reload
    command -v systemctl >/dev/null && systemctl daemon-reload || true
    # dev has to be a disk
    [ "$(lsblk -l -n -d -o TYPE "$dev" 2>/dev/null)" = disk ] || die "$dev is not a disk, please check option dev="
    # dev can't be mounted
    if [ "$(lsblk -l -n -o MOUNTPOINTS "$dev")" ] ; then
        printf '%s\n' "$dev is mounted :" "$(lsblk -o PATH,MOUNTPOINTS "$dev")"
        die "please run 'umount -vfR MOUNTPOINTS' based on above information"
    fi
    # mount_point can't be in use
    if mountpoint -q "$mount_point" ; then
        die "$mount_point is mounted" \
        "please run 'umount -vfR $mount_point' to umount them all" \
        "or set another mount_point="
    fi

    mkdir -p "$mount_point" || die "failed to create dir : $mount_point"
    for _wipefs_ in 1 2 3 ; do wipefs -q -a -f $(lsblk -l -n -o PATH "$dev") ; done # wipe 3 times
    if [ "$is_efi" = "y" ] ; then
        printf '%s\n' "label:gpt" "size=$efi_size,type=uefi" "type=linux" |
        sfdisk -q "$dev" || die "failed to sfdisk $dev"
        sleep 1 # wait for device init after partition
        devp=$(lsblk -l -n -o PATH "$dev" | tail -n1) ; devp=${devp%?}
        
        mkfs.fat -F 32 "${devp}1" || die "failed to mkfs ${devp}1"
        $mkfs_opt "${devp}2" || die "failed to mkfs.$rootfs ${devp}2"
        mount $mount_opt "${devp}2" "$mount_point" || die "failed to mount ${devp}2"
        mkdir -p "$mount_point/boot/efi" || die "failed to create dir : $mount_point/boot/efi"
        mount "${devp}1" "$mount_point/boot/efi" || die "failed to mount ${devp}1"
        uuid_efi="$(lsblk -l -n -o UUID "${devp}1")"
        uuid_root="$(lsblk -l -n -o UUID "${devp}2")"
        fstab_efi="UUID=$uuid_efi /boot/efi vfat rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=utf8,shortname=mixed,errors=remount-ro 0 2"
        fstab_root="UUID=$uuid_root / $fstab_opt"
    else
        # gpt + bios boot partition
        printf '%s\n' "label:gpt" 'size=1M,type="bios boot"' "type=linux" |
        sfdisk -q "$dev" || die "failed to sfdisk $dev"
        sleep 1 # wait for device init after partition
        devp=$(lsblk -l -n -o PATH "$dev" | tail -n1) ; devp=${devp%?}

        $mkfs_opt "${devp}2" || die "failed to mkfs.$rootfs ${devp}2"
        mount $mount_opt "${devp}2" "$mount_point" || die "failed to mount ${devp}2"
        uuid_root="$(lsblk -l -n -o UUID "${devp}2")"
        fstab_root="UUID=$uuid_root / $fstab_opt"
    fi
}

set_rootfs () {
    # prepare debootstrap
    ds_dir=$(mktemp -d) || die "failed to create debootstrap dir"
    curl -sfL 'https://salsa.debian.org/installer-team/debootstrap/-/archive/master/debootstrap-master.tar' |
    tar -xf- -C "$ds_dir" || die "failed to curl debootstrap"
    export DEBOOTSTRAP_DIR="$ds_dir/debootstrap-master"
    
    # prepare rootfs
    # https://salsa.debian.org/installer-team/debootstrap/-/tree/master/scripts?ref_type=heads
    # note that all scripts are linked to scripts/sid
    "$DEBOOTSTRAP_DIR"/debootstrap --no-check-sig --arch="$host_arch" --variant=minbase "$debian_suite" "$mount_point" "$deb_mirror" || die "failed to run debootstrap"
    sleep 5
    rm -f "$mount_point"/etc/resolv.conf
    cat /etc/resolv.conf > "$mount_point"/etc/resolv.conf
}

chroot_mount_misc () (
    cd "$mount_point" || die "failed to cd $mount_point"
    mkdir -p proc sys dev/pts dev/shm run tmp
    local do_mount
    do_mount() {
        local msg="$@"
        mount "$@" || die "failed to mount ${msg##* }"
    }

    # ref : https://github.com/archlinux/arch-install-scripts/blob/master/common
    do_mount -t proc proc proc
    do_mount -t sysfs sys sys
    if [ "$is_efi" = "y" ] ; then
        mkdir -p sys/firmware/efi/efivars
        do_mount -t efivarfs efivarfs sys/firmware/efi/efivars
    fi
    do_mount -t devtmpfs udev dev
    do_mount -t devpts devpts dev/pts
    do_mount -t tmpfs shm dev/shm
    do_mount --bind --make-private /run run
    do_mount -t tmpfs tmp tmp
)

set_chroot () {
chroot_mount_misc || exit 1
chroot "$mount_point" /bin/sh -s <<EOFCHROOT
. /etc/profile

# new apt sources
mkdir -p /etc/apt/sources.list.d/
case "$debian_suite" in
(unstable)
cat <<EOFSRC > /etc/apt/sources.list.d/debian.sources
Types: deb
URIs: $deb_mirror
Suites: $codename
Components: $deb_comp
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOFSRC
;;

(stable|testing)
cat <<EOFSRCSEC > /etc/apt/sources.list.d/debian.sources

Types: deb
URIs: $deb_mirror
Suites: $codename ${codename}-updates
Components: $deb_comp
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: $deb_sec_mirror
Suites: ${codename}-security
Components: $deb_comp
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOFSRCSEC
;;
esac
if [ -f /etc/apt/sources.list ] ; then
    printf '%s\n' "#see /etc/apt/sources.list.d/debian.sources" > /etc/apt/sources.list
fi

mkdir -p /etc/apt/apt.conf.d
cat <<EOFAPT > /etc/apt/apt.conf.d/99-no-recommends
APT {
    Install-Recommends "false";
    Install-Suggests "false";
};
EOFAPT

# dpkg.cfg, in case dist-upgrade needs it
mkdir -p /etc/dpkg/dpkg.cfg.d
printf '%s\n' "force-confold" "force-confmiss" > /etc/dpkg/dpkg.cfg.d/confold-confmiss

# update sources
apt-get update
apt-get -y dist-upgrade

# install packages
apt-get install -y $pkgs

# ucf.conf
printf '%s\n' "conf_force_conffold=YES" >> /etc/ucf.conf

# needrestart.conf
cat <<'EOFNR' > /etc/needrestart/conf.d/99.zzz.conf
\$nrconf{restart} = 'a';
\$nrconf{kernelhints} = -1;
\$nrconf{ucodehints} = 0;
\$nrconf{verbosity} = 0;
EOFNR

# fstab
printf '%s\n' "$fstab_root" >> /etc/fstab
[ "$is_efi" = "y" ] && printf '%s\n' "$fstab_efi" >> /etc/fstab
printf '%s\n' "tmpfs /tmp tmpfs defaults,nosuid,nodev,size=80% 0 0" >> /etc/fstab

# network
cat <<EOFNET > /etc/systemd/network/eth.network
[Match]
Name=e*
### if you don't know the predicted name of the interface, use MACAddress= and comment out Name=
#MACAddress=
[Network]
DHCP=yes
### uncomment to enable static ip, at the mean time comment out DHCP=
#Address=192.168.1.10/24
#Gateway=192.168.1.1
EOFNET

# hosts
printf '%s\n' "127.0.0.1 $hostname" >> /etc/hosts

# hostname
printf '%s\n' "$hostname" > /etc/hostname

# alternatives
update-alternatives --set editor /usr/bin/vim.basic

# zstd on zram 
case "$pkgs" in
(*systemd-zram-generator*)
rm -f /etc/systemd/zram-generator.conf
mkdir -p /etc/systemd/zram-generator.conf.d
printf '%s\n' "[zram0]" "compression-algorithm = zstd" > /etc/systemd/zram-generator.conf.d/zram0.conf
;;
esac

# locale
# based on code in dpkg-query --control-show locales config
printf '%s\n' 'en_US.UTF-8 UTF-8' 'C.UTF-8 UTF-8' > /etc/locale.gen
printf '%s\n' 'LANG=C.UTF-8' > /etc/locale.conf # new location since debian 13
printf '%s\n' 'LANG=C.UTF-8' > /etc/default/locale # legacy location to debian 12
dpkg-reconfigure locales

# timezone
# based on code in dpkg-query --control-show tzdata config
ln -sf /usr/share/zoneinfo/$timezone /etc/localtime
dpkg-reconfigure tzdata

# sshd
cat <<EOFSSHD >> /etc/ssh/sshd_config

PasswordAuthentication no
PrintLastLog no
LogLevel QUIET
EOFSSHD

# disable AcceptEnv
sed -i -e '/^AcceptEnv/ s|^|#|' /etc/ssh/sshd_config

install -m 700 -d /root/.ssh
printf '%s\n' '$ssh_pub' | install /dev/stdin -m 600 /root/.ssh/authorized_keys
printf '%s\n' 'root:$pw' | chpasswd -e

# disable motd from debian
sed -i -e '/pam_motd.so/ s|^|#|' /etc/pam.d/login /etc/pam.d/sshd

# disable deprecated user_readenv (man pam_env)
sed -i '/pam_env.so/ s|user_readenv=1|user_readenv=0|' /etc/pam.d/sshd

# sysctl
mkdir -p /etc/sysctl.d
cat <<EOFSYSCTL > /etc/sysctl.d/99.zzz.conf
# tcp forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
$(if [ "$tcp_bbr" = yes ] ; then printf '%s\n' "# bbr" "net.core.default_qdisc = fq" "net.ipv4.tcp_congestion_control = bbr" ; fi)
# increase nofile on debian, alpine, void
fs.nr_open = 1073741816
EOFSYSCTL

# link fd, bat
if [ -x /usr/bin/batcat ] ; then ln -sf /usr/bin/batcat /usr/local/bin/bat ; fi
if [ -x /usr/bin/fdfind ] ; then ln -sf /usr/bin/fdfind /usr/local/bin/fd ; fi

# download latest netbootxyz for rescure from grub or UEFI SHELL

xyz_ver=\$( curl -sfL https://api.github.com/repos/netbootxyz/netboot.xyz/releases/latest | grep '"tag_name"' | cut -d '"' -f 4)
xyz_url="https://github.com/netbootxyz/netboot.xyz/releases/download/\${xyz_ver}/netboot.xyz"

if [ "$is_efi" = "y" ]; then
    case "$arch" in
        (aarch64) curl -sfL -o /boot/efi/netboot.xyz.efi \${xyz_url}-arm64.efi || true ;;
        (x86_64) curl -sfL -o /boot/efi/netboot.xyz.efi \${xyz_url}.efi || true ;;
    esac
else
    curl -sfL -o /boot/netboot.xyz.lkrn \${xyz_url}.lkrn
fi

# install grub to also removable place : EFI/BOOT
# https://wiki.debian.org/GrubEFIReinstall
if [ "$is_efi" = "y" ] ; then
    grub-install --recheck --force-extra-removable
    printf '%s\n' "grub-efi-$host_arch grub2/force_efi_extra_removable boolean true" | debconf-set-selections
else
    grub-install --recheck $dev
fi

# initramfs
cat <<EOFINIT >> /etc/initramfs-tools/initramfs.conf

MODULES=dep
COMPRESS=zstd
COMPRESSLEVEL=6
EOFINIT

if [ "$rootfs" = btrfs ] ; then
    printf '%s\n' 'zstd' 'btrfs' >> /etc/initramfs-tools/modules
fi

# kernel
if [ "$is_vm" = yes ] ; then
    apt-get install -y linux-image-cloud-$host_arch
else
    apt-get install -y linux-image-$host_arch
fi

# GRUB configuration

# grub color
# https://wiki.debian.org/GRUB2?action=show&redirect=Grub2#Configure_console_menu_colors
cat <<EOFGRUBCOLOR > /boot/grub/custom.cfg
set menu_color_normal=white/black
set menu_color_highlight=red/black
EOFGRUBCOLOR

# default grub
mv /etc/default/grub /etc/default/grub.bak
cat <<EOFGRUB > /etc/default/grub
GRUB_DEFAULT=0
GRUB_DISTRIBUTOR="Debian"
GRUB_TIMEOUT=1
GRUB_CMDLINE_LINUX_DEFAULT="quiet zswap.enabled=0 nomodeset"
GRUB_DISABLE_SUBMENU=y
GRUB_DISABLE_RECOVERY=true
GRUB_DISABLE_OS_PROBER=true
GRUB_TERMINAL_OUTPUT=console
GRUB_TERMINAL_INPUT=console
GRUB_PRELOAD_MODULES="linux part_gpt part_msdos"
EOFGRUB

# update grub.cfg
update-grub2

# disable services
systemctl disable rsync.service apt-daily-upgrade.timer apt-daily.timer e2scrub_all.timer e2scrub_reap.service

# enable services
systemctl enable ssh systemd-networkd systemd-timesyncd

# init apt-file database
case "$pkgs" in (*apt-file*) apt-file update ;; esac

# insert /run/reboot-required for kernel installation
cat <<EOFREBOOT | install -D -m 755 /dev/stdin /etc/kernel/postinst.d/zz-reboot-required
#!/bin/sh
touch /run/reboot-required
echo "\\\$1" >> /run/reboot-required.pkgs
EOFREBOOT

# TODO MUST BE LAST OPERATION
# auto remove unneeded packages
apt-get autopurge -y

# handle resolv.conf
if [ "$autodns" = yes ] ; then
    apt-get install -y systemd-resolved
    systemctl enable systemd-resolved
    [ -h /etc/resolv.conf ] || ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
else
    systemctl disable systemd-resolved 2>/dev/null # in case this is auto installed by debootstrap
    rm -f /etc/resolv.conf
    printf '%s\n' "nameserver $dns" > /etc/resolv.conf
fi

# clean cache
apt-get clean
EOFCHROOT
}

post_chroot () {
    :
}

check_cmd () {
    local missing=0 cmd
    for cmd do
        command -v "$cmd" >/dev/null ||
        { printf '\033[31mERR: \033[0m%s\n' "$cmd not found, please install related package that provides $cmd" ; missing=1 ; }
    done
    [ "$missing" = 1 ] && exit 1
}

out () { printf '\033[32mINFO: \033[0m%s\n' "$@" ; }

die () { printf '\033[31mERR: \033[0m%s\n' "$@" ; exit 1 ; }

cleanup () {
    sync
    fstrim -av || true
}

check_root () {
    [ "$(id -u)" = 0 ] || die "please run as root/sudo/doas"
}

fix_alpine () {
    if command -v setup-devd > /dev/null ; then
        # busybox mdev has bugs, use mdevd instead
        setup-devd mdevd > /dev/null 2>&1
    fi
}

fix_clock () {
    # some distro, alpine virt for instance, clock is not synced on boot
    # but if the RTC time is wrong, this causes problems
    hwclock -s >/dev/null 2>&1 || true
}

check_network () {
    curl --connect-timeout 5 -m 10 -sfI $deb_mirror >/dev/null 2>&1 || die "failed to do network test with curl $deb_mirror, possible causes:" "clock(fix it if wrong): $(date)" "network: please check ip r and ip a" "dns: please check /etc/resolve.conf"
}

# real job

deps="wget curl tar xz gzip sfdisk mount lsblk mountpoint perl ar wipefs sed awk"
export LANG=C
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

check_root
check_cmd $deps
#fix_clock
check_network
fix_alpine
set_var
set_mount
set_rootfs
set_chroot
post_chroot
cleanup

out "Congrats, all done" \
"Special Notes:" \
"1. The network is configured with systemd-networkd" \
"2. All ethernet interfaces are set to DHCP" \
"3. For static ip or multiple interfaces : " \
"4. Please go to $mount_point/etc/systemd/network/ and do some editing before reboot"
