#!/bin/sh
export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin/:/sbin:/bin"
set_var () {
    #### TODO IMPORTANT VARIABLE ####

    is_in_china="no" # set to "yes" if the computer to be installed is located in china. otherwise set to "no"
    is_vm="yes" # set to "yes" for vm/vps. "no" for real hardware and vmware guest
    hostname="debian"
    dev="/dev/vda" # which drive to install to, use lsblk to find it
    rootfs="ext4" # btrfs or ext4
    autodns="no" # if yes, then install and enable systemd-resolved. if no, then use 119.29.29.29 for china, 1.1.1.1 for others
    efi_size="64M" # 1) at least 40M 2) 64M is a good enough
    pw='$6$6uBlduKtkwiJw7wY$IaZKonJKpI.cN5/0c.vRuXnztBWPUfI5B9VYYEGddzmrrNMiYsmdVxzu5JzpnsTxEuiEo95JoF3V9c4BccXgI0' # must be in single quote to prevent shell expansion. generate by : echo 'your_password' | mkpasswd -m sha-512 -s
    ssh_pub='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBJLSxzI5IVEHV7NXo7k2arm3fo756ouGNSywQbx1IOk' # generate by ssh-keygen or get existing one from: head -n1 ~/.ssh/authorized_keys
    debian_suite="bookworm" # supported: by code name:  bookworm | trixie | sid  OR  by branch : stable | testing | unstable . code name is preferred
    timezone="Asia/Shanghai"
    pkgs="apt-file bat bc ca-certificates cron cron-daemon-common curl dbus dbus-user-session fdisk fd-find file init initramfs-tools iproute2 ipset iptables iputils-ping jq less locales logrotate man-db manpages manpages-dev ncdu ncurses-term needrestart ssh procps psmisc rsync systemd systemd-sysv systemd-timesyncd systemd-zram-generator tmux tree unattended-upgrades vim whiptail wireguard-tools zstd" # select preinstalled packages
    mount_point="/mnt/debian_c7bN4b"

    #### TODO IMPORTANT VARIABLE ####

    # arch
    arch=$(uname -m)
    case "$arch" in
        (aarch64) host_arch="arm64" ; console=ttyAMA0 ;;
        (x86_64) host_arch="amd64" ; console=ttyS0 ;;
        (*) die "unsupported arch : $arch" ;;
    esac
    
    # systemd-resolved or not
    if [ "$autodns" = yes ] ; then
        pkgs="$pkgs systemd-resolved"
    fi
    
    # check efi
    is_efi=""
    if [ -d /sys/firmware/efi/efivars ] ; then
        check_cmd mkfs.fat
        is_efi="y"
        pkgs="$pkgs efibootmgr grub-efi dosfstools"
    else
        pkgs="$pkgs grub-pc"
    fi
    
    # set mirror for debootstrap
    deb_mirror="https://deb.debian.org/debian/"
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
    # "sid" in the end is the script name, needed since this commit :
    # https://salsa.debian.org/installer-team/debootstrap/-/commit/2d3eae916af51cc49ab0989cea1f5bfb58012179
    # note that all scripts are linked to scripts/sid
    "$DEBOOTSTRAP_DIR"/debootstrap --no-check-gpg --arch="$host_arch" --variant=minbase "$debian_suite" "$mount_point" "$deb_mirror" sid || die "failed to run debootstrap"
    sleep 5
    rm -f "$mount_point"/etc/resolv.conf
    tee "$mount_point"/etc/resolv.conf "$mount_point"/etc/resolv.conf.bk < /etc/resolv.conf > /dev/null
}

chroot_mount_misc () (
    cd "$mount_point" || die "failed to cd $mount_point"
    mkdir -p proc sys dev run tmp
    
    local do_mount
    do_mount() {
        local msg="$@"
        mount "$@" || die "failed to mount ${msg##* }"
    }

    do_mount -t proc proc proc
    do_mount -t sysfs sysfs sys
    # use --rbind for dev, because some system may use udev/devtmpfs for /dev
    # use --make-rslave so we are able to unmount
    do_mount --rbind --make-rslave /dev dev
    do_mount --bind --make-slave /run run
    do_mount -t tmpfs tmpfs tmp

    if [ "$is_efi" = "y" ] ; then
        mkdir -p sys/firmware/efi/efivars
        do_mount -t efivarfs efivarfs sys/firmware/efi/efivars
    fi
)

set_chroot () {
chroot_mount_misc || exit 1
chroot "$mount_point" /bin/sh -s <<EOFCHROOT
. /etc/profile

# apt sources
_comp="main contrib non-free non-free-firmware"
_deburl="https://deb.debian.org/debian/"
_securl="https://security.debian.org/debian-security/"
printf '%s\n' "deb \$_deburl $debian_suite \$_comp" > /etc/apt/sources.list
case $debian_suite in
    (unstable|sid) : ;;
    (*) printf '%s\n' "deb \$_deburl ${debian_suite}-updates \$_comp" "deb \$_securl ${debian_suite}-security \$_comp" >> /etc/apt/sources.list ;;
esac

# update sources
apt-get update

# install packages
apt-get install -q -d -y --no-install-recommends $pkgs
apt-get install -q -y --no-install-recommends $pkgs

# restore resolv.conf due to systemd-resolved
mv /etc/resolv.conf.bk /etc/resolv.conf

cat <<EOFAPT > /etc/apt/apt.conf.d/99-no-recommends
APT::Install-Recommends "0";
APT::Install-Suggests "0";
EOFAPT

# ucf.conf dpkg.cfg
printf '%s\n' "conf_force_conffold=YES" >> /etc/ucf.conf
printf '%s\n' "force-confold" "force-confmiss" >> /etc/dpkg/dpkg.cfg

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

# unattended-upgrades custom
printf '%s\n' \
'Unattended-Upgrade::OnlyOnACPower "false";' \
'Unattended-Upgrade::Skip-Updates-On-Metered-Connections "false";' \
'APT::Periodic::Update-Package-Lists "always";' \
'APT::Periodic::Unattended-Upgrade "always";' \
'APT::Periodic::CleanInterval "always";' \
> /etc/apt/apt.conf.d/99unattended-upgrades-custom

# download timer
cat <<EOFDOWNTIMER | install -D -m 0644 /dev/stdin /etc/systemd/system/apt-daily.timer.d/override.conf
[Timer]
OnCalendar=
OnCalendar=06,18:00
RandomizedDelaySec=1h
EOFDOWNTIMER

# install timer
cat <<EOFINSTALLTIMER | install -D -m 0644 /dev/stdin /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf
[Timer]
OnCalendar=
OnCalendar=07,19:00
RandomizedDelaySec=1h
EOFINSTALLTIMER

# zstd on zram 
cat <<EOFZRAM > /etc/systemd/zram-generator.conf
[zram0]
zram-size = ram / 2
compression-algorithm = zstd
EOFZRAM

# locale
# based on code in dpkg-query --control-show locales config
printf '%s\n' 'en_US.UTF-8 UTF-8' 'C.UTF-8 UTF-8' > /etc/locale.gen
printf '%s\n' 'LANG=C.UTF-8' > /etc/default/locale
dpkg-reconfigure -f noninteractive locales

# timezone
# based on code in dpkg-query --control-show tzdata config
ln -sf /usr/share/zoneinfo/$timezone /etc/localtime
dpkg-reconfigure -f noninteractive tzdata

# sshd
cat <<EOFSSHD >> /etc/ssh/sshd_config

PasswordAuthentication no
PrintLastLog no
LogLevel QUIET
EOFSSHD


# disable AcceptEnv
sed -i -e '/^AcceptEnv/ s|^|#|' /etc/ssh/sshd_config

cat <<EOFSSHDAR | install -D -m 0644 /dev/stdin /etc/systemd/system/ssh.service.d/override.conf

[Service]
Restart=always
EOFSSHDAR

install -m 700 -d /root/.ssh
printf '%s\n' '$ssh_pub' | install /dev/stdin -m 600 /root/.ssh/authorized_keys
printf '%s\n' 'root:$pw' | chpasswd -e

# UMASK to 077
sed -i 's|^UMASK.*|UMASK 077|' /etc/login.defs

# disable motd from debian
sed -i -e '/pam_motd.so/ s|^|#|' /etc/pam.d/login /etc/pam.d/sshd

# disable deprecated user_readenv (man pam_env)
sed -i '/pam_env.so/ s|user_readenv=1|user_readenv=0|' /etc/pam.d/sshd

# disable ssh-keygen comment
for file in /etc/ssh/ssh_host_* ; do
    case "\$file" in
        (*.pub) : ;;
        (*) ssh-keygen -c -C "" -f "\$file" >/dev/null 2>&1 ;;
    esac
done

# ntp servers
if [ "$is_in_china" = yes ] ; then
cat <<EOFNTP >> /etc/systemd/timesyncd.conf

NTP=ntp.aliyun.com ntp1.aliyun.com time1.cloud.tencent.com time2.cloud.tencent.com
EOFNTP
fi

# sysctl
mkdir -p /etc/sysctl.d
cat <<EOFSYSCTL > /etc/sysctl.d/99.zzz.conf
# tcp forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# tcp mem
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.optmem_max = 65536
net.ipv4.tcp_rmem = 4096 1048576 2097152
net.ipv4.tcp_wmem = 4096 65536 16777216

# tcp connection
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
# 0x1 0x2 0x400
net.ipv4.tcp_fastopen = 1027
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# tcp keepalive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 12
net.ipv4.tcp_keepalive_probes = 6
# bbr
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = bbr

net.ipv4.ip_local_port_range = 20000 65535
# increase nofile on debian, alpine, void
fs.nr_open = 1073741816
fs.file-max = 9223372036854775807
fs.file-nr = 832        0       9223372036854775807
EOFSYSCTL

# link fd, bat
ln -sf /usr/bin/batcat /usr/local/bin/bat
ln -sf /usr/bin/fdfind /usr/local/bin/fd

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

# grub
cp -a /etc/default/grub /etc/default/grub.\$(dpkg-query -W -f '\${Version}' grub2-common)
cat <<EOFGRUB > /etc/default/grub
GRUB_DEFAULT=0
GRUB_DISTRIBUTOR="Debian"
GRUB_TIMEOUT=1
GRUB_CMDLINE_LINUX_DEFAULT="quiet zswap.enabled=0 nomodeset"
#GRUB_CMDLINE_LINUX_DEFAULT="quiet console=$console zswap.enabled=0 nomodeset"
GRUB_DISABLE_SUBMENU=y
GRUB_DISABLE_RECOVERY=true
GRUB_DISABLE_OS_PROBER=true
GRUB_TERMINAL_OUTPUT=console
GRUB_TERMINAL_INPUT=console
GRUB_PRELOAD_MODULES="linux part_gpt part_msdos"
EOFGRUB

# grub color
# https://wiki.debian.org/GRUB2?action=show&redirect=Grub2#Configure_console_menu_colors
cat <<EOFGRUBCOLOR > /boot/grub/custom.cfg
set menu_color_normal=white/black
set menu_color_highlight=red/black
EOFGRUBCOLOR

# install grub to also removable place : EFI/BOOT
# https://wiki.debian.org/GrubEFIReinstall
if [ "$is_efi" = "y" ] ; then
    grub-install --recheck --force-extra-removable
    printf '%s\n' "grub-efi-$host_arch grub2/force_efi_extra_removable boolean true" | debconf-set-selections
    #dpkg-reconfigure -f noninteractive "grub-efi-$host_arch"
else
    grub-install --recheck $dev
fi

# initramfs
cat <<EOFINIT >> /etc/initramfs-tools/initramfs.conf

MODULES=dep
COMPRESS=zstd
COMPRESSLEVEL=1
EOFINIT

if [ "$rootfs" = btrfs ] ; then
    printf '%s\n' 'zstd' 'btrfs' >> /etc/initramfs-tools/modules
fi

# kernel
if [ "$is_vm" = yes ] ; then
    apt-get -y install linux-image-cloud-$host_arch
else
    apt-get -y install linux-image-$host_arch
fi

update-grub2

# fix warning of /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
apt-get install -y python3-gi

# clean cache
apt-get -y autopurge
apt-get clean
apt-file update

# disable services
# disable unattended-upgrade for sid
case $debian_suite in
    (sid|unstable) systemctl disable apt-daily.timer apt-daily-upgrade.timer ;;
esac

systemctl disable rsync.service

# enable services
systemctl enable ssh systemd-networkd systemd-timesyncd

# dns resolv.conf
rm -f /etc/resolv.conf # we don't need it

if [ "$autodns" = yes ] ; then
    systemctl enable systemd-resolved
else
    systemctl disable systemd-resolved 2>/dev/null # in case this is auto installed by debootstrap
    if [ "$is_in_china" = yes ] ; then
        printf '%s\n' "nameserver 119.29.29.29" > /etc/resolv.conf
    else
        printf '%s\n' "nameserver 1.1.1.1" > /etc/resolv.conf
    fi
fi

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
}

check_root () {
    [ "$(id -u)" = 0 ] || die "please run as root/sudo/doas"
}

fix_alpine () {
    if command -v apk > /dev/null ; then
        # busybox mdev has bugs, use mdevd instead
        setup-devd mdevd > /dev/null 2>&1
    fi
}

fix_clock () {
    # some distro, alpine virt for instance, clock is not synced on boot
    hwclock -s >/dev/null 2>&1
}

check_network () {
    curl --connect-timeout 5 -m 10 -sfI https://deb.debian.org >/dev/null 2>&1 || die "please check your network"
}

# real job
deps="wget curl tar xz gzip sfdisk mount lsblk mountpoint perl ar wipefs sed"
export LANG=C
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
check_root
check_cmd $deps
fix_clock
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
