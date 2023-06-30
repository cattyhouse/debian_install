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

# apt and dpkg commands

- debdiff : compare the new conf with old conf and call vim to merge
```sh
debdiff () {
    # fd 3 is used to get rid of "Vim: Warning: Input is not from a terminal"
    while read -u 3 -r -d '' ; do
        vim -d "$REPLY" "${REPLY%.*}"
        rm -i "$REPLY"
    done 3< <(find /etc/ -regextype posix-extended -iregex ".+\.(dpkg-|ucf-).+" -print0)
}
```
- aptu : upgrade

```sh
aptu () {
    local ignore_hold=
    [ "$1" = "-a" ] && ignore_hold="--ignore-hold"
    apt-get update &&
    apt-get -y $ignore_hold dist-upgrade &&
    apt-get -y autopurge &&
    apt-get clean
    debdiff
}
```
- info query

```sh
apt-cache search -n PATTERN # search by name
apt-get changelog PACKAGE # view changelog of package
apt-cache show PACKAGE # show info about the package

```
- aptlistlocal : list packages installed by `dpkg -i` but not found in sources.list
```sh
aptlistlocal () {
    apt list '?obsolete ?installed'
}
```

- dpkglistpkgs : list packages with colored version

```sh
dpkglistpkgs () {
    dpkg-query --show |
    awk '{ print $1,"\033[32m"$2"\033[0m" }' | less
}
```
- dpkglistpkgsbysize : list packages sorted by colored size

```sh
dpkglistpkgsbysize () {
    dpkg-query --show -f '${Package}\t${Installed-Size}KB\n' | sort -nr -k2 |
    awk '{ print $1,"\033[32m"$2"\033[0m" }' | less
}
```


- aptrmoldkernel : remove old kernels

```sh
aptrmoldkernel () {
    local running latest _kernel _header
    running=$(uname -r)
    latest=$(realpath /vmlinuz) ; latest=${latest#*-}
    _kernel=$(dpkg-query --show | grep -E 'linux-image-[0-9]+\.[0-9]+' | grep -v -E "$running|$latest" | awk '{ print $1 }')
    _header=$(dpkg-query --show | grep -E 'linux-headers-[0-9]+\.[0-9]+' | grep -v -E "$running|$latest" | awk '{ print $1 }')
    if [ -z "$_kernel" ] && [ -z "$_header" ] ; then
        echo "nothing to remove"
        echo "running kernel : $running"
        echo "latest kernel  : $latest"
    else
        apt-get purge $_kernel $_header
    fi
}
```

# debian Q&A
## why is the service enabled automatically
- each package may have a postinst shell script, rsync for example: `/var/lib/dpkg/info/rsync.postinst`. when dpkg --configure is called, `deb-systemd-helper enable` is called in the script, thus the service is enabled. to see a rough list of **debian** enabled services `fd -p postinst /var/lib/dpkg -X grep 'deb-systemd-helper enable'`
- you may need to run `systemctl disable NAME.service` if you don't want it to run on boot

## how to list all enabled services and timers
- enabled services and timers are usually symlinked to the `*.target.wants` directory, so we can use find to list them all and sort by type.

```sh
find \
/usr/lib/systemd \
/etc/systemd \
/run/systemd \
-type l \
-regextype posix-extended \
-iregex ".*target\.wants.*\.(timer|service)$" \
-printf '%f\n' |
sort -t. -k2 |
uniq |
less
```

## how does unattended-upgrades work
- `apt-daily.timer` runs `apt-daily.service` on a schedule. then `/usr/lib/apt/apt.systemd.daily update` is run, this will call `apt-get update` and `unattended-upgrades --download-only` to refresh the metadata and download packages if any.

- `apt-daily-upgrade.timer` runs `apt-daily-upgrade.service` on a schedule. then `/usr/lib/apt/apt.systemd.daily install` is run, this will call `unattended-upgrades` to install downloaded packages if any
- also there are some options as decribed in `/usr/lib/apt/apt.systemd.daily`, it controls how often `unattended-upgrades` gets run. by default it is eveyday but there are some offsets. it is better to set `APT::Periodic::Unattended-Upgrade "always"`, so it is controlled solely by the `apt-daily.timer` and `apt-daily-upgrade.timer`
- timer can also be customized using, e.g. `systemctl edit apt-daily.timer`

## enable btrfs compress

> compress must be enabled on mount before new data written. but what if it was not mounted with compress option?

- edit /etc/fstab, prepare for remount. if `compress=zstd:1` is not present, add it
```
UUID=... / btrfs compress=zstd:1 0 0
```

- defrag the whole root with `-czstd`
```
btrfs -v filesystem defrag -r -czstd -f /
```
- remount
```
systemctl daemon-reload
mount -a -o remount
```
- check
```sh
mount | grep btrfs # check mount options
compsize -x / # check overall compress ratio
```

## free btrfs space
- check usage first
```sh
btrfs fi df / # notice total=
btrfs fi us / # notice Device unallocated:
```
- free unused metadata and data by btrfs balance
```sh
target=
while read -r target ; do
    btrfs -v balance start -musage=80 -dusage=80 "$target"
done < <(findmnt -n -t btrfs -o TARGET)
```
- check usage after

```sh
btrfs fi df / # should see less total= size
btrfs fi us / # should see more in Device unallocated:
```

## pipe cron output to journald

> debian's cron, by default send output to mail only, if there is no mail agent installed, it outputs a warning like `CRON:  (CRON) info (No MTA installed, discarding output)`, there is no option to send output to somewhere else. however we still can do something, `crontab -e` will be like this:

```sh
MAILTO="" # set MAILTO="" to not send any mail, makes that "No MTA installed ..." message gone

# pipe output to systemd-cat and it will be send to journald
# use journalctl -g KEYWORD to search, KEYWORD is the tag that systemd-cat uses.

# send stdout only
* * * * * echo "test" | systemd-cat -t cron.test
# send stderr only, in this case, 2>&1 must be before >/dev/null
* * * * * curl something 2>&1 >/dev/null | systemc-cat -t cron.curl
# send both stdout and stderr
* * * * * osbackup 2>&1 | systemd-cat -t cron.osbackup
```