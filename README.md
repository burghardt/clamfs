# ClamFS

ClamFS - User-space fs with on-access antivirus scanning

## Description

ClamFS is a [FUSE-based user-space file system](https://en.wikipedia.org/wiki/Filesystem_in_Userspace)
for Linux and [BSD](https://www.freshports.org/security/clamfs/)
with on-access anti-virus file scanning through [clamd daemon](https://manpages.debian.org/testing/clamav-daemon/clamd.8.en.html)
(a file scanning service developed by [ClamAV Project](https://www.clamav.net/)).

## Features

 * User-space file system (no kernel patches, recompilation, etc.)
 * Configuration stored in XML files
 * FUSE (and libfuse3) used as file system back-end
 * Scan files using ClamAV
 * ScanCache (LRU with time-based and out-of-memory expiration) speeds up file access
 * Sends mail to administrator when detect virus

## Getting Started

These instructions will get you a copy of the project up and running on your
local machine.

### Installing packages

#### Arch

[ClamFS package](https://aur.archlinux.org/packages/clamfs/)
is available from [AUR](https://aur.archlinux.org/) repository.

#### Debian, Ubuntu, etc.

[Debian GNU/Linux](https://packages.debian.org/clamfs),
[Ubuntu](https://packages.ubuntu.com/clamfs) and
[Devuan](https://pkginfo.devuan.org/cgi-bin/d1pkgweb-query?search=clamfs)
have `clamfs` package in their repositories.

```
sudo apt install clamfs clamav-daemon clamav-freshclam
```

#### Gentoo

Gentoo provides [sys-fs/clamfs package](https://packages.gentoo.org/packages/sys-fs/clamfs).

#### FreeBSD, DragonFly BSD

[FreeBSD](https://www.freshports.org/security/clamfs/) and [DragonFly BSD]() has `security/clamfs` in ports.

Install package...
```
pkg install clamfs
```

... or install from ports.
```
cd /usr/ports/security/clamfs ; make install clean
```

### Building from sources

#### Prerequisites

To build ClamFS on any GNU/Linux or *BSD you need:
 * [FUSE](https://github.com/libfuse/libfuse) &gt;= 3
 * [POCO](https://pocoproject.org/) &gt;= 1.2.9
 * [Boost](https://www.boost.org/) &gt;= 1.33
 * [RLog](https://www.arg0.net/rlog)
 * [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/),
   [autoconf](https://www.gnu.org/software/autoconf/),
   [automake](https://www.gnu.org/software/automake/),
   [make](https://www.gnu.org/software/make/)...

To run ClamFS `clamd` service from [ClamAV project](https://www.clamav.net/)
is required.

Note 1: POCO versions up to 1.2.8 contain 4-BSDL licensed files and thus you
should avoid linking it against any GPL licensed code. I strongly advise using
version 1.2.9 or newer (as license issues has been fixed).

Note 2: ClamFS version up to 1.0.1 required also
[GNU CommonCPP](https://www.gnu.org/software/commoncpp/)
library. This dependency was dropped in version 1.1.0 (with commit 3bdb8ec).

#### Installing dependencies

##### Arch

Sync following packages to build ClamFS:
```
pacman -Syu base-devel fuse3 poco boost rlog
```

##### Debian, Ubuntu, etc.

To build ClamFS on Debian GNU/Linux and Ubuntu install these packages:
 * libfuse3-dev
 * libpoco-dev
 * libboost-dev
 * librlog-dev
 * pkg-config

As a run-time dependency install:
 * clamav-daemon
 * fuse

Run following command to install al dependencies.
```
sudo apt-get -y --no-install-recommends install \
      build-essential pkg-config autoconf automake \
      libfuse3-dev libpoco-dev libboost-dev librlog-dev \
      clamav-daemon clamav-freshclam
```

##### FreeBSD, DragonFly BSD

To build ClamFS on FreeBSD and DragonFly BSD you need those ports:
 * [sysutils/fusefs-libs3](https://www.freshports.org/sysutils/fusefs-libs3/)
 * [devel/poco](https://www.freshports.org/devel/poco/)
 * [devel/boost-libs](https://www.freshports.org/devel/boost-libs/)
 * [devel/rlog](https://www.freshports.org/devel/rlog/)
 * [devel/pkgconf](https://www.freshports.org/devel/pkgconf/)
 * [devel/autoconf](https://www.freshports.org/devel/autoconf/)
 * [devel/automake](https://www.freshports.org/devel/automake/)

As a run-time dependency you need:
 * [security/clamav](https://www.freshports.org/security/clamav/)

Note: older FreeBSD version required port named `sysutils/fusefs-kmod`.
This is no longer the case as `fuse` module is part of kernel.

#### Downloading

Just download the release package and extract it with `tar`.

```
tar xf clamfs-<version>.tar.gz
```

Or clone repository.

```
git clone https://github.com/burghardt/clamfs.git
```

#### Building

If using cloned repository rebuild autotools configuration with `autogen.sh`
script. If using release tarballs skip this step.
```
sh autogen.sh
```

Configure package with `configure` script.
```
sh configure
```

Finally build sources with `make`.
```
make -j
```

#### Installing

Run `make install` (as root) to install binaries.
```
sudo make install
```

### Usage

ClamFS requires only one argument - configuration file name. Configuration is
stored as XML document. Sample configuration is available in `doc` directory,
in file named [clamfs.xml](doc/clamfs.xml).

#### Sample output

```
17:11:44 (clamfs.cxx:993) ClamFS v1.1.0-snapshoot (git-7d4beda)
17:11:44 (clamfs.cxx:994) Copyright (c) 2007-2019 Krzysztof Burghardt <krzysztof@burghardt.pl>
17:11:44 (clamfs.cxx:995) https://github.com/burghardt/clamfs
17:11:44 (clamfs.cxx:1004) ClamFS need to be invoked with one parameter - location of configuration file
17:11:44 (clamfs.cxx:1005) Example: src/clamfs /etc/clamfs/home.xml
```

#### Configuration

Please refer to [clamfs.xml](doc/clamfs.xml) for comprehensive list of
configuration options. Only three options are mandatory:
 * `<clamd socket="" />` to set path to `clamd` socket
 * `<filesystem root="" />` to set place from ClamFS will read files
 * `<filesystem mountpoint="" />` to set mount point where virtual filesystem
   will be attached in directory tree

#### Different scan modes

ClamFS versions up to 1.1.0 use `fname` mode and pass only file name (with
`SCAN` command) to clamd.

In ClamFS versions after 1.1.0 three different modes are available to pass
files to clamd. Default method is `fdpass`.

##### mode="fname" - pass file name (with SCAN command)

This is the simplest mode. In this mode clamd opens and reads file by itself.
Permissions have to be set to allow clamd to access the file. Also this mode
works only when clamd and ClamFS are no the same machine and both have access
to files. Using this mode might require permissions or ACLs setup for clamd
user. Please note that attempts to run clamd as root to bypass permissions
is usually a bad idea.

##### mode="fdpass" - pass file descriptor (with FILDES command)

This is the default mode when BSD 4.4 / RFC2292 style fd passing is available
in the operating system. In this mode ClamFS opens file and passes file
descriptor to clamd over UNIX domain socket. Finally clamd reads file by
itself. This mode works only when clamd and ClamFS are no the same machine
and operating system supports file descriptor sharing.

##### mode="stream" - pass file stream (with INSTREAM command)

Last mode offers ability to use remote clamd instances. In this mode ClamFS
opens and reads file. Than sends it to clamd over the UNIX domain or TCP/IP
socket. This works for local and remote clamd instances, but for local clamd
instance `fdpass` is preferred scanning method.

#### Additional configuration steps for FreeBSD

FreeBSD's `fuse` kernel module has to be loaded before starting ClamFS. This
can be done ad-hoc with `kldload fuse` command.

To have it loaded at boot time, add the following line to `/boot/loader.conf`.
```sh
fuse_load="YES"
```

Or append fuse module to `kld_list` in `/etc/rc.conf`.
```sh
kld_list="fuse"
```

Also configure ClamAV daemon and signature downloader service to start during
boot with following options appended to `/etc/rc.conf`.
```sh
clamav_clamd_enable="YES"
clamav_freshclam_enable="YES"
```

Finally start required services with following commands.
```sh
service kld start
service clamav-freshclam start
service clamav-clamd start
```

#### Mounting and unmounting ClamFS file systems

To mount ClamFS filesystem run ClamFS with configuration filename as a parameter.
```sh
clamfs /etc/clamfs/netshare.xml
```

To unmount ClamFS use `fusermount` with `-u` flag and
`<filesystem mountpoint="/net/share" />` value as a parameter.
```sh
sudo fusermount -u /net/share
```

## Fine tuning

### Starting without clamd available

A new “check” option was added to allow you to mount a ClamFS file system when
clamd is not available, such as during an early stage of the boot process.
To disable ClamAV Daemon (clamd) check on ClamFS startup set option check to
no:
```xml
<clamd socket="/var/run/clamav/clamd.ctl" check="no" />
```

### Mounting file systems from /etc/fstab

With `check=no` mounting ClamFS file systems form /etc/fstab is possible using
fuse mount helper (/sbin/mount.fuse). ClamFS will be started on boot with
configuration file defined here provided as its argument. Simple definition
of ClamFS mount point in /etc/fstab looks like:
```
clamfs#/etc/clamfs/share.xml  /clamfs/share  fuse  defaults  0  0
```

### Using remote clamd instances

ClamFS can reach remote clamd instances using TCP/IP sockets. This type of
connection requires `mode="stream"` settings and use clamd's `INSTREAM`
command to scan files smaller than `StreamMaxLength` which defaults to 25 MiB.
```xml
<clamd socket="<IP>:<port>" mode="stream" />
```

Default clamd port is `3310`. For server running at address `192.168.1.101`
configuration is:
```xml
<clamd socket="192.168.1.101:3310" mode="stream" />
```

### Read-only mounts

The “readonly” option was added to the filesystem options allowing you to
create a read-only protected file system. Just extend filesystem definition
in config file with `readonly` option set to `yes`:
```xml
<filesystem root="/share" mountpoint="/clamfs/share" readonly="yes" />
```

### Program name reported as unknown when virus found

```
16:33:24 (clamav.cxx:152) (< unknown >:19690) (root:0) /tmp/eicar.com: Eicar-Test-Signature FOUND
```

To see program name instead of `< unknown >` in log messages on FreeBSD one
need to mount `/proc` filesystem. Add following line to `/etc/fstab`.
```
proc /proc procfs rw 0 0
```
And mount `/proc` with `mount /proc`.

Program name should be reported correctly with mounted `/proc`.
```
16:37:31 (clamav.cxx:152) (hexdump:19740) (root:0) /tmp/eicar.com: Eicar-Test-Signature FOUND
```

### Using ClamFS with WINE

Following steps setups on-access file scanning with ClamAV for WINE instance.

1. Install ClamFS runtime dependencies.
   ```sh
   sudo apt install clamav-freshclam clamav-daemon
   ```
2. Move original `C:\` drive to new location.
   ```sh
   mv ~/.wine/drive_c ~/.wine/raw_drive_c
   mkdir ~/.wine/drive_c
   ```
3. Copy [clamfs.xml](doc/clamfs.xml) to `~/.wine/clamfs.xml`.
4. Set following options in `clamfs.xml`. Make sure `mode="fdpass"` and
`public="no"` are set.
   ```xml
   <clamd socket="/var/run/clamav/clamd.ctl" mode="fdpass" check="yes" />
   <filesystem root="/home/user/.wine/raw_drive_c" mountpoint="/home/user/.wine/drive_c" public="no" />
   ```
5. Mount ClamFS filesystem as normal user with this command.
   ```sh
   clamfs ~/.wine/clamfs.xml
   ```
6. Run any WINE software and check logs with.
   ```sh
   sudo tail -F /var/log/clamav/clamav.log /var/log/syslog
   ```

For legacy configuration without `mode=fdpass` enabled please refer to my blog
post [Wine with on-access ClamAV scanning](https://blog.burghardt.pl/2007/11/wine-with-on-access-clamav-scanning/)
if you are interested in running ClamFS version &lt;= 1.1.0 to protect WINE
installation.

### Installing FUSE v3 from sources

If your operating system does not provide binary package for `libfuse3` (like
Ubuntu 18.04 LTS) installing `fuse3` from sources into `/usr/local` might be
simplest method to install this dependency. Following commands installs current
`master` branch from Github `libfuse` repository:

```sh
sudo apt-get -y --no-install-recommends install meson ninja-build
mkdir /tmp/fuse3 ; cd /tmp/fuse3
git clone --depth 1 https://github.com/libfuse/libfuse.git .
mkdir build ; cd build
meson ..
ninja
sudo ninja install
```

Please note that Debian 9 (codename "Stretch") is unable to build fuse3 as
meson version provided in stretch repository is too old (package version is
0.37.1, but fuse requires &gt;= 0.42).

## License

This project is licensed under the GPLv2 License - see the
[COPYING](COPYING) file for details.

## Historical repositories at SourceForge

Long time ago [ClamFS](http://clamfs.sourceforge.net/) was developed on
[SourceForge](https://sourceforge.net/projects/clamfs/) and some CVS and
SVN repositories still resides there. Right now all development takes place
on GitHub.
