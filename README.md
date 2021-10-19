# BMD

BMD (Bhyve Management Daemon) controls bhyve processes in order to VM configuration files.
BMD reads all VM configuration files on the start up and boots VMs according to them.

When bmd received SIGTERM, bmd stops all running VMs by sending SIGTERM to
bhyve processes and wait for them and then quit the daemon.

Sending SIGHUP to bmd triggers that bmd reloads all the VM configuration files.
If boot parameter is changed, bmd boots or shutdown VM according to new boot parameter.
If new VM config files are found, bmd boots VMs according to them.
If bmd detects VM config files are deleted, bmd shutdown the VMs.

Bmd doesn't manage network environment to get avoid double management from FreeBSD rc scripts.
All bridges must be created by the rc script.
Bmd creates or destroys tap interfaces and assigns to bridge automatically.
Uses need to specify bridge interfaces for each VM.

Bmd doesn't manage disk images, neither.
Most of administrators have disk management policy and tools.
So, it is better that disk images are created to follow the policy.

## Installation

```
$ make
$ sudo make install
$ sudo make installconfig
```

If you want to install different path from `/usr/local`,
set `LOCALBASE` environment variable like following.

```
$ export LOCALBASE=/opt/local
$ make
$ sudo make install
$ sudo make installconfig
```

## Basic Usage

1. Enable the daemon

    `service bmd enable`

2. Starting the daemon

    `service bmd start`

3. Stopping the daemon

    `service bmd stop`

4. Reload VM config files

    `service bmd reload`

## BMD options

BMD can take following options. Write the options after "bmd_flags=" in /etc/rc.conf.

| option | description | default |
|:-------|:------------|:--------|
| -F | foreground mode | (none) |
| -c dirname | VM configuration directory | $LOCALBASE/etc/bmd.d |
| -f filename |  PID filename | /var/run/bmd.pid |
| -p dirname | plugin install directory | $LOCALBASE/libexec/bmd |
| -m perm| unixdomain socket permission | 0600 |

## VM Config files

VM configuration files are written in simple text format.
The format is "key = value(s)".
One configuration file is for one VM.

By default VM Config files are written in `${LOCALBASE}/etc/bmd.d`.
The filename is a virtual machine name by default.

### Configuration keys

Following keys are available.

| key | description | required | default value |
|----:|:------------|:---------|:--------------|
| boot | One of followings<br>"no": don't boot <br>"yes": boot at daemon start or reload<br>"oneshot": boot at daemon start only<br>"always": always reboot after shutdown VM | no | no |
| boot_delay | boot delay in seconds | no | 0 |
| comport | Specify com1 port<br> e.g. /dev/nmdm0B | no | (none) |
| debug_port | gdb debug port | no | (none) |
| disk | disk image filename(s)<br>e.g.<br>/var/images/vm-disk-0 nvme:/var/images/vm-disk-1 | yes | (none) |
| error_logfile | log filename of bhyve messages | no | (none) |
| graphics | set "yes" to use frame buffer device | no | no |
| graphics_listen | vnc port number | no | 5900 |
| graphics_password | password for vnc access | no | password |
| graphics_res | resolution of vnc<br>e.g. 1280x720 | no | 1024x768 |
| graphics_vga | vga conf of bhyve<br>one of "on", "off", "io" | no | io |
| graphics_wait | set "yes" to wait for initial connection to vnc | no | no |
| hookcmd | hook command filepath | no | (none) |
| hostbridge | "standard" or "amd" | no | standard |
| install | set "yes" to boot from ISO | no | no |
| installcmd | install script for grub-bhyve<br>e.g. "kopenbsd -h com0 (cd0)/6.9/amd64/bsd.rd" | no | (none) |
| iso | ISO image filename | no | (none) |
| loadcmd | boot script for grub-bhyve<br>e.g. "kopenbsd -h com0 -r sd0a (hd0,gpt4)/bsd" | no | (none)
| loader | "bhyveload": use bhyveload<br>"grub": use grub-bhyve<br>"uefi": uefi boot | yes | (none) |
| loader_timeout | loader timeout in seconds | no | 3 |
| memory | memory size<br>e.g. 2G | yes | (none) |
| name | Virtual machine name| no | same as filename |
| ncpu | number of CPUs | yes | (none) |
| network | bridge name(s)<br>e.g. bridge0 e1000:bridge1 | no | (none) |
| reboot_on_change | set "yes" to force ACPI reboot if VM config file is changed when bmd reloads it| no | no |
| stop_timeout | VM exit timeout in seconds<br>if expired, force to kill VM | no | 300 |
| utctime | "yes": RTC keeps UTC time<br>"no" : RTC keeps localtime | no | yes |
| wired_memory | set "yes" to wire VM memory | no | no |
| xhci_mouse | set "yes" to use xhci tablet | no | no |

## Example configurations

### FreeBSD Guest

```
boot=yes
loader_timeout=15
comport=/dev/nmdm0B
ncpu=2
memory=2G
disk=/dev/zvol/zpool/images/freebsd
iso=/zpool/iso/FreeBSD-13.0-RELEASE-amd64-disc1.iso 
network=bridge0
loader=bhyveload
```

### NetBSD Guest

```
boot=yes
ncpu=2
memory=2G
comport=/dev/nmdm1B
disk=/dev/zvol/zpool/images/netbsd
iso=/zpool/iso/NetBSD-9.2-amd64.iso
network=bridge0
loader=grub
installcmd="knetbsd -h -r cd0a (cd0)/netbsd"
loadcmd="knetbsd -h -r dk0a (hd0,gpt1)/netbsd"
```

### OpenBSD Guest

```
boot=yes
ncpu=2
memory=2G
comport=/dev/nmdm2B
iso=/zpool/iso/OpenBSD-6.9-amd64.iso
disk=/dev/zvol/zpool/images/openbsd
network=bridge0
loader=grub
installcmd="kopenbsd -h com0 (cd0)/6.9/amd64/bsd.rd"
loadcmd="kopenbsd -h com0 -r sd0a (hd0,gpt4)/bsd"
# after `sysupgrade -n`
#loadcmd="kopenbsd -h com0 -r sd0a (hd0,gpt4)/bsd.upgrade"
```

### CentOS Guest

```
boot=yes
ncpu=2
memory=4G
disk=/dev/zvol/zpool/images/centos
#iso=/zpool/iso/CentOS-8.2.2004-x86_64-dvd1.iso
network = bridge0
loader = uefi
graphics=yes
graphics_port=5901
xhci_mouse=yes
```

### Ubuntu Guest

```
boot=yes
ncpu=2
memory=4G
disk=/dev/zvol/zpool/images/ubuntu
#iso=/zpool/iso/ubuntu-20.04.2.0-desktop-amd64.iso
network=bridge0
loader=uefi
graphics=yes
graphics_port=5903
graphics_res=1280x720
xhci_mouse=yes
```

# plugins

# bmdctl

BMD control command via Unix Domain socket.
Following subcommands are available.

| subcommand | parameter | description |
|:-----------|:----------|:------------|
| boot | VM name | boot VM |
| install | VM name | boot VM from ISO |
| shutdown | VM name | ACPI shutdown VM |
| poweroff | VM name | force to power off VM<br>***Warning: damage to disk image*** |
| reset | VM name | force to reset VM<br>***Warning: damage to disk image*** |
| reload | VM name | reload VM config file |
| console | VM name | get comport console via `cu -l` |
| run | [-i] [-s] VM name | directory boot with serial console that is redirect to stdio.<br>VM booted from this subcommand is independent from bmd.<br>-i: install mode<br>-s: single user mode|
| list | (none) | list VMs |

# Known Issues

## 1. Install mode doesn't work on UEFI boot

There is no way to customize UEFI variables at boot for now.
Following patch may allow us to choose boot disks.

https://reviews.freebsd.org/D19976

## 2. The second `disk` keyword doesn't override previous value

`disk`, `network` and `iso` keywords append values as a list.
The other keys are override the previous value.
The config parser should understand '+=' operator for appending values.
