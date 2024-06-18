# BMD

BMD (Bhyve Management Daemon) controls bhyve processes in order to VM configuration files.
BMD reads all VM configuration files on the start up and boots VMs according to them.

When bmd received SIGTERM, bmd stops all running VMs by sending SIGTERM to
bhyve processes and wait for them and then quit the daemon.

Sending SIGHUP to bmd triggers that bmd reloads all the VM configuration files.
If boot parameter is changed, bmd boots or shutdown VM according to new boot parameter.
If new VM config files are found, bmd boots VMs according to them.
If bmd detects that some VM config files are deleted, bmd shutdown the VMs.

Bmd doesn't manage network environment to get avoid double management from FreeBSD rc scripts.
All bridges must be created by the rc script.
Bmd creates and destroys tap interfaces automatically
and also assigns to the bridges.
Uses need to specify which bridge interfaces are used for each VM.

If you prefer to use vale(4) switches for outer network connectivity,
they must also be created and attached to a physical nic
while the system starts. `/etc/rc.local` may help you.
Bmd doesn't create tap interfaces in case of vale(4) use.

Bmd doesn't manage disk images, neither.
Most of administrators have their own disk management policy and tools.
So, it is better that disk images are created to follow the policy.

## Requirements

1. grub2-bhyve package
2. uefi-edk2-bhyve-csm package

## Installation

```
$ make
$ sudo make install
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

## Logging

BMD writes log messages to LOG_DAEMON facility. Usually it is written in
the `/var/log/daemon.log` file by the syslogd(8). You can see error messages
of BMD and informational messages such as starting a VM or stopping a VM with
or without an error.

## BMD options

BMD can take following options. Write the options after "bmd_flags=" in /etc/rc.conf.

| option | description | default |
|:-------|:------------|:--------|
| -F | foreground mode | (none) |
| -c filename | configuration filename | $LOCALBASE/etc/bmd.conf |
| -f filename |  PID filename | /var/run/bmd.pid |
| -p dirname | plugin install directory | $LOCALBASE/libexec/bmd |
| -m perm| unixdomain socket permission | 0600 |

## Configuration file

Bmd configuration file consists of 3 types of sections. Each section has
key-value parameters and variables settings.

### Sections

1. Global section

   Global section contains bmd options and global variables.
   The global section must be written in a file which root privileged user owns.
   If the other user owns the file, the global section is parsed but ignored.

2. Template section

   Template is a part of configuration for Virtual Machines. Configurations
   common to multiple VMs can be written in one template.

3. VM section

   Virtual Machine Configuration is written in this section.

### Macros

Following 2 macros are available.

1. .apply

   This macro takes one or more template names to apply onto VM configuration.
   This macro can be written in template or vm sections.

2. .include

	This macro takes one file path to include another configurations. A file
	path can contain '*' and '?' literals for pattern matting. '.include'
	macro cannot be written in sections, must be written outside of section.

### Variables

All variables belongs to global or local scope. A global scope variable is
defined in global section and referred in all sections. A local scope variable
is defined in VM section or template section and independent for each
individual VM configurations. Variables defined in template section is
available after applied from VM section. Before applying template, no variables
are available written in template section.
In template section, variables that defined before apply macro in VM section is
available.

Bmd always sets following variables.

| Variable name | scope  | value |
|---------------|--------|-------|
| LOCALBASE     | global | As same as LOCALBASE macro in compile time.<br> Default value is '/usr/local'  |
| ID            | local | Unique number for each individual VMs that starts from 0. |
| NAME          | local | VM name |


### Arithmetic Calculation

Arithmetic calculations are performed by enclosing with `$((` `))`. It's
similar to /bin/sh. Numbers must be integers. Variables must contain integer
number strings. Number format is decimal or octal or hexmal as same as
C language. Supported operators are '+' '-' '*' '/' '%'. '(' and ')' are
also available.

### VM Configurations

Configurations are simply written "key = value;". If a key takes one or more
values, multiple values can be written with comma separated. Or, '+=' operator
can be used.

Following keys are available.

| key | description | required | default value |
|----:|:------------|:---------|:--------------|
| boot | One of followings<br>"no": don't boot <br>"yes": boot at daemon start or reload<br>"oneshot": boot at daemon start only<br>"always": always reboot after shutdown VM | no | no |
| boot_delay | boot delay in seconds | no | 0 |
| comport | Specify com1 port<br> e.g. /dev/nmdm0B <br> "auto" assigns nmdm number automatically | no | (none) |
| debug_port | gdb debug port | no | (none) |
| disk | disk image filename(s)<br>e.g.<br>/var/images/vm-disk-0 nvme:/var/images/vm-disk-1 | yes | (none) |
| err_logfile | log filename of bhyve messages | no | (none) |
| graphics | set "yes" to use frame buffer device | no | no |
| graphics_listen | vnc port number | no | 5900 |
| graphics_password | password for vnc access | no | (none) |
| graphics_res | resolution of vnc<br>e.g. 1280x720 | no | 1024x768 |
| graphics_vga | vga conf of bhyve<br>one of "on", "off", "io" | no | io |
| graphics_wait | set "yes" to wait for initial connection to vnc | no | no |
| hookcmd | hook command filepath | no | (none) |
| hostbridge | "standard" or "amd" | no | standard |
| install | set "yes" to boot from ISO | no | no |
| installcmd | install script for grub-bhyve<br>e.g. "kopenbsd -h com0 (cd0)/6.9/amd64/bsd.rd" <br> "auto" inspects iso image. | no | (none) |
| iso | ISO image filename | no | (none) |
| keymap | keymap for vnc | no | (none) |
| loadcmd | boot script for grub-bhyve<br>e.g. "kopenbsd -h com0 -r sd0a (hd0,gpt4)/bsd" <br> "auto" inspects disk image. | no | (none)
| loader | "bhyveload": use bhyveload<br>"grub": use grub-bhyve<br>"uefi": uefi boot | yes | (none) |
| loader_timeout | loader timeout in seconds | no | 15 |
| bhyveload_loader | path to the OS loader | no | (none) |
| bhyveload_env | The FreeBSD loader environment | no | (none) |
| memory | memory size<br>e.g. 2G | yes | (none) |
| name | Virtual machine name| no | vm section name |
| ncpu | number of CPUs or CPU topology (sockets:cores:threads) | no | 1 |
| cpu_pin | Pin guest's vCPU to host CPU | no | (none) |
| network | bridge or vale name(s)<br>e.g. bridge0 vale1 | no | (none) |
| owner | owner of VM | no | same as the file owner in which the vm section is written |
| passthru | PCI passthrough device id<br>e.g. 1/0/130| no | (none) |
| reboot_on_change | set "yes" to force ACPI reboot if VM config file is changed when bmd reloads it| no | no |
| stop_timeout | VM exit timeout in seconds<br>if expired, force to kill VM | no | 300 |
| tpm | TPM device name | no | (none) |
| utctime | "yes": RTC keeps UTC time<br>"no" : RTC keeps localtime | no | yes |
| wired_memory | set "yes" to wire VM memory | no | no |
| xhci_mouse | set "yes" to use xhci tablet | no | no |

### Global Configurations

Following keys are available for bmd.

| key | description | required | default value |
|----:|:------------|:---------|:--------------|
| cmd_socket_path | unix domain socket path | no | /var/run/bmd.sock |
| cmd_socket_mode | unix domain socket mode | no | 0600 |
| vars_directory | in which directory to write UEFI variables | no | /usr/local/var/cache/bmd |
| nmdm_offset | basic offset of auto assigned nmdm | no | 200 |
| pid_file | file to write bmd's pid | no | /var/run/bmd.pid |

## Example configurations

### Global Variables

```
global {
	$imgpath = /dev/zvol/zpool/images;
	$isopath = /zpool/iso;
}
```

### Templates

```
template default_disk {
	disk = ${imgpath}/${NAME};
}

template graphics {
	graphics=yes;
	graphics_port=$((5900 + ${ID}));
	xhci_mouse=yes;
}

template serial {
	comport = auto;
}

template internet {
	network = bridge0;
}

template grub_inspect {
	loader=grub;
	loadcmd="auto";
	installcmd="auto";
}

```

### FreeBSD Guest

```
vm freebsd {
	boot=yes;
	loader_timeout=15;
	ncpu=2;
	memory=2G;
	iso=${isopath}/FreeBSD-13.0-RELEASE-amd64-disc1.iso;
	loader=bhyveload;
	.apply default_disk, serial, internet;
}
```

### NetBSD Guest

```
vm netbsd {
	boot=yes;
	ncpu=2;
	memory=2G;
	iso=${isopath}/NetBSD-9.2-amd64.iso;
	.apply default_disk, serial, internet, grub_inspect;
}
```

### OpenBSD Guest

```
vm openbsd {
	boot=yes;
	ncpu=2;
	memory=2G;
	iso=${isopath}/OpenBSD-6.9-amd64.iso;
	.apply default_disk, serial, internet, grub_inspect;
}
```

### CentOS Guest

```
vm centos {
	boot=yes;
	ncpu=2;
	memory=4G;
	#iso=${isopath}/CentOS-8.2.2004-x86_64-dvd1.iso;
	loader = uefi;
	.apply default_disk, internet, graphics;
}
```

### Ubuntu Guest

```
vm ubuntu {
	boot=yes;
	ncpu=2;
	memory=4G;
	#iso=${isopath}/ubuntu-20.04.2.0-desktop-amd64.iso;
	loader=uefi;
	graphics_res=1280x720;
	.apply default_disk, internet, graphics;
}
```

# Auto Inspection

When `loadcmd` or `installcmd` is set to `auto`, bmd inspects disk and iso
images and generates loadcmd and installcmd values. This feature supports
NetBSD and OpenBSD disk and iso images for now, and requires `loader=grub;`.

# plugins

## hook command plugin

Bmd invokes hook command when VM status is changed.
The command line is as following.

`${hookcmd} ${vm name} ${state}`

${state} is one of followings.

* LOAD

  loader is invoked

* RUN

  bhyve starts to run

* STOP

  bmd stops bhyve

* TERMINATE

  bhyve terminated

* REMOVE

  bmd detects that VM config file is deleted.

* RESTART

  bmd restarts VM

## avahi plugin

If VM is set `graphics=yes` and `avahi-publish` command is installed,
Bmd publish remote frame buffer service under the VM name and vnc port.
The publishing is kept while VM is running.

# bmdctl

BMD control command via Unix Domain socket.
Following subcommands are available.

| subcommand | parameter | description |
|:-----------|:----------|:------------|
| boot [-c]<br>start [-c] | VM name | boot VM and [-c] takes console via `bmd console` |
| install [-c] | VM name | boot VM from ISO and [-c] takes console via `bmd console`.|
| shutdown<br>stop | VM name | ACPI shutdown VM |
| poweroff | VM name | force to power off VM<br>***Warning: damage to disk image*** |
| reset | VM name | force to reset VM<br>***Warning: damage to disk image*** |
| console | VM name | open the comport device and emulate `cu -l` |
| showcomport | VM name | show current comport device to see which is assigned automatically |
| showvgaport | VM name | show current vnc listen address and port number |
| showconfig | [VM name] | run configuration parser manually and print configurations. No effects for running bmd. |
| inspect | VM name | run auto inspection manually |
| run | [-i] [-s] VM name | boot directly with serial console that is redirect to stdio.<br>VM booted from this subcommand is independent from bmd.<br>-i: install mode<br>-s: single user mode|
| list  | [-r] [-s colname] | list VMs sorted by 'colname' |

# Known Issues

## 1. Configuration keys are condensed compared to bhyve

It's under development.
