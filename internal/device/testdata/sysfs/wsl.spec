# WSL2 utility VM (Hyper-V storvsc): sdd is this distro's root, sdc is swap; sda and sdb
# are WSL system VHDs mounted in other, invisible namespaces. Shunya can't see those
# mounts from sysfs/procfs; it marks the disks virtual and warns.

/sys/class/dmi/id/sys_vendor = Microsoft Corporation
/sys/class/dmi/id/product_name = Virtual Machine

disk sda 8:0 /sys/devices/LNXSYSTM:00/LNXSYBUS:00/ACPI0004:00/MSFT1000:00/fd1d2cbd-ce7c-535c-966b-eb5f811c95f0/host0/target0:0:0/0:0:0:0/block/sda
size = 730960
ro = 0
removable = 0
queue/rotational = 1
cd ../..
vendor = Msft
model = Virtual Disk
rev = 1.0
wwid = naa.60022480df18deb7e179255b7b21f6fa
disk sdc 8:32 /sys/devices/LNXSYSTM:00/LNXSYBUS:00/ACPI0004:00/MSFT1000:00/fd1d2cbd-ce7c-535c-966b-eb5f811c95f0/host0/target0:0:0/0:0:0:2/block/sdc
size = 2097160
ro = 0
removable = 0
queue/rotational = 1
cd ../..
vendor = Msft
model = Virtual Disk
rev = 1.0
wwid = naa.600224802d67b3c5934761e5dfa7b7d5
disk sdd 8:48 /sys/devices/LNXSYSTM:00/LNXSYBUS:00/ACPI0004:00/MSFT1000:00/fd1d2cbd-ce7c-535c-966b-eb5f811c95f0/host0/target0:0:0/0:0:0:3/block/sdd
size = 2147483648
ro = 0
removable = 0
queue/rotational = 1
cd ../..
vendor = Msft
model = Virtual Disk
rev = 1.0
wwid = naa.60022480887de3713de6cbe6ac77fe14

/proc/self/ns/mnt -> mnt:[4026532214]
/proc/self/mountinfo <<EOF
82 67 8:48 / / rw,relatime - ext4 /dev/sdd rw,discard
113 82 0:24 / /sys rw - sysfs sysfs rw
EOF
/proc/swaps <<EOF
Filename				Type		Size		Used		Priority
/dev/sdc                                partition	1048576		0		-2
EOF
