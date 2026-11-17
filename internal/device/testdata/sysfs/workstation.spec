# Workstation: NVMe system disk (EFI + root + swap partitions), a spare SATA SSD,
# a SATA HDD mounted only inside another mount namespace (e.g. a container), a USB
# stick, an eMMC and an SD card, an attached loop image, an unused loop and a ram disk.

/sys/class/dmi/id/sys_vendor = Dell Inc.
/sys/class/dmi/id/product_name = Precision 3660

# ---- NVMe system disk ----
disk nvme0n1 259:0 /sys/devices/pci0000:00/0000:00:06.0/0000:01:00.0/nvme/nvme0/nvme0n1 ..
size = 1953525168
ro = 0
removable = 0
queue/rotational = 0
queue/logical_block_size = 512
queue/physical_block_size = 512
wwid = eui.002538b511a2c3d4
cd ..
model = Samsung SSD 980 PRO 1TB
serial = S5GXNF0R123456
firmware_rev = 5B2QGXA7
transport = pcie
part nvme0n1p1 1 259:1 2048 1048576
part nvme0n1p2 2 259:2 1050624 1919918080
part nvme0n1p3 3 259:3 1920968704 32556464

# ---- spare SATA SSD (no partitions) ----
disk sda 8:0 /sys/devices/pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0/block/sda
size = 976773168
ro = 0
removable = 0
queue/rotational = 0
queue/logical_block_size = 512
queue/physical_block_size = 4096
cd ../..
vendor = ATA
model = CT500MX500SSD1
rev = 046
wwid = naa.500a0751e1a2b3c4
vpd_pg80 =vpd80 2117E1A2B3C4

# ---- SATA HDD, partition mounted in another namespace ----
disk sdb 8:16 /sys/devices/pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0/block/sdb
size = 7814037168
ro = 0
removable = 0
queue/rotational = 1
queue/logical_block_size = 512
queue/physical_block_size = 4096
cd ../..
vendor = ATA
model = WDC WD40EFRX-68N
rev = 0A82
wwid = naa.50014ee2b1c2d3e4
vpd_pg80 =vpd80      WD-WCC7K1ABCDEF
part sdb1 1 8:17 2048 7814033408

# ---- USB stick: reports rotational=1 (typical for usb-storage), serial only via USB ----
disk sdc 8:32 /sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/host6/target6:0:0/6:0:0:0/block/sdc
size = 60063744
ro = 0
removable = 1
queue/rotational = 1
queue/logical_block_size = 512
queue/physical_block_size = 512
cd ../..
vendor = SanDisk
model = Cruzer Blade
rev = 1.00
cd /sys/devices/pci0000:00/0000:00:14.0/usb1/1-2
idVendor = 0781
idProduct = 5567
serial = 4C530001230616118063

# ---- eMMC and SD card ----
disk mmcblk0 179:0 /sys/devices/pci0000:00/0000:00:1a.0/mmc_host/mmc0/mmc0:0001/block/mmcblk0
size = 61071360
ro = 0
removable = 0
queue/rotational = 0
queue/logical_block_size = 512
queue/physical_block_size = 512
cd ../..
type = MMC
name = HBG4a2
serial = 0x1a2b3c4d
fwrev = 0x0300000000000000
cid = 90014a484247346132a1b2c3d4e5f600
disk mmcblk1 179:32 /sys/devices/pci0000:00/0000:00:1a.1/mmc_host/mmc1/mmc1:aaaa/block/mmcblk1
size = 124735488
ro = 0
removable = 0
queue/rotational = 0
queue/logical_block_size = 512
queue/physical_block_size = 512
cd ../..
type = SD
name = SD64G
serial = 0x00001234
cid = 035344534436344780000012340138ff

# ---- loop devices and a ram disk ----
disk loop0 7:0 /sys/devices/virtual/block/loop0 -
size = 409600
ro = 1
removable = 0
queue/rotational = 1
queue/logical_block_size = 512
queue/physical_block_size = 512
loop/backing_file = /var/lib/snapd/snaps/core_123.snap
disk loop1 7:1 /sys/devices/virtual/block/loop1 -
size = 0
ro = 0
removable = 0
queue/rotational = 1
disk ram0 1:0 /sys/devices/virtual/block/ram0 -
size = 8192
ro = 0
removable = 0
queue/rotational = 0

# ---- procfs: two mount namespaces (host + a container) ----
/proc/self/ns/mnt -> mnt:[4026531841]
/proc/self/mountinfo <<EOF
24 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
25 24 259:1 / /boot/efi rw,relatime shared:2 - vfat /dev/nvme0n1p1 rw
26 24 0:5 / /dev rw,nosuid shared:3 - devtmpfs devtmpfs rw
27 24 0:22 / /sys rw shared:4 - sysfs sysfs rw
28 24 7:0 / /snap/core/123 ro,nodev,relatime shared:5 - squashfs /dev/loop0 ro
EOF
/proc/1/ns/mnt -> mnt:[4026531841]
/proc/1/mountinfo <<EOF
24 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
EOF
/proc/4242/ns/mnt -> mnt:[4026532999]
/proc/4242/mountinfo <<EOF
300 299 0:80 / / rw - overlay overlay rw
301 300 8:17 /srv /data rw,relatime - ext4 /dev/sdb1 rw
EOF
/proc/swaps <<EOF
Filename				Type		Size		Used		Priority
/dev/nvme0n1p3                          partition	16278228	0		-2
EOF
