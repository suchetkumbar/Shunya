# Laptop with full-disk encryption: /boot on sda1, LUKS2 on sda2, LVM volume group
# vg0 inside the LUKS mapping with root and swap volumes. The root disk is reached
# only through dm-1 (LVM) -> dm-0 (dm-crypt) -> sda2 -> sda.

/sys/class/dmi/id/sys_vendor = LENOVO
/sys/class/dmi/id/product_name = 20XWCTO1WW

disk sda 8:0 /sys/devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda
size = 1000215216
ro = 0
removable = 0
queue/rotational = 0
queue/logical_block_size = 512
queue/physical_block_size = 4096
cd ../..
vendor = ATA
model = Samsung SSD 870
rev = 2B6Q
wwid = naa.5002538f41234567
vpd_pg80 =vpd80 S6PNNX0T123456A
part sda1 1 8:1 2048 2097152
part sda2 2 8:2 2099200 998115983
holders/dm-0 -> ../../../../../../../../../../virtual/block/dm-0

disk dm-0 253:0 /sys/devices/virtual/block/dm-0 -
size = 998083215
ro = 0
removable = 0
queue/rotational = 0
dm/name = luks-3f2a9c1e
dm/uuid = CRYPT-LUKS2-3f2a9c1e0b7d4e5f8a9b0c1d2e3f4a5b-luks-3f2a9c1e
slaves/sda2 -> ../../../../pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda/sda2
holders/dm-1 -> ../../dm-1
holders/dm-2 -> ../../dm-2

disk dm-1 253:1 /sys/devices/virtual/block/dm-1 -
size = 981305344
ro = 0
removable = 0
queue/rotational = 0
dm/name = vg0-root
dm/uuid = LVM-Xk2Jq0aL8mN3pR5sT7uV9wY1zA3bC5dEfG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z
slaves/dm-0 -> ../../dm-0

disk dm-2 253:2 /sys/devices/virtual/block/dm-2 -
size = 16777216
ro = 0
removable = 0
queue/rotational = 0
dm/name = vg0-swap
dm/uuid = LVM-Xk2Jq0aL8mN3pR5sT7uV9wY1zA3bC5dEaB1cD3eF5gH7iJ9kL1mN3oP5qR7sT9u
slaves/dm-0 -> ../../dm-0

/proc/self/ns/mnt -> mnt:[4026531841]
/proc/self/mountinfo <<EOF
21 1 253:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vg0-root rw
22 21 8:1 / /boot rw,relatime shared:2 - ext4 /dev/sda1 rw
23 21 0:5 / /dev rw - devtmpfs devtmpfs rw
EOF
/proc/swaps <<EOF
Filename				Type		Size		Used		Priority
/dev/mapper/vg0-swap                    partition	8388604		0		-2
EOF
