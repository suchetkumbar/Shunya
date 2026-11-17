# The Shunya lab VM (QEMU q35, Alpine): virtio boot disk vda (/boot + /), and one target
# per bus: virtio vdb, AHCI HDD sda, AHCI SSD sdb, NVMe nvme0n1, USB sdc, plus the
# cloud-init seed CD (sr0). Mirrors lab/lab.sh; serials match lab/lab.env.

/sys/class/dmi/id/sys_vendor = QEMU
/sys/class/dmi/id/product_name = Standard PC (Q35 + ICH9, 2009)
/etc/shunya-lab = 5d1f0c7e2a9b4c6d8e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f

disk vda 253:0 /sys/devices/pci0000:00/0000:00:02.0/virtio1/block/vda
size = 4194304
ro = 0
removable = 0
queue/rotational = 1
queue/logical_block_size = 512
queue/physical_block_size = 512
serial = SHUNYA-BOOT-0
part vda1 1 253:1 2048 235520
part vda2 2 253:2 237568 2048
part vda3 3 253:3 239616 3952640

disk vdb 253:16 /sys/devices/pci0000:00/0000:00:03.0/virtio2/block/vdb
size = 2097152
ro = 0
removable = 0
queue/rotational = 1
queue/logical_block_size = 512
queue/physical_block_size = 512
serial = SHUNYA-VIRTIO-01

disk sda 8:0 /sys/devices/pci0000:00/0000:00:04.0/ata1/host0/target0:0:0/0:0:0:0/block/sda
size = 2097152
ro = 0
removable = 0
queue/rotational = 1
queue/logical_block_size = 512
queue/physical_block_size = 512
cd ../..
vendor = ATA
model = SHUNYA LAB SATA
rev = 2.5+
wwid = t10.ATA     SHUNYA LAB SATA                         SHUNYA-SATA-HDD-01
vpd_pg80 =vpd80 SHUNYA-SATA-HDD-01

disk sdb 8:16 /sys/devices/pci0000:00/0000:00:04.0/ata2/host1/target1:0:0/1:0:0:0/block/sdb
size = 2097152
ro = 0
removable = 0
queue/rotational = 0
queue/logical_block_size = 512
queue/physical_block_size = 512
cd ../..
vendor = ATA
model = SHUNYA LAB SATA
rev = 2.5+
wwid = t10.ATA     SHUNYA LAB SATA                         SHUNYA-SATA-SSD-01
vpd_pg80 =vpd80 SHUNYA-SATA-SSD-01

disk nvme0n1 259:0 /sys/devices/pci0000:00/0000:00:05.0/nvme/nvme0/nvme0n1 ..
size = 2097152
ro = 0
removable = 0
queue/rotational = 0
queue/logical_block_size = 512
queue/physical_block_size = 512
wwid = eui.5348554e59410001
cd ..
model = QEMU NVMe Ctrl
serial = SHUNYA-NVME-01
firmware_rev = 10.0.13
transport = pcie

disk sdc 8:32 /sys/devices/pci0000:00/0000:00:06.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0/block/sdc
size = 1048576
ro = 0
removable = 1
queue/rotational = 1
queue/logical_block_size = 512
queue/physical_block_size = 512
cd ../..
vendor = QEMU
model = QEMU HARDDISK
rev = 2.5+
cd /sys/devices/pci0000:00/0000:00:06.0/usb2/2-1
idVendor = 46f4
idProduct = 0001
serial = SHUNYA-USB-01

disk sr0 11:0 /sys/devices/pci0000:00/0000:00:1f.2/ata6/host5/target5:0:0/5:0:0:0/block/sr0
size = 740
ro = 0
removable = 1
queue/rotational = 1
cd ../..
vendor = QEMU
model = QEMU DVD-ROM
type = 5
rev = 2.5+

/proc/self/ns/mnt -> mnt:[4026531840]
/proc/self/mountinfo <<EOF
20 1 253:3 / / rw,relatime - ext4 /dev/vda3 rw
21 20 253:1 / /boot rw,relatime - ext4 /dev/vda1 rw
22 20 0:5 / /dev rw - devtmpfs devtmpfs rw
EOF
/proc/swaps <<EOF
Filename				Type		Size		Used		Priority
EOF
