# Server: root on a SAS SSD, MD RAID1 across two SATA HDDs mounted at /srv, and a
# two-device btrfs filesystem whose mountinfo entry has an anonymous device number
# (0:45) and names only one of its members. No swap.

/sys/class/dmi/id/sys_vendor = Supermicro
/sys/class/dmi/id/product_name = SYS-1029P-WTR

# ---- SAS SSD with root ----
disk sdc 8:32 /sys/devices/pci0000:00/0000:00:01.0/0000:02:00.0/host0/port-0:0/end_device-0:0/target0:0:0/0:0:0:0/block/sdc
size = 3750748848
ro = 0
removable = 0
queue/rotational = 0
queue/logical_block_size = 512
queue/physical_block_size = 4096
cd ../..
vendor = SEAGATE
model = XS1920SE70004
rev = 0004
wwid = naa.5000c500a1b2c3d4
sas_address = 0x5000c500a1b2c3d5
vpd_pg80 =vpd80 HLJ0A1B20000C123D4E5
part sdc1 1 8:33 2048 3750744064

# ---- MD RAID1 members ----
disk sda 8:0 /sys/devices/pci0000:00/0000:00:17.0/ata1/host1/target1:0:0/1:0:0:0/block/sda
size = 3907029168
ro = 0
removable = 0
queue/rotational = 1
queue/logical_block_size = 512
queue/physical_block_size = 4096
cd ../..
vendor = ATA
model = ST2000NM0055-1V4
rev = SN05
wwid = naa.5000c500b0000001
vpd_pg80 =vpd80 ZC100001
part sda1 1 8:1 2048 3907025072
holders/md0 -> ../../../../../../../../../virtual/block/md0

disk sdb 8:16 /sys/devices/pci0000:00/0000:00:17.0/ata2/host2/target2:0:0/2:0:0:0/block/sdb
size = 3907029168
ro = 0
removable = 0
queue/rotational = 1
queue/logical_block_size = 512
queue/physical_block_size = 4096
cd ../..
vendor = ATA
model = ST2000NM0055-1V4
rev = SN05
wwid = naa.5000c500b0000002
vpd_pg80 =vpd80 ZC100002
part sdb1 1 8:17 2048 3907025072
holders/md0 -> ../../../../../../../../../virtual/block/md0

disk md0 9:0 /sys/devices/virtual/block/md0 -
size = 3906764800
ro = 0
removable = 0
queue/rotational = 1
md/level = raid1
slaves/sda1 -> ../../x
slaves/sdb1 -> ../../x

# ---- btrfs across two disks ----
disk sdd 8:48 /sys/devices/pci0000:00/0000:00:17.0/ata3/host3/target3:0:0/3:0:0:0/block/sdd
size = 1953525168
ro = 0
removable = 0
queue/rotational = 1
cd ../..
vendor = ATA
model = TOSHIBA HDWD110
rev = A8M0
vpd_pg80 =vpd80 X0000001
disk sde 8:64 /sys/devices/pci0000:00/0000:00:17.0/ata4/host4/target4:0:0/4:0:0:0/block/sde
size = 1953525168
ro = 0
removable = 0
queue/rotational = 1
cd ../..
vendor = ATA
model = TOSHIBA HDWD110
rev = A8M0
vpd_pg80 =vpd80 X0000002
/sys/fs/btrfs/7a1c0d6e-1111-2222-3333-444455556666/devices/sdd -> ../../../../devices/x/sdd
/sys/fs/btrfs/7a1c0d6e-1111-2222-3333-444455556666/devices/sde -> ../../../../devices/x/sde

/proc/self/ns/mnt -> mnt:[4026531841]
/proc/self/mountinfo <<EOF
21 1 8:33 / / rw,relatime shared:1 - xfs /dev/sdc1 rw
22 21 9:0 / /srv rw,relatime shared:2 - ext4 /dev/md0 rw
23 21 0:45 / /backup rw,relatime shared:3 - btrfs /dev/sdd rw,space_cache=v2
EOF
/proc/swaps <<EOF
Filename				Type		Size		Used		Priority
EOF
