// Package device discovers block devices, classifies their media, works out which ones
// the running system depends on, and fingerprints them.
//
// Discovery is read-only and uses only sysfs and procfs through an fs.FS: no device node
// is opened, no ioctl is issued, no command is run. That keeps it safe on the
// development host and makes every scenario testable with a fake tree (see testdata/).
package device

// Transport is the bus or kernel layer a block device sits on.
type Transport string

const (
	TransportNVMe    Transport = "nvme"
	TransportSATA    Transport = "sata" // libata (AHCI, legacy IDE)
	TransportSAS     Transport = "sas"
	TransportSCSI    Transport = "scsi" // other SCSI (incl. iSCSI, FC) not identified further
	TransportUSB     Transport = "usb"
	TransportVirtio  Transport = "virtio"
	TransportMMC     Transport = "mmc"
	TransportHyperV  Transport = "hyperv" // Hyper-V storvsc (Azure, WSL2)
	TransportLoop    Transport = "loop"
	TransportDM      Transport = "dm"
	TransportMD      Transport = "md"
	TransportRAM     Transport = "ram" // ram, zram, brd
	TransportUnknown Transport = "unknown"
)

// MediaType is what the planner (Milestone 3) chooses sanitisation methods from.
type MediaType string

const (
	MediaHDD      MediaType = "hdd"
	MediaSSD      MediaType = "ssd" // SATA/SAS solid state
	MediaNVMeSSD  MediaType = "nvme-ssd"
	MediaUSBFlash MediaType = "usb-flash"
	MediaUSBDisk  MediaType = "usb-disk" // HDD or SSD behind a USB bridge
	MediaEMMC     MediaType = "emmc"
	MediaSDCard   MediaType = "sd-card"
	MediaOptical  MediaType = "optical"
	MediaVirtual  MediaType = "virtual" // paravirtual disk; the physical medium is unknowable
	MediaLogical  MediaType = "logical" // loop, dm, md, ram: not a physical medium
	MediaUnknown  MediaType = "unknown"
)

// Confidence states how much the media classification can be trusted.
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Status summarises whether the device may be selected as a wipe target.
type Status string

const (
	// StatusProtected: the running system depends on it (root, boot). Never wipeable.
	StatusProtected Status = "PROTECTED"
	// StatusInUse: mounted, swap, or held by dm/md/btrfs. Refused until released.
	StatusInUse Status = "IN-USE"
	// StatusIgnored: not a storage medium Shunya wipes (optical, ram).
	StatusIgnored Status = "IGNORED"
	// StatusAvailable: no use found. Milestone 2's guards re-check before any write.
	StatusAvailable Status = "AVAILABLE"
)

// Report is the result of one enumeration.
type Report struct {
	System   System   `json:"system"`
	Devices  []Device `json:"devices"`
	Warnings []string `json:"warnings,omitempty"`
}

// System describes the machine enumeration ran on.
type System struct {
	DMIVendor  string `json:"dmi_vendor"`
	DMIProduct string `json:"dmi_product"`
	// LabMarker reports that /etc/shunya-lab exists. The token inside is checked by the
	// lab lock (Milestone 2), not here.
	LabMarker       bool `json:"lab_marker"`
	MountNamespaces int  `json:"mount_namespaces"`
}

// Device is one whole block device from /sys/block.
type Device struct {
	Name               string    `json:"name"`
	Path               string    `json:"path"`
	SysPath            string    `json:"sys_path"`
	DevNum             string    `json:"dev"`
	SizeBytes          uint64    `json:"size_bytes"`
	LogicalSectorSize  uint32    `json:"logical_sector_size"`
	PhysicalSectorSize uint32    `json:"physical_sector_size"`
	Rotational         bool      `json:"rotational"`
	Removable          bool      `json:"removable"`
	ReadOnly           bool      `json:"read_only"`
	Transport          Transport `json:"transport"`
	Vendor             string    `json:"vendor,omitempty"`
	Model              string    `json:"model,omitempty"`
	Serial             string    `json:"serial,omitempty"`
	SerialSource       string    `json:"serial_source,omitempty"`
	Firmware           string    `json:"firmware,omitempty"`
	// WWID is the kernel's world-wide identifier: "naa.…" (WWN), "eui.…" (EUI-64),
	// "nvme.…", "t10.…", or for MMC "cid.…" (card identification register).
	WWID            string      `json:"wwid,omitempty"`
	LoopBackingFile string      `json:"loop_backing_file,omitempty"`
	Partitions      []Partition `json:"partitions,omitempty"`
	Holders         []Holder    `json:"holders,omitempty"`
	Mounts          []MountRef  `json:"mounts,omitempty"`
	Swaps           []string    `json:"swaps,omitempty"`
	Media           Media       `json:"media"`
	Fingerprint     Fingerprint `json:"fingerprint"`
	Status          Status      `json:"status"`
	Reasons         []string    `json:"reasons,omitempty"`

	typeHint string // device/type: SCSI peripheral type ("0" disk, "5" CD/DVD) or MMC card type
}

// Partition of a whole device.
type Partition struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Number      uint64   `json:"number"`
	StartSector uint64   `json:"start_sector"` // in 512-byte units, as sysfs reports
	SizeBytes   uint64   `json:"size_bytes"`
	Holders     []Holder `json:"holders,omitempty"`
}

// HolderKind is the kind of virtual device stacked on top of a disk or partition.
type HolderKind string

const (
	HolderCrypt     HolderKind = "dm-crypt"
	HolderLVM       HolderKind = "lvm"
	HolderMultipath HolderKind = "multipath"
	HolderDM        HolderKind = "dm"
	HolderMD        HolderKind = "md"
	HolderOther     HolderKind = "other"
)

// Holder is a device that holds (is stacked on) a disk or partition, with its own holders.
type Holder struct {
	Name    string     `json:"name"`
	Kind    HolderKind `json:"kind"`
	DMName  string     `json:"dm_name,omitempty"`
	Level   string     `json:"level,omitempty"` // md RAID level
	Holders []Holder   `json:"holders,omitempty"`
}

// MountRef is a mount that lives on this device, directly or through partitions/holders.
type MountRef struct {
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fs_type"`
	Source     string `json:"source"`
	// Via is the chain from the mounted device down to (excluding) this device.
	Via       []string `json:"via,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
}

// Media is the classification result.
type Media struct {
	Type       MediaType  `json:"type"`
	Confidence Confidence `json:"confidence"`
	// Virtual is set when the device is emulated or paravirtual (QEMU, Hyper-V, …), so
	// hardware commands may behave unlike real drives (see design/LAB_CAPABILITIES.md).
	Virtual bool     `json:"virtual"`
	Reasons []string `json:"reasons"`
}
