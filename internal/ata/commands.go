package ata

import (
	"errors"
	"fmt"
	"time"
)

// ATA command codes Shunya uses (ACS-4). backend.Block's allowlist mirrors this list.
const (
	CmdReadDMAExt          = 0x25
	CmdReadNativeMaxExt    = 0x27
	CmdWriteDMAExt         = 0x35
	CmdSetMaxAddressExt    = 0x37
	CmdDeviceConfiguration = 0xb1 // with feature FeatureDCOIdentify only
	CmdFlushCacheExt       = 0xea
	CmdIdentifyDevice      = 0xec
	CmdSecuritySetPassword = 0xf1
	CmdSecurityUnlock      = 0xf2
	CmdSecurityErasePrep   = 0xf3
	CmdSecurityEraseUnit   = 0xf4
	CmdSecurityDisablePass = 0xf6

	FeatureDCOIdentify = 0xc2
)

// deviceLBA is the DEVICE register value for LBA addressing (bit 6).
const deviceLBA = 0x40

// MaxLBA48 is the largest 48-bit LBA.
const MaxLBA48 = 1<<48 - 1

// MaxTransferSectors bounds one read or write command. 256 × 512 B = 128 KiB stays
// below every Linux max_sectors_kb default, so SG_IO never has to split a command.
const MaxTransferSectors = 256

const defaultTimeout = 30 * time.Second

// IdentifyCmd is IDENTIFY DEVICE (ECh, PIO data-in, one block).
func IdentifyCmd() Command {
	return Command{Name: "IDENTIFY DEVICE", TF: Taskfile{Count: 1, Command: CmdIdentifyDevice},
		Proto: ProtoPIOIn, Dir: DirIn, Sectors: 1, Timeout: defaultTimeout}
}

// ReadNativeMaxExt is READ NATIVE MAX ADDRESS EXT (27h): the highest LBA the drive has,
// ignoring an HPA (but not a DCO). It returns that LBA in the registers.
func ReadNativeMaxExt() Command {
	return Command{Name: "READ NATIVE MAX ADDRESS EXT", TF: Taskfile{Device: deviceLBA, Command: CmdReadNativeMaxExt},
		Proto: ProtoNonData, Dir: DirNone, Ext: true, Timeout: defaultTimeout}
}

// SetMaxAddressExtVolatile is SET MAX ADDRESS EXT (37h) with the Value Volatile bit
// (COUNT bit 0) cleared: the new maximum lasts until the next power-on or hardware
// reset, after which the drive's previous (non-volatile) setting returns. It must be
// issued immediately after READ NATIVE MAX ADDRESS EXT. There is deliberately no
// non-volatile variant.
func SetMaxAddressExtVolatile(maxLBA uint64) (Command, error) {
	if maxLBA > MaxLBA48 {
		return Command{}, fmt.Errorf("SET MAX: LBA %d beyond 48 bits", maxLBA)
	}
	return Command{Name: "SET MAX ADDRESS EXT (volatile)", TF: Taskfile{LBA: maxLBA, Device: deviceLBA, Command: CmdSetMaxAddressExt},
		Proto: ProtoNonData, Dir: DirNone, Ext: true, Timeout: defaultTimeout}, nil
}

// DCOIdentify is DEVICE CONFIGURATION IDENTIFY (B1h/C2h, PIO data-in, one block). The
// other DCO subcommands (SET, RESTORE, FREEZE LOCK) change the drive permanently and
// cannot be built.
func DCOIdentify() Command {
	return Command{Name: "DEVICE CONFIGURATION IDENTIFY", TF: Taskfile{Feature: FeatureDCOIdentify, Count: 1, Command: CmdDeviceConfiguration},
		Proto: ProtoPIOIn, Dir: DirIn, Sectors: 1, Timeout: defaultTimeout}
}

// FlushCacheExt is FLUSH CACHE EXT (EAh).
func FlushCacheExt() Command {
	return Command{Name: "FLUSH CACHE EXT", TF: Taskfile{Device: deviceLBA, Command: CmdFlushCacheExt},
		Proto: ProtoNonData, Dir: DirNone, Ext: true, Timeout: 2 * time.Minute}
}

// ErrTransfer: a read/write request outside what one command may carry.
var ErrTransfer = errors.New("bad ATA transfer")

func rwCheck(lba uint64, sectors int) error {
	if sectors <= 0 || sectors > MaxTransferSectors || lba > MaxLBA48 || lba+uint64(sectors)-1 > MaxLBA48 {
		return fmt.Errorf("%w: LBA %d, %d sectors", ErrTransfer, lba, sectors)
	}
	return nil
}

// ReadDMAExt is READ DMA EXT (25h) of sectors 512-byte blocks at lba.
func ReadDMAExt(lba uint64, sectors int) (Command, error) {
	if err := rwCheck(lba, sectors); err != nil {
		return Command{}, err
	}
	return Command{Name: "READ DMA EXT", TF: Taskfile{Count: uint16(sectors), LBA: lba, Device: deviceLBA, Command: CmdReadDMAExt},
		Proto: ProtoDMA, Dir: DirIn, Ext: true, Sectors: sectors, Timeout: defaultTimeout}, nil
}

// WriteDMAExt is WRITE DMA EXT (35h) of sectors 512-byte blocks at lba.
func WriteDMAExt(lba uint64, sectors int) (Command, error) {
	if err := rwCheck(lba, sectors); err != nil {
		return Command{}, err
	}
	return Command{Name: "WRITE DMA EXT", TF: Taskfile{Count: uint16(sectors), LBA: lba, Device: deviceLBA, Command: CmdWriteDMAExt},
		Proto: ProtoDMA, Dir: DirOut, Ext: true, Sectors: sectors, Timeout: defaultTimeout}, nil
}

// Security feature set commands (ACS-3 §7.41–7.47). SET PASSWORD, UNLOCK, ERASE UNIT
// and DISABLE PASSWORD carry one 512-byte block: word 0 holds the control bits, words
// 1–16 the 32-byte password (bytes in order, not swapped).

// PasswordBytes is the ATA password length; shorter passwords are zero-padded.
const PasswordBytes = 32

func securityCmd(name string, code uint8, timeout time.Duration) Command {
	return Command{Name: name, TF: Taskfile{Count: 1, Command: code}, Proto: ProtoPIOOut, Dir: DirOut, Sectors: 1, Timeout: timeout}
}

// passwordBlock builds the data block: word 0 = control, words 1–16 = password.
func passwordBlock(control uint16, pw string) ([]byte, error) {
	if len(pw) == 0 || len(pw) > PasswordBytes {
		return nil, fmt.Errorf("ATA password must be 1 to %d bytes", PasswordBytes)
	}
	b := make([]byte, SectorBytes)
	b[0], b[1] = byte(control), byte(control>>8)
	copy(b[2:2+PasswordBytes], pw)
	return b, nil
}

// SecuritySetUserPassword sets the user password at security level High (word 0: bit 0
// = 0 user, bit 8 = 0 High). With level High the master password can still unlock the
// drive; Shunya never sets the master password or level Maximum.
func SecuritySetUserPassword(pw string) (Command, []byte, error) {
	b, err := passwordBlock(0, pw)
	return securityCmd("SECURITY SET PASSWORD (user, high)", CmdSecuritySetPassword, defaultTimeout), b, err
}

// SecurityUnlockUser unlocks a locked drive with the user password.
func SecurityUnlockUser(pw string) (Command, []byte, error) {
	b, err := passwordBlock(0, pw)
	return securityCmd("SECURITY UNLOCK (user)", CmdSecurityUnlock, defaultTimeout), b, err
}

// SecurityErasePrepare is SECURITY ERASE PREPARE (F3h); ERASE UNIT must follow it
// immediately.
func SecurityErasePrepare() Command {
	return Command{Name: "SECURITY ERASE PREPARE", TF: Taskfile{Command: CmdSecurityErasePrep}, Proto: ProtoNonData, Dir: DirNone, Timeout: defaultTimeout}
}

// SecurityEraseUnit is SECURITY ERASE UNIT (F4h) with the user password; word 0 bit 1
// selects the enhanced mode. timeout must cover the drive's whole erase.
func SecurityEraseUnit(pw string, enhanced bool, timeout time.Duration) (Command, []byte, error) {
	ctl := uint16(0)
	name := "SECURITY ERASE UNIT (normal)"
	if enhanced {
		ctl |= 1 << 1
		name = "SECURITY ERASE UNIT (enhanced)"
	}
	b, err := passwordBlock(ctl, pw)
	return securityCmd(name, CmdSecurityEraseUnit, timeout), b, err
}

// SecurityDisableUserPassword removes the user password (Security disabled again).
func SecurityDisableUserPassword(pw string) (Command, []byte, error) {
	b, err := passwordBlock(0, pw)
	return securityCmd("SECURITY DISABLE PASSWORD (user)", CmdSecurityDisablePass, defaultTimeout), b, err
}

// SANITIZE DEVICE (B4h, ACS-3 §7.36), 48-bit non-data. The subcommand is the FEATURE
// field; each erase carries a fixed key in the LBA field so a stray command can't start
// one. Never built: SANITIZE FREEZE LOCK EXT (0020h, lasts until power-off) and
// SANITIZE ANTIFREEZE LOCK EXT (0040h).
const (
	CmdSanitizeDevice = 0xb4

	SanitizeStatusExt    = 0x0000
	SanitizeCryptoExt    = 0x0011
	SanitizeBlockEraseEx = 0x0012
	SanitizeOverwriteExt = 0x0014

	keyCrypto    = 0x43727970 // "Cryp"
	keyBlock     = 0x426b4572 // "BkEr"
	keyOverwrite = 0x00004f57 // "OW" in LBA 47:32
)

// SanitizeStatus is SANITIZE STATUS EXT: the registers report progress and state.
func SanitizeStatus() Command {
	return Command{Name: "SANITIZE STATUS EXT", TF: Taskfile{Feature: SanitizeStatusExt, Device: deviceLBA, Command: CmdSanitizeDevice},
		Proto: ProtoNonData, Dir: DirNone, Ext: true, Timeout: defaultTimeout}
}

// SanitizeCryptoScramble is CRYPTO SCRAMBLE EXT (failure mode bit clear).
func SanitizeCryptoScramble() Command {
	return Command{Name: "SANITIZE CRYPTO SCRAMBLE EXT", TF: Taskfile{Feature: SanitizeCryptoExt, LBA: keyCrypto, Device: deviceLBA, Command: CmdSanitizeDevice},
		Proto: ProtoNonData, Dir: DirNone, Ext: true, Timeout: defaultTimeout}
}

// SanitizeBlockErase is BLOCK ERASE EXT.
func SanitizeBlockErase() Command {
	return Command{Name: "SANITIZE BLOCK ERASE EXT", TF: Taskfile{Feature: SanitizeBlockEraseEx, LBA: keyBlock, Device: deviceLBA, Command: CmdSanitizeDevice},
		Proto: ProtoNonData, Dir: DirNone, Ext: true, Timeout: defaultTimeout}
}

// SanitizeOverwrite is OVERWRITE EXT with passes (1–16) of the 32-bit pattern, no
// inversion between passes.
func SanitizeOverwrite(passes int, pattern uint32) (Command, error) {
	if passes < 1 || passes > 16 {
		return Command{}, fmt.Errorf("ATA sanitize overwrite: %d passes (1–16)", passes)
	}
	return Command{Name: "SANITIZE OVERWRITE EXT", TF: Taskfile{Feature: SanitizeOverwriteExt, Count: uint16(passes & 0xf),
		LBA: keyOverwrite<<32 | uint64(pattern), Device: deviceLBA, Command: CmdSanitizeDevice},
		Proto: ProtoNonData, Dir: DirNone, Ext: true, Timeout: defaultTimeout}, nil
}
