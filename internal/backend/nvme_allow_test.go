package backend

import (
	"errors"
	"testing"

	"shunya/internal/nvme"
)

func TestCheckNVMeAllowsBuiltCommands(t *testing.T) {
	f1, _ := nvme.FormatNVM(1, 4, nvme.SESUserData, false, 0, false, nvme.FormatTimeout)
	f2, _ := nvme.FormatNVM(1, 0, nvme.SESCryptoErs, true, 1, true, nvme.FormatTimeout)
	s1, _ := nvme.Sanitize(nvme.SanactBlockErase, 0, 0)
	s2, _ := nvme.Sanitize(nvme.SanactCryptoErase, 0, 0)
	s3, _ := nvme.Sanitize(nvme.SanactOverwrite, 3, 0x55aa55aa)
	for _, tc := range []struct {
		c   nvme.Command
		buf int
		mut bool
	}{
		{nvme.IdentifyController(), 4096, false}, {nvme.IdentifyNamespace(1), 4096, false}, {nvme.IdentifyActiveNamespaces(), 4096, false},
		{nvme.SanitizeStatusLog(), 512, false}, {f1, 0, true}, {f2, 0, true}, {s1, 0, true}, {s2, 0, true}, {s3, 0, true},
	} {
		var data []byte
		if tc.buf > 0 {
			data = make([]byte, tc.buf)
		}
		got, err := CheckNVMe(tc.c.Cmd, data)
		if err != nil || got.Mutating != tc.mut {
			t.Errorf("%s: %+v %v", tc.c.Name, got, err)
		}
	}
}

func TestCheckNVMeRefuses(t *testing.T) {
	buf := make([]byte, 4096)
	san, _ := nvme.Sanitize(nvme.SanactBlockErase, 0, 0)
	fmtc, _ := nvme.FormatNVM(1, 0, nvme.SESUserData, false, 0, false, nvme.FormatTimeout)
	mod := func(c nvme.AdminCmd, f func(*nvme.AdminCmd)) nvme.AdminCmd { f(&c); return c }
	for name, tc := range map[string]struct {
		c    nvme.AdminCmd
		data []byte
	}{
		"firmware download":       {nvme.AdminCmd{Opcode: 0x11, DataLen: 4096}, buf},
		"firmware commit":         {nvme.AdminCmd{Opcode: 0x10}, nil},
		"namespace management":    {nvme.AdminCmd{Opcode: 0x0d}, nil},
		"namespace attach":        {nvme.AdminCmd{Opcode: 0x15}, nil},
		"set features":            {nvme.AdminCmd{Opcode: 0x09}, nil},
		"security send":           {nvme.AdminCmd{Opcode: 0x81}, nil},
		"vendor":                  {nvme.AdminCmd{Opcode: 0xc0}, nil},
		"identify CNS 0x10":       {nvme.AdminCmd{Opcode: 0x06, CDW10: 0x10, DataLen: 4096}, buf},
		"identify short buffer":   {nvme.AdminCmd{Opcode: 0x06, CDW10: 1, DataLen: 4096}, buf[:100]},
		"identify with address":   {nvme.AdminCmd{Opcode: 0x06, CDW10: 1, DataLen: 4096, Addr: 0x1000}, buf},
		"other log page":          {nvme.AdminCmd{Opcode: 0x02, CDW10: 0x02 | 127<<16, DataLen: 512}, buf[:512]},
		"sanitize exit failure":   {mod(san.Cmd, func(c *nvme.AdminCmd) { c.CDW10 = 1 }), nil},
		"sanitize auto-restart":   {mod(san.Cmd, func(c *nvme.AdminCmd) { c.CDW10 |= 1 << 3 }), nil},
		"sanitize no-deallocate":  {mod(san.Cmd, func(c *nvme.AdminCmd) { c.CDW10 |= 1 << 9 }), nil},
		"sanitize with nsid":      {mod(san.Cmd, func(c *nvme.AdminCmd) { c.NSID = 1 }), nil},
		"format broadcast":        {mod(fmtc.Cmd, func(c *nvme.AdminCmd) { c.NSID = nvme.NSIDAll }), nil},
		"format no secure erase":  {mod(fmtc.Cmd, func(c *nvme.AdminCmd) { c.CDW10 &^= 7 << 9 }), nil},
		"format reserved bits":    {mod(fmtc.Cmd, func(c *nvme.AdminCmd) { c.CDW10 |= 1 << 20 }), nil},
		"format with data":        {mod(fmtc.Cmd, func(c *nvme.AdminCmd) { c.DataLen = 4096 }), buf},
		"block erase with passes": {mod(san.Cmd, func(c *nvme.AdminCmd) { c.CDW10 |= 2 << 4 }), nil},
	} {
		if _, err := CheckNVMe(tc.c, tc.data); !errors.Is(err, ErrNVMeRefused) {
			t.Errorf("%s: allowed (%v)", name, err)
		}
	}
}
