package backend_test

import (
	"testing"
	"time"

	"shunya/internal/ata"
	"shunya/internal/backend"
)

// Every command internal/ata can build is on the allowlist, with the right class.
func TestCheckATAAllowsEveryATACommand(t *testing.T) {
	type cmd struct {
		c        ata.Command
		data     []byte
		mutating bool
	}
	must := func(c ata.Command, err error) ata.Command {
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	withData := func(c ata.Command, d []byte, err error) cmd {
		if err != nil {
			t.Fatal(err)
		}
		return cmd{c, d, true}
	}
	cmds := []cmd{
		{ata.IdentifyCmd(), make([]byte, 512), false},
		{ata.DCOIdentify(), make([]byte, 512), false},
		{ata.ReadNativeMaxExt(), nil, false},
		{ata.FlushCacheExt(), nil, false},
		{must(ata.ReadDMAExt(1<<40, 256)), make([]byte, 256*512), false},
		{must(ata.WriteDMAExt(5, 1)), make([]byte, 512), true},
		{must(ata.SetMaxAddressExtVolatile(12345)), nil, true},
		{ata.SecurityErasePrepare(), nil, true},
		withData(ata.SecuritySetUserPassword("pw")),
		withData(ata.SecurityUnlockUser("pw")),
		withData(ata.SecurityEraseUnit("pw", true, time.Hour)),
		withData(ata.SecurityDisableUserPassword("pw")),
	}
	for _, c := range cmds {
		got, err := backend.CheckATA(c.c.CDB(), c.data)
		if err != nil {
			t.Errorf("%s: %v", c.c.Name, err)
			continue
		}
		if got.Mutating != c.mutating {
			t.Errorf("%s: mutating %v, want %v", c.c.Name, got.Mutating, c.mutating)
		}
	}
}

func TestCheckATAAllowsSanitizeCommands(t *testing.T) {
	ow, _ := ata.SanitizeOverwrite(1, 0)
	for _, c := range []ata.Command{ata.SanitizeStatus(), ata.SanitizeCryptoScramble(), ata.SanitizeBlockErase(), ow} {
		got, err := backend.CheckATA(c.CDB(), nil)
		if err != nil || got.Mutating != (c.TF.Feature != 0) {
			t.Errorf("%s: %+v %v", c.Name, got, err)
		}
	}
}
