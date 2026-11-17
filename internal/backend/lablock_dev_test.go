//go:build !release

package backend

import "testing"

// Dev builds refuse block devices unless the machine is the lab VM (brief §2.3.2).

func TestLabLockRefusesOutsideVM(t *testing.T) {
	withLabToken(t, testToken)
	// A real workstation with an otherwise free SATA SSD: refused only by the lab lock.
	v, err := Check(Env{FS: spec(t, "workstation")}, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed || !hasReason(v, "lab lock: not a QEMU/KVM machine (DMI vendor \"Dell Inc.\"") {
		t.Fatalf("verdict %+v", v)
	}
	if !hasReason(v, "lab lock: /etc/shunya-lab missing") {
		t.Fatalf("reasons %q", v.Reasons)
	}
}

func TestLabLockConditions(t *testing.T) {
	tests := []struct {
		name   string
		token  string // compiled-in
		mutate func(m map[string]string)
		reason string // "" = allowed
	}{
		{"all conditions hold", testToken, nil, ""},
		{"no compiled token", "", nil, "this build carries no lab token"},
		{"token mismatch", "aa" + testToken[2:], nil, "token in /etc/shunya-lab does not match"},
		{"marker missing", testToken, func(m map[string]string) { m["etc/shunya-lab"] = "" }, "/etc/shunya-lab missing"},
		{"marker malformed", testToken, func(m map[string]string) { m["etc/shunya-lab"] = "hello world\n" }, "malformed"},
		{"vendor not QEMU", testToken, func(m map[string]string) {
			m["sys/class/dmi/id/sys_vendor"] = "LENOVO\n"
			m["sys/class/dmi/id/product_name"] = "ThinkPad\n"
		}, "not a QEMU/KVM machine"},
		{"KVM product name accepted", testToken, func(m map[string]string) {
			m["sys/class/dmi/id/sys_vendor"] = "Red Hat\n"
			m["sys/class/dmi/id/product_name"] = "KVM\n"
		}, ""},
		{"DMI unreadable", testToken, func(m map[string]string) {
			m["sys/class/dmi/id/sys_vendor"] = ""
			m["sys/class/dmi/id/product_name"] = ""
		}, "not a QEMU/KVM machine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, m := labEnv(t)
			withLabToken(t, tt.token)
			if tt.mutate != nil {
				edits := map[string]string{}
				tt.mutate(edits)
				for k, v := range edits {
					if v == "" {
						delete(m, k)
					} else {
						m[k].Data = []byte(v)
					}
				}
			}
			v, err := Check(env, "/dev/sdb")
			if err != nil {
				t.Fatal(err)
			}
			if tt.reason == "" {
				if !v.Allowed {
					t.Fatalf("refused: %q", v.Reasons)
				}
				return
			}
			if v.Allowed || !hasReason(v, tt.reason) {
				t.Fatalf("reasons %q, want %q", v.Reasons, tt.reason)
			}
		})
	}
}

func TestBuildKindDev(t *testing.T) {
	if BuildKind != "dev" || RequiresConfirmation() {
		t.Fatalf("BuildKind %q, confirmation %v", BuildKind, RequiresConfirmation())
	}
}
