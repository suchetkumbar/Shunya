//go:build release

package backend

import "testing"

// Release builds drop the VM check but keep every other guard (brief §2.3.3).

func TestReleaseDropsVMCheck(t *testing.T) {
	withLabToken(t, "") // release binaries carry no token
	v, err := Check(Env{FS: spec(t, "workstation")}, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Allowed {
		t.Fatalf("free SATA SSD on a real machine refused in release build: %q", v.Reasons)
	}
	v, err = Check(Env{FS: spec(t, "workstation")}, "/dev/nvme0n1")
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed || !hasReason(v, "PROTECTED: root filesystem /") {
		t.Fatalf("root disk not refused in release build: %+v", v)
	}
}

func TestBuildKindRelease(t *testing.T) {
	if BuildKind != "release" || !RequiresConfirmation() {
		t.Fatalf("BuildKind %q, confirmation %v", BuildKind, RequiresConfirmation())
	}
}
