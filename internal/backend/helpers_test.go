package backend

import (
	"path/filepath"
	"testing"
	"testing/fstest"

	"shunya/internal/sysfs/sysfstest"
)

// testToken matches /etc/shunya-lab in internal/device/testdata/sysfs/lab-vm.spec.
const testToken = "5d1f0c7e2a9b4c6d8e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f"

// spec loads a fake sysfs scenario shared with the device package.
func spec(t *testing.T, name string) fstest.MapFS {
	t.Helper()
	m, err := sysfstest.Load(filepath.Join("..", "device", "testdata", "sysfs", name+".spec"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// withLabToken sets the compiled-in lab token for one test (dev builds read it; release
// builds ignore it).
func withLabToken(t *testing.T, tok string) {
	t.Helper()
	old := labToken
	labToken = tok
	t.Cleanup(func() { labToken = old })
}

// labEnv is the lab VM scenario with a matching token: lab lock satisfied.
func labEnv(t *testing.T) (Env, fstest.MapFS) {
	t.Helper()
	withLabToken(t, testToken)
	m := spec(t, "lab-vm")
	return Env{FS: m}, m
}
