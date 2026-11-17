package backend

import (
	"os"

	"golang.org/x/sys/unix"

	"shunya/internal/device"
	"shunya/internal/sysfs"
)

// LiveEnv is the running system: "/" via os.DirFS, plus protection for the filesystem
// holding this executable (st_dev of /proc/self/exe; stat reads the inode, not a device).
func LiveEnv() (Env, error) {
	env := Env{FS: os.DirFS("/")}
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/exe", &st); err != nil {
		return env, err
	}
	env.Protect = append(env.Protect, device.Protect{
		Dev: sysfs.DevNum{Major: unix.Major(st.Dev), Minor: unix.Minor(st.Dev)},
		Why: "holds the running shunya binary",
	})
	return env, nil
}
