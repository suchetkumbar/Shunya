package engine

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// fsDevice returns the "major:minor" of the file system holding path (stat's st_dev; no
// device is opened) and, if that is a loop device, its backing file from sysfs.
func fsDevice(path string) (dev, loopBacking string, err error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", "", err
	}
	dev = fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev))
	if b, err := os.ReadFile("/sys/dev/block/" + dev + "/loop/backing_file"); err == nil {
		loopBacking = strings.TrimSpace(string(b))
	}
	return dev, loopBacking, nil
}
