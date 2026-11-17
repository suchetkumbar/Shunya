package backend

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"shunya/internal/sysfs"
)

// labToken is compiled into lab builds only:
//
//	go build -ldflags "-X shunya/internal/backend.labToken=$(cat lab/secrets/lab-token)"
//
// Ordinary dev builds leave it empty, and an empty token never matches, so a dev binary
// built by accident or copied elsewhere refuses every block device. Release builds
// ignore it.
var labToken string

// HasLabToken reports whether this binary carries a lab token.
func HasLabToken() bool { return labToken != "" }

// ParseLabToken parses /etc/shunya-lab: one line of 32–128 lowercase hex characters.
func ParseLabToken(b []byte) (string, error) {
	s := strings.TrimRight(string(b), "\r\n")
	if len(s) < 32 || len(s) > 128 {
		return "", errors.New("lab token: want 32-128 hex characters")
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", errors.New("lab token: not lowercase hex")
		}
	}
	return s, nil
}

// devLabLock implements the dev-build lab lock (brief §2.3.2). It returns refusal reasons.
func devLabLock(r *sysfs.Reader) []string {
	var out []string
	vendor := r.String("sys/class/dmi/id/sys_vendor")
	product := r.String("sys/class/dmi/id/product_name")
	id := strings.ToUpper(vendor + " " + product)
	if !strings.Contains(id, "QEMU") && !strings.Contains(id, "KVM") {
		out = append(out, fmt.Sprintf("lab lock: not a QEMU/KVM machine (DMI vendor %q, product %q); "+
			"dev builds touch block devices only inside the lab VM", vendor, product))
	}
	b, err := r.Bytes("etc/shunya-lab")
	switch {
	case err != nil:
		out = append(out, "lab lock: /etc/shunya-lab missing")
	case labToken == "":
		out = append(out, "lab lock: this build carries no lab token (only `make lab-test` builds do)")
	default:
		tok, err := ParseLabToken(b)
		if err != nil {
			out = append(out, "lab lock: /etc/shunya-lab malformed: "+err.Error())
		} else if subtle.ConstantTimeCompare([]byte(tok), []byte(labToken)) != 1 {
			out = append(out, "lab lock: token in /etc/shunya-lab does not match this build")
		}
	}
	return out
}
