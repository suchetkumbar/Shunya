package backend

import (
	"strings"
	"testing"

	"shunya/internal/device"
)

func TestConfirmation(t *testing.T) {
	d := &device.Device{Path: "/dev/sdb", Serial: "SHUNYA-SATA-SSD-01", Fingerprint: device.Fingerprint{Value: "fp1:abc"}}
	short := &device.Device{Path: "/dev/sdx", Serial: "X9", Fingerprint: device.Fingerprint{Value: "fp1:def"}}
	tests := []struct {
		name string
		dev  *device.Device
		c    *Confirmation
		ok   bool
	}{
		{"missing", d, nil, false},
		{"last four", d, &Confirmation{Typed: "D-01"}, true},
		{"last four, spaces and case", d, &Confirmation{Typed: "  d-01\n"}, true},
		{"wrong four", d, &Confirmation{Typed: "D-02"}, false},
		{"too short", d, &Confirmation{Typed: "01"}, false},
		{"whole serial is not last four", d, &Confirmation{Typed: "SHUNYA-SATA-SSD-01"}, false},
		{"short serial needs full serial", short, &Confirmation{Typed: "X9"}, true},
		{"short serial wrong", short, &Confirmation{Typed: "X8"}, false},
		{"yes-really listed", d, &Confirmation{YesReally: true, Approved: []string{"fp1:zzz", "fp1:abc"}}, true},
		{"yes-really unlisted", d, &Confirmation{YesReally: true, Approved: []string{"fp1:zzz"}}, false},
		{"yes-really empty list", d, &Confirmation{YesReally: true}, false},
		{"approved list without yes-really", d, &Confirmation{Approved: []string{"fp1:abc"}}, false},
		{"no serial", &device.Device{Path: "/dev/sdy"}, &Confirmation{Typed: ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Check(tt.dev)
			if (err == nil) != tt.ok {
				t.Fatalf("Check = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestParseApprovedList(t *testing.T) {
	in := "# fleet batch 7\n\nfp1:" + strings.Repeat("ab", 32) + "  # bay 1\nfp1:" + strings.Repeat("CD", 32) + "\n"
	got, err := ParseApprovedList([]byte(in))
	if err != nil || len(got) != 2 || got[1] != "fp1:"+strings.Repeat("cd", 32) {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"fp1:abc\n", "fp2:" + strings.Repeat("ab", 32), "/dev/sda\n", "fp1:" + strings.Repeat("zz", 32)} {
		if _, err := ParseApprovedList([]byte(bad)); err == nil {
			t.Errorf("want error for %q", bad)
		}
	}
}

func TestParseLabToken(t *testing.T) {
	tok, err := ParseLabToken([]byte(testToken + "\n"))
	if err != nil || tok != testToken {
		t.Fatalf("%q %v", tok, err)
	}
	for _, bad := range []string{"", "\n", "abc", strings.Repeat("g", 64), testToken + " extra", strings.Repeat("a", 300)} {
		if _, err := ParseLabToken([]byte(bad)); err == nil {
			t.Errorf("want error for %q", bad)
		}
	}
}

func FuzzParseApprovedList(f *testing.F) {
	f.Add([]byte("# c\nfp1:" + strings.Repeat("ab", 32) + " # x\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		fps, err := ParseApprovedList(b)
		if err != nil {
			return
		}
		for _, fp := range fps {
			if len(fp) != 68 || !strings.HasPrefix(fp, "fp1:") {
				t.Fatalf("bad fingerprint accepted: %q", fp)
			}
		}
	})
}

func FuzzParseLabToken(f *testing.F) {
	f.Add([]byte(testToken))
	f.Fuzz(func(t *testing.T, b []byte) {
		tok, err := ParseLabToken(b)
		if err != nil {
			return
		}
		if len(tok) < 32 || strings.TrimSpace(tok) != tok {
			t.Fatalf("bad token accepted: %q", tok)
		}
	})
}
