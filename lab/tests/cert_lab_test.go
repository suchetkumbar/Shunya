//go:build labtest && linux

package labtests

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func tool(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// Milestone 7 acceptance in the lab: a real erase (Format NVM) gets a certificate from a
// root-certified station key; the separate shunya-verify binary verifies it offline,
// including the PDF; independent tools check the PDF: qpdf (structure), pdftotext (the
// text is the JSON's), pdftoppm + zbarimg (the QR code decodes to URL + certificate ID).
func TestLabCertificate(t *testing.T) {
	env := inLab(t)
	dev := pathOf(t, env, "SHUNYA-NVME-01")
	dir, key := workDir(t)
	verifyBin, err := filepath.Abs("./shunya-verify")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root")
	pass := filepath.Join(dir, "pass")
	os.WriteFile(pass, []byte("lab root passphrase, offline\n"), 0o600)
	shunya(t, 0, "keys", "init-root", "--passphrase-file", pass, root)
	sc := filepath.Join(dir, "station.cert.json")
	shunya(t, 0, "keys", "issue-station", "--root", filepath.Join(root, "root.key"), "--station-key", key,
		"--name", "lab-vm", "--out", sc, "--passphrase-file", pass)

	j := filepath.Join(dir, "format.journal")
	out := shunya(t, 0, "wipe", "--method", "nvme-format-user-data-erase", "--execute", "--verify",
		"--journal", j, "--key", key, "--station-cert", sc, dev)
	if !strings.Contains(out, "CERTIFICATE ") {
		t.Fatalf("no certificate:\n%s", out)
	}
	cj, cp := j+".cert.json", j+".cert.pdf"

	vout, err := exec.Command(verifyBin, "--json", "--root", filepath.Join(root, "root.pub"),
		"--revocations", filepath.Join(root, "revocations.json"), "--pdf", cp, cj).CombinedOutput()
	if err != nil {
		t.Fatalf("shunya-verify: %v\n%s", err, vout)
	}
	var v struct {
		Valid      bool   `json:"valid"`
		ID         string `json:"id"`
		Trust      string `json:"trust"`
		PDFChecked bool   `json:"pdf_checked"`
		Cert       struct {
			VerifyURL string `json:"verify_url"`
			Device    struct {
				Serial, Model string
			} `json:"device"`
			Erasure struct {
				Method    string `json:"method"`
				NISTLevel string `json:"nist_level"`
			} `json:"erasure"`
		} `json:"certificate"`
	}
	if err := json.Unmarshal(vout, &v); err != nil {
		t.Fatalf("%v\n%s", err, vout)
	}
	if !v.Valid || v.Trust != "station-certificate" || !v.PDFChecked || v.Cert.Erasure.Method != "nvme-format-user-data-erase" ||
		v.Cert.Erasure.NISTLevel != "clear" || v.Cert.Device.Serial != "SHUNYA-NVME-01" {
		t.Fatalf("verify result: %s", vout)
	}

	// Independent PDF tools.
	t.Log(tool(t, "qpdf", "--check", cp))
	text := tool(t, "pdftotext", "-layout", cp, "-")
	for _, want := range []string{"Certificate of Data Erasure", v.ID, "SHUNYA-NVME-01", "nvme-format-user-data-erase", "CLEAR", "lab-vm"} {
		if !strings.Contains(text, want) {
			t.Errorf("pdftotext lacks %q:\n%s", want, text)
		}
	}
	png := filepath.Join(dir, "page")
	tool(t, "pdftoppm", "-r", "200", "-png", "-f", "1", "-l", "1", "-singlefile", cp, png)
	qr := strings.TrimSpace(tool(t, "zbarimg", "--raw", "-q", png+".png"))
	if qr != v.Cert.VerifyURL+v.ID {
		t.Fatalf("zbarimg decoded %q, want %q", qr, v.Cert.VerifyURL+v.ID)
	}
	t.Logf("QR decodes to %s", qr)
	os.WriteFile(filepath.Join(results(t), "certificate.json"), mustRead(t, cj), 0o644)
	os.WriteFile(filepath.Join(results(t), "certificate.pdf"), mustRead(t, cp), 0o644)

	// Revoked as compromised: the same certificate now fails, offline.
	var st struct {
		KeyID string `json:"key_id"`
	}
	json.Unmarshal(mustRead(t, sc), &st)
	shunya(t, 0, "keys", "revoke", "--root", filepath.Join(root, "root.key"), "--revocations", filepath.Join(root, "revocations.json"),
		"--key-id", st.KeyID, "--reason", "compromised", "--passphrase-file", pass)
	bad, err := exec.Command(verifyBin, "--root", filepath.Join(root, "root.pub"), "--revocations", filepath.Join(root, "revocations.json"), cj).CombinedOutput()
	if err == nil || !strings.Contains(string(bad), "compromised") {
		t.Fatalf("revoked station still verifies: %v\n%s", err, bad)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
