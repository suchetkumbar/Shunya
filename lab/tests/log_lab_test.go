//go:build labtest && linux

package labtests

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Milestone 8 acceptance in the lab: the transparency log runs in the VM
// (shunya-verify serve on 127.0.0.1); a real erase (Format NVM) is verified by
// sampling with a seed the log gives after the wipe; the certificate is logged; the
// QR code, decoded from the rendered PDF, leads to the log's page, which shows VALID;
// an audit proves the log consistent with what it published before.
func TestLabTransparencyLog(t *testing.T) {
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

	const addr = "127.0.0.1:8089"
	base := "http://" + addr
	tool(t, verifyBin, "log-key", "--origin", addr+"/log", "--out", dir)
	vkey := filepath.Join(dir, "log.vkey")
	logDir := filepath.Join(dir, "log")
	srvLog, _ := os.Create(filepath.Join(dir, "serve.log"))
	srv := exec.Command(verifyBin, "serve", "--init", "--dir", logDir, "--log-key", filepath.Join(dir, "log.key"),
		"--root", filepath.Join(root, "root.pub"), "--revocations", filepath.Join(root, "revocations.json"), "--listen", addr)
	srv.Stdout, srv.Stderr = srvLog, srvLog
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			srv.Process.Signal(syscall.SIGTERM)
			srv.Wait()
		}
	}
	defer stop()
	waitUp(t, base+"/checkpoint")

	j := filepath.Join(dir, "format.journal")
	out := shunya(t, 0, "wipe", "--method", "nvme-format-user-data-erase", "--execute", "--sample", "256",
		"--log", base, "--log-key", vkey, "--journal", j, "--key", key, "--station-cert", sc, dev)
	for _, want := range []string{"from a seed from the transparency log", "CERTIFICATE ", "LOGGED "} {
		if !strings.Contains(out, want) {
			t.Fatalf("wipe output lacks %q:\n%s", want, out)
		}
	}
	cj, cp := j+".cert.json", j+".cert.pdf"

	vout, err := exec.Command(verifyBin, "--json", "--root", filepath.Join(root, "root.pub"), "--revocations", filepath.Join(root, "revocations.json"),
		"--log-key", vkey, "--require-log", "--pdf", cp, cj).CombinedOutput()
	if err != nil {
		t.Fatalf("shunya-verify: %v\n%s", err, vout)
	}
	var v struct {
		Valid bool   `json:"valid"`
		ID    string `json:"id"`
		Log   struct {
			Index   uint64 `json:"index"`
			Checked bool   `json:"checked"`
		} `json:"log"`
		Cert struct {
			VerifyURL string `json:"verify_url"`
		} `json:"certificate"`
	}
	if err := json.Unmarshal(vout, &v); err != nil {
		t.Fatalf("%v\n%s", err, vout)
	}
	if !v.Valid || !v.Log.Checked || v.Cert.VerifyURL != base+"/c/" || !strings.Contains(string(vout), `"seed_source": "tlog-checkpoint"`) {
		t.Fatalf("verify result: %s", vout)
	}

	// Scan the QR code from the rendered PDF and follow it, as a recycler's phone would.
	img := filepath.Join(dir, "page")
	tool(t, "pdftoppm", "-r", "200", "-gray", "-f", "1", "-l", "1", "-singlefile", cp, img)
	zout, err := exec.Command("zbarimg", "--raw", "-q", img+".pgm").Output()
	if err != nil {
		t.Fatalf("zbarimg: %v", err)
	}
	url := strings.TrimSpace(string(zout))
	if url != base+"/c/"+v.ID {
		t.Fatalf("QR decodes to %q", url)
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{">VALID<", "SHUNYA-NVME-01", "nvme-format-user-data-erase", "CLEAR", "lab-vm", "tlog-checkpoint"} {
		if resp.StatusCode != 200 || !strings.Contains(string(page), want) {
			t.Fatalf("verifier page lacks %q (%d):\n%s", want, resp.StatusCode, page)
		}
	}
	t.Logf("QR %s → verifier page: VALID", url)

	// The server publishes the revocation list it checks against, byte for byte.
	rresp, err := http.Get(base + "/revocations")
	if err != nil {
		t.Fatal(err)
	}
	rl, _ := io.ReadAll(rresp.Body)
	rresp.Body.Close()
	if string(rl) != string(mustRead(t, filepath.Join(root, "revocations.json"))) {
		t.Fatalf("published revocation list differs: %s", rl)
	}

	// Audit over HTTP twice: the second run proves consistency with the first.
	state := filepath.Join(dir, "audit.state")
	a1 := tool(t, verifyBin, "audit", "--log", base, "--log-key", vkey, "--state", state)
	a2 := tool(t, verifyBin, "audit", "--log", base, "--log-key", vkey, "--state", state)
	if !strings.Contains(a1, "AUDIT PASSED") || !strings.Contains(a2, "consistent with the checkpoint saved before") {
		t.Fatalf("audit:\n%s\n%s", a1, a2)
	}
	stop()
	logText, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
	if !strings.Contains(string(logText), `"msg":"stopped"`) || !strings.Contains(string(logText), `"path":"/seed"`) {
		t.Fatalf("server log:\n%s", logText)
	}
	os.WriteFile(filepath.Join(results(t), "logged-certificate.json"), mustRead(t, cj), 0o644)
	os.WriteFile(filepath.Join(results(t), "verifier-page.html"), page, 0o644)
	os.WriteFile(filepath.Join(results(t), "serve.log"), logText, 0o644)
}

func waitUp(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s did not come up", url)
}
