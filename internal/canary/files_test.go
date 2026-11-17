package canary

import (
	"archive/zip"
	"bytes"
	"image/jpeg"
	"io"
	"strings"
	"testing"
)

func TestGeneratedFilesAreValid(t *testing.T) {
	files, err := GenerateFiles([]byte("seed-1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 6 {
		t.Fatalf("%d files", len(files))
	}
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f.Marker] || !strings.HasPrefix(f.Marker, MarkerPrefix) {
			t.Fatalf("%s: marker %q not unique", f.Name, f.Marker)
		}
		seen[f.Marker] = true
		if n := bytes.Count(f.Data, []byte(f.Marker)); n < 2 {
			t.Fatalf("%s: marker appears %d times uncompressed", f.Name, n)
		}
		if f.Size < 64<<10 {
			t.Errorf("%s: only %d bytes; want files spanning many blocks", f.Name, f.Size)
		}
		switch f.Type {
		case "jpg":
			if _, err := jpeg.Decode(bytes.NewReader(f.Data)); err != nil {
				t.Fatalf("%s does not decode: %v", f.Name, err)
			}
		case "pdf":
			if !bytes.HasPrefix(f.Data, []byte("%PDF-1.4\n")) || !bytes.HasSuffix(f.Data, []byte("%%EOF\n")) {
				t.Fatalf("%s: bad PDF framing", f.Name)
			}
			x := bytes.LastIndex(f.Data, []byte("startxref\n"))
			if x < 0 || !bytes.HasPrefix(f.Data[bytes.Index(f.Data, []byte("xref\n0 ")):], []byte("xref")) {
				t.Fatalf("%s: no xref", f.Name)
			}
		case "docx":
			zr, err := zip.NewReader(bytes.NewReader(f.Data), int64(len(f.Data)))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, zf := range zr.File {
				if zf.Name == "word/document.xml" {
					rc, _ := zf.Open()
					b, _ := io.ReadAll(rc)
					found = bytes.Contains(b, []byte(f.Marker))
				}
			}
			if !found {
				t.Fatalf("%s: document.xml lacks the marker", f.Name)
			}
		}
	}
	again, _ := GenerateFiles([]byte("seed-1"), 2)
	for i := range files {
		if files[i].SHA256 != again[i].SHA256 {
			t.Fatal("not deterministic")
		}
	}
}
