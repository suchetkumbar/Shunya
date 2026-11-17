package canary

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand/v2"
	"strings"
	"time"
)

// Planted is a real file the harness puts on a file system before the wipe, to prove a
// carver can recover it (before) and can't (after).
type Planted struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // jpg, pdf, docx
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Marker string `json:"marker"` // unique ASCII string stored uncompressed in the file
	Data   []byte `json:"-"`
}

// MarkerPrefix starts every planted-file marker.
const MarkerPrefix = "SHUNYA-MARKER-"

func marker(seed []byte, name string) string {
	h := sha256.Sum256(append(append([]byte("shunya-marker-v1\x00"), seed...), name...))
	return MarkerPrefix + hex.EncodeToString(h[:12])
}

// GenerateFiles returns one JPEG, PDF and DOCX per copy, deterministic in seed. Every
// file carries its marker several times, uncompressed, so a raw scan finds it.
func GenerateFiles(seed []byte, copies int) ([]Planted, error) {
	var out []Planted
	for i := range copies {
		for _, typ := range []string{"jpg", "pdf", "docx"} {
			name := fmt.Sprintf("planted-%d.%s", i, typ)
			mk := marker(seed, name)
			r := rand.New(rand.NewPCG(uint64(i), uint64(len(typ))^uint64(seed[0])))
			var data []byte
			var err error
			switch typ {
			case "jpg":
				data, err = makeJPEG(mk, r)
			case "pdf":
				data = makePDF(mk, r)
			case "docx":
				data, err = makeDOCX(mk, r)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			h := sha256.Sum256(data)
			out = append(out, Planted{Name: name, Type: typ, Size: len(data), SHA256: hex.EncodeToString(h[:]), Marker: mk, Data: data})
		}
	}
	return out, nil
}

// Markers returns the markers of files.
func Markers(files []Planted) []string {
	var m []string
	for _, f := range files {
		m = append(m, f.Marker)
	}
	return m
}

// makeJPEG encodes a noisy 640×480 image (≈200 KB, incompressible enough to span many
// blocks) and inserts COM (comment) segments holding the marker right after SOI.
func makeJPEG(mk string, r *rand.Rand) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, 640, 480))
	for y := range 480 {
		for x := range 640 {
			img.Set(x, y, color.RGBA{uint8(x ^ y), uint8(r.Uint32()), uint8(y * 3), 255})
		}
	}
	var enc bytes.Buffer
	if err := jpeg.Encode(&enc, img, &jpeg.Options{Quality: 90}); err != nil {
		return nil, err
	}
	b := enc.Bytes()
	if len(b) < 2 || b[0] != 0xff || b[1] != 0xd8 {
		return nil, fmt.Errorf("encoder did not start with SOI")
	}
	var com bytes.Buffer
	for range 4 {
		payload := "shunya planted file " + mk
		com.Write([]byte{0xff, 0xfe, byte((len(payload) + 2) >> 8), byte(len(payload) + 2)})
		com.WriteString(payload)
	}
	return append(append([]byte{0xff, 0xd8}, com.Bytes()...), b[2:]...), nil
}

// makePDF writes a one-page PDF 1.4 with the marker as visible text, plus an
// uncompressed padding stream (≈120 KB) of comment lines that repeat the marker, and a
// correct cross-reference table.
func makePDF(mk string, r *rand.Rand) []byte {
	var pad strings.Builder
	for pad.Len() < 120<<10 {
		fmt.Fprintf(&pad, "%% %s %016x\n", mk, r.Uint64())
	}
	content := fmt.Sprintf("BT /F1 18 Tf 50 750 Td (Shunya planted file %s) Tj ET\n%s", mk, pad.String())
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offs := make([]int, len(objs))
	for i, o := range objs {
		offs[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

// makeDOCX builds a minimal WordprocessingML package. document.xml is stored, not
// deflated, so the marker is visible on the raw disk; a stored random part makes the
// file ≈100 KB.
func makeDOCX(mk string, r *rand.Rand) ([]byte, error) {
	parts := []struct {
		name, body string
	}{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Default Extension="bin" ContentType="application/octet-stream"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`</Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`</Relationships>`},
		{"word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
			strings.Repeat(`<w:p><w:r><w:t>Shunya planted file `+mk+`</w:t></w:r></w:p>`, 8) +
			`</w:body></w:document>`},
	}
	pad := make([]byte, 100<<10)
	for i := range pad {
		pad[i] = byte(r.Uint32())
	}
	parts = append(parts, struct{ name, body string }{"word/media/padding.bin", string(pad)})
	// CreateRaw with the CRC and sizes known up front: no data descriptors (flag bit 3),
	// which carvers such as photorec reject for stored entries.
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, p := range parts {
		w, err := zw.CreateRaw(&zip.FileHeader{Name: p.name, Method: zip.Store, CRC32: crc32.ChecksumIEEE([]byte(p.body)),
			CompressedSize64: uint64(len(p.body)), UncompressedSize64: uint64(len(p.body)),
			ReaderVersion: 20, CreatorVersion: 20, Modified: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
