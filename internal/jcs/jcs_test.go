package jcs

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The vectors below are copied from RFC 8785 (https://www.rfc-editor.org/rfc/rfc8785.txt,
// SHA-256 63d52294eb0e3f0014174288186d388b4ddbf2c67d1ce8af1d9726eb0c3ab240):
// §3.2.2–3.2.4 (the sample object and its UTF-8 bytes), §3.2.3 (property sorting) and
// Appendix B (number serialization).

const rfcSample = `{
       "numbers": [333333333.33333329, 1E30, 4.50,
                   2e-3, 0.000000000000000000000000001],
       "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
       "literals": [null, true, false]
     }`

// §3.2.4, the canonical sample as hex.
const rfcSampleHex = `
     7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72
     75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
     5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31
     65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
     5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30
     30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d`

func TestRFCSample(t *testing.T) {
	want, err := hex.DecodeString(strings.Join(strings.Fields(rfcSampleHex), ""))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonicalize([]byte(rfcSample))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// §3.2.3, as text.
	if string(got) != `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}` {
		t.Fatalf("text form %s", got)
	}
}

func TestRFCSorting(t *testing.T) {
	in := `{
       "\u20ac": "Euro Sign",
       "\r": "Carriage Return",
       "\ufb33": "Hebrew Letter Dalet With Dagesh",
       "1": "One",
       "\ud83d\ude00": "Emoji: Grinning Face",
       "\u0080": "Control",
       "\u00f6": "Latin Small Letter O With Diaeresis"
     }`
	want := []string{"Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis",
		"Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"}
	out, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	// Values appear in property order; find each in turn.
	rest := string(out)
	for _, w := range want {
		i := strings.Index(rest, `"`+w+`"`)
		if i < 0 {
			t.Fatalf("%q out of order in %s", w, out)
		}
		rest = rest[i+len(w):]
	}
	// UTF-8 byte order would put U+FB33 (ef ac b3) before U+1F600 (f0 9f 98 80); UTF-16
	// puts the surrogate pair (d83d) first.
	if !strings.Contains(string(out), "😀\":\"Emoji: Grinning Face\",\"\ufb33\"") {
		t.Fatalf("emoji/hebrew order: %s", out)
	}
}

func TestRFCNumbers(t *testing.T) {
	for _, v := range []struct{ ieee, want string }{
		{"0000000000000000", "0"},
		{"8000000000000000", "0"},
		{"0000000000000001", "5e-324"},
		{"8000000000000001", "-5e-324"},
		{"7fefffffffffffff", "1.7976931348623157e+308"},
		{"ffefffffffffffff", "-1.7976931348623157e+308"},
		{"4340000000000000", "9007199254740992"},
		{"c340000000000000", "-9007199254740992"},
		{"4430000000000000", "295147905179352830000"},
		{"44b52d02c7e14af5", "9.999999999999997e+22"},
		{"44b52d02c7e14af6", "1e+23"},
		{"44b52d02c7e14af7", "1.0000000000000001e+23"},
		{"444b1ae4d6e2ef4e", "999999999999999700000"},
		{"444b1ae4d6e2ef4f", "999999999999999900000"},
		{"444b1ae4d6e2ef50", "1e+21"},
		{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
		{"3eb0c6f7a0b5ed8d", "0.000001"},
		{"41b3de4355555553", "333333333.3333332"},
		{"41b3de4355555554", "333333333.33333325"},
		{"41b3de4355555555", "333333333.3333333"},
		{"41b3de4355555556", "333333333.3333334"},
		{"41b3de4355555557", "333333333.33333343"},
		{"becbf647612f3696", "-0.0000033333333333333333"},
		{"43143ff3c1cb0959", "1424953923781206.2"},
	} {
		bits, _ := strconv.ParseUint(v.ieee, 16, 64)
		f := math.Float64frombits(bits)
		got, err := FormatNumber(f)
		if err != nil || got != v.want {
			t.Errorf("%s: %q %v, want %q", v.ieee, got, err, v.want)
		}
		// The canonical form must also survive a parse: the number as text in a document.
		out, err := Canonicalize([]byte("[" + strconv.FormatFloat(f, 'g', -1, 64) + "]"))
		if err != nil || string(out) != "["+v.want+"]" {
			t.Errorf("%s in a document: %s %v", v.ieee, out, err)
		}
	}
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := FormatNumber(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestStringEscapes(t *testing.T) {
	// ECMAScript JSON.stringify: the two-character escapes, \u00xx (lower case) for the
	// other controls, everything else (DEL, U+2028, '/', non-ASCII) literally.
	out, err := Canonicalize([]byte(`"\b\t\n\f\r\u0000\u001F\u007f\u2028\/<>&é"`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "\"\\b\\t\\n\\f\\r\\u0000\\u001f\x7f /<>&é\""; string(out) != want {
		t.Fatalf("%q, want %q", out, want)
	}
}

func TestRefusals(t *testing.T) {
	for _, in := range []string{
		``, ` `, `{`, `[1,]`, `{"a":1,}`, `{"a" 1}`, `01`, `1.`, `.5`, `-`, `1e`, `+1`, `0x10`,
		`"\x"`, `"\u12"`, "\"a\nb\"", `tru`, `nul`, `[1] [2]`, `[1]x`, `'a'`,
		`{"a":1,"a":2}`,         // duplicate property (RFC 8785 §3.1, I-JSON)
		`{"\u0061":1,"a":2}`,    // duplicate after unescaping
		`"\ud800"`, `"\udc00x"`, // lone surrogates
		`"\ud800\u0041"`,                           // high surrogate not followed by a low one
		"\"\xff\"", "\"\xc3\"", "\"\xed\xa0\x80\"", // invalid UTF-8, UTF-8-encoded surrogate
		`1e400`, `-1e400`, // out of IEEE 754 range
		"\xef\xbb\xbf{}", // byte order mark
	} {
		if out, err := Canonicalize([]byte(in)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %q %v", in, out, err)
		}
	}
	deep := strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1)
	if _, err := Canonicalize([]byte(deep)); !errors.Is(err, ErrInvalid) {
		t.Error("over-deep nesting accepted")
	}
	ok := strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth)
	if _, err := Canonicalize([]byte(ok)); err != nil {
		t.Errorf("depth %d refused: %v", MaxDepth, err)
	}
}

func TestMarshal(t *testing.T) {
	type inner struct {
		Z int    `json:"z"`
		A string `json:"a"`
	}
	v := struct {
		B   []inner `json:"b"`
		A   string  `json:"a"`
		Big uint64  `json:"big"`
	}{B: []inner{{1, "<x>"}}, A: "é", Big: 1 << 53}
	out, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"a":"é","b":[{"a":"<x>","z":1}],"big":9007199254740992}` {
		t.Fatalf("%s", out)
	}
	// Integers past 2^53 would change value in any IEEE 754 consumer: refused.
	if _, err := Marshal(struct{ N uint64 }{1<<53 + 1}); !errors.Is(err, ErrInvalid) {
		t.Errorf("2^53+1: %v", err)
	}
	if !IsCanonical(out) || IsCanonical([]byte(`{"b":1,"a":2}`)) || IsCanonical([]byte(`{ "a":1}`)) {
		t.Error("IsCanonical")
	}
}

func FuzzCanonicalize(f *testing.F) {
	for _, s := range []string{rfcSample, `{"a":[1,2.5,-0,1e21,"x\u0000"],"b":{}}`, `[]`, `"é"`, `1e-7`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := Canonicalize(in)
		if err != nil {
			return
		}
		// Canonical output is a fixed point, and valid JSON to an independent parser
		// with the same meaning.
		again, err := Canonicalize(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not idempotent: %q -> %q -> %q %v", in, out, again, err)
		}
		var a, b any
		if err := json.Unmarshal(in, &a); err != nil {
			t.Fatalf("accepted what encoding/json refuses: %q: %v", in, err)
		}
		if err := json.Unmarshal(out, &b); err != nil {
			t.Fatalf("output %q: %v", out, err)
		}
		if !reflect.DeepEqual(a, b) { // DeepEqual compares floats with ==, so -0 == 0
			t.Fatalf("meaning changed: %#v vs %#v", a, b)
		}
	})
}
