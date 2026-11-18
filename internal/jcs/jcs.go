// Package jcs implements the JSON Canonicalization Scheme (RFC 8785): one byte string
// per JSON value, so a signature over it does not depend on whitespace, property
// order, escaping or number spelling.
//
// The parser is strict, because a canonicalizer that silently repairs input lets two
// different documents sign the same: duplicate property names, lone UTF-16
// surrogates, invalid UTF-8, a byte order mark, numbers outside IEEE 754 doubles and
// anything outside RFC 8259's grammar are refused (ErrInvalid). Numbers are
// serialized as ECMAScript's Number.prototype.toString does (RFC 8785 §3.2.2.3);
// Marshal additionally refuses integers beyond ±2^53, which no IEEE 754 consumer can
// read back exactly.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrInvalid is wrapped by every refusal.
var ErrInvalid = errors.New("jcs: invalid input")

// MaxDepth bounds nesting (each level costs stack; real documents are shallow).
const MaxDepth = 64

// Canonicalize parses one JSON value and returns its canonical form.
func Canonicalize(in []byte) ([]byte, error) {
	p := parser{in: in}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.in) {
		return nil, p.fail("data after the value")
	}
	var out bytes.Buffer
	if err := write(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Marshal encodes v with encoding/json and canonicalizes the result. Integers beyond
// ±2^53 are refused (see the package comment).
func Marshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	p := parser{in: b, exactInts: true}
	val, err := p.value(0)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := write(&out, val); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// IsCanonical reports whether b is valid JSON already in canonical form.
func IsCanonical(b []byte) bool {
	c, err := Canonicalize(b)
	return err == nil && bytes.Equal(c, b)
}

// The parsed value: nil (null), bool, float64, string, []any or object.
type object []member

type member struct {
	key string
	val any
}

type parser struct {
	in        []byte
	i         int
	exactInts bool
}

func (p *parser) fail(f string, a ...any) error {
	return fmt.Errorf("%w: offset %d: %s", ErrInvalid, p.i, fmt.Sprintf(f, a...))
}

func (p *parser) space() {
	for p.i < len(p.in) {
		switch p.in[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	p.space()
	if p.i >= len(p.in) {
		return nil, p.fail("unexpected end")
	}
	switch c := p.in[p.i]; {
	case c == '{' || c == '[':
		if depth >= MaxDepth {
			return nil, p.fail("nested deeper than %d", MaxDepth)
		}
		if c == '{' {
			return p.object(depth + 1)
		}
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	for _, lit := range []struct {
		s string
		v any
	}{{"true", true}, {"false", false}, {"null", nil}} {
		if bytes.HasPrefix(p.in[p.i:], []byte(lit.s)) {
			p.i += len(lit.s)
			return lit.v, nil
		}
	}
	return nil, p.fail("unexpected %q", p.in[p.i])
}

func (p *parser) object(depth int) (any, error) {
	p.i++ // {
	obj := object{}
	seen := map[string]bool{}
	p.space()
	if p.i < len(p.in) && p.in[p.i] == '}' {
		p.i++
		return obj, nil
	}
	for {
		p.space()
		if p.i >= len(p.in) || p.in[p.i] != '"' {
			return nil, p.fail("want a property name")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if seen[k] {
			return nil, p.fail("duplicate property %q", k)
		}
		seen[k] = true
		p.space()
		if p.i >= len(p.in) || p.in[p.i] != ':' {
			return nil, p.fail("want ':'")
		}
		p.i++
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		obj = append(obj, member{k, v})
		p.space()
		if p.i >= len(p.in) {
			return nil, p.fail("unterminated object")
		}
		switch p.in[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return obj, nil
		default:
			return nil, p.fail("want ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	p.i++ // [
	arr := []any{}
	p.space()
	if p.i < len(p.in) && p.in[p.i] == ']' {
		p.i++
		return arr, nil
	}
	for {
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.space()
		if p.i >= len(p.in) {
			return nil, p.fail("unterminated array")
		}
		switch p.in[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return arr, nil
		default:
			return nil, p.fail("want ',' or ']'")
		}
	}
}

// number follows RFC 8259 §6 exactly, then converts to the nearest double.
func (p *parser) number() (any, error) {
	start := p.i
	digits := func() int {
		n := 0
		for p.i < len(p.in) && p.in[p.i] >= '0' && p.in[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.in[p.i] == '-' {
		p.i++
	}
	intStart := p.i
	if n := digits(); n == 0 {
		return nil, p.fail("bad number")
	} else if n > 1 && p.in[intStart] == '0' {
		return nil, p.fail("leading zero")
	}
	integer := true
	if p.i < len(p.in) && p.in[p.i] == '.' {
		p.i++
		integer = false
		if digits() == 0 {
			return nil, p.fail("bad fraction")
		}
	}
	if p.i < len(p.in) && (p.in[p.i] == 'e' || p.in[p.i] == 'E') {
		p.i++
		integer = false
		if p.i < len(p.in) && (p.in[p.i] == '+' || p.in[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return nil, p.fail("bad exponent")
		}
	}
	text := string(p.in[start:p.i])
	f, err := strconv.ParseFloat(text, 64)
	if err != nil { // only range errors remain after the grammar check
		return nil, p.fail("number %s outside IEEE 754 double range", text)
	}
	if p.exactInts && integer {
		// Checked on the text: 2^53+1 parses to the double 2^53.
		if n, err := strconv.ParseInt(text, 10, 64); err != nil || n > 1<<53 || n < -(1<<53) {
			return nil, p.fail("integer %s beyond ±2^53 cannot be represented exactly", text)
		}
	}
	return f, nil
}

// str decodes a string, refusing invalid UTF-8, raw control characters and lone
// surrogates (which have no UTF-8 form and would be silently replaced elsewhere).
func (p *parser) str() (string, error) {
	p.i++ // "
	var b strings.Builder
	for {
		if p.i >= len(p.in) {
			return "", p.fail("unterminated string")
		}
		c := p.in[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c < 0x20:
			return "", p.fail("control character in string")
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			b.WriteRune(r)
		case c < utf8.RuneSelf:
			b.WriteByte(c)
			p.i++
		default:
			r, n := utf8.DecodeRune(p.in[p.i:])
			if r == utf8.RuneError && n <= 1 {
				return "", p.fail("invalid UTF-8")
			}
			b.WriteRune(r)
			p.i += n
		}
	}
}

func (p *parser) escape() (rune, error) {
	if p.i+1 >= len(p.in) {
		return 0, p.fail("unterminated escape")
	}
	c := p.in[p.i+1]
	p.i += 2
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
	default:
		return 0, p.fail("bad escape \\%c", c)
	}
	u, err := p.hex4()
	if err != nil {
		return 0, err
	}
	switch {
	case utf16.IsSurrogate(rune(u)) && u < 0xdc00:
		if p.i+1 < len(p.in) && p.in[p.i] == '\\' && p.in[p.i+1] == 'u' {
			p.i += 2
			lo, err := p.hex4()
			if err != nil {
				return 0, err
			}
			if lo >= 0xdc00 && lo <= 0xdfff {
				return utf16.DecodeRune(rune(u), rune(lo)), nil
			}
		}
		return 0, p.fail("lone high surrogate")
	case utf16.IsSurrogate(rune(u)):
		return 0, p.fail("lone low surrogate")
	}
	return rune(u), nil
}

func (p *parser) hex4() (uint16, error) {
	if p.i+4 > len(p.in) {
		return 0, p.fail("short \\u escape")
	}
	v, err := strconv.ParseUint(string(p.in[p.i:p.i+4]), 16, 16)
	if err != nil || strings.ContainsAny(string(p.in[p.i:p.i+4]), "+-") {
		return 0, p.fail("bad \\u escape")
	}
	p.i += 4
	return uint16(v), nil
}

func write(out *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case float64:
		s, err := FormatNumber(v)
		if err != nil {
			return err
		}
		out.WriteString(s)
	case string:
		writeString(out, v)
	case []any:
		out.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := write(out, e); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case object:
		sorted := slices.Clone(v)
		slices.SortFunc(sorted, func(a, b member) int { return compareUTF16(a.key, b.key) })
		out.WriteByte('{')
		for i, m := range sorted {
			if i > 0 {
				out.WriteByte(',')
			}
			writeString(out, m.key)
			out.WriteByte(':')
			if err := write(out, m.val); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("%w: unexpected %T", ErrInvalid, v)
	}
	return nil
}

// compareUTF16 orders strings by their UTF-16 code units (RFC 8785 §3.2.3).
func compareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

// writeString escapes as ECMAScript's JSON.stringify (RFC 8785 §3.2.2.2).
func writeString(out *bytes.Buffer, s string) {
	const hexdig = "0123456789abcdef"
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if c < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexdig[c>>4])
				out.WriteByte(hexdig[c&0xf])
			} else {
				out.WriteByte(c)
			}
		}
	}
	out.WriteByte('"')
}

// FormatNumber serializes a double as ECMAScript's Number.prototype.toString
// (ECMA-262 Number::toString, RFC 8785 §3.2.2.3). Go's shortest round-trip digits
// are the same digit string ECMAScript chooses; only the layout differs.
func FormatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: %v is not a JSON number", ErrInvalid, f)
	}
	if f == 0 {
		return "0", nil // and -0
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// d.ddddde±xx: digits s (k of them), value = 0.s × 10^n.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(exp)
	k, n := len(digits), x+1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	}
	es := "+"
	if n-1 < 0 {
		es = "-"
	}
	ex := strconv.Itoa(abs(n - 1))
	if k == 1 {
		return sign + digits + "e" + es + ex, nil
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + es + ex, nil
}

func abs(i int) int {
	if i < 0 {
		return -i
	}
	return i
}
