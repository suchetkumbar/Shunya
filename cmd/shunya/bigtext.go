package main

import "strings"

// A 5-row block font for the one-click screen's status words ("WIPING 43%",
// "DONE", "FAILED"), readable from across a room.
var bigGlyphs = map[rune][5]string{
	'A': {" ███ ", "█   █", "█████", "█   █", "█   █"},
	'C': {" ████", "█    ", "█    ", "█    ", " ████"},
	'D': {"████ ", "█   █", "█   █", "█   █", "████ "},
	'E': {"█████", "█    ", "████ ", "█    ", "█████"},
	'F': {"█████", "█    ", "████ ", "█    ", "█    "},
	'G': {" ████", "█    ", "█  ██", "█   █", " ████"},
	'H': {"█   █", "█   █", "█████", "█   █", "█   █"},
	'I': {"█████", "  █  ", "  █  ", "  █  ", "█████"},
	'K': {"█   █", "█  █ ", "███  ", "█  █ ", "█   █"},
	'L': {"█    ", "█    ", "█    ", "█    ", "█████"},
	'N': {"█   █", "██  █", "█ █ █", "█  ██", "█   █"},
	'O': {" ███ ", "█   █", "█   █", "█   █", " ███ "},
	'P': {"████ ", "█   █", "████ ", "█    ", "█    "},
	'R': {"████ ", "█   █", "████ ", "█  █ ", "█   █"},
	'S': {" ████", "█    ", " ███ ", "    █", "████ "},
	'T': {"█████", "  █  ", "  █  ", "  █  ", "  █  "},
	'U': {"█   █", "█   █", "█   █", "█   █", " ███ "},
	'V': {"█   █", "█   █", "█   █", " █ █ ", "  █  "},
	'W': {"█   █", "█   █", "█ █ █", "██ ██", "█   █"},
	'Y': {"█   █", " █ █ ", "  █  ", "  █  ", "  █  "},
	'0': {" ███ ", "█  ██", "█ █ █", "██  █", " ███ "},
	'1': {"  █  ", " ██  ", "  █  ", "  █  ", " ███ "},
	'2': {"████ ", "    █", " ███ ", "█    ", "█████"},
	'3': {"████ ", "    █", " ███ ", "    █", "████ "},
	'4': {"█   █", "█   █", "█████", "    █", "    █"},
	'5': {"█████", "█    ", "████ ", "    █", "████ "},
	'6': {" ███ ", "█    ", "████ ", "█   █", " ███ "},
	'7': {"█████", "    █", "   █ ", "  █  ", "  █  "},
	'8': {" ███ ", "█   █", " ███ ", "█   █", " ███ "},
	'9': {" ███ ", "█   █", " ████", "    █", " ███ "},
	'%': {"██  █", "██ █ ", "  █  ", " █ ██", "█  ██"},
	' ': {"   ", "   ", "   ", "   ", "   "},
	'!': {"█", "█", "█", " ", "█"},
}

// bigText renders s (upper-cased) in the block font; characters without a glyph are
// dropped. The plain text is kept on the last line for screen readers and logs.
func bigText(s string) string {
	s = strings.ToUpper(s)
	var rows [5]strings.Builder
	for _, r := range s {
		g, ok := bigGlyphs[r]
		if !ok {
			continue
		}
		for i := range rows {
			rows[i].WriteString(g[i])
			rows[i].WriteString(" ")
		}
	}
	out := make([]string, 0, 6)
	for i := range rows {
		out = append(out, strings.TrimRight(rows[i].String(), " "))
	}
	return strings.Join(append(out, s), "\n")
}
