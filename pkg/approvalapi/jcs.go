package approvalapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize returns the RFC 8785 (JCS) form of a JSON document: object members
// sorted by the UTF-16 code units of their names, no insignificant whitespace, strings
// escaped as ECMAScript JSON.stringify does, and numbers in ECMAScript shortest form.
// Duplicate member names are refused.
func Canonicalize(doc []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var buf bytes.Buffer
	if err := canonValue(dec, &buf); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("jcs: trailing data")
	}
	return buf.Bytes(), nil
}

func canonValue(dec *json.Decoder, buf *bytes.Buffer) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("jcs: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return canonObject(dec, buf)
		case '[':
			buf.WriteByte('[')
			for i := 0; dec.More(); i++ {
				if i > 0 {
					buf.WriteByte(',')
				}
				if err := canonValue(dec, buf); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return fmt.Errorf("jcs: %w", err)
			}
			buf.WriteByte(']')
			return nil
		}
		return fmt.Errorf("jcs: unexpected %v", t)
	case string:
		writeString(buf, t)
	case json.Number:
		s, err := canonNumber(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("jcs: unexpected token %T", tok)
	}
	return nil
}

func canonObject(dec *json.Decoder, buf *bytes.Buffer) error {
	type member struct {
		key string
		val []byte
	}
	var members []member
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("jcs: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("jcs: object key is not a string")
		}
		if seen[key] {
			return fmt.Errorf("jcs: duplicate member %q", key)
		}
		seen[key] = true
		var vb bytes.Buffer
		if err := canonValue(dec, &vb); err != nil {
			return err
		}
		members = append(members, member{key, vb.Bytes()})
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("jcs: %w", err)
	}
	sort.Slice(members, func(i, j int) bool { return lessUTF16(members[i].key, members[j].key) })
	buf.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeString(buf, m.key)
		buf.WriteByte(':')
		buf.Write(m.val)
	}
	buf.WriteByte('}')
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			buf.WriteString(`\u00`)
			buf.WriteByte(hex[r>>4])
			buf.WriteByte(hex[r&0xf])
		default:
			buf.WriteString(s[i : i+size])
		}
		i += size
	}
	buf.WriteByte('"')
}

// canonNumber formats a JSON number as ECMAScript Number.prototype.toString does for
// an IEEE 754 double (RFC 8785 section 3.2.2.3).
func canonNumber(lit string) (string, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return "", fmt.Errorf("jcs: number %q: %w", lit, err)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("jcs: number %q out of range", lit)
	}
	if f == 0 {
		return "0", nil
	}
	neg := f < 0
	if neg {
		f = -f
	}
	// Shortest round-trip digits and decimal exponent: f = 0.d1d2...dk * 10^n.
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddddde±XX
	mant, expPart, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(expPart)
	k := len(digits)
	n := x + 1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		sign := "+"
		if n-1 < 0 {
			sign = "-"
		}
		ex := n - 1
		if ex < 0 {
			ex = -ex
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(ex)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(ex)
		}
	}
	if neg {
		out = "-" + out
	}
	return out, nil
}
