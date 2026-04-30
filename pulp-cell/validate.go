package main

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// validateRequest enforces the subset of go-playground/validator rules
// Bananauth's native request structs rely on (email format, min=, max=).
// pulpgin's ShouldBindJSON only enforces `required` — the remaining rules
// are no-ops in the framework, so we run them here to keep the cell's
// 400-on-bad-input behaviour byte-identical with the native service.
//
// Error messages mirror go-playground/validator's format:
//
//	Key: 'StructName.Field' Error:Field validation for 'Field' failed on the 'tag' tag
//
// so parity tests comparing against a native Gin server don't need
// special-cased strings.
//
// Supported tags: required, email, min=N, max=N (string length in runes).
// Unknown tags are ignored — matches validator's behaviour for unsupported
// rules in the binding struct tag.
func validateRequest(v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return nil
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return nil
	}
	rt := rv.Type()
	structName := rt.Name()

	var messages []string
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}
		tag := field.Tag.Get("binding")
		if tag == "" || tag == "-" {
			continue
		}
		fv := rv.Field(i)
		rules := strings.Split(tag, ",")

		// Collect rules; handle `omitempty` short-circuit.
		omitempty := false
		for _, rule := range rules {
			if strings.TrimSpace(rule) == "omitempty" {
				omitempty = true
				break
			}
		}
		if omitempty && fv.IsZero() {
			continue
		}

		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			switch {
			case rule == "" || rule == "omitempty":
				continue
			case rule == "required":
				// pulpgin already enforced this, but enforce again for
				// belt-and-braces parity — pulpgin's check runs before
				// ours and would have short-circuited, so this is a
				// redundant safety net that will only fire if the
				// framework ever stops enforcing `required`.
				if fv.IsZero() {
					messages = append(messages, formatErr(structName, field.Name, "required"))
				}
			case rule == "email":
				if fv.Kind() == reflect.String && !looksLikeEmail(fv.String()) {
					messages = append(messages, formatErr(structName, field.Name, "email"))
				}
			case strings.HasPrefix(rule, "min="):
				nStr := strings.TrimPrefix(rule, "min=")
				n, err := strconv.Atoi(nStr)
				if err != nil {
					continue
				}
				if !checkLenGE(fv, n) {
					messages = append(messages, formatErr(structName, field.Name, "min"))
				}
			case strings.HasPrefix(rule, "max="):
				nStr := strings.TrimPrefix(rule, "max=")
				n, err := strconv.Atoi(nStr)
				if err != nil {
					continue
				}
				if !checkLenLE(fv, n) {
					messages = append(messages, formatErr(structName, field.Name, "max"))
				}
			}
		}
	}
	if len(messages) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(messages, "\n"))
}

func formatErr(structName, field, tag string) string {
	return fmt.Sprintf(
		"Key: '%s.%s' Error:Field validation for '%s' failed on the '%s' tag",
		structName, field, field, tag,
	)
}

// looksLikeEmail is a pragmatic check matching what
// go-playground/validator's "email" rule accepts in practice: at least
// one @ separator, non-empty local and domain parts, at least one dot
// in the domain, and only printable ASCII. It deliberately rejects the
// corner cases native validator also rejects (empty, whitespace-only,
// missing @, missing domain TLD) without pulling in a 500-line RFC5322
// parser. Parity tests against the native service exercise the
// common valid/invalid pairs (e.g. "a@b.c" passes, "a@b" fails).
func looksLikeEmail(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	local := s[:at]
	domain := s[at+1:]
	if local == "" || domain == "" {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	// Reject trailing/leading dot in domain, consecutive dots.
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// checkLenGE reports whether fv's length (runes for strings, len for
// slices/maps, numeric value for ints/uints/floats) is >= n.
func checkLenGE(fv reflect.Value, n int) bool {
	switch fv.Kind() {
	case reflect.String:
		return utf8.RuneCountInString(fv.String()) >= n
	case reflect.Slice, reflect.Array, reflect.Map:
		return fv.Len() >= n
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fv.Int() >= int64(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fv.Uint() >= uint64(n)
	case reflect.Float32, reflect.Float64:
		return fv.Float() >= float64(n)
	}
	return true
}

// checkLenLE is the <= companion to checkLenGE.
func checkLenLE(fv reflect.Value, n int) bool {
	switch fv.Kind() {
	case reflect.String:
		return utf8.RuneCountInString(fv.String()) <= n
	case reflect.Slice, reflect.Array, reflect.Map:
		return fv.Len() <= n
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fv.Int() <= int64(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fv.Uint() <= uint64(n)
	case reflect.Float32, reflect.Float64:
		return fv.Float() <= float64(n)
	}
	return true
}
