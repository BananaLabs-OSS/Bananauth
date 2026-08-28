// Package authvalidate implements Bananauth's platform-neutral request
// validation subset. It has no Pulp, HTTP, storage, or WASI dependency.
package authvalidate

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

func Validate(value any) error {
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return nil
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return nil
	}
	rt := rv.Type()
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
		optional := false
		for _, rule := range rules {
			if strings.TrimSpace(rule) == "omitempty" {
				optional = true
				break
			}
		}
		if optional && fv.IsZero() {
			continue
		}
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			switch {
			case rule == "" || rule == "omitempty":
			case rule == "required" && fv.IsZero():
				messages = append(messages, formatError(rt.Name(), field.Name, "required"))
			case rule == "email" && fv.Kind() == reflect.String && !LooksLikeEmail(fv.String()):
				messages = append(messages, formatError(rt.Name(), field.Name, "email"))
			case strings.HasPrefix(rule, "min="):
				if n, err := strconv.Atoi(strings.TrimPrefix(rule, "min=")); err == nil && !lengthCompare(fv, n, true) {
					messages = append(messages, formatError(rt.Name(), field.Name, "min"))
				}
			case strings.HasPrefix(rule, "max="):
				if n, err := strconv.Atoi(strings.TrimPrefix(rule, "max=")); err == nil && !lengthCompare(fv, n, false) {
					messages = append(messages, formatError(rt.Name(), field.Name, "max"))
				}
			}
		}
	}
	if len(messages) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(messages, "\n"))
}

func LooksLikeEmail(value string) bool {
	value = strings.TrimSpace(value)
	at := strings.IndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return false
	}
	domain := value[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") ||
		strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func formatError(structName, field, tag string) string {
	return fmt.Sprintf("Key: '%s.%s' Error:Field validation for '%s' failed on the '%s' tag", structName, field, field, tag)
}

func lengthCompare(value reflect.Value, n int, minimum bool) bool {
	var number float64
	switch value.Kind() {
	case reflect.String:
		number = float64(utf8.RuneCountInString(value.String()))
	case reflect.Slice, reflect.Array, reflect.Map:
		number = float64(value.Len())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		number = float64(value.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		number = float64(value.Uint())
	case reflect.Float32, reflect.Float64:
		number = value.Float()
	default:
		return true
	}
	if minimum {
		return number >= float64(n)
	}
	return number <= float64(n)
}
