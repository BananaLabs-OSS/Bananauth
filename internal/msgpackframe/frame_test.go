package msgpackframe

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestOrdinaryMessagePackShapeParity(t *testing.T) {
	for _, value := range []any{nil, true, int64(42), "hello", []byte{1, 2, 3}, []any{}, map[string]any{}, map[string]any{"rows": []any{int64(1), "two"}}} {
		wire, err := msgpack.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var old, got any
		if err := msgpack.Unmarshal(wire, &old); err != nil {
			t.Fatal(err)
		}
		if err := Unmarshal(wire, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(old, got) {
			t.Fatalf("shape changed: %T", value)
		}
	}
}

func TestOrdinaryMessagePackSizeAndDepthParity(t *testing.T) {
	for _, size := range []int{0, 1024, 32760, 32768} {
		value := bytes.Repeat([]byte("x"), size)
		wire, err := msgpack.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		if err := Unmarshal(wire, &got); err != nil || !bytes.Equal(value, got) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	var value any = "leaf"
	for i := 0; i < 64; i++ {
		value = []any{value}
	}
	wire, err := msgpack.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var got any
	if err := Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryFrameTruncationAndTrailingBytes(t *testing.T) {
	wire, err := msgpack.Marshal(map[string]any{"message": "hello"})
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{nil, wire[:len(wire)-1], append(append([]byte(nil), wire...), 0xc0)} {
		original := map[string]string{"untouched": "yes"}
		if err := Unmarshal(invalid, &original); !errors.Is(err, ErrInvalidMessagePackFrame) {
			t.Fatalf("expected frame error, got %v", err)
		}
		if len(original) != 1 || original["untouched"] != "yes" {
			t.Fatal("decode began before structural validation")
		}
	}
}
