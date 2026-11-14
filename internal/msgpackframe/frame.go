// Package msgpackframe validates complete MessagePack values before decoding.
package msgpackframe

import (
	"encoding/binary"
	"errors"

	"github.com/vmihailenco/msgpack/v5"
)

// ErrInvalidMessagePackFrame reports malformed, truncated or trailing wire
// bytes. It deliberately contains no guest-controlled payload.
var ErrInvalidMessagePackFrame = errors.New("invalid MessagePack frame")

// MessagePackValueSpan returns the byte length of the first complete value.
// It validates structure before typed decoding can allocate from declared
// container sizes. Strings, binary and extension payloads are opaque. The
// scanner allocates no containers and uses constant space even for deep input.
func MessagePackValueSpan(data []byte) (int, error) {
	at := 0
	pending := uint64(1)
	for pending != 0 {
		if at >= len(data) {
			return 0, ErrInvalidMessagePackFrame
		}
		code := data[at]
		at++
		pending--
		var payload, children uint64
		switch {
		case code < 0x80 || code >= 0xe0: // positive/negative fixint
		case code >= 0x80 && code <= 0x8f:
			children = uint64(code&15) * 2
		case code >= 0x90 && code <= 0x9f:
			children = uint64(code & 15)
		case code >= 0xa0 && code <= 0xbf:
			payload = uint64(code & 31)
		default:
			width := 0
			kind := byte(0)
			switch code {
			case 0xc0, 0xc2, 0xc3:
			case 0xc4, 0xd9:
				width = 1
				kind = 'p'
			case 0xc5, 0xda:
				width = 2
				kind = 'p'
			case 0xc6, 0xdb:
				width = 4
				kind = 'p'
			case 0xc7:
				width = 1
				kind = 'e'
			case 0xc8:
				width = 2
				kind = 'e'
			case 0xc9:
				width = 4
				kind = 'e'
			case 0xca, 0xce, 0xd2:
				payload = 4
			case 0xcb, 0xcf, 0xd3:
				payload = 8
			case 0xcc, 0xd0:
				payload = 1
			case 0xcd, 0xd1:
				payload = 2
			case 0xd4:
				payload = 2
			case 0xd5:
				payload = 3
			case 0xd6:
				payload = 5
			case 0xd7:
				payload = 9
			case 0xd8:
				payload = 17
			case 0xdc:
				width = 2
				kind = 'a'
			case 0xdd:
				width = 4
				kind = 'a'
			case 0xde:
				width = 2
				kind = 'm'
			case 0xdf:
				width = 4
				kind = 'm'
			default:
				return 0, ErrInvalidMessagePackFrame
			}
			if width != 0 {
				if len(data)-at < width {
					return 0, ErrInvalidMessagePackFrame
				}
				var count uint64
				switch width {
				case 1:
					count = uint64(data[at])
				case 2:
					count = uint64(binary.BigEndian.Uint16(data[at : at+2]))
				case 4:
					count = uint64(binary.BigEndian.Uint32(data[at : at+4]))
				}
				at += width
				switch kind {
				case 'p':
					payload = count
				case 'e':
					payload = count + 1
				case 'a':
					children = count
				case 'm':
					children = count * 2
				}
			}
		}
		remaining := uint64(len(data) - at)
		if payload > remaining {
			return 0, ErrInvalidMessagePackFrame
		}
		at += int(payload)
		remaining -= payload
		// Every outstanding child needs at least one wire byte. This rejects a
		// tiny frame declaring a huge map before any decoder preallocates it.
		if pending > remaining || children > remaining-pending {
			return 0, ErrInvalidMessagePackFrame
		}
		pending += children
	}
	return at, nil
}

// ValidateMessagePackFrame requires exactly one structurally complete value.
func ValidateMessagePackFrame(data []byte) error {
	n, err := MessagePackValueSpan(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return ErrInvalidMessagePackFrame
	}
	return nil
}

// Unmarshal validates one complete frame before decoding. Structural validation
// does not authorize its contents or impose an application-specific byte limit.
func Unmarshal(data []byte, target any) error {
	if err := ValidateMessagePackFrame(data); err != nil {
		return err
	}
	return msgpack.Unmarshal(data, target)
}
