// Package main implements a canonical RFC 8949 Core Deterministic CBOR
// encoder and a differential test runner against the Rust golden fixtures.
//
// The Go encoder must produce byte-identical output to the Rust encoder in
// crates/ledger-format/src/cbor.rs for the shared fixture corpus.
package main

import (
	"bytes"
	"fmt"
	"math"
	"sort"
)

// ValueKind identifies the semantic class of a CBOR data item.
type ValueKind uint8

const (
	// KindUnsigned is CBOR major type 0.
	KindUnsigned ValueKind = iota
	// KindNegative is CBOR major type 1, encoded as -(n+1).
	KindNegative
	// KindBytes is CBOR major type 2.
	KindBytes
	// KindText is CBOR major type 3.
	KindText
	// KindArray is CBOR major type 4.
	KindArray
	// KindMap is CBOR major type 5.
	KindMap
	// KindFloat is CBOR major type 7, an IEEE 754 float.
	KindFloat
	// KindBool is CBOR major type 7, true or false.
	KindBool
	// KindNull is CBOR major type 7, null.
	KindNull
)

// Value is an in-memory CBOR data item.
//
// Only the field matching Kind is meaningful. Negative stores the magnitude n;
// the encoded value is -(n+1).
type Value struct {
	Kind    ValueKind
	Uint    uint64
	Str     string
	Bytes   []byte
	Items   []Value
	Entries []Entry
	Float   float64
	Bool    bool
}

// Entry is one key-value pair of a CBOR map.
type Entry struct {
	Key   Value
	Value Value
}

// EncodeError describes a value that cannot be encoded canonically.
type EncodeError string

// Error returns the message text of the encoding error.
func (e EncodeError) Error() string { return string(e) }

const (
	// ErrNonCanonicalFloat reports -0.0 or NaN, which have no canonical
	// encoding.
	ErrNonCanonicalFloat EncodeError = "float is -0.0, NaN, or not minimal width"
	// ErrDuplicateMapKey reports a map holding two entries whose canonical key
	// bytes are identical.
	ErrDuplicateMapKey EncodeError = "duplicate map key"
)

// Uint returns an unsigned integer value.
func Uint(v uint64) Value { return Value{Kind: KindUnsigned, Uint: v} }

// Negative returns a negative integer value whose encoded form is -(n+1).
func Negative(n uint64) Value { return Value{Kind: KindNegative, Uint: n} }

// Bytes returns a raw byte string value.
func Bytes(b []byte) Value { return Value{Kind: KindBytes, Bytes: b} }

// Text returns a UTF-8 text string value.
func Text(s string) Value { return Value{Kind: KindText, Str: s} }

// Array returns an array value holding items in order.
func Array(items ...Value) Value { return Value{Kind: KindArray, Items: items} }

// Map returns a map value from entries. The encoder sorts the entries
// canonically and rejects duplicate keys.
func Map(entries ...Entry) Value { return Value{Kind: KindMap, Entries: entries} }

// Float returns a float value encoded at the minimal width that round-trips.
func Float(f float64) Value { return Value{Kind: KindFloat, Float: f} }

// Bool returns a boolean value.
func Bool(b bool) Value { return Value{Kind: KindBool, Bool: b} }

// Null returns the null value.
func Null() Value { return Value{Kind: KindNull} }

// Encode returns the canonical CBOR bytes for value, or an error when the
// value cannot be encoded canonically.
func Encode(value Value) ([]byte, error) {
	out := make([]byte, 0, 64)
	out, err := appendValue(out, value)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func appendValue(out []byte, v Value) ([]byte, error) {
	switch v.Kind {
	case KindUnsigned:
		return appendUint(out, 0, v.Uint), nil
	case KindNegative:
		return appendUint(out, 1, v.Uint), nil
	case KindBytes:
		out = appendUint(out, 2, uint64(len(v.Bytes)))
		return append(out, v.Bytes...), nil
	case KindText:
		out = appendUint(out, 3, uint64(len(v.Str)))
		return append(out, v.Str...), nil
	case KindArray:
		out = appendUint(out, 4, uint64(len(v.Items)))
		var err error
		for _, item := range v.Items {
			out, err = appendValue(out, item)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case KindMap:
		return appendMap(out, v.Entries)
	case KindFloat:
		if math.IsNaN(v.Float) || (math.Signbit(v.Float) && v.Float == 0) {
			return nil, ErrNonCanonicalFloat
		}
		return appendMinimalFloat(out, v.Float), nil
	case KindBool:
		if v.Bool {
			return append(out, 0xf5), nil
		}
		return append(out, 0xf4), nil
	case KindNull:
		return append(out, 0xf6), nil
	default:
		return nil, fmt.Errorf("unsupported value kind %d", v.Kind)
	}
}

// appendUint appends a canonical integer of the given major type.
//
// The integer uses the shortest encoding: one byte for 0..23, then 1, 2, 4,
// or 8 additional bytes. This matches RFC 8949 section 3.1 and the Rust
// reference encoder.
func appendUint(out []byte, major byte, v uint64) []byte {
	head := major << 5
	switch {
	case v <= 23:
		return append(out, head|byte(v))
	case v <= math.MaxUint8:
		return append(out, head|24, byte(v))
	case v <= math.MaxUint16:
		return append(out, head|25, byte(v>>8), byte(v))
	case v <= math.MaxUint32:
		return append(out, head|26, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(out,
			head|27,
			byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// encodedEntry holds a pre-encoded map entry so the map can be sorted by its
// canonical key bytes.
type encodedEntry struct {
	key   []byte
	value []byte
}

// appendMap appends a canonical map.
//
// Each key and value is encoded first, duplicate canonical keys are rejected,
// and the entries are sorted by encoded key length then bytewise. This matches
// RFC 8949 section 4.2.3 and the Rust reference encoder.
func appendMap(out []byte, entries []Entry) ([]byte, error) {
	encoded := make([]encodedEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		keyBytes, err := Encode(entry.Key)
		if err != nil {
			return nil, err
		}
		valueBytes, err := Encode(entry.Value)
		if err != nil {
			return nil, err
		}
		keyStr := string(keyBytes)
		if _, dup := seen[keyStr]; dup {
			return nil, ErrDuplicateMapKey
		}
		seen[keyStr] = struct{}{}
		encoded = append(encoded, encodedEntry{key: keyBytes, value: valueBytes})
	}
	sort.Slice(encoded, func(i, j int) bool {
		a, b := encoded[i].key, encoded[j].key
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		return bytes.Compare(a, b) < 0
	})
	out = appendUint(out, 5, uint64(len(entries)))
	for _, entry := range encoded {
		out = append(out, entry.key...)
		out = append(out, entry.value...)
	}
	return out, nil
}

// appendMinimalFloat appends a float at the minimal width that round-trips.
//
// Width selection matches the Rust reference encoder: half precision when the
// value round-trips exactly, else single precision when the value round-trips
// through float32, else double precision. The caller must reject -0.0 and NaN
// before calling this function.
func appendMinimalFloat(out []byte, value float64) []byte {
	if halfBits, ok := valueRoundTripsAsF16(value); ok {
		return append(out, 0xf9, byte(halfBits>>8), byte(halfBits))
	}
	if float64(float32(value)) == value {
		bits := math.Float32bits(float32(value))
		return append(out, 0xfa, byte(bits>>24), byte(bits>>16), byte(bits>>8), byte(bits))
	}
	bits := math.Float64bits(value)
	return append(out,
		0xfb,
		byte(bits>>56), byte(bits>>48), byte(bits>>40), byte(bits>>32),
		byte(bits>>24), byte(bits>>16), byte(bits>>8), byte(bits))
}

// valueRoundTripsAsF16 returns the half-precision bits for value, and true, if
// value round-trips exactly through half precision.
//
// The value must round-trip through float32 first; a value not representable
// in single precision can never be representable in half precision. The final
// round-trip check compares the half value against the original float64.
func valueRoundTripsAsF16(value float64) (uint16, bool) {
	single := float32(value)
	if float64(single) != value {
		return 0, false
	}
	halfBits := f32BitsToF16(math.Float32bits(single))
	if f16BitsToF64(halfBits) == value {
		return halfBits, true
	}
	return 0, false
}

// f32BitsToF16 converts IEEE 754 single-precision bits to half-precision bits
// using round-to-nearest-even on the discarded mantissa bits.
func f32BitsToF16(bits uint32) uint16 {
	sign := uint16((bits >> 16) & 0x8000)
	exp := int32((bits >> 23) & 0xff)
	mant := bits & 0x7fffff

	if exp == 0xff {
		// Infinity or NaN: preserve the class in half precision. Callers
		// reject NaN upstream, so this path only carries a NaN class bit.
		var class uint16
		if mant != 0 {
			class = 1
		}
		return sign | 0x7c00 | class
	}

	exp16 := exp - 127 + 15
	if exp16 >= 0x1f {
		// Magnitude overflows half precision: round to infinity.
		return sign | 0x7c00
	}

	if exp16 > 0 {
		// Normal half value: shift the 23-bit mantissa down 13 bits.
		m16 := uint16(mant >> 13)
		roundBit := (mant >> 12) & 1
		sticky := mant & 0x0fff
		if roundBit == 1 && (sticky != 0 || m16&1 == 1) {
			m16++
			if m16 == 0x400 {
				// Mantissa overflow: carry into the exponent field.
				return sign | uint16(exp16+1)<<10
			}
		}
		return sign | uint16(exp16)<<10 | m16
	}

	// Subnormal or zero in half precision. exp16 <= 0.
	shift := uint32(14 - exp16)
	if shift >= 25 {
		// Magnitude rounds to zero; the round bit is never set at this shift.
		return sign
	}
	full := mant | 0x800000
	m16 := uint16(full >> shift)
	roundBit := (full >> (shift - 1)) & 1
	sticky := full & ((1 << (shift - 1)) - 1)
	if roundBit == 1 && (sticky != 0 || m16&1 == 1) {
		m16++
	}
	return sign | m16
}

// f16BitsToF64 converts half-precision bits to an exact float64. Every half
// value is exactly representable as a double, so the arithmetic is exact.
func f16BitsToF64(bits uint16) float64 {
	sign := 1.0
	if bits&0x8000 != 0 {
		sign = -1.0
	}
	exp := int32((bits >> 10) & 0x1f)
	mant := float64(bits & 0x03ff)
	var magnitude float64
	switch {
	case exp == 0:
		magnitude = mant * math.Exp2(-24)
	case exp == 31:
		if mant == 0 {
			magnitude = math.Inf(1)
		} else {
			magnitude = math.NaN()
		}
	default:
		magnitude = (1.0 + mant/1024.0) * math.Exp2(float64(exp-15))
	}
	return sign * magnitude
}
