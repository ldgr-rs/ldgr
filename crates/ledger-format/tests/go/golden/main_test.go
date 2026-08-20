package main

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalFloatWidth(t *testing.T) {
	cases := []struct {
		name  string
		value float64
		want  []byte
	}{
		{"half_1.0", 1.0, []byte{0xf9, 0x3c, 0x00}},
		{"half_1.5", 1.5, []byte{0xf9, 0x3e, 0x00}},
		{"single_1_plus_2pow_neg13", 1.0 + math.Exp2(-13), []byte{0xfa, 0x3f, 0x80, 0x04, 0x00}},
		{"double_1e100", 1e100, []byte{0xfb, 0x54, 0xb2, 0x49, 0xad, 0x25, 0x94, 0xc3, 0x7d}},
	}
	for _, tc := range cases {
		got, err := Encode(Float(tc.value))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: got %X want %X", tc.name, got, tc.want)
		}
	}
}

func TestFloatBoundaryWidths(t *testing.T) {
	// Every expected byte pattern below is verified against the Rust reference
	// encoder encode_minimal_float in crates/ledger-format/src/cbor, which
	// the differential corpus also pins. The cases exercise the f32BitsToF16
	// boundary branches: max finite normal, the mantissa-overflow carry, the
	// exponent overflow, subnormals, round-to-zero, and infinities.
	cases := []struct {
		name  string
		value float64
		want  []byte
	}{
		// Max finite half normal (0x7bff): exact in f32, round-trips as half.
		{"max_half_65504", 65504.0, []byte{0xf9, 0x7b, 0xff}},
		// 65520 lies above max half. The f16 conversion keeps 0x7bff (round
		// bit clear), so it does not round-trip: single.
		{"tie_65520", 65520.0, []byte{0xfa, 0x47, 0x7f, 0xf0, 0x00}},
		// 65528 makes m16 carry to 0x400 and then to infinity; it does not
		// round-trip: single.
		{"carry_65528", 65528.0, []byte{0xfa, 0x47, 0x7f, 0xf8, 0x00}},
		// 65536 overflows the half exponent (exp16 >= 0x1f): single.
		{"overflow_65536", 65536.0, []byte{0xfa, 0x47, 0x80, 0x00, 0x00}},
		// Min half subnormal: exact, half 0x0001.
		{"half_min_subnormal_2pow_neg24", math.Exp2(-24), []byte{0xf9, 0x00, 0x01}},
		// Below min half subnormal; the half round-trip fails (rounds to zero),
		// so the width is single. f32 bits of 2^-25 are 0x33000000.
		{"single_2pow_neg25", math.Exp2(-25), []byte{0xfa, 0x33, 0x00, 0x00, 0x00}},
		// Min half normal (0x0400): exact, half.
		{"half_min_normal_2pow_neg14", math.Exp2(-14), []byte{0xf9, 0x04, 0x00}},
		// Min subnormal f32: not representable in half, single with bits
		// 0x00000001.
		{"single_min_subnormal_f32_2pow_neg149", math.Exp2(-149), []byte{0xfa, 0x00, 0x00, 0x00, 0x01}},
		// +Inf and -Inf round-trip through half in the reference encoder: the
		// f16 patterns 0x7c00 and 0xfc00 expand back to the same infinities.
		{"half_pos_inf", math.Inf(1), []byte{0xf9, 0x7c, 0x00}},
		{"half_neg_inf", math.Inf(-1), []byte{0xf9, 0xfc, 0x00}},
		// A f16 subnormal with m = 3 (3 * 2^-24, half 0x0003): exact in f32
		// and in half, so the width is half.
		{"half_subnormal_3_2pow_neg24", 3 * math.Exp2(-24), []byte{0xf9, 0x00, 0x03}},
		// 1.5 * 2^-25 lies strictly between half subnormals (f16 subnormals
		// are integer multiples of 2^-24), so it cannot round-trip in half
		// and encodes as single. This corrects the misconception that any
		// value in (2^-25, 2^-24) is half-representable.
		{"single_1p5_2pow_neg25", 1.5 * math.Exp2(-25), []byte{0xfa, 0x33, 0x40, 0x00, 0x00}},
	}
	for _, tc := range cases {
		got, err := Encode(Float(tc.value))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: got %X want %X", tc.name, got, tc.want)
		}
	}
}

func TestFloatRejectsNonFiniteNonCanonical(t *testing.T) {
	// -0.0 and NaN have no canonical float encoding. Infinities are allowed
	// and encode as half; they are covered by TestFloatBoundaryWidths.
	for _, name := range []string{"neg_zero", "nan"} {
		var value float64
		switch name {
		case "neg_zero":
			value = math.Copysign(0, -1)
		case "nan":
			value = math.NaN()
		}
		if _, err := Encode(Float(value)); err == nil {
			t.Errorf("%s: expected an encoding error", name)
		}
	}
}

func TestMapSortsByLengthThenBytewise(t *testing.T) {
	val := Map(
		Entry{Key: Text("bb"), Value: Uint(3)},
		Entry{Key: Text("a"), Value: Uint(1)},
		Entry{Key: Text("b"), Value: Uint(2)},
	)
	got, err := Encode(val)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xa3, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02, 0x62, 0x62, 0x62, 0x03}
	if !bytes.Equal(got, want) {
		t.Errorf("got %X want %X", got, want)
	}
}

func TestMapSortsLengthBeforeBytewise(t *testing.T) {
	// The key 256 (3 bytes, 0x19 0x01 0x00) sorts after "a" (2 bytes,
	// 0x61 0x61) even though its first byte is smaller. Length precedes
	// bytes in RFC 8949 section 4.2.3.
	val := Map(
		Entry{Key: Uint(256), Value: Uint(2)},
		Entry{Key: Text("a"), Value: Uint(1)},
	)
	got, err := Encode(val)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xa2, 0x61, 0x61, 0x01, 0x19, 0x01, 0x00, 0x02}
	if !bytes.Equal(got, want) {
		t.Errorf("got %X want %X", got, want)
	}
}

func TestShortestFormIntegers(t *testing.T) {
	cases := []struct {
		name string
		kind ValueKind
		n    uint64
		want []byte
	}{
		{"unsigned_0", KindUnsigned, 0, []byte{0x00}},
		{"unsigned_23", KindUnsigned, 23, []byte{0x17}},
		{"unsigned_24", KindUnsigned, 24, []byte{0x18, 0x18}},
		{"unsigned_255", KindUnsigned, 255, []byte{0x18, 0xff}},
		{"unsigned_256", KindUnsigned, 256, []byte{0x19, 0x01, 0x00}},
		{"unsigned_65535", KindUnsigned, 65535, []byte{0x19, 0xff, 0xff}},
		{"unsigned_65536", KindUnsigned, 65536, []byte{0x1a, 0x00, 0x01, 0x00, 0x00}},
		{"unsigned_u32max", KindUnsigned, math.MaxUint32, []byte{0x1a, 0xff, 0xff, 0xff, 0xff}},
		{
			"unsigned_2pow32",
			KindUnsigned,
			1 << 32,
			[]byte{0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		},
		{
			"unsigned_u64max",
			KindUnsigned,
			math.MaxUint64,
			[]byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		{"negative_0", KindNegative, 0, []byte{0x20}},
		{"negative_23", KindNegative, 23, []byte{0x37}},
		{"negative_24", KindNegative, 24, []byte{0x38, 0x18}},
		{"negative_255", KindNegative, 255, []byte{0x38, 0xff}},
		{"negative_256", KindNegative, 256, []byte{0x39, 0x01, 0x00}},
		{"negative_65535", KindNegative, 65535, []byte{0x39, 0xff, 0xff}},
		{"negative_65536", KindNegative, 65536, []byte{0x3a, 0x00, 0x01, 0x00, 0x00}},
		{"negative_2pow32m1", KindNegative, math.MaxUint32, []byte{0x3a, 0xff, 0xff, 0xff, 0xff}},
		{
			"negative_2pow64m1",
			KindNegative,
			math.MaxUint64,
			[]byte{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
	}
	for _, tc := range cases {
		got, err := Encode(Value{Kind: tc.kind, Uint: tc.n})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: got %X want %X", tc.name, got, tc.want)
		}
	}
}

func TestGoldenFixtureDifferential(t *testing.T) {
	dir := fixtureDirFromSource()
	paths, err := listFixturePaths(dir)
	if err != nil {
		t.Fatalf("list fixtures: %v", err)
	}
	if len(paths) < 30 {
		t.Fatalf("fixture corpus too small: %d", len(paths))
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		got, encodeErr := encodeFixture(path)
		if encodeErr != nil {
			t.Errorf("%s: %v", name, encodeErr)
			continue
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("%s: %v", name, readErr)
			continue
		}
		want, decodeErr := hexBytes(string(data))
		if decodeErr != nil {
			t.Errorf("%s: %v", name, decodeErr)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: got %X want %X", name, got, want)
		}
	}

	// The runner must agree with the direct per-fixture check: one ok line
	// per fixture and no mismatch.
	var out bytes.Buffer
	total, mismatches, err := RunFixtureComparison(dir, &out)
	if err != nil {
		t.Fatal(err)
	}
	if total != len(paths) {
		t.Errorf("runner counted %d fixtures, want %d", total, len(paths))
	}
	if mismatches != 0 {
		t.Errorf("runner reported %d mismatches:\n%s", mismatches, out.String())
	}
	if count := strings.Count(out.String(), "ok "); count != total {
		t.Errorf("expected %d ok lines, got %d", total, count)
	}
}

func TestRunFixtureComparisonDetectsMismatch(t *testing.T) {
	dir := t.TempDir()
	// A fixture whose declared value encodes as 0x01 but whose golden hex is
	// 0x05: the runner must report a mismatch and exit-relevant result.
	jsonFile := filepath.Join(dir, "wrong.hex.json")
	hexFile := filepath.Join(dir, "wrong.hex")
	if err := os.WriteFile(jsonFile, []byte(
		`{"schema_version":1,"name":"wrong","description":"","value":{"type":"unsigned","value":1}}`,
	), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hexFile, []byte("05\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	total, mismatches, err := RunFixtureComparison(dir, &out)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("runner counted %d fixtures, want 1", total)
	}
	if mismatches != 1 {
		t.Errorf("runner reported %d mismatches, want 1:\n%s", mismatches, out.String())
	}
	if !strings.Contains(out.String(), "FAIL wrong") {
		t.Errorf("runner output must list the failing fixture, got:\n%s", out.String())
	}
}
