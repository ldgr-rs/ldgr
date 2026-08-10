package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// fixtureFile is the top-level shape of a fixture expectation file. The value
// field is kept raw because its shape depends on the declared type.
type fixtureFile struct {
	SchemaVersion int             `json:"schema_version"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Value         json.RawMessage `json:"value"`
}

// fixtureEntry is one raw key-value pair of a map fixture.
type fixtureEntry struct {
	Key   json.RawMessage `json:"key"`
	Value json.RawMessage `json:"value"`
}

// fixtureValue is the shape of the "value" object in a fixture file. Only the
// fields used by the declared type are meaningful.
type fixtureValue struct {
	Type    string            `json:"type"`
	Value   json.RawMessage   `json:"value"`
	N       json.RawMessage   `json:"n"`
	Hex     string            `json:"hex"`
	Items   []json.RawMessage `json:"items"`
	Entries []fixtureEntry    `json:"entries"`
}

// listFixturePaths returns the sorted .hex fixture paths in dir.
func listFixturePaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".hex" {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

// hexBytes decodes hex text into bytes, ignoring whitespace.
func hexBytes(text string) ([]byte, error) {
	compact := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		compact = append(compact, c)
	}
	if len(compact)%2 != 0 {
		return nil, errors.New("hex string has odd length")
	}
	out := make([]byte, 0, len(compact)/2)
	for i := 0; i < len(compact); i += 2 {
		hi, err := hexDigit(compact[i])
		if err != nil {
			return nil, err
		}
		lo, err := hexDigit(compact[i+1])
		if err != nil {
			return nil, err
		}
		out = append(out, hi<<4|lo)
	}
	return out, nil
}

// hexDigit converts one hex character to its 4-bit value.
func hexDigit(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex digit %q", c)
	}
}

// rawUint parses a raw JSON number as a uint64.
func rawUint(raw json.RawMessage) (uint64, error) {
	return strconv.ParseUint(string(raw), 10, 64)
}

// parseFixtureValue converts a raw JSON "value" object into a Value. Floats
// are carried as decimal strings in the fixture schema, so the value field is
// decoded as text and parsed with strconv.
func parseFixtureValue(raw json.RawMessage) (Value, error) {
	var fv fixtureValue
	if err := json.Unmarshal(raw, &fv); err != nil {
		return Value{}, err
	}
	switch fv.Type {
	case "unsigned":
		n, err := rawUint(fv.Value)
		if err != nil {
			return Value{}, fmt.Errorf("unsigned value: %w", err)
		}
		return Uint(n), nil
	case "negative":
		n, err := rawUint(fv.N)
		if err != nil {
			return Value{}, fmt.Errorf("negative magnitude: %w", err)
		}
		return Negative(n), nil
	case "text":
		var s string
		if err := json.Unmarshal(fv.Value, &s); err != nil {
			return Value{}, fmt.Errorf("text value: %w", err)
		}
		return Text(s), nil
	case "bytes":
		b, err := hexBytes(fv.Hex)
		if err != nil {
			return Value{}, fmt.Errorf("bytes hex: %w", err)
		}
		return Bytes(b), nil
	case "array":
		items := make([]Value, 0, len(fv.Items))
		for _, rawItem := range fv.Items {
			item, err := parseFixtureValue(rawItem)
			if err != nil {
				return Value{}, err
			}
			items = append(items, item)
		}
		return Array(items...), nil
	case "map":
		entries := make([]Entry, 0, len(fv.Entries))
		for _, pair := range fv.Entries {
			key, err := parseFixtureValue(pair.Key)
			if err != nil {
				return Value{}, err
			}
			val, err := parseFixtureValue(pair.Value)
			if err != nil {
				return Value{}, err
			}
			entries = append(entries, Entry{Key: key, Value: val})
		}
		return Map(entries...), nil
	case "float":
		var s string
		if err := json.Unmarshal(fv.Value, &s); err != nil {
			return Value{}, fmt.Errorf("float value: %w", err)
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return Value{}, fmt.Errorf("float literal %q: %w", s, err)
		}
		return Float(f), nil
	case "bool":
		var b bool
		if err := json.Unmarshal(fv.Value, &b); err != nil {
			return Value{}, fmt.Errorf("bool value: %w", err)
		}
		return Bool(b), nil
	case "null":
		return Null(), nil
	default:
		return Value{}, fmt.Errorf("unknown fixture type %q", fv.Type)
	}
}

// encodeFixture loads the companion .json file for the .hex fixture at path,
// parses the described semantic value, and encodes it canonically.
func encodeFixture(hexPath string) ([]byte, error) {
	jsonPath := strings.TrimSuffix(hexPath, ".hex") + ".json"
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}
	var file fixtureFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", jsonPath, err)
	}
	if file.SchemaVersion != 1 {
		return nil, fmt.Errorf("%s: unsupported schema version %d", jsonPath, file.SchemaVersion)
	}
	value, err := parseFixtureValue(file.Value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", jsonPath, err)
	}
	return Encode(value)
}

// RunFixtureComparison compares the Go encoder output to every golden fixture
// in dir. It writes one "ok <name>" line per matching fixture and one
// "FAIL <name>" line per mismatch. It returns the total fixture count and the
// number of mismatches.
func RunFixtureComparison(dir string, out io.Writer) (total, mismatches int, err error) {
	paths, err := listFixturePaths(dir)
	if err != nil {
		return 0, 0, err
	}
	total = len(paths)
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		got, encodeErr := encodeFixture(path)
		if encodeErr != nil {
			fmt.Fprintf(out, "FAIL %s: %v\n", name, encodeErr)
			mismatches++
			continue
		}
		hexText, readErr := os.ReadFile(path)
		if readErr != nil {
			fmt.Fprintf(out, "FAIL %s: %v\n", name, readErr)
			mismatches++
			continue
		}
		want, decodeErr := hexBytes(string(hexText))
		if decodeErr != nil {
			fmt.Fprintf(out, "FAIL %s: %v\n", name, decodeErr)
			mismatches++
			continue
		}
		if bytes.Equal(got, want) {
			fmt.Fprintf(out, "ok %s\n", name)
		} else {
			fmt.Fprintf(out, "FAIL %s: got %X want %X\n", name, got, want)
			mismatches++
		}
	}
	return total, mismatches, nil
}

// defaultFixtureDir returns the fixture corpus directory for the CLI.
//
// Without an explicit argument the runner searches for the corpus relative to
// the current directory, which is normally the go module directory
// crates/ledger-format/tests/go.
func defaultFixtureDir() string {
	candidates := []string{
		"../fixtures",
		"crates/ledger-format/tests/fixtures",
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return candidates[0]
}

// fixtureDirFromSource returns the fixture corpus directory relative to this
// source file, so tests do not depend on the working directory.
func fixtureDirFromSource() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return defaultFixtureDir()
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", "fixtures")
}
