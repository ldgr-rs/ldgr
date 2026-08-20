package main

// Cross-language conformance for the versioned RunConfig canonical bytes.
//
// The Rust encoder in crates/ledger-sim/src/config_canonical.rs and this Go
// encoder must produce byte-identical output for every fixture in
// crates/ledger-format/tests/fixtures/run-config/run_config_v1.json. The
// blake3 hash column of the fixture file is verified by the Rust test in
// crates/ledger-sim/tests/canonical_config.rs; Go verifies the wire bytes.

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
)

// runConfigFixtureDir locates the shared fixture corpus relative to this
// source file: crates/ledger-format/tests/go/golden -> ../../fixtures.
func runConfigFixtureDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "../fixtures"
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", "fixtures", "run-config")
}

func TestRunConfigConformance(t *testing.T) {
	fixtures, err := loadRunConfigFixtures(filepath.Join(runConfigFixtureDir(), "run_config_v1.json"))
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("fixture corpus is empty")
	}
	for _, fixture := range fixtures {
		var desc runConfigDesc
		if err := json.Unmarshal(fixture.Config, &desc); err != nil {
			t.Fatalf("%s: %v", fixture.Name, err)
		}
		got, err := encodeRunConfig(&desc)
		if err != nil {
			t.Errorf("%s: encode: %v", fixture.Name, err)
			continue
		}
		want, err := decodeHex(fixture.Hex)
		if err != nil {
			t.Fatalf("%s: fixture hex: %v", fixture.Name, err)
		}
		if !bytesEqual(got, want) {
			t.Errorf("%s: bytes mismatch\n got %X\nwant %X", fixture.Name, got, want)
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
