package main

import (
	"fmt"
	"os"
)

// main runs the golden fixture comparison for the CLI.
//
// It accepts one optional argument: the fixture directory. Without one it uses
// defaultFixtureDir. The process exits 0 when every fixture matches and 1 when
// any fixture mismatches or an error occurs.
func main() {
	dir := defaultFixtureDir()
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	total, mismatches, err := RunFixtureComparison(dir, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger golden: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%d/%d fixtures match\n", total-mismatches, total)
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "%d fixture mismatches\n", mismatches)
		os.Exit(1)
	}
}
