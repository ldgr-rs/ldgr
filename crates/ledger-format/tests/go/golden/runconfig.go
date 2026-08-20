package main

// RunConfig v1 canonical encoding, implemented independently from the Rust
// codec in crates/ledger-sim/src/config_canonical.rs.
//
// The fixture corpus crates/ledger-format/tests/fixtures/run-config describes
// each shape semantically (seed hex, policy tag, decimal floats, ...). This
// file maps that description onto canonical CBOR with the same field rules as
// the Rust encoder:
//
//   document := [1, { fields }]
//
//   dns           := [ [text name, unsigned actor], ... ]  sorted by name
//   seed          := bytes(32)
//   links         := [ [unsigned from, unsigned to,
//                       [unsigned base_delay, unsigned jitter,
//                        float loss_probability, unsigned reorder_window]], ... ]
//   swarm         := [float drop, float delay, unsigned max_delay_ticks,
//                     float crash, unsigned fault_classes_per_run]
//   policy        := [unsigned tag, ...payload]
//   monitor       := bool
//   max_steps     := unsigned
//   fs_journaling := null | unsigned (0=writeback, 1=ordered, 2=data)
//   dropped_events:= [bytes(32), ...]
//   fault_schedule:= [ [unsigned tag, ...payload], ... ]
//
// Policy tags: 0 random, 1 pct (priority_changes), 2 bandit (two floats),
// 3 replay, 4 dpor. Fault tags: 0 drop (id), 1 delay (send, ticks),
// 2 partition (src, dst), 3 crash (id), 4 corrupt (write, xor_mask),
// 5 crash_state (write, state).
//
// Floats are minimal-width canonical CBOR floats; NaN, +-infinity, and -0.0
// are rejected on encode, exactly like the Rust module.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
)

// runConfigFixture is one entry of the v1 fixture corpus.
type runConfigFixture struct {
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
	Hex    string          `json:"hex"`
}

// runConfigDoc is the top-level v1 fixture document.
type runConfigDoc struct {
	SchemaVersion int                `json:"schema_version"`
	FormatVersion int                `json:"format_version"`
	Shapes        []runConfigFixture `json:"shapes"`
}

// runConfigDesc mirrors the semantic config description in the fixtures.
type runConfigDesc struct {
	Seed          string          `json:"seed"`
	Policy        policyDesc      `json:"policy"`
	MaxSteps      uint64          `json:"max_steps"`
	DroppedEvents []string        `json:"dropped_events"`
	Swarm         swarmDesc       `json:"swarm"`
	Links         []linkDesc      `json:"links"`
	DNS           []dnsDesc       `json:"dns"`
	FaultSchedule []faultDesc     `json:"fault_schedule"`
	FsJournaling  json.RawMessage `json:"fs_journaling"`
	Monitor       bool            `json:"monitor"`
}

type policyDesc struct {
	Tag                 string  `json:"tag"`
	PriorityChanges     uint64  `json:"priority_changes"`
	ExplorationConstant *string `json:"exploration_constant"`
	PctMix              *string `json:"pct_mix"`
}

type swarmDesc struct {
	DropProbability    string `json:"drop_probability"`
	DelayProbability   string `json:"delay_probability"`
	MaxDelayTicks      uint64 `json:"max_delay_ticks"`
	CrashProbability   string `json:"crash_probability"`
	FaultClassesPerRun uint64 `json:"fault_classes_per_run"`
}

type linkDesc struct {
	From            uint64 `json:"from"`
	To              uint64 `json:"to"`
	BaseDelay       uint64 `json:"base_delay"`
	Jitter          uint64 `json:"jitter"`
	LossProbability string `json:"loss_probability"`
	ReorderWindow   uint64 `json:"reorder_window"`
}

type dnsDesc struct {
	Name  string `json:"name"`
	Actor uint64 `json:"actor"`
}

type faultDesc struct {
	Tag     string `json:"tag"`
	ID      string `json:"id"`
	Send    string `json:"send"`
	Ticks   uint64 `json:"ticks"`
	Src     uint64 `json:"src"`
	Dst     uint64 `json:"dst"`
	Write   string `json:"write"`
	XorMask uint64 `json:"xor_mask"`
	State   uint64 `json:"state"`
}

// decodeHex converts a hex string into raw bytes.
func decodeHex(text string) ([]byte, error) {
	compact := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		compact = append(compact, c)
	}
	if len(compact)%2 != 0 {
		return nil, fmt.Errorf("hex string has odd length")
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

// parseDecimalFloat parses a decimal string as a float64, matching the Rust
// parse of the same literal (both produce the correctly rounded double).
func parseDecimalFloat(field, text string) (float64, error) {
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, fmt.Errorf("%s %q: %w", field, text, err)
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Signbit(value) && value == 0 {
		return 0, fmt.Errorf("%s %q: non-finite or -0.0 float", field, text)
	}
	return value, nil
}

// hashBytes returns the fixture value for a 32-byte hash hex string.
func hashBytes(field, text string) (Value, error) {
	raw, err := decodeHex(text)
	if err != nil {
		return Value{}, fmt.Errorf("%s: %w", field, err)
	}
	if len(raw) != 32 {
		return Value{}, fmt.Errorf("%s: hash has %d bytes, want 32", field, len(raw))
	}
	return Bytes(raw), nil
}

// policyValue maps the description onto the policy sub-encoding.
func policyValue(policy policyDesc) (Value, error) {
	switch policy.Tag {
	case "random":
		return Array(Uint(0)), nil
	case "pct":
		return Array(Uint(1), Uint(policy.PriorityChanges)), nil
	case "bandit":
		if policy.ExplorationConstant == nil || policy.PctMix == nil {
			return Value{}, fmt.Errorf("bandit needs exploration_constant and pct_mix")
		}
		exploration, err := parseDecimalFloat("exploration_constant", *policy.ExplorationConstant)
		if err != nil {
			return Value{}, err
		}
		mix, err := parseDecimalFloat("pct_mix", *policy.PctMix)
		if err != nil {
			return Value{}, err
		}
		return Array(Uint(2), Float(exploration), Float(mix)), nil
	case "replay":
		return Array(Uint(3)), nil
	case "dpor":
		return Array(Uint(4)), nil
	default:
		return Value{}, fmt.Errorf("unknown policy tag %q", policy.Tag)
	}
}

// faultValue maps the description onto the fault sub-encoding.
func faultValue(fault faultDesc) (Value, error) {
	switch fault.Tag {
	case "drop":
		id, err := hashBytes("drop.id", fault.ID)
		if err != nil {
			return Value{}, err
		}
		return Array(Uint(0), id), nil
	case "delay":
		send, err := hashBytes("delay.send", fault.Send)
		if err != nil {
			return Value{}, err
		}
		return Array(Uint(1), send, Uint(fault.Ticks)), nil
	case "partition":
		return Array(Uint(2), Uint(fault.Src), Uint(fault.Dst)), nil
	case "crash":
		id, err := hashBytes("crash.id", fault.ID)
		if err != nil {
			return Value{}, err
		}
		return Array(Uint(3), id), nil
	case "corrupt":
		write, err := hashBytes("corrupt.write", fault.Write)
		if err != nil {
			return Value{}, err
		}
		return Array(Uint(4), write, Uint(fault.XorMask)), nil
	case "crash_state":
		write, err := hashBytes("crash_state.write", fault.Write)
		if err != nil {
			return Value{}, err
		}
		return Array(Uint(5), write, Uint(fault.State)), nil
	default:
		return Value{}, fmt.Errorf("unknown fault tag %q", fault.Tag)
	}
}

// fsJournalingValue maps null or a mode name onto the sub-encoding.
func fsJournalingValue(raw json.RawMessage) (Value, error) {
	if string(raw) == "null" {
		return Null(), nil
	}
	var mode string
	if err := json.Unmarshal(raw, &mode); err != nil {
		return Value{}, fmt.Errorf("fs_journaling: %w", err)
	}
	switch mode {
	case "writeback":
		return Uint(0), nil
	case "ordered":
		return Uint(1), nil
	case "data":
		return Uint(2), nil
	default:
		return Value{}, fmt.Errorf("unknown fs_journaling mode %q", mode)
	}
}

// encodeRunConfig maps one fixture description onto canonical v1 bytes.
func encodeRunConfig(desc *runConfigDesc) ([]byte, error) {
	seed, err := hashBytes("seed", desc.Seed)
	if err != nil {
		return nil, err
	}
	policy, err := policyValue(desc.Policy)
	if err != nil {
		return nil, err
	}
	drop, err := parseDecimalFloat("swarm.drop_probability", desc.Swarm.DropProbability)
	if err != nil {
		return nil, err
	}
	delay, err := parseDecimalFloat("swarm.delay_probability", desc.Swarm.DelayProbability)
	if err != nil {
		return nil, err
	}
	crash, err := parseDecimalFloat("swarm.crash_probability", desc.Swarm.CrashProbability)
	if err != nil {
		return nil, err
	}
	swarm := Array(
		Float(drop),
		Float(delay),
		Uint(desc.Swarm.MaxDelayTicks),
		Float(crash),
		Uint(desc.Swarm.FaultClassesPerRun),
	)

	links := make([]Value, 0, len(desc.Links))
	for _, link := range desc.Links {
		loss, err := parseDecimalFloat("links.loss_probability", link.LossProbability)
		if err != nil {
			return nil, err
		}
		links = append(links, Array(
			Uint(link.From),
			Uint(link.To),
			Array(Uint(link.BaseDelay), Uint(link.Jitter), Float(loss), Uint(link.ReorderWindow)),
		))
	}

	// DNS entries travel sorted by name, bytewise, matching DnsTable::iter.
	dnsSorted := append([]dnsDesc(nil), desc.DNS...)
	sort.Slice(dnsSorted, func(i, j int) bool { return dnsSorted[i].Name < dnsSorted[j].Name })
	dnsValues := make([]Value, 0, len(dnsSorted))
	for _, entry := range dnsSorted {
		dnsValues = append(dnsValues, Array(Text(entry.Name), Uint(entry.Actor)))
	}

	dropped := make([]Value, 0, len(desc.DroppedEvents))
	for _, hex := range desc.DroppedEvents {
		hash, err := hashBytes("dropped_events", hex)
		if err != nil {
			return nil, err
		}
		dropped = append(dropped, hash)
	}

	faults := make([]Value, 0, len(desc.FaultSchedule))
	for _, fault := range desc.FaultSchedule {
		value, err := faultValue(fault)
		if err != nil {
			return nil, err
		}
		faults = append(faults, value)
	}

	fsJournaling, err := fsJournalingValue(desc.FsJournaling)
	if err != nil {
		return nil, err
	}

	document := Array(
		Uint(1),
		Map(
			Entry{Key: Text("dns"), Value: Array(dnsValues...)},
			Entry{Key: Text("seed"), Value: seed},
			Entry{Key: Text("links"), Value: Array(links...)},
			Entry{Key: Text("swarm"), Value: swarm},
			Entry{Key: Text("policy"), Value: policy},
			Entry{Key: Text("monitor"), Value: Bool(desc.Monitor)},
			Entry{Key: Text("max_steps"), Value: Uint(desc.MaxSteps)},
			Entry{Key: Text("fs_journaling"), Value: fsJournaling},
			Entry{Key: Text("dropped_events"), Value: Array(dropped...)},
			Entry{Key: Text("fault_schedule"), Value: Array(faults...)},
		),
	)
	return Encode(document)
}

// loadRunConfigFixtures reads the shared v1 fixture corpus.
func loadRunConfigFixtures(path string) ([]runConfigFixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc runConfigDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.SchemaVersion != 1 {
		return nil, fmt.Errorf("%s: unsupported schema version %d", path, doc.SchemaVersion)
	}
	if doc.FormatVersion != 1 {
		return nil, fmt.Errorf("%s: unsupported run-config format version %d", path, doc.FormatVersion)
	}
	return doc.Shapes, nil
}
