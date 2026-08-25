# Failure specs

Failure specs are small declarative programs that say which faults to inject and when. You write a scenario file, compile it to see what it does, and apply it to a run.

## Workflow

```bash
# See what a scenario does
ledger faults compile --file scenario.fspec

# Run a workload under its faults
ledger faults apply --file scenario.fspec --seed-hex <64-HEX> --workload kv
```

`compile` lists the faults without running anything. `apply` runs the named workload under the compiled fault schedule and prints the result. The default workload is `kv`.

## What a scenario can describe

Scenarios cover the faults you need to test distributed behavior. The DSL supports crash states, network partitions, storage faults at causal positions, and related timing faults. Examples of fault kinds the DSL expresses are `drop`, `partition`, `crash-restart`, `corrupt`, `torn-write`, `clock-skew`, and `bounded-latency`.

The canonical scenario library ships eight named examples: partition, crash-restart, corruption, clock-skew, torn-write, bounded-latency, leader-stepdown, and membership-churn. They live in the failure-spec crate as a compiled library; use `ledger faults compile --file` on your own scenario files and compare against those names.

## Example

A scenario file is line-oriented. From the canonical library:

```fspec
scenario partition
partition leader->replica
```

```fspec
scenario torn-write
torn-write on O_APPEND
```

```fspec
scenario clock-skew
clock-skew replica-2 by 500ms
```

Keep files small and check them with `compile` before running:

```bash
ledger scaffold --template kv ./my-kv
# then write a scenario file, for example ./my-kv/scenario.fspec, with one of the forms above
ledger faults compile --file ./my-kv/scenario.fspec
```

## How it connects to the engine

The scenario compiler produces ordered fault entries and a fault schedule. The same file with the same seed always yields the same schedule. You do not need a live journal to get deterministic results.

## Tips

- Keep scenarios small. One fault kind per scenario makes the minimized output easier to read.
- Use `compile` first. It shows the fault list and catches syntax errors before you spend time on a campaign.
- Pair a scenario with an oracle. A fault without a property to check is just noise. See `docs/guides/oracles.md`.

## Troubleshooting

- `compile` reports a parse error - check the line the error points at. The DSL is line-oriented and whitespace-sensitive. Compare your file to the scenarios in your scaffolded project.
- `apply` reports no faults injected - the scenario compiled but the seed did not hit the fault window. Try a different `--seed-hex` or widen the fault window in the scenario.
- You see many voided faults - the scenario targeted events that did not occur in this run. Narrow the target or run with more steps (`--max-steps`) so the events appear.

## Where to look next

- `ledger faults compile --file scenario.fspec` - compile a scenario and list its faults.
- `ledger scaffold --template kv ./my-kv` - a ready-made workload to pair with scenarios.
- Try the eight canonical names above as starting points and edit from there.
