# Workloads

A workload is the program ldgr runs inside the simulator. Each workload defines one or more cooperative tasks. A task is a list of instructions or an async function that talks only through effects. The engine schedules those tasks deterministically and journals every effect.

## Scaffolding a workload

The fastest way to start is the scaffold:

```bash
ledger scaffold --template kv ./my-kv
cd ./my-kv && cargo test
```

Templates:

- `consensus` - mini-Raft style replicated log
- `kv` - mini-KV with read/write and replication
- `2pc` - two-phase commit coordinator

Each scaffold emits a crate with a ready workload and tests. Use it as a starting point and replace the logic with your own protocol.

## Task programs

At the lowest level a task is a program: a vector of instructions.

```rust
use ledger_sim::{Instruction, Policy, RunConfig, Simulation};

let programs = vec![
    vec![
        Instruction::Send { to: 1, payload: 42 },
        Instruction::Done,
    ],
    vec![
        Instruction::Receive,
        Instruction::Outcome,
        Instruction::Done,
    ],
];

let config = RunConfig::builder()
    .seed([7; 32])
    .max_steps(256)
    .policy(Policy::Random)
    .build();

let run = Simulation::new(config, programs).run().unwrap();
```

For richer protocols, use `Simulation::with_tasks` with async task builders. Each builder receives a `Boundary` handle and returns a future. The same effects are available there.

## Available effects

Each instruction maps to one effect. Use them instead of host APIs.

| Effect | Instruction | What it does |
| -------- | ------------- | -------------- |
| Messaging | `Send { to, payload }` | Send a payload to another task immediately. |
| Messaging | `SendTimed { to, payload, delay }` | Send with simulated network delay. |
| Messaging | `Receive` | Receive a message or block until one arrives. |
| Time | `Sleep(ticks)` | Sleep for virtual time units. |
| Time | `Yield` | Yield to the scheduler. |
| Time | `ReadClock` | Read virtual time into the task register. |
| Storage | `FsWrite { path, value }` | Write a key-value entry into SimFs. |
| Storage | `FsRead { path }` | Read from SimFs. |
| Storage | `FsFsync` | Persist dirty entries. |
| Storage | `FsCrash` | Trigger a storage crash. |
| Input | `Set(value)` | Record a value (legacy form, zeroed keys). |
| Input | `Input { generator, replay, value }` | Record a value with PBT keys. |
| Assertion | `Assert(bool)` | Record an assertion. |
| Outcome | `Outcome` | Emit an outcome entry from the task register. |
| Control | `Done` | Stop the task. |

*This table is illustrative. Run `ledger scaffold --template kv` for generated, compiling workload code, and `cargo doc --open` for the exact instruction set.*

Example with storage and time:

```rust
vec![
    Instruction::FsWrite { path: "k".into(), value: 1 },
    Instruction::FsFsync,
    Instruction::Sleep(10),
    Instruction::FsRead { path: "k".into() },
    Instruction::Outcome,
    Instruction::Done,
]
```

## Rules for workload code

Workload code must go through effects. It must not call host facilities directly. The lint enforces this on simulation paths.

| Instead of | Use |
| ------------ | ----- |
| `std::time::Instant`, `SystemTime` | `ReadClock` / virtual time |
| `rand::thread_rng`, `getrandom` | seeded RNG via `SeedTree` / `Effects::rng` |
| `std::thread::spawn` | `Simulation::with_tasks` / `Boundary::spawn_task` |
| `std::fs` | `FsWrite` / `FsRead` / `FsFsync` |
| `std::net` | `Send` / `Receive` / `SimNet` |
| `std::env::var` | pass inputs via effects or seeds |

Host-side code (CLI, worker, adapters, the `ldgr-rt` facade) may use host facilities at an explicit boundary. Simulation code may not.

If you need a host API inside a simulation for a justified reason, add a focused `// ledger-lint:allow:<pattern>` comment and keep the justification next to it. Do not add a marker to hide a leak.

## History for oracles

Some workloads expose a history for oracle checks. The `HistoryOperation` view maps journal entries to reads and writes with witness hashes. See `docs/guides/oracles.md` and the scaffolded mini-KV workload for the pattern.
