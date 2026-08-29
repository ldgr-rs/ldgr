//! Golden fixtures for canonical RunConfig bytes.
//!
//! Two encoders are covered:
//!
//! - The frozen legacy `v0` encoder, byte-for-byte the unversioned codec that
//!   lived in `ledger-worker/src/proto.rs` before the v1 migration. The
//!   fixtures capture the exact bytes and blake3 hashes the legacy codec
//!   produced on this host (x86_64, 64-bit `usize`). The `baseline` section
//!   matches a build without `sim-fs-journaling`; the `sim-fs-journaling`
//!   section matches a build with it. That feature divergence is exactly what
//!   v1 removes.
//! - The versioned `v1` encoder in `ledger-sim::config_canonical`. The v1
//!   fixture file lives under `crates/ledger-format/tests/fixtures/run-config/`
//!   so the Go conformance runner in that crate's `tests/go/golden` consumes
//!   the same machine-readable corpus.
//!
//! `regenerate_v0_fixtures` and `regenerate_v1_fixtures` are `#[ignore]`d
//! writers; run them on purpose after an approved format change.

use std::path::Path;

use ledger_format::cbor::{self, CborValue};
use ledger_format::hash_from_hex;
use ledger_sim::{
    ConfigCanonicalError, FORMAT_VERSION, LinkConfig, Policy, RunConfig, SimFault, SwarmConfig,
    canonical_hash, from_canonical_bytes, to_canonical_bytes,
};

fn fixtures_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Cross-crate fixture corpus shared with the Go conformance runner.
fn v1_fixture_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("ledger-format")
        .join("tests")
        .join("fixtures")
        .join("run-config")
        .join("run_config_v1.json")
}

fn hex_bytes(text: &str) -> Vec<u8> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.len().is_multiple_of(2), "odd hex length {compact}");
    let mut out = Vec::with_capacity(compact.len() / 2);
    for index in (0..compact.len()).step_by(2) {
        out.push(u8::from_str_radix(&compact[index..index + 2], 16).expect("hex digits"));
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn blake3_hex(bytes: &[u8]) -> String {
    to_hex(blake3::hash(bytes).as_bytes())
}

// ---------------------------------------------------------------------------
// Representative shapes (single source of truth)
// ---------------------------------------------------------------------------

/// One fixed representative shape. The same shapes freeze the legacy v0 bytes
/// and pin the v1 bytes, so the migration delta is visible in both corpora.
fn shapes() -> Vec<RunConfig> {
    let list = vec![
        RunConfig::default(),
        RunConfig::builder().seed([0xab; 32]).build(),
        RunConfig::builder()
            .policy(Policy::Pct {
                priority_changes: 7,
            })
            .build(),
        RunConfig::builder()
            .policy(Policy::Bandit {
                exploration_constant: std::f64::consts::SQRT_2,
                pct_mix: ledger_sim::Probability::new(0.1).unwrap(),
            })
            .build(),
        // Both floats encode as half-precision CBOR floats.
        RunConfig::builder()
            .policy(Policy::Bandit {
                exploration_constant: 0.5,
                pct_mix: ledger_sim::Probability::new(0.25).unwrap(),
            })
            .build(),
        RunConfig::builder().policy(Policy::Replay).build(),
        RunConfig::builder().policy(Policy::Dpor).build(),
        RunConfig::builder().max_steps(1).build(),
        RunConfig::builder().monitor(false).build(),
        rich(),
    ];
    #[cfg(feature = "sim-fs-journaling")]
    {
        let mut list = list;
        list.push(
            RunConfig::builder()
                .fs_journaling(Some(ledger_sim::JournalingMode::Writeback))
                .build(),
        );
        list.push(
            RunConfig::builder()
                .fs_journaling(Some(ledger_sim::JournalingMode::Data))
                .build(),
        );
        list
    }
    #[cfg(not(feature = "sim-fs-journaling"))]
    {
        list
    }
}

fn shape_names() -> Vec<&'static str> {
    let base = [
        "default",
        "custom_seed",
        "policy_pct",
        "policy_bandit",
        "policy_bandit_half",
        "policy_replay",
        "policy_dpor",
        "max_steps_edge",
        "monitor_off",
        "rich",
    ];
    #[cfg(feature = "sim-fs-journaling")]
    {
        let mut names = base.to_vec();
        names.extend(["fs_journaling_writeback", "fs_journaling_data"]);
        names
    }
    #[cfg(not(feature = "sim-fs-journaling"))]
    {
        base.to_vec()
    }
}

/// Every optional field populated, to exercise every sub-encoding once.
fn rich() -> RunConfig {
    let config = RunConfig::builder()
        .seed([0x42; 32])
        .policy(Policy::Pct {
            priority_changes: 3,
        })
        .max_steps(42_042)
        .dropped_events(vec![[0xaa; 32], [0xbb; 32]])
        .swarm(SwarmConfig {
            drop_probability: ledger_sim::Probability::new(0.1).unwrap(),
            delay_probability: ledger_sim::Probability::new(0.2).unwrap(),
            max_delay_ticks: 7,
            crash_probability: ledger_sim::Probability::new(0.05).unwrap(),
            fault_classes_per_run: 4,
        })
        .links(vec![
            (
                0,
                1,
                LinkConfig {
                    base_delay: 5,
                    jitter: 2,
                    loss_probability: ledger_sim::Probability::new(0.5).unwrap(),
                    reorder_window: 3,
                },
            ),
            (
                1,
                0,
                LinkConfig {
                    base_delay: 9,
                    jitter: 1,
                    loss_probability: ledger_sim::Probability::new(0.1).unwrap(),
                    reorder_window: 0,
                },
            ),
        ])
        .fault_schedule(vec![
            SimFault::Drop([0xcc; 32]),
            SimFault::Delay {
                send: [0xdd; 32],
                ticks: 3,
            },
            SimFault::Partition { src: 0, dst: 1 },
            SimFault::Crash([0xee; 32]),
            SimFault::Corrupt {
                write: [0x11; 32],
                xor_mask: 0xff,
            },
            SimFault::CrashState {
                write: [0x22; 32],
                state: 2,
            },
        ])
        .monitor(false)
        .build();
    // Insert out of sorted order; the encoder must sort via DnsTable::iter.
    let mut dns = ledger_sim::DnsTable::new();
    dns.insert("beta.test", 2);
    dns.insert("alpha.test", 1);
    dns.insert("z.example", 4);
    config.with_dns(dns)
}

/// Machine-readable description of one shape, shared with the Go conformance
/// runner. Floats are shortest-round-trip decimal strings.
fn description(config: &RunConfig) -> serde_json::Value {
    let swarm = config.swarm();
    let swarm_value = serde_json::json!({
        "drop_probability": format!("{}", swarm.drop_probability),
        "delay_probability": format!("{}", swarm.delay_probability),
        "max_delay_ticks": swarm.max_delay_ticks,
        "crash_probability": format!("{}", swarm.crash_probability),
        "fault_classes_per_run": swarm.fault_classes_per_run,
    });
    let policy = match config.policy() {
        Policy::Random => serde_json::json!({"tag": "random"}),
        Policy::Pct { priority_changes } => {
            serde_json::json!({"tag": "pct", "priority_changes": priority_changes})
        }
        Policy::Bandit {
            exploration_constant,
            pct_mix,
        } => serde_json::json!({
            "tag": "bandit",
            "exploration_constant": format!("{exploration_constant}"),
            "pct_mix": format!("{pct_mix}"),
        }),
        Policy::Replay => serde_json::json!({"tag": "replay"}),
        Policy::Dpor => serde_json::json!({"tag": "dpor"}),
    };
    let links = config
        .links()
        .iter()
        .map(|(from, to, link)| {
            serde_json::json!({
                "from": from,
                "to": to,
                "base_delay": link.base_delay,
                "jitter": link.jitter,
                "loss_probability": format!("{}", link.loss_probability),
                "reorder_window": link.reorder_window,
            })
        })
        .collect::<Vec<_>>();
    let dns = config
        .dns()
        .iter()
        .map(|(name, actor)| serde_json::json!({"name": name, "actor": actor}))
        .collect::<Vec<_>>();
    let faults = config
        .fault_schedule()
        .iter()
        .map(|fault| match fault {
            SimFault::Drop(id) => serde_json::json!({"tag": "drop", "id": to_hex(id)}),
            SimFault::Delay { send, ticks } => {
                serde_json::json!({"tag": "delay", "send": to_hex(send), "ticks": ticks})
            }
            SimFault::Partition { src, dst } => {
                serde_json::json!({"tag": "partition", "src": src, "dst": dst})
            }
            SimFault::Crash(id) => serde_json::json!({"tag": "crash", "id": to_hex(id)}),
            SimFault::Corrupt { write, xor_mask } => {
                serde_json::json!({"tag": "corrupt", "write": to_hex(write), "xor_mask": xor_mask})
            }
            SimFault::CrashState { write, state } => serde_json::json!({
                "tag": "crash_state",
                "write": to_hex(write),
                "state": state,
            }),
        })
        .collect::<Vec<_>>();
    #[cfg(feature = "sim-fs-journaling")]
    let fs_journaling = match config.fs_journaling() {
        None => serde_json::Value::Null,
        Some(ledger_sim::JournalingMode::Writeback) => serde_json::json!("writeback"),
        Some(ledger_sim::JournalingMode::Ordered) => serde_json::json!("ordered"),
        Some(ledger_sim::JournalingMode::Data) => serde_json::json!("data"),
    };
    #[cfg(not(feature = "sim-fs-journaling"))]
    let fs_journaling = serde_json::Value::Null;
    serde_json::json!({
        "seed": to_hex(&config.seed()),
        "policy": policy,
        "max_steps": config.max_steps(),
        "dropped_events": config.dropped_events().iter().map(|hash| to_hex(hash)).collect::<Vec<_>>(),
        "swarm": swarm_value,
        "links": links,
        "dns": dns,
        "fault_schedule": faults,
        "fs_journaling": fs_journaling,
        "monitor": config.monitor(),
    })
}

fn config_from_description(desc: &serde_json::Value) -> RunConfig {
    let seed = hash_from_hex(desc["seed"].as_str().expect("seed hex")).expect("seed decodes");
    let policy_desc = &desc["policy"];
    let policy = match policy_desc["tag"].as_str().expect("policy tag") {
        "random" => Policy::Random,
        "pct" => Policy::Pct {
            priority_changes: policy_desc["priority_changes"].as_u64().expect("pct") as usize,
        },
        "bandit" => Policy::Bandit {
            exploration_constant: policy_desc["exploration_constant"]
                .as_str()
                .expect("bandit constant")
                .parse()
                .expect("bandit constant parses"),
            pct_mix: policy_desc["pct_mix"]
                .as_str()
                .expect("pct mix")
                .parse()
                .expect("pct mix parses"),
        },
        "replay" => Policy::Replay,
        "dpor" => Policy::Dpor,
        other => panic!("unknown policy tag {other:?}"),
    };
    let swarm = &desc["swarm"];
    let links = desc["links"]
        .as_array()
        .expect("links array")
        .iter()
        .map(|link| {
            (
                link["from"].as_u64().expect("link from") as usize,
                link["to"].as_u64().expect("link to") as usize,
                LinkConfig {
                    base_delay: link["base_delay"].as_u64().expect("base_delay"),
                    jitter: link["jitter"].as_u64().expect("jitter"),
                    loss_probability: link["loss_probability"]
                        .as_str()
                        .expect("loss")
                        .parse()
                        .expect("loss parses"),
                    reorder_window: link["reorder_window"].as_u64().expect("reorder") as usize,
                },
            )
        })
        .collect();
    let mut dns = ledger_sim::DnsTable::new();
    for entry in desc["dns"].as_array().expect("dns array") {
        dns.insert(
            entry["name"].as_str().expect("dns name"),
            entry["actor"].as_u64().expect("dns actor") as usize,
        );
    }
    let faults = desc["fault_schedule"]
        .as_array()
        .expect("faults array")
        .iter()
        .map(|fault| match fault["tag"].as_str().expect("fault tag") {
            "drop" => SimFault::Drop(hash_from_hex(fault["id"].as_str().expect("id")).expect("id")),
            "delay" => SimFault::Delay {
                send: hash_from_hex(fault["send"].as_str().expect("send")).expect("send"),
                ticks: fault["ticks"].as_u64().expect("ticks"),
            },
            "partition" => SimFault::Partition {
                src: fault["src"].as_u64().expect("src") as u32,
                dst: fault["dst"].as_u64().expect("dst") as u32,
            },
            "crash" => {
                SimFault::Crash(hash_from_hex(fault["id"].as_str().expect("id")).expect("id"))
            }
            "corrupt" => SimFault::Corrupt {
                write: hash_from_hex(fault["write"].as_str().expect("write")).expect("write"),
                xor_mask: fault["xor_mask"].as_u64().expect("xor_mask"),
            },
            "crash_state" => SimFault::CrashState {
                write: hash_from_hex(fault["write"].as_str().expect("write")).expect("write"),
                state: fault["state"].as_u64().expect("state"),
            },
            other => panic!("unknown fault tag {other:?}"),
        })
        .collect();
    let builder = RunConfig::builder()
        .seed(seed)
        .policy(policy)
        .max_steps(desc["max_steps"].as_u64().expect("max_steps") as usize)
        .dropped_events(
            desc["dropped_events"]
                .as_array()
                .expect("dropped_events array")
                .iter()
                .map(|hex| hash_from_hex(hex.as_str().expect("dropped hex")).expect("dropped"))
                .collect(),
        )
        .swarm(SwarmConfig {
            drop_probability: swarm["drop_probability"]
                .as_str()
                .expect("drop_probability")
                .parse()
                .expect("drop_probability parses"),
            delay_probability: swarm["delay_probability"]
                .as_str()
                .expect("delay_probability")
                .parse()
                .expect("delay_probability parses"),
            max_delay_ticks: swarm["max_delay_ticks"].as_u64().expect("max_delay_ticks"),
            crash_probability: swarm["crash_probability"]
                .as_str()
                .expect("crash_probability")
                .parse()
                .expect("crash_probability parses"),
            fault_classes_per_run: swarm["fault_classes_per_run"]
                .as_u64()
                .expect("fault_classes_per_run") as usize,
        })
        .links(links)
        .dns(dns)
        .fault_schedule(faults)
        .monitor(desc["monitor"].as_bool().expect("monitor"));
    #[cfg(feature = "sim-fs-journaling")]
    let builder = match &desc["fs_journaling"] {
        serde_json::Value::Null => builder,
        serde_json::Value::String(mode) => {
            let mode = match mode.as_str() {
                "writeback" => ledger_sim::JournalingMode::Writeback,
                "ordered" => ledger_sim::JournalingMode::Ordered,
                "data" => ledger_sim::JournalingMode::Data,
                other => panic!("unknown fs_journaling mode {other:?}"),
            };
            builder.fs_journaling(Some(mode))
        }
        other => panic!("unexpected fs_journaling value {other}"),
    };
    #[cfg(not(feature = "sim-fs-journaling"))]
    {
        assert!(
            matches!(desc["fs_journaling"], serde_json::Value::Null),
            "fs shape needs the sim-fs-journaling feature"
        );
    }
    builder.build()
}

/// Compare two configs field by field; `RunConfig` has no `PartialEq`.
fn assert_config_eq(expected: &RunConfig, actual: &RunConfig) {
    assert_eq!(expected.seed(), actual.seed(), "seed");
    assert_eq!(expected.policy(), actual.policy(), "policy");
    assert_eq!(expected.max_steps(), actual.max_steps(), "max_steps");
    assert_eq!(
        expected.dropped_events(),
        actual.dropped_events(),
        "dropped_events"
    );
    assert_eq!(*expected.swarm(), *actual.swarm(), "swarm");
    assert_eq!(expected.links(), actual.links(), "links");
    assert_eq!(*expected.dns(), *actual.dns(), "dns");
    assert_eq!(
        expected.fault_schedule(),
        actual.fault_schedule(),
        "fault_schedule"
    );
    assert_eq!(expected.monitor(), actual.monitor(), "monitor");
    #[cfg(feature = "sim-fs-journaling")]
    assert_eq!(
        expected.fs_journaling(),
        actual.fs_journaling(),
        "fs_journaling"
    );
}

// ---------------------------------------------------------------------------
// Frozen legacy v0 encoder (byte-for-byte the pre-migration worker codec)
// ---------------------------------------------------------------------------

/// Frozen copy of `ledger-worker::proto::canonical_bytes` at the v0 baseline.
/// The `sim-fs-journaling` tail exists only under the feature, so the legacy
/// bytes diverge across feature builds; the fixtures capture both variants.
fn v0_canonical_bytes(config: &RunConfig) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&config.seed());
    v0_encode_policy(&config.policy(), &mut out);
    out.extend_from_slice(&config.max_steps().to_le_bytes());
    out.push(u8::from(config.monitor()));
    v0_encode_swarm(config.swarm(), &mut out);
    out.extend_from_slice(&(config.dropped_events().len() as u64).to_le_bytes());
    for hash in config.dropped_events() {
        out.extend_from_slice(hash);
    }
    out.extend_from_slice(&(config.links().len() as u64).to_le_bytes());
    for (from, to, link) in config.links() {
        out.extend_from_slice(&(*from as u64).to_le_bytes());
        out.extend_from_slice(&(*to as u64).to_le_bytes());
        out.extend_from_slice(&link.base_delay.to_le_bytes());
        out.extend_from_slice(&link.jitter.to_le_bytes());
        out.extend_from_slice(&link.loss_probability.to_bits().to_le_bytes());
        out.extend_from_slice(&(link.reorder_window as u64).to_le_bytes());
    }
    let dns_count = config.dns().len() as u64;
    out.extend_from_slice(&dns_count.to_le_bytes());
    for (name, actor) in config.dns().iter() {
        let name_bytes = name.as_bytes();
        out.extend_from_slice(&(name_bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&(*actor as u64).to_le_bytes());
    }
    out.extend_from_slice(&(config.fault_schedule().len() as u64).to_le_bytes());
    for fault in config.fault_schedule() {
        v0_encode_fault(fault, &mut out);
    }
    #[cfg(feature = "sim-fs-journaling")]
    match &config.fs_journaling() {
        None => out.push(0),
        Some(mode) => {
            out.push(1);
            let tag = match mode {
                ledger_sim::JournalingMode::Writeback => 0u8,
                ledger_sim::JournalingMode::Ordered => 1u8,
                ledger_sim::JournalingMode::Data => 2u8,
            };
            out.push(tag);
        }
    }
    out
}

fn v0_encode_policy(policy: &Policy, out: &mut Vec<u8>) {
    match policy {
        Policy::Random => out.push(0),
        Policy::Pct { priority_changes } => {
            out.push(1);
            out.extend_from_slice(&(*priority_changes as u64).to_le_bytes());
        }
        Policy::Bandit {
            exploration_constant,
            pct_mix,
        } => {
            out.push(2);
            out.extend_from_slice(&exploration_constant.to_bits().to_le_bytes());
            out.extend_from_slice(&pct_mix.to_bits().to_le_bytes());
        }
        Policy::Replay => out.push(3),
        Policy::Dpor => out.push(4),
    }
}

fn v0_encode_swarm(swarm: &SwarmConfig, out: &mut Vec<u8>) {
    out.extend_from_slice(&swarm.drop_probability.to_bits().to_le_bytes());
    out.extend_from_slice(&swarm.delay_probability.to_bits().to_le_bytes());
    out.extend_from_slice(&swarm.max_delay_ticks.to_le_bytes());
    out.extend_from_slice(&swarm.crash_probability.to_bits().to_le_bytes());
    out.extend_from_slice(&(swarm.fault_classes_per_run as u64).to_le_bytes());
}

fn v0_encode_fault(fault: &SimFault, out: &mut Vec<u8>) {
    match fault {
        SimFault::Drop(id) => {
            out.push(0);
            out.extend_from_slice(id);
        }
        SimFault::Delay { send, ticks } => {
            out.push(1);
            out.extend_from_slice(send);
            out.extend_from_slice(&ticks.to_le_bytes());
        }
        SimFault::Partition { src, dst } => {
            out.push(2);
            out.extend_from_slice(&src.to_le_bytes());
            out.extend_from_slice(&dst.to_le_bytes());
        }
        SimFault::Crash(id) => {
            out.push(3);
            out.extend_from_slice(id);
        }
        SimFault::Corrupt { write, xor_mask } => {
            out.push(4);
            out.extend_from_slice(write);
            out.extend_from_slice(&xor_mask.to_le_bytes());
        }
        SimFault::CrashState { write, state } => {
            out.push(5);
            out.extend_from_slice(write);
            out.extend_from_slice(&state.to_le_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// v0 fixture capture and assertions
// ---------------------------------------------------------------------------

struct ShapeFixture {
    name: String,
    config: serde_json::Value,
    hex: String,
    hash: String,
}

fn v0_fixture_file() -> std::path::PathBuf {
    #[cfg(feature = "sim-fs-journaling")]
    let file_name = "run_config_v0_fs.json";
    #[cfg(not(feature = "sim-fs-journaling"))]
    let file_name = "run_config_v0_baseline.json";
    fixtures_dir().join(file_name)
}

fn write_v0_fixture_file() {
    #[cfg(feature = "sim-fs-journaling")]
    let feature_name = "sim-fs-journaling";
    #[cfg(not(feature = "sim-fs-journaling"))]
    let feature_name = "baseline";
    let shapes = shapes()
        .into_iter()
        .zip(shape_names())
        .map(|(config, name)| {
            let bytes = v0_canonical_bytes(&config);
            serde_json::json!({
                "name": name,
                "config": description(&config),
                "hex": to_hex(&bytes),
                "hash": blake3_hex(&bytes),
            })
        })
        .collect::<Vec<_>>();
    let document = serde_json::json!({
        "schema_version": 1,
        "format": "run-config-canonical",
        "format_version": 0,
        "encoder": "ledger-worker proto::canonical_bytes (unversioned, pre-v1)",
        "feature": feature_name,
        "platform": {
            "pointer_width": 64,
            "note": "v0 encodes usize as 8-byte LE; the bytes are host-width dependent"
        },
        "hash_algorithm": "blake3",
        "shapes": shapes,
    });
    std::fs::create_dir_all(fixtures_dir()).expect("create fixtures dir");
    let path = v0_fixture_file();
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&document).expect("json"),
    )
    .expect("write v0 fixtures");
    eprintln!("wrote {}", path.display());
}

fn read_v0_fixtures() -> Vec<ShapeFixture> {
    let text = std::fs::read_to_string(v0_fixture_file()).expect("read v0 fixture file");
    let document: serde_json::Value = serde_json::from_str(&text).expect("parse v0 fixtures");
    document["shapes"]
        .as_array()
        .expect("shapes array")
        .iter()
        .map(|shape| ShapeFixture {
            name: shape["name"].as_str().expect("name").to_string(),
            config: shape["config"].clone(),
            hex: shape["hex"].as_str().expect("hex").to_string(),
            hash: shape["hash"].as_str().expect("hash").to_string(),
        })
        .collect()
}

/// Regenerate the frozen legacy-v0 fixture file for the current feature build.
///
/// Runs the frozen v0 encoder and writes the exact bytes and blake3 hash the
/// pre-migration `ledger-worker::proto::canonical_bytes` produced. `#[ignore]`d
/// because it overwrites committed golden files.
#[test]
#[ignore]
fn regenerate_v0_fixtures() {
    write_v0_fixture_file();
}

/// The frozen v0 encoder still reproduces the captured legacy bytes, and the
/// captured blake3 hash still matches, before and after the v1 migration.
#[test]
fn frozen_v0_encoder_reproduces_legacy_fixtures() {
    let fixtures = read_v0_fixtures();
    assert_eq!(fixtures.len(), shape_names().len(), "shape count");
    for (fixture, (config, name)) in fixtures.iter().zip(shapes().into_iter().zip(shape_names())) {
        assert_eq!(fixture.name, name, "shape order");
        let bytes = v0_canonical_bytes(&config);
        assert_eq!(to_hex(&bytes), fixture.hex, "v0 bytes for {name}");
        assert_eq!(blake3_hex(&bytes), fixture.hash, "v0 hash for {name}");
    }
}

/// The v0 description table round-trips: a config rebuilt from the fixture
/// description encodes to the same frozen bytes.
#[test]
fn v0_fixture_descriptions_rebuild_the_shapes() {
    let fixtures = read_v0_fixtures();
    for fixture in &fixtures {
        let config = config_from_description(&fixture.config);
        let bytes = v0_canonical_bytes(&config);
        assert_eq!(to_hex(&bytes), fixture.hex, "rebuild for {}", fixture.name);
    }
}

/// v1 bytes differ from the legacy bytes on every shape, proving the migration
/// actually changed the canonical bytes and therefore the hashes.
#[test]
fn v1_bytes_differ_from_legacy_v0_bytes() {
    for (config, name) in shapes().into_iter().zip(shape_names()) {
        let v0 = v0_canonical_bytes(&config);
        let v1 = to_canonical_bytes(&config).expect("v1 encodes");
        assert_ne!(v0, v1, "v1 must differ from v0 for {name}");
    }
}

// ---------------------------------------------------------------------------
// v1 fixture capture and assertions
// ---------------------------------------------------------------------------

/// Regenerate the v1 fixture corpus under `crates/ledger-format/tests/fixtures`.
///
/// Must run with `sim-fs-journaling` enabled so the journaling-FS shapes are
/// included; the encoding itself is feature-independent. `#[ignore]`d because
/// it overwrites the committed cross-language golden file.
#[test]
#[ignore]
#[cfg(feature = "sim-fs-journaling")]
fn regenerate_v1_fixtures() {
    let shapes = shapes()
        .into_iter()
        .zip(shape_names())
        .map(|(config, name)| {
            let bytes = to_canonical_bytes(&config).expect("v1 encodes");
            serde_json::json!({
                "name": name,
                "config": description(&config),
                "hex": to_hex(&bytes),
                "hash": blake3_hex(&bytes),
            })
        })
        .collect::<Vec<_>>();
    let document = serde_json::json!({
        "schema_version": 1,
        "format": "run-config-canonical",
        "format_version": FORMAT_VERSION,
        "encoder": "ledger-sim config_canonical (versioned canonical CBOR)",
        "hash_algorithm": "blake3",
        "shapes": shapes,
    });
    let path = v1_fixture_path();
    std::fs::create_dir_all(path.parent().expect("fixture dir"))
        .expect("create run-config fixture dir");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&document).expect("json"),
    )
    .expect("write v1 fixtures");
    eprintln!("wrote {}", path.display());
}

/// The v1 corpus must cover every shape of the current build, so a new shape
/// without a regenerated `run_config_v1.json` fails here instead of staying
/// silently green.
///
/// With `sim-fs-journaling` the expected set is all twelve shapes. Without the
/// feature the two journaling-mode entries are unbuildable and therefore
/// absent from the buildable set (their decode rejection is asserted
/// separately), so the corpus must equal the ten buildable names plus exactly
/// those two entries.
fn assert_v1_corpus_covers_shapes(fixtures: &[ShapeFixture]) {
    let mut fixture_names = fixtures
        .iter()
        .map(|fixture| fixture.name.as_str())
        .collect::<Vec<_>>();
    fixture_names.sort_unstable();
    let mut expected = shape_names();
    expected.sort_unstable();
    #[cfg(feature = "sim-fs-journaling")]
    assert_eq!(fixture_names, expected, "v1 corpus must cover every shape");
    #[cfg(not(feature = "sim-fs-journaling"))]
    {
        let journaling: Vec<&str> = fixture_names
            .iter()
            .filter(|name| name.starts_with("fs_journaling_"))
            .copied()
            .collect();
        let buildable: Vec<&str> = fixture_names
            .iter()
            .filter(|name| !name.starts_with("fs_journaling_"))
            .copied()
            .collect();
        assert_eq!(
            journaling,
            ["fs_journaling_data", "fs_journaling_writeback"],
            "the only unbuildable corpus entries are the two journaling-mode shapes"
        );
        assert_eq!(
            buildable, expected,
            "v1 corpus must cover every buildable shape"
        );
    }
}

fn read_v1_fixtures() -> Vec<ShapeFixture> {
    let text = std::fs::read_to_string(v1_fixture_path()).expect("read v1 fixture file");
    let document: serde_json::Value = serde_json::from_str(&text).expect("parse v1 fixtures");
    assert_eq!(
        document["format_version"].as_u64(),
        Some(FORMAT_VERSION),
        "fixture format version"
    );
    document["shapes"]
        .as_array()
        .expect("shapes array")
        .iter()
        .map(|shape| ShapeFixture {
            name: shape["name"].as_str().expect("name").to_string(),
            config: shape["config"].clone(),
            hex: shape["hex"].as_str().expect("hex").to_string(),
            hash: shape["hash"].as_str().expect("hash").to_string(),
        })
        .collect()
}

#[test]
fn v1_fixtures_encode_decode_and_hash_match() {
    let fixtures = read_v1_fixtures();
    assert_v1_corpus_covers_shapes(&fixtures);
    for fixture in &fixtures {
        let has_journaling_mode =
            !matches!(fixture.config["fs_journaling"], serde_json::Value::Null);
        if has_journaling_mode && !cfg!(feature = "sim-fs-journaling") {
            // Without the feature the config cannot be built and decode is
            // asserted to reject the document (see
            // v1_decode_rejects_journaling_modes_without_the_feature).
            continue;
        }
        let config = config_from_description(&fixture.config);
        let bytes = to_canonical_bytes(&config).expect("v1 encodes");
        assert_eq!(to_hex(&bytes), fixture.hex, "v1 bytes for {}", fixture.name);
        assert_eq!(
            blake3_hex(&bytes),
            fixture.hash,
            "v1 hash for {}",
            fixture.name
        );
        let decoded = from_canonical_bytes(&bytes).expect("v1 decodes");
        assert_config_eq(&config, &decoded);
        // Decode the fixture bytes directly and re-encode: idempotent.
        let decoded = from_canonical_bytes(&hex_bytes(&fixture.hex)).expect("fixture decodes");
        assert_config_eq(&config, &decoded);
        let reencoded = to_canonical_bytes(&decoded).expect("re-encodes");
        assert_eq!(to_hex(&reencoded), fixture.hex, "decode-encode idempotent");
    }
}

/// Without `sim-fs-journaling` a document carrying a mode is rejected instead
/// of silently dropping data on a decode-encode round trip.
#[test]
#[cfg(not(feature = "sim-fs-journaling"))]
fn v1_decode_rejects_journaling_modes_without_the_feature() {
    let fixtures = read_v1_fixtures();
    for fixture in &fixtures {
        if matches!(fixture.config["fs_journaling"], serde_json::Value::Null) {
            continue;
        }
        let error = from_canonical_bytes(&hex_bytes(&fixture.hex)).expect_err("must reject");
        assert_eq!(
            error,
            ConfigCanonicalError::FsJournalingNotSupported,
            "{}",
            fixture.name
        );
    }
}

// ---------------------------------------------------------------------------
// Module invariants
// ---------------------------------------------------------------------------

#[test]
fn versioned_bytes_start_with_version_one() {
    let bytes = to_canonical_bytes(&RunConfig::default()).expect("encodes");
    // Outer array of two items: 0x82, then unsigned 1 (0x01), then the map.
    assert_eq!(&bytes[..2], &[0x82, 0x01], "document [1, map]");
}

#[test]
fn canonical_hash_matches_blake3_of_canonical_bytes() {
    for config in shapes() {
        let hash = canonical_hash(&config).expect("hashes");
        let bytes = to_canonical_bytes(&config).expect("encodes");
        let expected = *blake3::hash(&bytes).as_bytes();
        assert_eq!(hash, expected);
    }
}

#[test]
fn same_dns_different_insert_order_encodes_equal() {
    let mut dns_a = ledger_sim::DnsTable::new();
    dns_a.insert("z.test", 2);
    dns_a.insert("a.test", 1);
    let mut dns_b = ledger_sim::DnsTable::new();
    dns_b.insert("a.test", 1);
    dns_b.insert("z.test", 2);
    let a = RunConfig::builder().seed([9u8; 32]).dns(dns_a).build();
    let b = RunConfig::builder().seed([9u8; 32]).dns(dns_b).build();
    assert_eq!(
        to_canonical_bytes(&a).expect("a"),
        to_canonical_bytes(&b).expect("b"),
        "dns sorted by name"
    );
}

#[test]
fn encode_rejects_non_finite_floats() {
    for value in [f64::INFINITY, f64::NEG_INFINITY] {
        let err = ledger_sim::Probability::new(value).unwrap_err();
        assert_eq!(err, ledger_sim::ProbabilityError::NonFinite);
        // Decode path still rejects raw non-finite CBOR with typed error.
        let mut fields = minimal_fields();
        set_field(
            &mut fields,
            "swarm",
            CborValue::Array(vec![
                CborValue::Float(value),
                CborValue::Float(0.0),
                CborValue::Unsigned(0),
                CborValue::Float(0.0),
                CborValue::Unsigned(2),
            ]),
        );
        let bytes = craft_document(fields);
        assert_eq!(
            from_canonical_bytes(&bytes).expect_err("non-finite must fail"),
            ConfigCanonicalError::NonFiniteFloat("swarm.drop_probability")
        );
    }
    // NaN is non-canonical CBOR
    assert_eq!(
        ledger_sim::Probability::new(f64::NAN).unwrap_err(),
        ledger_sim::ProbabilityError::NonFinite
    );
    {
        let mut raw = Vec::new();
        ledger_format::cbor::array(&mut raw, 2);
        ledger_format::cbor::unsigned(&mut raw, 1);
        raw.push(0xfb);
        raw.extend_from_slice(&f64::NAN.to_bits().to_be_bytes());
        let err = from_canonical_bytes(&raw).expect_err("nan bits");
        assert!(matches!(err, ConfigCanonicalError::Cbor(_)));
    }
    let bandit = RunConfig::builder()
        .policy(Policy::Bandit {
            exploration_constant: f64::INFINITY,
            pct_mix: ledger_sim::Probability::new(0.1).unwrap(),
        })
        .build();
    assert_eq!(
        to_canonical_bytes(&bandit).expect_err("infinite bandit constant"),
        ConfigCanonicalError::NonFiniteFloat("policy.bandit.exploration_constant")
    );
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let err = ledger_sim::Probability::new(value).unwrap_err();
        assert_eq!(err, ledger_sim::ProbabilityError::NonFinite);
    }
}

/// A swarm delay bound of `u64::MAX` has no representable draw modulus on
/// either side of the canonical boundary: encode refuses it so every decodable
/// document can round-trip, and decode refuses it so the executor never draws
/// against an unrepresentable modulus.
#[test]
fn encode_rejects_unrepresentable_swarm_delay_bound() {
    let config = RunConfig::builder()
        .swarm(SwarmConfig {
            max_delay_ticks: u64::MAX,
            ..SwarmConfig::default()
        })
        .build();
    assert_eq!(
        to_canonical_bytes(&config).expect_err("u64::MAX delay bound"),
        ConfigCanonicalError::InvalidMaxDelayTicks(u64::MAX)
    );
    // The same config with the largest representable bound encodes and
    // round-trips.
    let ok = RunConfig::builder()
        .swarm(SwarmConfig {
            max_delay_ticks: u64::MAX - 1,
            ..SwarmConfig::default()
        })
        .build();
    let bytes = to_canonical_bytes(&ok).expect("largest representable bound");
    let decoded = from_canonical_bytes(&bytes).expect("round trip");
    assert_eq!(decoded.swarm().max_delay_ticks, u64::MAX - 1);
}

#[test]
fn decode_rejects_unrepresentable_swarm_delay_bound() {
    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "swarm",
        CborValue::Array(vec![
            CborValue::Float(0.0),
            CborValue::Float(0.0),
            CborValue::Unsigned(u64::MAX),
            CborValue::Float(0.0),
            CborValue::Unsigned(2),
        ]),
    );
    let bytes = craft_document(fields);
    assert_eq!(
        from_canonical_bytes(&bytes).expect_err("u64::MAX delay bound"),
        ConfigCanonicalError::InvalidMaxDelayTicks(u64::MAX)
    );
}

/// A link jitter of `u64::MAX` has no representable draw modulus on either
/// side of the canonical boundary, matching the swarm delay-bound treatment.
#[test]
fn encode_rejects_unrepresentable_link_jitter() {
    let config = RunConfig::builder()
        .links(vec![(
            0,
            1,
            LinkConfig {
                jitter: u64::MAX,
                ..LinkConfig::default()
            },
        )])
        .build();
    assert_eq!(
        to_canonical_bytes(&config).expect_err("u64::MAX jitter"),
        ConfigCanonicalError::InvalidLinkJitter(u64::MAX)
    );
    // The largest representable jitter encodes and round-trips.
    let ok = RunConfig::builder()
        .links(vec![(
            0,
            1,
            LinkConfig {
                jitter: u64::MAX - 1,
                ..LinkConfig::default()
            },
        )])
        .build();
    let bytes = to_canonical_bytes(&ok).expect("largest representable jitter");
    let decoded = from_canonical_bytes(&bytes).expect("round trip");
    assert_eq!(decoded.links()[0].2.jitter, u64::MAX - 1);
}

#[test]
fn decode_rejects_unrepresentable_link_jitter() {
    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "links",
        CborValue::Array(vec![CborValue::Array(vec![
            CborValue::Unsigned(0),
            CborValue::Unsigned(1),
            CborValue::Array(vec![
                CborValue::Unsigned(0),
                CborValue::Unsigned(u64::MAX),
                CborValue::Float(0.0),
                CborValue::Unsigned(0),
            ]),
        ])]),
    );
    let bytes = craft_document(fields);
    assert_eq!(
        from_canonical_bytes(&bytes).expect_err("u64::MAX jitter"),
        ConfigCanonicalError::InvalidLinkJitter(u64::MAX)
    );
}

// ---------------------------------------------------------------------------
// Malformed-input decode tests (raw CBOR crafted via the public format
// primitives, so every rejected byte pattern is explicit)
// ---------------------------------------------------------------------------

/// Craft a structurally valid v1 document with arbitrary field values.
///
/// The caller controls the map entries, so malformed shapes are easy to build
/// without depending on the encode path.
fn craft_document(fields: Vec<(&str, CborValue)>) -> Vec<u8> {
    let entries = fields
        .into_iter()
        .map(|(name, value)| (CborValue::Text(name.to_string()), value))
        .collect();
    CborValue::Array(vec![
        CborValue::Unsigned(FORMAT_VERSION),
        CborValue::Map(entries),
    ])
    .try_to_canonical_bytes()
    .expect("crafted document encodes")
}

/// Replace the value of one named field in place.
fn set_field(fields: &mut Vec<(&'static str, CborValue)>, name: &'static str, value: CborValue) {
    for (field_name, slot) in fields.iter_mut() {
        if *field_name == name {
            *slot = value;
            return;
        }
    }
    panic!("field {name} not present");
}

fn minimal_fields() -> Vec<(&'static str, CborValue)> {
    vec![
        ("dns", CborValue::Array(Vec::new())),
        ("seed", CborValue::Bytes(vec![0u8; 32])),
        ("links", CborValue::Array(Vec::new())),
        (
            "swarm",
            CborValue::Array(vec![
                CborValue::Float(0.0),
                CborValue::Float(0.0),
                CborValue::Unsigned(0),
                CborValue::Float(0.0),
                CborValue::Unsigned(2),
            ]),
        ),
        ("policy", CborValue::Array(vec![CborValue::Unsigned(0)])),
        ("monitor", CborValue::Bool(true)),
        ("max_steps", CborValue::Unsigned(10_000)),
        ("dropped_events", CborValue::Array(Vec::new())),
        ("fs_journaling", CborValue::Null),
        ("fault_schedule", CborValue::Array(Vec::new())),
    ]
}

fn valid_document() -> Vec<u8> {
    craft_document(minimal_fields())
}

#[test]
fn decode_rejects_wrong_version() {
    let mut bytes = valid_document();
    bytes[1] = 0x02; // version 2 in place of version 1
    assert_eq!(
        from_canonical_bytes(&bytes).expect_err("version 2"),
        ConfigCanonicalError::UnsupportedVersion(2)
    );
}

#[test]
fn decode_rejects_truncated_and_trailing_bytes() {
    let bytes = valid_document();
    for cut in 1..bytes.len() {
        let error = from_canonical_bytes(&bytes[..cut]).expect_err("truncated");
        assert!(
            !matches!(
                error,
                ConfigCanonicalError::WrongDocumentShape
                    | ConfigCanonicalError::MissingField(_)
                    | ConfigCanonicalError::UnsupportedVersion(_)
            ),
            "short {cut} bytes must fail in the CBOR layer, got {error:?}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0x00);
    let error = from_canonical_bytes(&trailing).expect_err("trailing");
    assert!(matches!(error, ConfigCanonicalError::Cbor(_)));
}

#[test]
fn decode_rejects_non_document_shapes() {
    // Single-item array: not [version, map].
    let mut out = Vec::new();
    cbor::array(&mut out, 1);
    cbor::unsigned(&mut out, 1);
    assert_eq!(
        from_canonical_bytes(&out).expect_err("one item"),
        ConfigCanonicalError::WrongDocumentShape
    );
    // Second item not a map.
    let mut out = Vec::new();
    cbor::array(&mut out, 2);
    cbor::unsigned(&mut out, 1);
    cbor::unsigned(&mut out, 0);
    assert_eq!(
        from_canonical_bytes(&out).expect_err("version plus unsigned"),
        ConfigCanonicalError::WrongDocumentShape
    );
}

#[test]
fn decode_rejects_nan_and_infinity_float_bits() {
    // NaN raw bits fail in the canonical CBOR layer (NonCanonicalFloat),
    // surfaced as the typed Cbor wrapper.
    let mut raw = Vec::new();
    cbor::array(&mut raw, 2);
    cbor::unsigned(&mut raw, 1);
    raw.push(0xfb); // float64 header
    raw.extend_from_slice(&f64::NAN.to_bits().to_be_bytes());
    let error = from_canonical_bytes(&raw).expect_err("nan bits");
    assert!(matches!(error, ConfigCanonicalError::Cbor(_)));

    // Infinity is a *valid* canonical CBOR float, so it must be rejected by
    // the run-config layer with the typed error.
    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "swarm",
        CborValue::Array(vec![
            CborValue::Float(f64::INFINITY),
            CborValue::Float(0.0),
            CborValue::Unsigned(0),
            CborValue::Float(0.0),
            CborValue::Unsigned(2),
        ]),
    );
    let bytes = craft_document(fields);
    assert_eq!(
        from_canonical_bytes(&bytes).expect_err("infinity"),
        ConfigCanonicalError::NonFiniteFloat("swarm.drop_probability")
    );
}

#[test]
fn decode_rejects_oversized_declared_lengths() {
    // A map whose declared count exceeds the remaining input: the canonical
    // reader must fail with LengthOverflow instead of over-reading.
    let mut raw = Vec::new();
    cbor::array(&mut raw, 2);
    cbor::unsigned(&mut raw, 1);
    cbor::map(&mut raw, 1_000_000);
    let error = from_canonical_bytes(&raw).expect_err("oversized map");
    assert!(matches!(error, ConfigCanonicalError::Cbor(_)));

    // A nested array inside the map declaring more items than the input can
    // hold must also fail in the CBOR layer.
    let mut raw = Vec::new();
    cbor::array(&mut raw, 2);
    cbor::unsigned(&mut raw, 1);
    cbor::map(&mut raw, 1);
    cbor::text(&mut raw, "dropped_events");
    raw.push(0x97); // array with 2^40 declared items
    cbor::unsigned(&mut raw, 1 << 40);
    let error = from_canonical_bytes(&raw).expect_err("oversized field array");
    assert!(matches!(error, ConfigCanonicalError::Cbor(_)));
}

#[test]
fn decode_rejects_unsorted_and_duplicate_map_keys() {
    // Feed the map entries in reverse canonical order via raw bytes: the
    // canonical reader rejects unsorted keys.
    let mut raw = Vec::new();
    cbor::array(&mut raw, 2);
    cbor::unsigned(&mut raw, 1);
    let entries = [
        "fault_schedule",
        "fs_journaling",
        "dropped_events",
        "max_steps",
        "monitor",
        "policy",
        "swarm",
        "links",
        "seed",
        "dns",
    ];
    cbor::map(&mut raw, entries.len());
    for name in entries {
        cbor::text(&mut raw, name);
        cbor::null(&mut raw);
    }
    let error = from_canonical_bytes(&raw).expect_err("unsorted keys");
    assert!(matches!(error, ConfigCanonicalError::Cbor(_)));

    let mut raw = Vec::new();
    cbor::array(&mut raw, 2);
    cbor::unsigned(&mut raw, 1);
    cbor::map(&mut raw, 2);
    cbor::text(&mut raw, "seed");
    cbor::null(&mut raw);
    cbor::text(&mut raw, "seed");
    cbor::null(&mut raw);
    let error = from_canonical_bytes(&raw).expect_err("duplicate keys");
    assert!(matches!(error, ConfigCanonicalError::Cbor(_)));
}

#[test]
fn decode_rejects_unknown_and_missing_fields() {
    let mut fields = minimal_fields();
    fields.push(("bogus", CborValue::Bool(true)));
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("unknown field");
    assert_eq!(
        error,
        ConfigCanonicalError::UnknownField("bogus".to_string())
    );

    let fields = minimal_fields()
        .into_iter()
        .filter(|(name, _)| *name != "monitor")
        .collect::<Vec<_>>();
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("missing field");
    assert_eq!(error, ConfigCanonicalError::MissingField("monitor"));
}

#[test]
fn decode_rejects_wrong_field_types() {
    let mut fields = minimal_fields();
    set_field(&mut fields, "monitor", CborValue::Unsigned(1));
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("monitor as int");
    assert_eq!(error, ConfigCanonicalError::WrongFieldType("monitor"));

    let mut fields = minimal_fields();
    set_field(&mut fields, "seed", CborValue::Bytes(vec![0u8; 31]));
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("seed 31 bytes");
    assert_eq!(
        error,
        ConfigCanonicalError::InvalidHashLength {
            field: "seed",
            len: 31,
        }
    );
}

#[test]
fn decode_rejects_unknown_policy_and_fault_tags() {
    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "policy",
        CborValue::Array(vec![CborValue::Unsigned(9)]),
    );
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("policy tag 9");
    assert_eq!(error, ConfigCanonicalError::InvalidPolicyTag(9));

    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "fault_schedule",
        CborValue::Array(vec![CborValue::Array(vec![
            CborValue::Unsigned(99),
            CborValue::Bytes(vec![0u8; 32]),
        ])]),
    );
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("fault tag 99");
    assert_eq!(error, ConfigCanonicalError::InvalidFaultTag(99));
}

#[test]
fn decode_rejects_bad_policy_payloads() {
    // Pct without its payload.
    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "policy",
        CborValue::Array(vec![CborValue::Unsigned(1)]),
    );
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("pct payload");
    assert_eq!(error, ConfigCanonicalError::WrongFieldType("policy"));

    // Bandit with a non-float payload.
    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "policy",
        CborValue::Array(vec![
            CborValue::Unsigned(2),
            CborValue::Unsigned(1),
            CborValue::Unsigned(1),
        ]),
    );
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("bandit payload");
    assert_eq!(
        error,
        ConfigCanonicalError::WrongFieldType("policy.bandit.exploration_constant")
    );
}

#[test]
fn decode_rejects_duplicate_and_oversized_dns_names() {
    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "dns",
        CborValue::Array(vec![
            CborValue::Array(vec![
                CborValue::Text("dup.test".into()),
                CborValue::Unsigned(1),
            ]),
            CborValue::Array(vec![
                CborValue::Text("dup.test".into()),
                CborValue::Unsigned(2),
            ]),
        ]),
    );
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("duplicate dns");
    assert_eq!(
        error,
        ConfigCanonicalError::DuplicateDnsName("dup.test".to_string())
    );

    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "dns",
        CborValue::Array(vec![CborValue::Array(vec![
            CborValue::Text("x".repeat(256)),
            CborValue::Unsigned(1),
        ])]),
    );
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("long dns name");
    assert_eq!(error, ConfigCanonicalError::DnsNameTooLong(256));
}

#[test]
fn decode_rejects_bad_swarm_and_link_shapes() {
    let mut fields = minimal_fields();
    // Four items instead of five.
    set_field(
        &mut fields,
        "swarm",
        CborValue::Array(vec![
            CborValue::Float(0.0),
            CborValue::Float(0.0),
            CborValue::Unsigned(0),
            CborValue::Float(0.0),
        ]),
    );
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("swarm 4 items");
    assert_eq!(error, ConfigCanonicalError::WrongFieldType("swarm"));

    let mut fields = minimal_fields();
    set_field(
        &mut fields,
        "links",
        CborValue::Array(vec![CborValue::Array(vec![
            CborValue::Unsigned(0),
            CborValue::Unsigned(1),
            CborValue::Array(vec![
                CborValue::Unsigned(1),
                CborValue::Unsigned(2),
                CborValue::Float(0.5),
            ]),
        ])]),
    );
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("link 3 inner");
    assert_eq!(error, ConfigCanonicalError::WrongFieldType("links"));
}

/// Portrait of a 32-bit target: a `usize` field that fits `u64` but not the
/// pointer width must be rejected by a checked conversion.
#[test]
#[cfg(target_pointer_width = "32")]
fn decode_rejects_usize_overflow_on_32_bit_targets() {
    let mut fields = minimal_fields();
    set_field(&mut fields, "max_steps", CborValue::Unsigned(1 << 40));
    let error = from_canonical_bytes(&craft_document(fields)).expect_err("usize overflow");
    assert_eq!(error, ConfigCanonicalError::IntegerOutOfRange("max_steps"));
}

#[test]
fn decode_rejects_non_canonical_integer_widths() {
    // max_steps = 7 must use the one-byte form; the 16-bit form is
    // non-canonical and the CBOR layer must reject it.
    let mut raw = Vec::new();
    cbor::array(&mut raw, 2);
    cbor::unsigned(&mut raw, 1);
    cbor::map(&mut raw, 2);
    cbor::text(&mut raw, "seed");
    cbor::bytes(&mut raw, &[0u8; 32]);
    cbor::text(&mut raw, "max_steps");
    raw.push(0x19); // uint16 header
    raw.extend_from_slice(&7u16.to_be_bytes());
    let error = from_canonical_bytes(&raw).expect_err("non-canonical width");
    assert!(matches!(error, ConfigCanonicalError::Cbor(_)));
}
