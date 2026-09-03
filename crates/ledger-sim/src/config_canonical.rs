//! Versioned canonical encoding for [`RunConfig`].
//!
//! Format version 1 layout, RFC 8949 Core Deterministic CBOR:
//!
//! ```text
//! document := [ 1, { fields } ]
//! ```
//!
//! The outer array carries the format version as its first item and the field
//! map as its second. The map has exactly thirteen keys, ten required and
//! three optional with defaults; the encoder emits them in canonical key
//! order and the decoder rejects any unsorted, duplicate, or unknown key and
//! any missing required key.
//!
//! Canonical key order (RFC 8949 section 4.2.3: encoded key length, then
//! bytewise):
//!
//! ```text
//! dns, seed, links, swarm, policy, monitor, max_steps,
//! reorder_draw, fs_journaling, dropped_events, fault_schedule,
//! max_file_extent, max_resident_bytes
//! ```
//!
//! The 12-byte `reorder_draw` key precedes the 13-byte `fs_journaling` key,
//! which precedes the 14-byte `dropped_events` and `fault_schedule` keys even
//! though `d` sorts before `f` bytewise; encoded length dominates the
//! comparison.
//!
//! Field encodings:
//!
//! ```text
//! dns             := [ [ text name, unsigned actor ], ... ]  sorted by name
//! seed            := bytes(32)
//! links           := [ [ unsigned from, unsigned to,
//!                        [ unsigned base_delay, unsigned jitter,
//!                          float loss_probability, unsigned reorder_window
//!                          (, null | unsigned capacity,
//!                             unsigned queue_policy)? ] ], ... ]
//! swarm           := [ float drop_probability, float delay_probability,
//!                      unsigned max_delay_ticks, float crash_probability,
//!                      unsigned fault_classes_per_run ]
//! policy          := [ unsigned tag, ...payload ]
//! monitor         := bool
//! max_steps       := unsigned
//! dropped_events  := [ bytes(32), ... ]
//! fs_journaling   := null | unsigned mode      (0 = writeback, 1 = ordered, 2 = data)
//! fault_schedule  := [ [ unsigned tag, ...payload ], ... ]
//! reorder_draw    := bool                      (optional, default false)
//! max_file_extent := null | unsigned           (optional, default null)
//! max_resident_bytes := null | unsigned        (optional, default null)
//! ```
//!
//! Link capacity encoding: a link with the default bounded-queue config
//! (`capacity` none, `queue_policy` drop) encodes as the historical 4-item
//! array, byte-identical to format-version-1 documents written before bounded
//! queues existed. A link with a bound or a non-default policy encodes as a
//! 6-item array with `capacity` (`null` for explicit unbounded, unsigned
//! otherwise) and `queue_policy` (`0` drop, `1` block) appended. The decoder
//! accepts 4 (defaults) or 6 (explicit) and rejects any other length, so a
//! configured capacity always changes the canonical bytes and therefore the
//! [`canonical_hash`] digest.
//!
//! Queue policy tags: `0` drop, `1` block.
//!
//! Policy tags and payloads:
//!
//! ```text
//! 0 random  := [ 0 ]
//! 1 pct     := [ 1, unsigned priority_changes ]
//! 2 bandit  := [ 2, float exploration_constant, float pct_mix ]
//! 3 replay  := [ 3 ]
//! 4 dpor    := [ 4 ]
//! ```
//!
//! Fault tags and payloads:
//!
//! ```text
//! 0 drop        := [ 0, bytes(32) id ]
//! 1 delay       := [ 1, bytes(32) send, unsigned ticks ]
//! 2 partition   := [ 2, unsigned src, unsigned dst ]
//! 3 crash       := [ 3, bytes(32) id ]
//! 4 corrupt     := [ 4, bytes(32) write, unsigned xor_mask ]
//! 5 crash_state := [ 5, bytes(32) write, unsigned state ]
//! ```
//!
//! Float rules: every float is a minimal-width canonical CBOR float
//! (half, then single, then double, in that preference order). `NaN`,
//! `+-infinity`, and `-0.0` are rejected on encode and on decode, so the
//! bytes are only defined for finite nonzero-sign probabilities and
//! constants.
//!
//! Feature independence: `fs_journaling` is encoded in every build. A build
//! without `sim-fs-journaling` always writes `null` and rejects any document
//! whose `fs_journaling` is not `null`, so the canonical bytes of an equal
//! config are identical across feature builds.
//!
//! The version 1 bytes supersede the unversioned legacy encoder that lived in
//! `ledger-worker::proto` (see `tests/canonical_config.rs` for the frozen
//! legacy fixtures). `max_steps`, actor ids, and link endpoints are unsigned
//! CBOR integers; the decoder converts with checked `try_from` so the bytes
//! are portable across pointer widths.

use ledger_format::{ActorId, CborError, CborValue, EntryHash};

use crate::config::{Policy, Probability, RunConfig, SimFault, SwarmConfig};
use crate::net::LinkConfig;

/// Current format version of the canonical RunConfig bytes.
pub const FORMAT_VERSION: u64 = 1;

/// Hard bound on one encoded DNS name, in bytes.
///
/// Bounds hostile input before the name joins the decode-side DNS table.
pub const MAX_DNS_NAME_LEN: usize = 255;

/// Typed errors from encoding or decoding canonical RunConfig bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigCanonicalError {
    /// The underlying canonical CBOR codec rejected the value or bytes.
    Cbor(CborError),
    /// The document does not carry the current [`FORMAT_VERSION`].
    UnsupportedVersion(u64),
    /// The document is not the `[version, { fields }]` shape.
    WrongDocumentShape,
    /// The field map holds a key this format does not define.
    UnknownField(String),
    /// The field map omits a required field.
    MissingField(&'static str),
    /// A field holds a value of the wrong CBOR kind.
    WrongFieldType(&'static str),
    /// A 32-byte hash field (seed, dropped event, fault id) has another length.
    InvalidHashLength {
        /// Field name carrying the bad hash.
        field: &'static str,
        /// Actual byte length.
        len: usize,
    },
    /// The policy array carries an unknown tag.
    InvalidPolicyTag(u64),
    /// A fault array carries an unknown tag.
    InvalidFaultTag(u64),
    /// The `fs_journaling` field carries an unknown mode tag.
    InvalidFsJournalingTag(u64),
    /// The document requests a journaling-FS mode but this build has no
    /// `sim-fs-journaling` feature, so the config cannot round-trip.
    FsJournalingNotSupported,
    /// A float field is `NaN` or infinite.
    NonFiniteFloat(&'static str),
    /// A `usize` field does not fit the target pointer width.
    IntegerOutOfRange(&'static str),
    /// The swarm delay bound has no representable draw modulus.
    ///
    /// A bound of `u64::MAX` needs the modulus `2^64`, which does not fit the
    /// wire format or the draw arithmetic; the executor rejects it too.
    InvalidMaxDelayTicks(u64),
    /// A link jitter bound has no representable draw modulus.
    ///
    /// `jitter == u64::MAX` would need the modulus `2^64`; the executor draw
    /// saturates as a direct-construction fallback, but the canonical codec
    /// rejects the value outright.
    InvalidLinkJitter(u64),
    /// A link reorder window exceeds the representable bound.
    InvalidReorderWindow(usize),
    /// A link queue-policy tag is not `0` (drop) or `1` (block).
    InvalidQueuePolicyTag(u64),
    /// A DNS name exceeds [`MAX_DNS_NAME_LEN`] bytes.
    DnsNameTooLong(usize),
    /// Two DNS entries carry the same name; the table would collapse them.
    DuplicateDnsName(String),
    /// A probability field is outside 0.0 ..= 1.0 or is -0.0.
    ProbabilityOutOfRange(&'static str),
}

impl core::fmt::Display for ConfigCanonicalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cbor(error) => write!(f, "canonical CBOR: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported run-config format version: {version}")
            }
            Self::WrongDocumentShape => {
                write!(f, "document is not [version, {{ fields }}]")
            }
            Self::UnknownField(field) => write!(f, "unknown run-config field: {field}"),
            Self::MissingField(field) => write!(f, "missing run-config field: {field}"),
            Self::WrongFieldType(field) => write!(f, "wrong type for run-config field: {field}"),
            Self::InvalidHashLength { field, len } => {
                write!(f, "{field} must be 32 bytes, got {len}")
            }
            Self::InvalidPolicyTag(tag) => write!(f, "unknown policy tag: {tag}"),
            Self::InvalidFaultTag(tag) => write!(f, "unknown fault tag: {tag}"),
            Self::InvalidFsJournalingTag(tag) => write!(f, "unknown fs_journaling tag: {tag}"),
            Self::FsJournalingNotSupported => write!(
                f,
                "non-null fs_journaling needs the sim-fs-journaling feature"
            ),
            Self::NonFiniteFloat(field) => write!(f, "non-finite float in field: {field}"),
            Self::IntegerOutOfRange(field) => {
                write!(f, "integer out of range for field: {field}")
            }
            Self::InvalidMaxDelayTicks(ticks) => write!(
                f,
                "swarm.max_delay_ticks {ticks} has no representable draw modulus"
            ),
            Self::InvalidLinkJitter(ticks) => {
                write!(f, "links.jitter {ticks} has no representable draw modulus")
            }
            Self::InvalidReorderWindow(window) => {
                write!(f, "links.reorder_window {window} exceeds the bound")
            }
            Self::InvalidQueuePolicyTag(tag) => {
                write!(f, "unknown links.queue_policy tag: {tag}")
            }
            Self::DnsNameTooLong(len) => {
                write!(f, "DNS name exceeds {MAX_DNS_NAME_LEN} bytes, got {len}")
            }
            Self::DuplicateDnsName(name) => write!(f, "duplicate DNS name in document: {name}"),
            Self::ProbabilityOutOfRange(field) => {
                write!(f, "probability out of range in field: {field}")
            }
        }
    }
}

impl std::error::Error for ConfigCanonicalError {}

/// Encode `config` as versioned canonical bytes.
///
/// # Errors
/// Returns [`ConfigCanonicalError`] when a float field is `NaN` or infinite,
/// or when the canonical CBOR codec rejects a value.
pub fn to_canonical_bytes(config: &RunConfig) -> Result<Vec<u8>, ConfigCanonicalError> {
    let document = CborValue::Array(vec![
        CborValue::Unsigned(FORMAT_VERSION),
        CborValue::Map(fields(config)?),
    ]);
    document
        .try_to_canonical_bytes()
        .map_err(ConfigCanonicalError::Cbor)
}

/// Decode versioned canonical bytes back into a [`RunConfig`].
///
/// # Errors
/// Returns [`ConfigCanonicalError`] for a wrong version, malformed or
/// non-canonical CBOR, an unknown or missing field, a wrong field type, a
/// non-finite float, an out-of-range integer, an oversized or duplicate DNS
/// name, an unknown policy or fault tag, or a journaling-FS mode this build
/// cannot represent.
pub fn from_canonical_bytes(input: &[u8]) -> Result<RunConfig, ConfigCanonicalError> {
    let document = CborValue::from_canonical_bytes(input).map_err(ConfigCanonicalError::Cbor)?;
    let CborValue::Array(items) = document else {
        return Err(ConfigCanonicalError::WrongDocumentShape);
    };
    if items.len() != 2 {
        return Err(ConfigCanonicalError::WrongDocumentShape);
    }
    let Some(CborValue::Unsigned(version)) = items.first() else {
        return Err(ConfigCanonicalError::WrongDocumentShape);
    };
    if *version != FORMAT_VERSION {
        return Err(ConfigCanonicalError::UnsupportedVersion(*version));
    }
    let CborValue::Map(fields) = &items[1] else {
        return Err(ConfigCanonicalError::WrongDocumentShape);
    };

    let mut seen = [false; 13];
    let mut seed = None;
    let mut policy = None;
    let mut max_steps = None;
    let mut dropped_events = None;
    let mut swarm = None;
    let mut links = None;
    let mut dns = None;
    let mut fault_schedule = None;
    let mut fs_journaling: Option<DecodedJournalingMode> = None;
    let mut monitor = None;
    let mut reorder_draw = false;
    let mut max_file_extent = None;
    let mut max_resident_bytes = None;

    for (key, value) in fields {
        let CborValue::Text(name) = key else {
            return Err(ConfigCanonicalError::WrongFieldType("map key"));
        };
        let index = match name.as_str() {
            "dns" => 0,
            "seed" => 1,
            "links" => 2,
            "swarm" => 3,
            "policy" => 4,
            "monitor" => 5,
            "max_steps" => 6,
            "fs_journaling" => 7,
            "dropped_events" => 8,
            "fault_schedule" => 9,
            "reorder_draw" => 10,
            "max_file_extent" => 11,
            "max_resident_bytes" => 12,
            other => return Err(ConfigCanonicalError::UnknownField(other.to_string())),
        };
        seen[index] = true;
        match index {
            0 => dns = Some(decode_dns(value)?),
            1 => seed = Some(decode_hash(value, "seed")?),
            2 => links = Some(decode_links(value)?),
            3 => swarm = Some(decode_swarm(value)?),
            4 => policy = Some(decode_policy(value)?),
            5 => monitor = Some(bool_of(value, "monitor")?),
            6 => max_steps = Some(usize_of(value, "max_steps")?),
            7 => fs_journaling = Some(decode_fs_journaling(value)?),
            8 => dropped_events = Some(decode_hash_list(value, "dropped_events")?),
            9 => fault_schedule = Some(decode_faults(value)?),
            10 => reorder_draw = bool_of(value, "reorder_draw")?,
            11 => max_file_extent = Some(optional_u64(value, "max_file_extent")?),
            12 => max_resident_bytes = Some(optional_u64(value, "max_resident_bytes")?),
            _ => unreachable!("index bounded to thirteen fields"),
        }
    }

    const FIELD_NAMES: [&str; 10] = [
        "dns",
        "seed",
        "links",
        "swarm",
        "policy",
        "monitor",
        "max_steps",
        "fs_journaling",
        "dropped_events",
        "fault_schedule",
    ];
    let mut missing = None;
    for (index, name) in FIELD_NAMES.iter().enumerate() {
        if !seen[index] {
            missing = Some(*name);
            break;
        }
    }
    // The reorder-draw and budget fields are optional: absent means the
    // defaults (deterministic window pick, format-hard extent, unlimited
    // resident). `null` also means the default, so round trips are stable.
    let reorder_draw = if seen[10] { reorder_draw } else { false };
    let max_file_extent = if seen[11] {
        max_file_extent.unwrap_or(None)
    } else {
        None
    };
    let max_resident_bytes = if seen[12] {
        max_resident_bytes.unwrap_or(None)
    } else {
        None
    };
    let Some(missing) = missing else {
        // Every required field is present; the `let ... else` guards below
        // are therefore unreachable and exist only to keep the typed error
        // path explicit instead of panicking.
        let seed = take_field(seed, "seed")?;
        let policy = take_field(policy, "policy")?;
        let max_steps = take_field(max_steps, "max_steps")?;
        let dropped_events = take_field(dropped_events, "dropped_events")?;
        let swarm = take_field(swarm, "swarm")?;
        let links = take_field(links, "links")?;
        let dns = take_field(dns, "dns")?;
        let fault_schedule = take_field(fault_schedule, "fault_schedule")?;
        #[cfg(feature = "sim-fs-journaling")]
        let fs_journaling = take_field(fs_journaling, "fs_journaling")?;
        #[cfg(not(feature = "sim-fs-journaling"))]
        take_field(fs_journaling, "fs_journaling")?;
        let monitor = take_field(monitor, "monitor")?;
        let builder = crate::config::RunConfigBuilder::new()
            .seed(seed)
            .policy(policy)
            .max_steps(max_steps)
            .dropped_events(dropped_events)
            .swarm(swarm)
            .links(links)
            .dns(dns)
            .fault_schedule(fault_schedule)
            .monitor(monitor)
            .reorder_draw(reorder_draw)
            .fs_budgets(max_file_extent, max_resident_bytes);
        #[cfg(feature = "sim-fs-journaling")]
        let builder = builder.fs_journaling(fs_journaling);
        #[cfg(not(feature = "sim-fs-journaling"))]
        // The decoded field is always `Some(())` here: a missing field already
        // failed above, and `null` maps to `Ok(())`. The unit placeholder can
        // carry no mode in this build, so the value is discarded.
        let _ = fs_journaling;
        return Ok(builder.build());
    };
    Err(ConfigCanonicalError::MissingField(missing))
}

/// The journaling-FS mode carried by a decoded document, when this build can
/// represent one. Without `sim-fs-journaling` the placeholder unit type keeps
/// the decode signature feature-independent.
#[cfg(feature = "sim-fs-journaling")]
type DecodedJournalingMode = Option<crate::simfs::JournalingMode>;
/// See the feature-gated alias; `()` is never a valid decoded mode.
#[cfg(not(feature = "sim-fs-journaling"))]
type DecodedJournalingMode = ();

/// Take one decoded field; the field set is verified complete before any call.
fn take_field<T>(field: Option<T>, name: &'static str) -> Result<T, ConfigCanonicalError> {
    field.ok_or(ConfigCanonicalError::MissingField(name))
}

/// Compute the blake3 hash of the canonical bytes of `config`.
///
/// # Errors
/// Returns [`ConfigCanonicalError`] when [`to_canonical_bytes`] rejects the
/// config.
pub fn canonical_hash(config: &RunConfig) -> Result<EntryHash, ConfigCanonicalError> {
    let bytes = to_canonical_bytes(config)?;
    Ok(EntryHash(*blake3::hash(&bytes).as_bytes()))
}

fn fields(config: &RunConfig) -> Result<Vec<(CborValue, CborValue)>, ConfigCanonicalError> {
    let dns = CborValue::Array(
        config
            .dns()
            .iter()
            .map(|(name, actor)| {
                CborValue::Array(vec![
                    CborValue::Text(name.to_string()),
                    CborValue::Unsigned(u64_of_usize(*actor)),
                ])
            })
            .collect(),
    );
    let seed = CborValue::Bytes(config.seed().0.to_vec());
    let links = CborValue::Array(
        config
            .links()
            .iter()
            .map(|(from, to, link)| {
                Ok(CborValue::Array(vec![
                    CborValue::Unsigned(u64_of_usize(*from)),
                    CborValue::Unsigned(u64_of_usize(*to)),
                    link_value(link)?,
                ]))
            })
            .collect::<Result<Vec<_>, ConfigCanonicalError>>()?,
    );
    let swarm = swarm_value(config.swarm())?;
    let policy = policy_value(&config.policy())?;
    let monitor = CborValue::Bool(config.monitor());
    let max_steps = CborValue::Unsigned(u64_of_usize(config.max_steps()));
    let dropped_events = CborValue::Array(
        config
            .dropped_events()
            .iter()
            .map(|hash| CborValue::Bytes(hash.0.to_vec()))
            .collect(),
    );
    let fs_journaling = fs_journaling_value(config);
    let fault_schedule = CborValue::Array(
        config
            .fault_schedule()
            .iter()
            .map(fault_value)
            .collect::<Result<Vec<_>, ConfigCanonicalError>>()?,
    );
    let reorder_draw = CborValue::Bool(config.reorder_draw());
    let max_file_extent = match config.max_file_extent() {
        Some(bytes) => CborValue::Unsigned(bytes),
        None => CborValue::Null,
    };
    let max_resident_bytes = match config.max_resident_bytes() {
        Some(bytes) => CborValue::Unsigned(bytes),
        None => CborValue::Null,
    };
    Ok(vec![
        (CborValue::Text("dns".into()), dns),
        (CborValue::Text("seed".into()), seed),
        (CborValue::Text("links".into()), links),
        (CborValue::Text("swarm".into()), swarm),
        (CborValue::Text("policy".into()), policy),
        (CborValue::Text("monitor".into()), monitor),
        (CborValue::Text("max_steps".into()), max_steps),
        (CborValue::Text("dropped_events".into()), dropped_events),
        (CborValue::Text("fs_journaling".into()), fs_journaling),
        (CborValue::Text("fault_schedule".into()), fault_schedule),
        (CborValue::Text("reorder_draw".into()), reorder_draw),
        (CborValue::Text("max_file_extent".into()), max_file_extent),
        (
            CborValue::Text("max_resident_bytes".into()),
            max_resident_bytes,
        ),
    ])
}

/// usize to u64 widens without loss on every supported pointer width.
#[inline]
fn u64_of_usize(value: usize) -> u64 {
    value as u64
}

fn float(value: f64, field: &'static str) -> Result<CborValue, ConfigCanonicalError> {
    if !value.is_finite() {
        return Err(ConfigCanonicalError::NonFiniteFloat(field));
    }
    Ok(CborValue::Float(value))
}

fn link_value(link: &LinkConfig) -> Result<CborValue, ConfigCanonicalError> {
    if link.jitter == u64::MAX {
        return Err(ConfigCanonicalError::InvalidLinkJitter(link.jitter));
    }
    if link.reorder_window > crate::net::MAX_REORDER_WINDOW {
        return Err(ConfigCanonicalError::InvalidReorderWindow(
            link.reorder_window,
        ));
    }
    let mut items = vec![
        CborValue::Unsigned(link.base_delay),
        CborValue::Unsigned(link.jitter),
        float(link.loss_probability.get(), "links.loss_probability")?,
        CborValue::Unsigned(u64_of_usize(link.reorder_window)),
    ];
    // Default bounded-queue config keeps the historical 4-item shape so
    // existing documents stay byte-identical. Any bound or non-drop policy
    // appends the capacity and policy, which then join the canonical hash.
    let is_default_queue =
        link.capacity.is_none() && link.queue_policy == crate::net::QueueFullPolicy::Drop;
    if !is_default_queue {
        let capacity = match link.capacity {
            Some(cap) => CborValue::Unsigned(u64_of_usize(cap)),
            None => CborValue::Null,
        };
        let policy = match link.queue_policy {
            crate::net::QueueFullPolicy::Drop => CborValue::Unsigned(0),
            crate::net::QueueFullPolicy::Block => CborValue::Unsigned(1),
        };
        items.push(capacity);
        items.push(policy);
    }
    Ok(CborValue::Array(items))
}

fn swarm_value(swarm: &SwarmConfig) -> Result<CborValue, ConfigCanonicalError> {
    if swarm.max_delay_ticks == u64::MAX {
        return Err(ConfigCanonicalError::InvalidMaxDelayTicks(
            swarm.max_delay_ticks,
        ));
    }
    Ok(CborValue::Array(vec![
        float(swarm.drop_probability.get(), "swarm.drop_probability")?,
        float(swarm.delay_probability.get(), "swarm.delay_probability")?,
        CborValue::Unsigned(swarm.max_delay_ticks),
        float(swarm.crash_probability.get(), "swarm.crash_probability")?,
        CborValue::Unsigned(u64_of_usize(swarm.fault_classes_per_run)),
    ]))
}

fn policy_value(policy: &Policy) -> Result<CborValue, ConfigCanonicalError> {
    Ok(match policy {
        Policy::Random => CborValue::Array(vec![CborValue::Unsigned(0)]),
        Policy::Pct { priority_changes } => CborValue::Array(vec![
            CborValue::Unsigned(1),
            CborValue::Unsigned(u64_of_usize(*priority_changes)),
        ]),
        Policy::Bandit {
            exploration_constant,
            pct_mix,
        } => CborValue::Array(vec![
            CborValue::Unsigned(2),
            float(*exploration_constant, "policy.bandit.exploration_constant")?,
            float(pct_mix.get(), "policy.bandit.pct_mix")?,
        ]),
        Policy::Replay => CborValue::Array(vec![CborValue::Unsigned(3)]),
        Policy::Dpor => CborValue::Array(vec![CborValue::Unsigned(4)]),
    })
}

fn fault_value(fault: &SimFault) -> Result<CborValue, ConfigCanonicalError> {
    Ok(match fault {
        SimFault::Drop(id) => CborValue::Array(vec![
            CborValue::Unsigned(0),
            CborValue::Bytes(id.0.to_vec()),
        ]),
        SimFault::Delay { send, ticks } => CborValue::Array(vec![
            CborValue::Unsigned(1),
            CborValue::Bytes(send.0.to_vec()),
            CborValue::Unsigned(*ticks),
        ]),
        SimFault::Partition { src, dst } => CborValue::Array(vec![
            CborValue::Unsigned(2),
            CborValue::Unsigned(u64::from(src.0)),
            CborValue::Unsigned(u64::from(dst.0)),
        ]),
        SimFault::Crash(id) => CborValue::Array(vec![
            CborValue::Unsigned(3),
            CborValue::Bytes(id.0.to_vec()),
        ]),
        SimFault::Corrupt { write, xor_mask } => CborValue::Array(vec![
            CborValue::Unsigned(4),
            CborValue::Bytes(write.0.to_vec()),
            CborValue::Unsigned(*xor_mask),
        ]),
        SimFault::CrashState { write, state } => CborValue::Array(vec![
            CborValue::Unsigned(5),
            CborValue::Bytes(write.0.to_vec()),
            CborValue::Unsigned(*state),
        ]),
    })
}

#[cfg(feature = "sim-fs-journaling")]
fn fs_journaling_value(config: &RunConfig) -> CborValue {
    match config.fs_journaling() {
        None => CborValue::Null,
        Some(crate::simfs::JournalingMode::Writeback) => CborValue::Unsigned(0),
        Some(crate::simfs::JournalingMode::Ordered) => CborValue::Unsigned(1),
        Some(crate::simfs::JournalingMode::Data) => CborValue::Unsigned(2),
    }
}

/// Encodes `null` in every build without `sim-fs-journaling`, so the bytes of
/// an equal config never depend on the feature set.
#[cfg(not(feature = "sim-fs-journaling"))]
fn fs_journaling_value(_config: &RunConfig) -> CborValue {
    CborValue::Null
}

fn bool_of(value: &CborValue, field: &'static str) -> Result<bool, ConfigCanonicalError> {
    match value {
        CborValue::Bool(value) => Ok(*value),
        _ => Err(ConfigCanonicalError::WrongFieldType(field)),
    }
}

fn usize_of(value: &CborValue, field: &'static str) -> Result<usize, ConfigCanonicalError> {
    match value {
        CborValue::Unsigned(value) => {
            usize::try_from(*value).map_err(|_| ConfigCanonicalError::IntegerOutOfRange(field))
        }
        _ => Err(ConfigCanonicalError::WrongFieldType(field)),
    }
}

/// Decode an optional `u64`: `null` or absent means `None`; a non-negative
/// integer is `Some`. Any other shape is a type error.
fn optional_u64(
    value: &CborValue,
    field: &'static str,
) -> Result<Option<u64>, ConfigCanonicalError> {
    match value {
        CborValue::Null => Ok(None),
        CborValue::Unsigned(value) => Ok(Some(*value)),
        _ => Err(ConfigCanonicalError::WrongFieldType(field)),
    }
}

fn u32_of(value: &CborValue, field: &'static str) -> Result<u32, ConfigCanonicalError> {
    match value {
        CborValue::Unsigned(value) => {
            u32::try_from(*value).map_err(|_| ConfigCanonicalError::IntegerOutOfRange(field))
        }
        _ => Err(ConfigCanonicalError::WrongFieldType(field)),
    }
}

fn u64_of(value: &CborValue, field: &'static str) -> Result<u64, ConfigCanonicalError> {
    match value {
        CborValue::Unsigned(value) => Ok(*value),
        _ => Err(ConfigCanonicalError::WrongFieldType(field)),
    }
}

fn finite_float_of(value: &CborValue, field: &'static str) -> Result<f64, ConfigCanonicalError> {
    match value {
        CborValue::Float(value) if value.is_finite() => Ok(*value),
        CborValue::Float(_) => Err(ConfigCanonicalError::NonFiniteFloat(field)),
        _ => Err(ConfigCanonicalError::WrongFieldType(field)),
    }
}

fn probability_of(
    value: &CborValue,
    field: &'static str,
) -> Result<Probability, ConfigCanonicalError> {
    match value {
        CborValue::Float(v) => {
            if !v.is_finite() {
                return Err(ConfigCanonicalError::NonFiniteFloat(field));
            }
            if v.is_sign_negative() || *v > 1.0 {
                return Err(ConfigCanonicalError::ProbabilityOutOfRange(field));
            }
            // Validated, so construction cannot fail.
            Ok(Probability::new(*v)
                .map_err(|_| ConfigCanonicalError::ProbabilityOutOfRange(field))?)
        }
        _ => Err(ConfigCanonicalError::WrongFieldType(field)),
    }
}

fn decode_hash(value: &CborValue, field: &'static str) -> Result<EntryHash, ConfigCanonicalError> {
    match value {
        CborValue::Bytes(bytes) => <[u8; 32]>::try_from(bytes.as_slice())
            .map(EntryHash)
            .map_err(|_| ConfigCanonicalError::InvalidHashLength {
                field,
                len: bytes.len(),
            }),
        _ => Err(ConfigCanonicalError::WrongFieldType(field)),
    }
}

fn decode_hash_list(
    value: &CborValue,
    field: &'static str,
) -> Result<Vec<EntryHash>, ConfigCanonicalError> {
    let CborValue::Array(items) = value else {
        return Err(ConfigCanonicalError::WrongFieldType(field));
    };
    items.iter().map(|item| decode_hash(item, field)).collect()
}

fn decode_policy(value: &CborValue) -> Result<Policy, ConfigCanonicalError> {
    let CborValue::Array(items) = value else {
        return Err(ConfigCanonicalError::WrongFieldType("policy"));
    };
    let Some((CborValue::Unsigned(tag), rest)) = items.split_first() else {
        return Err(ConfigCanonicalError::WrongFieldType("policy"));
    };
    match tag {
        0 => {
            expect_empty(rest, "policy")?;
            Ok(Policy::Random)
        }
        1 => {
            expect_len(rest, 1, "policy")?;
            Ok(Policy::Pct {
                priority_changes: usize_of(&rest[0], "policy.pct.priority_changes")?,
            })
        }
        2 => {
            expect_len(rest, 2, "policy")?;
            Ok(Policy::Bandit {
                exploration_constant: finite_float_of(
                    &rest[0],
                    "policy.bandit.exploration_constant",
                )?,
                pct_mix: probability_of(&rest[1], "policy.bandit.pct_mix")?,
            })
        }
        3 => {
            expect_empty(rest, "policy")?;
            Ok(Policy::Replay)
        }
        4 => {
            expect_empty(rest, "policy")?;
            Ok(Policy::Dpor)
        }
        other => Err(ConfigCanonicalError::InvalidPolicyTag(*other)),
    }
}

fn decode_swarm(value: &CborValue) -> Result<SwarmConfig, ConfigCanonicalError> {
    let CborValue::Array(items) = value else {
        return Err(ConfigCanonicalError::WrongFieldType("swarm"));
    };
    expect_len(items, 5, "swarm")?;
    let max_delay_ticks = u64_of(&items[2], "swarm.max_delay_ticks")?;
    if max_delay_ticks == u64::MAX {
        return Err(ConfigCanonicalError::InvalidMaxDelayTicks(max_delay_ticks));
    }
    Ok(SwarmConfig {
        drop_probability: probability_of(&items[0], "swarm.drop_probability")?,
        delay_probability: probability_of(&items[1], "swarm.delay_probability")?,
        max_delay_ticks,
        crash_probability: probability_of(&items[3], "swarm.crash_probability")?,
        fault_classes_per_run: usize_of(&items[4], "swarm.fault_classes_per_run")?,
    })
}

fn decode_links(
    value: &CborValue,
) -> Result<Vec<(usize, usize, LinkConfig)>, ConfigCanonicalError> {
    let CborValue::Array(items) = value else {
        return Err(ConfigCanonicalError::WrongFieldType("links"));
    };
    items.iter().map(decode_link).collect()
}

fn decode_link(value: &CborValue) -> Result<(usize, usize, LinkConfig), ConfigCanonicalError> {
    let CborValue::Array(items) = value else {
        return Err(ConfigCanonicalError::WrongFieldType("links"));
    };
    expect_len(items, 3, "links")?;
    let CborValue::Array(link_items) = &items[2] else {
        return Err(ConfigCanonicalError::WrongFieldType("links"));
    };
    if link_items.len() != 4 && link_items.len() != 6 {
        return Err(ConfigCanonicalError::WrongFieldType("links"));
    }
    let jitter = u64_of(&link_items[1], "links.jitter")?;
    if jitter == u64::MAX {
        return Err(ConfigCanonicalError::InvalidLinkJitter(jitter));
    }
    let reorder_window = usize_of(&link_items[3], "links.reorder_window")?;
    if reorder_window > crate::net::MAX_REORDER_WINDOW {
        return Err(ConfigCanonicalError::InvalidReorderWindow(reorder_window));
    }
    let (capacity, queue_policy) = if link_items.len() == 4 {
        (None, crate::net::QueueFullPolicy::Drop)
    } else {
        let capacity = match &link_items[4] {
            CborValue::Null => None,
            CborValue::Unsigned(cap) => Some(
                usize::try_from(*cap)
                    .map_err(|_| ConfigCanonicalError::IntegerOutOfRange("links.capacity"))?,
            ),
            _ => return Err(ConfigCanonicalError::WrongFieldType("links.capacity")),
        };
        let queue_policy = match &link_items[5] {
            CborValue::Unsigned(0) => crate::net::QueueFullPolicy::Drop,
            CborValue::Unsigned(1) => crate::net::QueueFullPolicy::Block,
            CborValue::Unsigned(tag) => {
                return Err(ConfigCanonicalError::InvalidQueuePolicyTag(*tag));
            }
            _ => return Err(ConfigCanonicalError::WrongFieldType("links.queue_policy")),
        };
        (capacity, queue_policy)
    };
    Ok((
        usize_of(&items[0], "links.from")?,
        usize_of(&items[1], "links.to")?,
        LinkConfig {
            base_delay: u64_of(&link_items[0], "links.base_delay")?,
            jitter,
            loss_probability: probability_of(&link_items[2], "links.loss_probability")?,
            reorder_window,
            capacity,
            queue_policy,
        },
    ))
}

fn decode_dns(value: &CborValue) -> Result<crate::net::DnsTable, ConfigCanonicalError> {
    let CborValue::Array(items) = value else {
        return Err(ConfigCanonicalError::WrongFieldType("dns"));
    };
    let mut table = crate::net::DnsTable::new();
    for item in items {
        let CborValue::Array(entry) = item else {
            return Err(ConfigCanonicalError::WrongFieldType("dns"));
        };
        expect_len(entry, 2, "dns")?;
        let CborValue::Text(name) = &entry[0] else {
            return Err(ConfigCanonicalError::WrongFieldType("dns.name"));
        };
        if name.len() > MAX_DNS_NAME_LEN {
            return Err(ConfigCanonicalError::DnsNameTooLong(name.len()));
        }
        let actor = usize_of(&entry[1], "dns.actor")?;
        if table.insert(name.clone(), actor) {
            return Err(ConfigCanonicalError::DuplicateDnsName(name.clone()));
        }
    }
    Ok(table)
}

fn decode_faults(value: &CborValue) -> Result<Vec<SimFault>, ConfigCanonicalError> {
    let CborValue::Array(items) = value else {
        return Err(ConfigCanonicalError::WrongFieldType("fault_schedule"));
    };
    items.iter().map(decode_fault).collect()
}

fn decode_fault(value: &CborValue) -> Result<SimFault, ConfigCanonicalError> {
    let CborValue::Array(items) = value else {
        return Err(ConfigCanonicalError::WrongFieldType("fault_schedule"));
    };
    let Some((CborValue::Unsigned(tag), rest)) = items.split_first() else {
        return Err(ConfigCanonicalError::WrongFieldType("fault_schedule"));
    };
    match tag {
        0 => {
            expect_len(rest, 1, "fault_schedule")?;
            Ok(SimFault::Drop(decode_hash(
                &rest[0],
                "fault_schedule.drop.id",
            )?))
        }
        1 => {
            expect_len(rest, 2, "fault_schedule")?;
            Ok(SimFault::Delay {
                send: decode_hash(&rest[0], "fault_schedule.delay.send")?,
                ticks: u64_of(&rest[1], "fault_schedule.delay.ticks")?,
            })
        }
        2 => {
            expect_len(rest, 2, "fault_schedule")?;
            Ok(SimFault::Partition {
                src: ActorId(u32_of(&rest[0], "fault_schedule.partition.src")?),
                dst: ActorId(u32_of(&rest[1], "fault_schedule.partition.dst")?),
            })
        }
        3 => {
            expect_len(rest, 1, "fault_schedule")?;
            Ok(SimFault::Crash(decode_hash(
                &rest[0],
                "fault_schedule.crash.id",
            )?))
        }
        4 => {
            expect_len(rest, 2, "fault_schedule")?;
            Ok(SimFault::Corrupt {
                write: decode_hash(&rest[0], "fault_schedule.corrupt.write")?,
                xor_mask: u64_of(&rest[1], "fault_schedule.corrupt.xor_mask")?,
            })
        }
        5 => {
            expect_len(rest, 2, "fault_schedule")?;
            Ok(SimFault::CrashState {
                write: decode_hash(&rest[0], "fault_schedule.crash_state.write")?,
                state: u64_of(&rest[1], "fault_schedule.crash_state.state")?,
            })
        }
        other => Err(ConfigCanonicalError::InvalidFaultTag(*other)),
    }
}

#[cfg(feature = "sim-fs-journaling")]
fn decode_fs_journaling(
    value: &CborValue,
) -> Result<Option<crate::simfs::JournalingMode>, ConfigCanonicalError> {
    match value {
        CborValue::Null => Ok(None),
        CborValue::Unsigned(0) => Ok(Some(crate::simfs::JournalingMode::Writeback)),
        CborValue::Unsigned(1) => Ok(Some(crate::simfs::JournalingMode::Ordered)),
        CborValue::Unsigned(2) => Ok(Some(crate::simfs::JournalingMode::Data)),
        CborValue::Unsigned(tag) => Err(ConfigCanonicalError::InvalidFsJournalingTag(*tag)),
        _ => Err(ConfigCanonicalError::WrongFieldType("fs_journaling")),
    }
}

#[cfg(not(feature = "sim-fs-journaling"))]
fn decode_fs_journaling(value: &CborValue) -> Result<DecodedJournalingMode, ConfigCanonicalError> {
    match value {
        CborValue::Null => Ok(()),
        CborValue::Unsigned(0..=2) => Err(ConfigCanonicalError::FsJournalingNotSupported),
        CborValue::Unsigned(tag) => Err(ConfigCanonicalError::InvalidFsJournalingTag(*tag)),
        _ => Err(ConfigCanonicalError::WrongFieldType("fs_journaling")),
    }
}

fn expect_len(
    items: &[CborValue],
    expected: usize,
    field: &'static str,
) -> Result<(), ConfigCanonicalError> {
    if items.len() == expected {
        Ok(())
    } else {
        Err(ConfigCanonicalError::WrongFieldType(field))
    }
}

fn expect_empty(items: &[CborValue], field: &'static str) -> Result<(), ConfigCanonicalError> {
    expect_len(items, 0, field)
}

#[cfg(test)]
mod probability_tests {
    use super::*;
    use crate::config::{Probability, SwarmConfig};
    use crate::net::LinkConfig;
    use ledger_format::CborValue;

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

    fn set_field(
        fields: &mut Vec<(&'static str, CborValue)>,
        name: &'static str,
        value: CborValue,
    ) {
        for (field_name, slot) in fields.iter_mut() {
            if *field_name == name {
                *slot = value;
                return;
            }
        }
        panic!("field {name} not present");
    }

    #[test]
    fn probability_decode_rejects_invalid_per_slot() {
        // NaN is non-canonical CBOR, rejected at CBOR layer; infinities at run-config layer
        assert_eq!(
            crate::config::Probability::new(f64::NAN).unwrap_err(),
            crate::config::ProbabilityError::NonFinite
        );
        let invalid = [
            (
                f64::INFINITY,
                ConfigCanonicalError::NonFiniteFloat("swarm.drop_probability"),
            ),
            (
                f64::NEG_INFINITY,
                ConfigCanonicalError::NonFiniteFloat("swarm.drop_probability"),
            ),
        ];
        for (value, expected) in invalid {
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
            let bytes = match CborValue::Array(vec![
                CborValue::Unsigned(FORMAT_VERSION),
                CborValue::Map(
                    fields
                        .into_iter()
                        .map(|(n, v)| (CborValue::Text(n.to_string()), v))
                        .collect(),
                ),
            ])
            .try_to_canonical_bytes()
            {
                Ok(b) => b,
                Err(e) => panic!("craft failed for value {:?} err {:?}", value, e),
            };
            let err = from_canonical_bytes(&bytes).expect_err("must reject");
            assert_eq!(err, expected);
        }
        // -0.0 is non-canonical CBOR, rejected at CBOR layer; >1 at Probability layer
        assert_eq!(
            crate::config::Probability::new(-0.0).unwrap_err(),
            crate::config::ProbabilityError::OutOfRange
        );
        {
            let fields = vec![
                ("dns", CborValue::Array(Vec::new())),
                ("seed", CborValue::Bytes(vec![0u8; 32])),
                ("links", CborValue::Array(Vec::new())),
                (
                    "swarm",
                    CborValue::Array(vec![
                        CborValue::Float(-0.0),
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
            ];
            let entries = fields
                .into_iter()
                .map(|(n, v)| (CborValue::Text(n.to_string()), v))
                .collect();
            let doc = CborValue::Array(vec![
                CborValue::Unsigned(FORMAT_VERSION),
                CborValue::Map(entries),
            ]);
            let err = doc.try_to_canonical_bytes().expect_err("must reject -0.0");
            assert_eq!(err, ledger_format::CborError::NonCanonicalFloat);
        }
        {
            let mut fields = minimal_fields();
            set_field(
                &mut fields,
                "swarm",
                CborValue::Array(vec![
                    CborValue::Float(1.0000001),
                    CborValue::Float(0.0),
                    CborValue::Unsigned(0),
                    CborValue::Float(0.0),
                    CborValue::Unsigned(2),
                ]),
            );
            let bytes = craft_document(fields);
            let err = from_canonical_bytes(&bytes).expect_err("must reject");
            assert_eq!(
                err,
                ConfigCanonicalError::ProbabilityOutOfRange("swarm.drop_probability")
            );
        }
        // Swarm delay slot: -0.0 is CBOR non-canonical, 1.5 is out of range
        {
            assert_eq!(
                crate::config::Probability::new(-0.0).unwrap_err(),
                crate::config::ProbabilityError::OutOfRange
            );
            let fields = vec![
                ("dns", CborValue::Array(Vec::new())),
                ("seed", CborValue::Bytes(vec![0u8; 32])),
                ("links", CborValue::Array(Vec::new())),
                (
                    "swarm",
                    CborValue::Array(vec![
                        CborValue::Float(0.0),
                        CborValue::Float(-0.0),
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
            ];
            let entries = fields
                .into_iter()
                .map(|(n, v)| (CborValue::Text(n.to_string()), v))
                .collect();
            let doc = CborValue::Array(vec![
                CborValue::Unsigned(FORMAT_VERSION),
                CborValue::Map(entries),
            ]);
            let err = doc.try_to_canonical_bytes().expect_err("must reject -0.0");
            assert_eq!(err, ledger_format::CborError::NonCanonicalFloat);
        }
        // Swarm crash slot
        {
            let mut fields = minimal_fields();
            set_field(
                &mut fields,
                "swarm",
                CborValue::Array(vec![
                    CborValue::Float(0.0),
                    CborValue::Float(0.0),
                    CborValue::Unsigned(0),
                    CborValue::Float(1.5),
                    CborValue::Unsigned(2),
                ]),
            );
            let bytes = craft_document(fields);
            assert_eq!(
                from_canonical_bytes(&bytes).unwrap_err(),
                ConfigCanonicalError::ProbabilityOutOfRange("swarm.crash_probability")
            );
        }
        // Link loss slot: -0.0 is CBOR non-canonical
        {
            assert_eq!(
                crate::config::Probability::new(-0.0).unwrap_err(),
                crate::config::ProbabilityError::OutOfRange
            );
            let fields = vec![
                ("dns", CborValue::Array(Vec::new())),
                ("seed", CborValue::Bytes(vec![0u8; 32])),
                (
                    "links",
                    CborValue::Array(vec![CborValue::Array(vec![
                        CborValue::Unsigned(0),
                        CborValue::Unsigned(1),
                        CborValue::Array(vec![
                            CborValue::Unsigned(0),
                            CborValue::Unsigned(0),
                            CborValue::Float(-0.0),
                            CborValue::Unsigned(0),
                        ]),
                    ])]),
                ),
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
            ];
            let entries = fields
                .into_iter()
                .map(|(n, v)| (CborValue::Text(n.to_string()), v))
                .collect();
            let doc = CborValue::Array(vec![
                CborValue::Unsigned(FORMAT_VERSION),
                CborValue::Map(entries),
            ]);
            let err = doc.try_to_canonical_bytes().expect_err("must reject -0.0");
            assert_eq!(err, ledger_format::CborError::NonCanonicalFloat);
        }
        {
            assert_eq!(
                crate::config::Probability::new(f64::NAN).unwrap_err(),
                crate::config::ProbabilityError::NonFinite
            );
            let fields = vec![
                ("dns", CborValue::Array(Vec::new())),
                ("seed", CborValue::Bytes(vec![0u8; 32])),
                (
                    "links",
                    CborValue::Array(vec![CborValue::Array(vec![
                        CborValue::Unsigned(0),
                        CborValue::Unsigned(1),
                        CborValue::Array(vec![
                            CborValue::Unsigned(0),
                            CborValue::Unsigned(0),
                            CborValue::Float(f64::NAN),
                            CborValue::Unsigned(0),
                        ]),
                    ])]),
                ),
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
            ];
            let entries = fields
                .into_iter()
                .map(|(n, v)| (CborValue::Text(n.to_string()), v))
                .collect();
            let doc = CborValue::Array(vec![
                CborValue::Unsigned(FORMAT_VERSION),
                CborValue::Map(entries),
            ]);
            let err = doc.try_to_canonical_bytes().expect_err("must reject NAN");
            assert_eq!(err, ledger_format::CborError::NonCanonicalFloat);
        }
        // Bandit pct_mix slot
        {
            let mut fields = minimal_fields();
            set_field(
                &mut fields,
                "policy",
                CborValue::Array(vec![
                    CborValue::Unsigned(2),
                    CborValue::Float(1.414),
                    CborValue::Float(2.0),
                ]),
            );
            let bytes = craft_document(fields);
            assert_eq!(
                from_canonical_bytes(&bytes).unwrap_err(),
                ConfigCanonicalError::ProbabilityOutOfRange("policy.bandit.pct_mix")
            );
        }
        {
            assert_eq!(
                crate::config::Probability::new(-0.0).unwrap_err(),
                crate::config::ProbabilityError::OutOfRange
            );
            let fields = vec![
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
                (
                    "policy",
                    CborValue::Array(vec![
                        CborValue::Unsigned(2),
                        CborValue::Float(1.414),
                        CborValue::Float(-0.0),
                    ]),
                ),
                ("monitor", CborValue::Bool(true)),
                ("max_steps", CborValue::Unsigned(10_000)),
                ("dropped_events", CborValue::Array(Vec::new())),
                ("fs_journaling", CborValue::Null),
                ("fault_schedule", CborValue::Array(Vec::new())),
            ];
            let entries = fields
                .into_iter()
                .map(|(n, v)| (CborValue::Text(n.to_string()), v))
                .collect();
            let doc = CborValue::Array(vec![
                CborValue::Unsigned(FORMAT_VERSION),
                CborValue::Map(entries),
            ]);
            let err = doc.try_to_canonical_bytes().expect_err("must reject -0.0");
            assert_eq!(err, ledger_format::CborError::NonCanonicalFloat);
        }
        {
            let mut fields = minimal_fields();
            set_field(
                &mut fields,
                "policy",
                CborValue::Array(vec![
                    CborValue::Unsigned(2),
                    CborValue::Float(1.414),
                    CborValue::Float(f64::INFINITY),
                ]),
            );
            let bytes = craft_document(fields);
            assert_eq!(
                from_canonical_bytes(&bytes).unwrap_err(),
                ConfigCanonicalError::NonFiniteFloat("policy.bandit.pct_mix")
            );
        }
    }

    #[test]
    fn roundtrip_stable_hash_over_generated_valid_configs() {
        let valid_probs = [0.0, 0.1, 0.5, 1.0];
        let mut configs = Vec::new();
        for &drop in &valid_probs {
            for &delay in &valid_probs {
                for &crash in &valid_probs {
                    for &loss in &valid_probs {
                        for &pct in &valid_probs {
                            let cfg = crate::config::RunConfig::builder()
                                .swarm(SwarmConfig {
                                    drop_probability: Probability::new(drop).unwrap(),
                                    delay_probability: Probability::new(delay).unwrap(),
                                    max_delay_ticks: 7,
                                    crash_probability: Probability::new(crash).unwrap(),
                                    fault_classes_per_run: 2,
                                })
                                .links(vec![(
                                    0,
                                    1,
                                    LinkConfig {
                                        base_delay: 1,
                                        jitter: 0,
                                        loss_probability: Probability::new(loss).unwrap(),
                                        reorder_window: 0,
                                        capacity: None,
                                        queue_policy: crate::net::QueueFullPolicy::Drop,
                                    },
                                )])
                                .policy(crate::config::Policy::Bandit {
                                    exploration_constant: 1.414,
                                    pct_mix: Probability::new(pct).unwrap(),
                                })
                                .build();
                            configs.push(cfg);
                        }
                    }
                }
            }
        }
        for cfg in configs {
            let bytes = to_canonical_bytes(&cfg).expect("encodes");
            let decoded = from_canonical_bytes(&bytes).expect("decodes");
            assert_eq!(cfg.swarm(), decoded.swarm());
            assert_eq!(cfg.links(), decoded.links());
            assert_eq!(cfg.policy(), decoded.policy());
            let h1 = canonical_hash(&cfg).expect("hash");
            let h2 = canonical_hash(&decoded).expect("hash decoded");
            assert_eq!(h1, h2);
            let bytes2 = to_canonical_bytes(&decoded).expect("re-encodes");
            assert_eq!(bytes, bytes2);
        }
    }

    #[test]
    fn document_holds_thirteen_keys_in_canonical_order() {
        use ledger_format::CborValue;
        let bytes = to_canonical_bytes(&crate::config::RunConfig::default()).expect("encodes");
        let document = CborValue::from_canonical_bytes(&bytes).expect("canonical bytes decode");
        let CborValue::Array(items) = document else {
            panic!("document is [version, map]");
        };
        assert_eq!(items.len(), 2);
        let CborValue::Map(fields) = &items[1] else {
            panic!("second item is the field map");
        };
        let names: Vec<String> = fields
            .iter()
            .map(|(key, _)| match key {
                CborValue::Text(name) => name.clone(),
                _ => panic!("field key is text"),
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "dns",
                "seed",
                "links",
                "swarm",
                "policy",
                "monitor",
                "max_steps",
                "reorder_draw",
                "fs_journaling",
                "dropped_events",
                "fault_schedule",
                "max_file_extent",
                "max_resident_bytes",
            ]
        );
        assert_eq!(fields.len(), 13, "ten required plus three optional");
    }

    #[test]
    fn bounded_capacity_round_trips_and_joins_the_hash() {
        use crate::net::{LinkConfig, QueueFullPolicy};
        let base = crate::config::RunConfig::builder()
            .links(vec![(
                0,
                1,
                LinkConfig {
                    reorder_window: 2,
                    ..LinkConfig::default()
                },
            )])
            .build();
        let bounded = crate::config::RunConfig::builder()
            .links(vec![(
                0,
                1,
                LinkConfig {
                    reorder_window: 2,
                    capacity: Some(4),
                    queue_policy: QueueFullPolicy::Block,
                    ..LinkConfig::default()
                },
            )])
            .build();
        let base_bytes = to_canonical_bytes(&base).expect("base encodes");
        let bounded_bytes = to_canonical_bytes(&bounded).expect("bounded encodes");
        assert_ne!(
            base_bytes, bounded_bytes,
            "capacity must join the canonical bytes"
        );
        assert_ne!(
            canonical_hash(&base).expect("hash"),
            canonical_hash(&bounded).expect("hash"),
            "capacity must join the boundary hash"
        );
        let decoded = from_canonical_bytes(&bounded_bytes).expect("decodes");
        assert_eq!(decoded.links(), bounded.links());
        assert_eq!(
            to_canonical_bytes(&decoded).expect("re-encodes"),
            bounded_bytes
        );
        // Default queue config stays byte-identical to the 4-item shape.
        let plain = crate::config::RunConfig::builder()
            .links(vec![(0, 1, LinkConfig::default())])
            .build();
        let plain_bytes = to_canonical_bytes(&plain).expect("encodes");
        let decoded = from_canonical_bytes(&plain_bytes).expect("decodes");
        assert_eq!(decoded.links()[0].2.capacity, None);
        assert_eq!(decoded.links()[0].2.queue_policy, QueueFullPolicy::Drop);
    }

    #[test]
    fn canonical_rejects_oversized_window_and_bad_policy() {
        use crate::net::{LinkConfig, MAX_REORDER_WINDOW};
        let bad = crate::config::RunConfig::builder()
            .links(vec![(
                0,
                1,
                LinkConfig {
                    reorder_window: MAX_REORDER_WINDOW + 1,
                    ..LinkConfig::default()
                },
            )])
            .build();
        assert_eq!(
            to_canonical_bytes(&bad).expect_err("oversized window"),
            ConfigCanonicalError::InvalidReorderWindow(MAX_REORDER_WINDOW + 1)
        );
        // Craft a 6-item link with an unknown queue-policy tag.
        let link = CborValue::Array(vec![
            CborValue::Unsigned(0),
            CborValue::Unsigned(0),
            CborValue::Array(vec![
                CborValue::Unsigned(0),
                CborValue::Unsigned(0),
                CborValue::Float(0.0),
                CborValue::Unsigned(0),
                CborValue::Null,
                CborValue::Unsigned(7),
            ]),
        ]);
        let mut fields = minimal_fields();
        set_field(&mut fields, "links", CborValue::Array(vec![link]));
        let bytes = craft_document(fields);
        assert_eq!(
            from_canonical_bytes(&bytes).expect_err("bad policy tag"),
            ConfigCanonicalError::InvalidQueuePolicyTag(7)
        );
        // A 5-item link array is neither legacy (4) nor extended (6).
        let short = CborValue::Array(vec![
            CborValue::Unsigned(0),
            CborValue::Unsigned(1),
            CborValue::Array(vec![
                CborValue::Unsigned(0),
                CborValue::Unsigned(0),
                CborValue::Float(0.0),
                CborValue::Unsigned(0),
                CborValue::Null,
            ]),
        ]);
        let mut fields = minimal_fields();
        set_field(&mut fields, "links", CborValue::Array(vec![short]));
        let bytes = craft_document(fields);
        assert_eq!(
            from_canonical_bytes(&bytes).expect_err("5-item link"),
            ConfigCanonicalError::WrongFieldType("links")
        );
    }
}
