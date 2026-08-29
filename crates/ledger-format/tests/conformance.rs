use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ledger_format::cbor::{self, CborError, CborValue};
use ledger_format::{EntryData, EntryKind, FaultSpec, ManifestVersion, Payload, RunManifest};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn hex_bytes(text: &str) -> Vec<u8> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.len().is_multiple_of(2), "hex string has odd length");
    let mut out = Vec::with_capacity(compact.len() / 2);
    let bytes = compact.as_bytes();
    for index in (0..bytes.len()).step_by(2) {
        let high = hex_digit_value(bytes[index]);
        let low = hex_digit_value(bytes[index + 1]);
        out.push(((high << 4) | low) as u8);
    }
    out
}

fn hex_digit_value(byte: u8) -> u32 {
    match byte {
        b'0'..=b'9' => u32::from(byte - b'0'),
        b'a'..=b'f' => u32::from(byte - b'a' + 10),
        b'A'..=b'F' => u32::from(byte - b'A' + 10),
        other => panic!("invalid hex digit {other:#x}"),
    }
}

/// A minimal JSON value model for the fixture expectation files.
///
/// The companion `.json` files declare the semantic value a fixture must
/// decode to. The crate has no JSON dependency, so the test parses the small
/// grammar it emits itself.
#[derive(Debug)]
enum Json {
    Str(String),
    Num(u64),
    Bool(bool),
    Null,
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

struct JsonParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && (self.input[self.pos] as char).is_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> u8 {
        self.skip_whitespace();
        assert!(self.pos < self.input.len(), "unexpected end of JSON input");
        self.input[self.pos]
    }

    fn take(&mut self) -> u8 {
        let byte = self.peek();
        self.pos += 1;
        byte
    }

    fn expect(&mut self, expected: u8) {
        let actual = self.take();
        assert_eq!(
            actual, expected,
            "expected JSON byte {expected:#x}, got {actual:#x}"
        );
    }

    fn expect_word(&mut self, word: &str) {
        for byte in word.bytes() {
            assert_eq!(self.take(), byte, "expected JSON keyword {word}");
        }
    }

    fn parse(&mut self) -> Json {
        match self.peek() {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => Json::Str(self.parse_string()),
            b't' => {
                self.expect_word("true");
                Json::Bool(true)
            }
            b'f' => {
                self.expect_word("false");
                Json::Bool(false)
            }
            b'n' => {
                self.expect_word("null");
                Json::Null
            }
            _ => Json::Num(self.parse_number()),
        }
    }

    fn parse_object(&mut self) -> Json {
        self.expect(b'{');
        let mut entries = Vec::new();
        if self.peek() == b'}' {
            self.take();
            return Json::Obj(entries);
        }
        loop {
            let key = self.parse_string();
            self.expect(b':');
            let value = self.parse();
            entries.push((key, value));
            match self.take() {
                b',' => continue,
                b'}' => break,
                other => panic!("unexpected JSON byte {other:#x} in object"),
            }
        }
        Json::Obj(entries)
    }

    fn parse_array(&mut self) -> Json {
        self.expect(b'[');
        let mut items = Vec::new();
        if self.peek() == b']' {
            self.take();
            return Json::Arr(items);
        }
        loop {
            items.push(self.parse());
            match self.take() {
                b',' => continue,
                b']' => break,
                other => panic!("unexpected JSON byte {other:#x} in array"),
            }
        }
        Json::Arr(items)
    }

    fn parse_string(&mut self) -> String {
        self.expect(b'"');
        let mut raw = Vec::new();
        loop {
            let byte = self.take();
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = self.take();
                    match escaped {
                        b'"' => raw.push(b'"'),
                        b'\\' => raw.push(b'\\'),
                        b'/' => raw.push(b'/'),
                        b'b' => raw.push(0x08),
                        b'f' => raw.push(0x0c),
                        b'n' => raw.push(b'\n'),
                        b'r' => raw.push(b'\r'),
                        b't' => raw.push(b'\t'),
                        b'u' => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                code = code * 16 + hex_digit_value(self.take());
                            }
                            let ch = char::from_u32(code).expect("valid unicode escape");
                            let mut buf = [0u8; 4];
                            raw.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        other => panic!("unknown JSON escape {other:#x}"),
                    }
                }
                byte => raw.push(byte),
            }
        }
        String::from_utf8(raw).expect("JSON string is valid UTF-8")
    }

    fn parse_number(&mut self) -> u64 {
        let start = self.pos;
        while self.pos < self.input.len()
            && matches!(
                self.input[self.pos],
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
            )
        {
            self.pos += 1;
        }
        let raw = std::str::from_utf8(&self.input[start..self.pos]).expect("number is ASCII");
        raw.parse()
            .unwrap_or_else(|_| panic!("non-integer JSON number {raw}"))
    }
}

fn parse_json(text: &str) -> Json {
    let mut parser = JsonParser::new(text.as_bytes());
    let value = parser.parse();
    parser.skip_whitespace();
    assert_eq!(parser.pos, parser.input.len(), "trailing JSON content");
    value
}

fn obj_lookup<'j>(entries: &'j [(String, Json)], key: &str) -> Option<&'j Json> {
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn obj_u64(entries: &[(String, Json)], key: &str) -> u64 {
    match obj_lookup(entries, key) {
        Some(Json::Num(value)) => *value,
        _ => panic!("missing integer field {key}"),
    }
}

fn obj_string(entries: &[(String, Json)], key: &str) -> String {
    match obj_lookup(entries, key) {
        Some(Json::Str(value)) => value.clone(),
        _ => panic!("missing string field {key}"),
    }
}

fn json_to_cbor(value: &Json) -> CborValue {
    let entries = match value {
        Json::Obj(entries) => entries,
        other => panic!("fixture expectation must be an object, got {other:?}"),
    };
    let kind = match obj_lookup(entries, "type") {
        Some(Json::Str(kind)) => kind.as_str(),
        _ => panic!("fixture expectation missing type"),
    };
    match kind {
        "unsigned" => CborValue::Unsigned(obj_u64(entries, "value")),
        "negative" => CborValue::Negative(obj_u64(entries, "n")),
        "bytes" => {
            let hex = obj_string(entries, "hex");
            CborValue::Bytes(hex_bytes(&hex))
        }
        "text" => CborValue::Text(obj_string(entries, "value")),
        "array" => {
            let items = match obj_lookup(entries, "items") {
                Some(Json::Arr(items)) => items,
                _ => panic!("array expectation missing items"),
            };
            CborValue::Array(items.iter().map(json_to_cbor).collect())
        }
        "map" => {
            let raw_entries = match obj_lookup(entries, "entries") {
                Some(Json::Arr(entries)) => entries,
                _ => panic!("map expectation missing entries"),
            };
            let pairs = raw_entries
                .iter()
                .map(|entry| {
                    let pair = match entry {
                        Json::Obj(pair) => pair,
                        other => panic!("map entry must be an object, got {other:?}"),
                    };
                    let key = obj_lookup(pair, "key")
                        .map(json_to_cbor)
                        .unwrap_or_else(|| panic!("map entry missing key"));
                    let value = obj_lookup(pair, "value")
                        .map(json_to_cbor)
                        .unwrap_or_else(|| panic!("map entry missing value"));
                    (key, value)
                })
                .collect();
            CborValue::Map(pairs)
        }
        "bool" => match obj_lookup(entries, "value") {
            Some(Json::Bool(value)) => CborValue::Bool(*value),
            _ => panic!("bool expectation missing value"),
        },
        "null" => CborValue::Null,
        "float" => {
            let text = obj_string(entries, "value");
            let value: f64 = text
                .parse()
                .unwrap_or_else(|_| panic!("invalid float literal {text}"));
            CborValue::Float(value)
        }
        other => panic!("unknown fixture type {other}"),
    }
}

fn list_fixture_paths() -> Vec<PathBuf> {
    let mut fixtures: Vec<PathBuf> = std::fs::read_dir(fixture_dir())
        .expect("fixtures directory readable")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "hex"))
        .collect();
    fixtures.sort();
    fixtures
}

#[test]
fn golden_fixtures_round_trip_identity() {
    let fixtures = list_fixture_paths();
    assert!(
        fixtures.len() >= 30,
        "fixture corpus too small: {}",
        fixtures.len()
    );
    for path in fixtures {
        let raw = std::fs::read_to_string(&path).expect("fixture readable");
        let bytes = hex_bytes(&raw);
        let decoded = CborValue::from_canonical_bytes(&bytes)
            .unwrap_or_else(|err| panic!("fixture {} must decode: {err:?}", path.display()));
        let reencoded = decoded.to_canonical_bytes();
        assert_eq!(
            reencoded,
            bytes,
            "decode then encode must be identity for {}",
            path.display()
        );
    }
}

#[test]
fn golden_fixture_semantic_expectations() {
    let dir = fixture_dir();
    let mut hex_count = 0usize;
    let mut json_count = 0usize;
    for entry in std::fs::read_dir(&dir).expect("fixtures directory readable") {
        let path = entry.expect("read_dir entry").path();
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("hex") => {
                hex_count += 1;
                let json_path = path.with_extension("json");
                assert!(
                    json_path.is_file(),
                    "missing companion {}",
                    json_path.display()
                );
                let raw = std::fs::read_to_string(&path).expect("fixture readable");
                let bytes = hex_bytes(&raw);
                let decoded = CborValue::from_canonical_bytes(&bytes).expect("fixture decodes");
                let expectation =
                    parse_json(&std::fs::read_to_string(&json_path).expect("companion readable"));
                let root_entries = match &expectation {
                    Json::Obj(entries) => entries,
                    other => panic!(
                        "companion {} must be an object, got {other:?}",
                        json_path.display()
                    ),
                };
                let expected =
                    json_to_cbor(obj_lookup(root_entries, "value").unwrap_or_else(|| {
                        panic!("companion {} missing value field", json_path.display())
                    }));
                assert_eq!(
                    decoded,
                    expected,
                    "semantic mismatch for {}",
                    path.display()
                );
                let reencoded = expected.to_canonical_bytes();
                assert_eq!(
                    reencoded,
                    bytes,
                    "expected value must encode to fixture bytes for {}",
                    path.display()
                );
            }
            Some("json") => json_count += 1,
            _ => {}
        }
    }
    assert_eq!(
        hex_count, json_count,
        "every fixture needs a companion expectation"
    );
    assert!(hex_count >= 30, "fixture corpus too small: {hex_count}");
}

#[test]
fn rejects_non_canonical_forms() {
    let cases: Vec<(Vec<u8>, CborError)> = vec![
        // Indefinite-length encodings are forbidden in canonical CBOR.
        (vec![0x9f], CborError::IndefiniteLengthForbidden),
        (vec![0xbf], CborError::IndefiniteLengthForbidden),
        (vec![0xff], CborError::IndefiniteLengthForbidden),
        // Integers not in shortest form.
        (
            vec![0x39, 0x00, 0xff],
            CborError::NonCanonicalIntegerEncoding,
        ),
        (
            vec![0x1a, 0x00, 0x00, 0x00, 0x18],
            CborError::NonCanonicalIntegerEncoding,
        ),
        // Duplicate map key.
        (
            vec![0xa2, 0x00, 0x01, 0x00, 0x02],
            CborError::DuplicateMapKey,
        ),
        // Map keys not sorted canonically.
        (
            vec![0xa2, 0x01, 0x01, 0x00, 0x02],
            CborError::UnsortedMapKeys,
        ),
        // NaN and -0.0 as half precision.
        (vec![0xf9, 0x7e, 0x00], CborError::NonCanonicalFloat),
        (vec![0xf9, 0x80, 0x00], CborError::NonCanonicalFloat),
        // 1.5 encoded as double fits single precision: non-canonical width.
        (
            vec![0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            CborError::NonCanonicalFloat,
        ),
        // Disallowed semantic tag.
        (vec![0xc0, 0x00], CborError::UnknownTag(0)),
        // Invalid UTF-8 inside a text string.
        (vec![0x61, 0xff], CborError::InvalidUtf8),
    ];

    for (input, expected) in cases {
        let result = CborValue::from_canonical_bytes(&input);
        assert_eq!(result, Err(expected), "input {input:02x?}");
    }
}

/// Curated hostile byte strings the canonical decoder must reject.
fn curated_hostile_inputs() -> Vec<Vec<u8>> {
    let huge = [0xffu8; 8];
    let mut hostile: Vec<Vec<u8>> = Vec::new();
    hostile.push(Vec::new());
    // Indefinite-length forms and the break simple value.
    hostile.push(vec![0x9f]);
    hostile.push(vec![0xbf]);
    hostile.push(vec![0xff]);
    hostile.push(vec![0x5f]);
    hostile.push(vec![0x7f]);
    // Truncated headers.
    hostile.push(vec![0x18]);
    hostile.push(vec![0x19, 0x01]);
    hostile.push(vec![0x1a, 0x00, 0x00]);
    hostile.push(vec![0x1b, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Non-shortest integers.
    hostile.push(vec![0x18, 0x00]);
    hostile.push(vec![0x39, 0x00, 0xff]);
    hostile.push(vec![0x1a, 0x00, 0x00, 0x00, 0x18]);
    hostile.push(vec![0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18]);
    // Huge declared lengths and counts (2^64 - 1) must not over-allocate.
    hostile.push({
        let mut v = vec![0x9b];
        v.extend_from_slice(&huge);
        v
    });
    hostile.push({
        let mut v = vec![0xbb];
        v.extend_from_slice(&huge);
        v
    });
    hostile.push({
        let mut v = vec![0x5b];
        v.extend_from_slice(&huge);
        v
    });
    hostile.push({
        let mut v = vec![0x7b];
        v.extend_from_slice(&huge);
        v
    });
    // Arrays and maps declaring more items than the input provides.
    hostile.push(vec![0x82, 0x01]);
    hostile.push(vec![0xa1, 0x01]);
    hostile.push(vec![0x43, 0xff]);
    // Nested huge count inside a valid outer array.
    hostile.push({
        let mut v = vec![0x82, 0x9b];
        v.extend_from_slice(&huge);
        v.push(0x00);
        v
    });
    // Invalid UTF-8.
    hostile.push(vec![0x61, 0xff]);
    // Floats: NaN, -0.0, non-minimal width, truncated payloads.
    hostile.push(vec![0xf9, 0x7e, 0x00]);
    hostile.push(vec![0xf9, 0x80, 0x00]);
    hostile.push(vec![0xf9, 0x3c]);
    hostile.push(vec![0xfa, 0x3f, 0x80]);
    hostile.push(vec![0xfb, 0x3f, 0xf8, 0x00]);
    hostile.push(vec![0xfa, 0x3f, 0x80, 0x00, 0x00]);
    hostile.push(vec![0xfa, 0x7f, 0x80, 0x00, 0x00]);
    hostile.push(vec![0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Disallowed tags.
    hostile.push(vec![0xc0, 0x00]);
    // Map key ordering violations.
    hostile.push(vec![0xa2, 0x01, 0x01, 0x00, 0x02]);
    hostile.push(vec![0xa2, 0x00, 0x01, 0x00, 0x02]);
    // Nesting far beyond the depth limit.
    hostile.push({
        let mut deep = vec![0x81; 300];
        deep.push(0x00);
        deep
    });
    // Unsupported simple values.
    hostile.push(vec![0x7c, 0x01]);
    hostile.push(vec![0xf8, 0x1f]);
    // Trailing bytes after a complete value.
    hostile.push(vec![0x00, 0x00]);
    hostile.push(vec![0xf6, 0x40]);
    hostile.push(vec![0x18, 0x18, 0x00]);
    hostile
}

#[test]
fn hostile_input_never_panics() {
    let hostile = curated_hostile_inputs();
    assert!(
        hostile.len() >= 30,
        "hostile corpus too small: {}",
        hostile.len()
    );
    for input in &hostile {
        let result = CborValue::from_canonical_bytes(input);
        assert!(
            result.is_err(),
            "hostile input {input:02x?} must be rejected, got {result:?}"
        );
    }

    // Mutations of a valid entry encoding: the reader must never panic,
    // whether it accepts or rejects a mutation. Every truncation is a proper
    // prefix of the full entry and is always rejected.
    let entry_bytes = sample_entry_bytes();
    let mut checks = 0usize;
    for end in 0..entry_bytes.len() {
        let truncated = &entry_bytes[..end];
        assert!(
            CborValue::from_canonical_bytes(truncated).is_err(),
            "truncation at byte {end} of {len} must be rejected",
            len = entry_bytes.len()
        );
        checks += 1;
    }
    for (index, _) in entry_bytes.iter().enumerate() {
        for replacement in [0x00, 0x9f, 0xbf, 0x5f, 0x7f, 0xff] {
            let mut mutated = entry_bytes.clone();
            mutated[index] = replacement;
            let _ = CborValue::from_canonical_bytes(&mutated);
            checks += 1;
        }
    }
    assert!(checks >= 100, "mutation coverage too small: {checks}");
}

fn sample_entry_bytes() -> Vec<u8> {
    EntryData {
        kind: EntryKind::Fault {
            fault: FaultSpec::Delay { ticks: 100 },
        },
        actor: 1,
        parents: vec![[1u8; 32], [2u8; 32]],
        vector_clock: vec![3, 4],
        sequence: 5,
        payload: Payload::Text("payload".into()),
    }
    .try_canonical_bytes()
    .expect("sample entry encodes")
}

fn sample_manifest_bytes() -> Vec<u8> {
    RunManifest {
        format_version: 1,
        root_seed: [7u8; 32],
        policy_tag: "pct".into(),
        journal_root: [9u8; 32],
        entry_count: 42,
        actor_heads: BTreeMap::from([(0u32, [1u8; 32]), (1u32, [2u8; 32])]),
        execution_identity: None,
        extensions: BTreeMap::from([("probe".into(), CborValue::Unsigned(1))]),
    }
    .to_canonical_bytes()
    .expect("sample manifest encodes")
}

#[test]
fn hostile_manifest_never_panics() {
    let manifest_bytes = sample_manifest_bytes();
    for input in &curated_hostile_inputs() {
        let result = RunManifest::from_canonical_bytes(input);
        assert!(
            result.is_err(),
            "hostile manifest input {input:02x?} must be rejected, got {result:?}"
        );
    }
    for end in 0..manifest_bytes.len() {
        let _ = RunManifest::from_canonical_bytes(&manifest_bytes[..end]);
    }
    for (index, _) in manifest_bytes.iter().enumerate() {
        for replacement in [0x00, 0x9f, 0xbf, 0x5f, 0x7f, 0xff] {
            let mut mutated = manifest_bytes.clone();
            mutated[index] = replacement;
            let _ = RunManifest::from_canonical_bytes(&mutated);
        }
    }
}

#[test]
fn tolerant_reader_never_panics_on_hostile_and_mutated_input() {
    let reader = cbor::TolerantReader::new();
    let hostile = curated_hostile_inputs();
    assert!(
        hostile.len() >= 30,
        "hostile corpus too small: {}",
        hostile.len()
    );
    let mut checks = 0usize;
    for input in &hostile {
        let _ = reader.parse(input);
        checks += 1;
    }

    // A valid canonical entry parses tolerantly to the same semantic value.
    let entry_bytes = sample_entry_bytes();
    assert_eq!(
        reader.parse(&entry_bytes),
        CborValue::from_canonical_bytes(&entry_bytes),
        "tolerant reader must agree with the canonical decoder on valid input"
    );
    // Every truncation of the entry is a proper prefix and must never panic.
    for end in 0..entry_bytes.len() {
        let _ = reader.parse(&entry_bytes[..end]);
        checks += 1;
    }
    // Single-byte mutations of the entry must never panic.
    for (index, _) in entry_bytes.iter().enumerate() {
        for replacement in [0x00, 0x9f, 0xbf, 0x5f, 0x7f, 0xff] {
            let mut mutated = entry_bytes.clone();
            mutated[index] = replacement;
            let _ = reader.parse(&mutated);
            checks += 1;
        }
    }

    // The manifest surface must never panic the tolerant reader either.
    let manifest_bytes = sample_manifest_bytes();
    for end in 0..manifest_bytes.len() {
        let _ = reader.parse(&manifest_bytes[..end]);
        checks += 1;
    }
    for (index, _) in manifest_bytes.iter().enumerate() {
        for replacement in [0x00, 0x9f, 0xbf, 0x5f, 0x7f, 0xff] {
            let mut mutated = manifest_bytes.clone();
            mutated[index] = replacement;
            let _ = reader.parse(&mutated);
            checks += 1;
        }
    }

    assert!(checks >= 300, "mutation coverage too small: {checks}");
}

#[test]
fn tolerant_reader_matches_canonical_decoder_on_fixtures() {
    let reader = cbor::TolerantReader::new();
    for path in list_fixture_paths() {
        let raw = std::fs::read_to_string(&path).expect("fixture readable");
        let bytes = hex_bytes(&raw);
        let canonical = CborValue::from_canonical_bytes(&bytes)
            .unwrap_or_else(|err| panic!("fixture {} must decode: {err:?}", path.display()));
        let tolerant = reader.parse(&bytes).unwrap_or_else(|err| {
            panic!("fixture {} must parse tolerantly: {err:?}", path.display())
        });
        assert_eq!(
            tolerant,
            canonical,
            "tolerant and canonical readers must agree for {}",
            path.display()
        );
    }
}

#[test]
fn entry_round_trip_stability() {
    let mut kinds: Vec<EntryKind> = vec![
        EntryKind::Spawn,
        EntryKind::Block,
        EntryKind::Wake,
        EntryKind::TimerSet,
        EntryKind::TimerFire,
        EntryKind::ClockRead,
        EntryKind::Send,
        EntryKind::Recv,
        EntryKind::FsWrite,
        EntryKind::FsFsync,
        EntryKind::FsRead,
        EntryKind::RngDraw { stream: 11 },
        EntryKind::Outcome,
        EntryKind::Assert,
        EntryKind::Snapshot,
        EntryKind::Epoch,
        EntryKind::InputStep {
            generator: 2,
            replay: 3,
        },
        EntryKind::CapRequest,
        EntryKind::CapGrant,
        EntryKind::CapInvoke,
        EntryKind::CapRevoke,
        EntryKind::Fault {
            fault: FaultSpec::Drop,
        },
        EntryKind::StepBegin,
        EntryKind::StepEnd,
    ];
    assert_eq!(kinds.len(), 24, "spec defines exactly 24 entry kinds");

    let faults = [
        FaultSpec::Drop,
        FaultSpec::Delay { ticks: 100 },
        FaultSpec::Partition { src: 1, dst: 2 },
        FaultSpec::Crash,
        FaultSpec::Corrupt,
        FaultSpec::CrashState(3),
    ];
    for fault in faults {
        kinds.push(EntryKind::Fault { fault });
    }

    for kind in &kinds {
        let data = EntryData {
            kind: *kind,
            actor: 7,
            parents: vec![[0xaa; 32]],
            vector_clock: vec![1, 2, 3],
            sequence: 4,
            payload: Payload::Pair { left: 5, right: 6 },
        };
        let first = data.try_canonical_bytes().expect("entry encodes");
        let second = data.try_canonical_bytes().expect("entry encodes");
        assert_eq!(
            first, second,
            "encoding must be byte-identical for {kind:?}"
        );
        match CborValue::from_canonical_bytes(&first).expect("entry decodes as CBOR") {
            CborValue::Array(items) => assert_eq!(items.len(), 6, "entry decodes as array of 6"),
            other => panic!("entry must decode as an array, got {other:?}"),
        }
    }
}

#[test]
fn manifest_version_migration() {
    let manifest = RunManifest {
        format_version: 1,
        root_seed: [7u8; 32],
        policy_tag: "bandit".into(),
        journal_root: [9u8; 32],
        entry_count: 1234,
        actor_heads: BTreeMap::from([(1u32, [1u8; 32]), (2u32, [2u8; 32])]),
        execution_identity: None,
        extensions: BTreeMap::from([("probe".into(), CborValue::Unsigned(99))]),
    };
    assert!(ManifestVersion::CURRENT.is_supported());
    assert!(ManifestVersion(1).is_supported());
    assert!(!ManifestVersion(2).is_supported());

    let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
    assert_eq!(bytes[0], 0x87, "manifest is an array of 7");
    let decoded = RunManifest::from_canonical_bytes(&bytes).expect("v1 manifest decodes");
    assert_eq!(decoded, manifest);

    // A v2 manifest is rejected as unsupported.
    let mut version_2 = bytes.clone();
    version_2[1] = 0x02;
    assert_eq!(
        RunManifest::from_canonical_bytes(&version_2),
        Err(CborError::UnsupportedVersion(2))
    );

    // A v0 manifest is also rejected as unsupported.
    let mut version_0 = bytes.clone();
    version_0[1] = 0x00;
    assert_eq!(
        RunManifest::from_canonical_bytes(&version_0),
        Err(CborError::UnsupportedVersion(0))
    );
}
