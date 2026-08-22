//! Generated `ledger.control.v1` wire bindings.
//!
//! The contract lives in
//! `crates/ledger-format/proto/ledger/control/v1/control.proto`. With the
//! `grpc` feature, this module holds the tonic/prost mirror of every message
//! and the service stubs. The build script regenerates
//! `gen/ledger.control.v1.rs` on every `grpc` build where `protoc` succeeds;
//! the checked-in copy keeps offline builds working because `include!`
//! resolves against this source tree, not `OUT_DIR`.
//!
//! This module is the single wire codec for the control plane. The former
//! hand-rolled codec in `pb.rs` was deleted after the generated bindings
//! proved wire-identical in parity tests; prost skips unknown fields, so
//! older readers tolerate newer writers.

#[cfg(feature = "grpc")]
include!("gen/ledger.control.v1.rs");

#[cfg(all(test, feature = "grpc"))]
mod tests {
    use super::*;
    use prost::Message;

    /// Build a wire-LEN tag followed by a raw length varint, no body.
    fn len_tag(field: u32, len: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_tag_varint(field, 2, &mut out);
        encode_raw_varint(len, &mut out);
        out
    }

    /// Append one LEN-delimited unknown field with a raw body.
    fn append_unknown_len(bytes: &mut Vec<u8>, field: u32, body: &[u8]) {
        bytes.extend(len_tag(field, body.len() as u64));
        bytes.extend_from_slice(body);
    }

    /// Append one VARINT unknown field with a raw value.
    fn append_unknown_varint(bytes: &mut Vec<u8>, field: u32, value: u64) {
        encode_tag_varint(field, 0, bytes);
        encode_raw_varint(value, bytes);
    }

    fn encode_raw_varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn encode_tag_varint(field: u32, wire_type: u32, out: &mut Vec<u8>) {
        encode_raw_varint((u64::from(field) << 3) | u64::from(wire_type), out);
    }

    fn sample_identity() -> WorkerIdentity {
        WorkerIdentity {
            worker_id: "worker-7".to_string(),
            version: "0.1.0".to_string(),
        }
    }

    fn sample_profile() -> RuntimeProfile {
        RuntimeProfile {
            engine_sha: "abc123".to_string(),
            toolchain: "pinned-1.97".to_string(),
            features: "grpc,sim-fs-journaling".to_string(),
            sut_hashes: vec!["sut-a".to_string(), "sut-b".to_string()],
            cpu_topology: "cpus=8".to_string(),
            env_sanitation: vec!["LEDGER_*".to_string()],
            fingerprint_hex: "ff".repeat(32),
        }
    }

    fn sample_register() -> RegisterWorkerRequest {
        RegisterWorkerRequest {
            identity: Some(sample_identity()),
            profile: Some(sample_profile()),
        }
    }

    // Round-trips prove encode/decode agreement for every message the
    // control plane exchanges in the v1 contract.

    #[test]
    fn worker_identity_round_trip() {
        let msg = sample_identity();
        let bytes = msg.encode_to_vec();
        assert_eq!(WorkerIdentity::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn runtime_profile_round_trip_preserves_repeated_fields() {
        let msg = sample_profile();
        let bytes = msg.encode_to_vec();
        assert_eq!(RuntimeProfile::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn register_worker_round_trip_preserves_submessages() {
        let msg = sample_register();
        let bytes = msg.encode_to_vec();
        let back = RegisterWorkerRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn heartbeat_round_trip() {
        let msg = HeartbeatRequest {
            worker_id: "w".to_string(),
            task_id: "t".to_string(),
            attempts: 7,
        };
        let bytes = msg.encode_to_vec();
        assert_eq!(HeartbeatRequest::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn lease_dispatch_round_trip() {
        let msg = LeaseResponse {
            tasks: vec![TaskDispatch {
                task_id: "t1".to_string(),
                run_config_bytes: vec![1, 2, 3],
                workload: "kv".to_string(),
                run_config_hash_hex: "ab".repeat(32),
            }],
        };
        let bytes = msg.encode_to_vec();
        assert_eq!(LeaseResponse::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn task_progress_counters_round_trip() {
        let msg = TaskProgress {
            task_id: "t".to_string(),
            phase: "run".to_string(),
            counters: [("steps".to_string(), 10u64), ("retries".to_string(), 2u64)]
                .into_iter()
                .collect(),
        };
        let bytes = msg.encode_to_vec();
        let back = TaskProgress::decode(bytes.as_slice()).unwrap();
        assert_eq!(back.counters.len(), 2);
        assert_eq!(back.counters.get("steps"), Some(&10));
        assert_eq!(back.counters.get("retries"), Some(&2));
    }

    // Wire-layout pins: the proto source names these field numbers, and a
    // renumber without an approved format change would flip these bytes.

    #[test]
    fn register_worker_field_numbers_stable() {
        let bytes = sample_register().encode_to_vec();
        assert_eq!(
            bytes[0], 0x0A,
            "RegisterWorkerRequest identity field should be 1/LEN => 0x0A"
        );
        assert_eq!(
            decode_field_tag(&bytes, 0),
            0x0A,
            "identity tag must be 1/LEN"
        );
        let len = decode_field_len(&bytes, 1) as usize;
        // Profile tag sits right after the identity body: tag, tag-len, body.
        let profile_tag_pos = varint_len(0x0A) + varint_len(len as u64) + len;
        assert_eq!(
            decode_field_tag(&bytes, profile_tag_pos),
            0x12,
            "profile field should be 2/LEN => 0x12"
        );
    }

    #[test]
    fn task_progress_map_entry_layout_stable() {
        let msg = TaskProgress {
            task_id: String::new(),
            phase: String::new(),
            counters: [("k".to_string(), 5u64)].into_iter().collect(),
        };
        let bytes = msg.encode_to_vec();
        // The empty strings are omitted, so only the map entry travels;
        // its tag is field 3 / LEN => 0x1A.
        assert_eq!(bytes[0], 0x1A, "counters must be field 3/LEN => 0x1A");
        let entry_len = decode_field_len(&bytes, 1) as usize;
        let entry = &bytes[varint_len(0x1A) + varint_len(entry_len as u64)..][..entry_len];
        // Entry body: key = field 1 / LEN => 0x0A, value = field 2 / VARINT => 0x10.
        assert_eq!(decode_field_tag(entry, 0), 0x0A, "map key must be 1/LEN");
        let key_len = decode_field_len(entry, 1) as usize;
        let key_pos = varint_len(0x0A) + varint_len(key_len as u64);
        assert_eq!(&entry[key_pos..key_pos + key_len], b"k");
        assert_eq!(
            decode_field_tag(entry, key_pos + key_len),
            0x10,
            "map value must be 2/VARINT"
        );
    }

    // Unknown fields are skipped, so older readers tolerate newer writers.

    #[test]
    fn unknown_fields_are_skipped() {
        let mut bytes = sample_identity().encode_to_vec();
        append_unknown_len(&mut bytes, 99, b"unknown-bytes");
        append_unknown_varint(&mut bytes, 100, 12345);
        let back = WorkerIdentity::decode(bytes.as_slice()).unwrap();
        assert_eq!(back, sample_identity());
    }

    // Malformed input must produce a typed decode error, never a panic.
    // prost performs the length checks the deleted hand codec used to run.

    #[test]
    fn truncated_input_returns_error() {
        let mut bytes = sample_identity().encode_to_vec();
        bytes.truncate(bytes.len() - 1);
        let err =
            WorkerIdentity::decode(bytes.as_slice()).expect_err("truncated input must not decode");
        assert!(err.to_string().contains("buffer underflow"), "got {err}");
    }

    #[test]
    fn length_prefix_at_u64_max_is_rejected_not_wrapped() {
        // A length prefix of u64::MAX must never wrap a length check into a
        // wrong-sized slice. prost bounds the length against the remaining
        // bytes before any allocation.
        let bytes = len_tag(1, u64::MAX);
        let err = WorkerIdentity::decode(bytes.as_slice())
            .expect_err("u64::MAX length prefix must not decode");
        let msg = err.to_string();
        assert!(
            msg.contains("buffer underflow")
                || msg.contains("length delimiter exceeds maximum usize value"),
            "got {msg}"
        );
    }

    #[test]
    fn length_prefix_exceeding_buffer_is_rejected() {
        // Claiming 1 MiB over a 4-byte body must fail without allocation.
        let mut bytes = len_tag(1, 1 << 20);
        bytes.extend_from_slice(b"abcd");
        let err = WorkerIdentity::decode(bytes.as_slice())
            .expect_err("oversized length prefix must not decode");
        let msg = err.to_string();
        assert!(
            msg.contains("buffer underflow") || msg.contains("delimited length exceeded"),
            "got {msg}"
        );
    }

    #[test]
    fn varint_overflow_returns_error() {
        // 11 continuation bytes overflow the 64-bit varint.
        let bytes = vec![0x80u8; 11];
        let err = WorkerIdentity::decode(bytes.as_slice())
            .expect_err("overflowed varint must not decode");
        assert!(err.to_string().contains("invalid varint"), "got {err}");
    }

    #[test]
    fn invalid_wire_type_returns_error() {
        // Field 1 with wire type 3 (group start): prost rejects it.
        let mut bytes = Vec::new();
        encode_tag_varint(1, 3, &mut bytes);
        let err = WorkerIdentity::decode(bytes.as_slice())
            .expect_err("invalid wire type must not decode");
        assert!(err.to_string().contains("invalid wire type"), "got {err}");
    }

    #[test]
    fn invalid_utf8_returns_error() {
        let mut bytes = len_tag(1, 1);
        bytes.push(0xFF);
        let err =
            WorkerIdentity::decode(bytes.as_slice()).expect_err("invalid UTF-8 must not decode");
        assert!(err.to_string().contains("not UTF-8 encoded"), "got {err}");
    }

    // Varint helpers for the layout pins (independent of the prost codec).

    fn varint_len(mut v: u64) -> usize {
        let mut n = 1;
        while v >= 0x80 {
            n += 1;
            v >>= 7;
        }
        n
    }

    fn decode_field_tag(bytes: &[u8], pos: usize) -> u64 {
        let mut shift = 0;
        let mut tag = 0u64;
        let mut pos = pos;
        loop {
            let b = bytes[pos];
            pos += 1;
            tag |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return tag;
            }
            shift += 7;
        }
    }

    fn decode_field_len(bytes: &[u8], pos: usize) -> u64 {
        let mut shift = 0;
        let mut len = 0u64;
        let mut pos = pos;
        loop {
            let b = bytes[pos];
            pos += 1;
            len |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return len;
            }
            shift += 7;
        }
    }
}
