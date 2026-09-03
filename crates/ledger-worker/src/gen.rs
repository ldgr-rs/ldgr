//! Generated `ledger.control.v2` wire bindings (contract in
//! `crates/ledger-format/proto/ledger/control/v2/control.proto`).
//! Checked-in copy keeps offline builds working; prost skips unknown fields.

#[cfg(feature = "grpc")]
include!("gen/ledger.control.v2.rs");

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

    fn sample_hello() -> WorkerHello {
        WorkerHello {
            worker_id: "worker-7".to_string(),
            version: "0.1.0".to_string(),
            execution_identity: framed([0xabu8; 32]),
            profile: Some(sample_profile()),
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

    fn sample_dispatch() -> TaskDispatch {
        TaskDispatch {
            task_id: "t1".to_string(),
            run_config_bytes: vec![1, 2, 3],
            workload: "kv".to_string(),
            run_config_hash_hex: "ab".repeat(32),
            execution_identity: framed([0xcdu8; 32]),
        }
    }

    fn sample_upload() -> ResultUpload {
        ResultUpload {
            task_id: "t1".to_string(),
            journal_root_hex: "ef".repeat(32),
            steps: 4096,
            ok: true,
            error: String::new(),
            execution_identity: framed([0xabu8; 32]),
        }
    }

    /// Framed wire form for one test digest: prefix plus 32-byte digest.
    fn framed(digest: [u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(34);
        out.extend_from_slice(&[0x1e, 0x20]);
        out.extend_from_slice(&digest);
        out
    }

    // Round-trips prove encode/decode agreement for every message the
    // session exchanges in the v2 contract.

    #[test]
    fn worker_hello_round_trip() {
        let msg = sample_hello();
        let bytes = msg.encode_to_vec();
        assert_eq!(WorkerHello::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn runtime_profile_round_trip_preserves_repeated_fields() {
        let msg = sample_profile();
        let bytes = msg.encode_to_vec();
        assert_eq!(RuntimeProfile::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn session_ack_round_trip() {
        let msg = SessionAck {
            accepted: false,
            assigned_worker_id: String::new(),
            reason: "build rejected".to_string(),
        };
        let bytes = msg.encode_to_vec();
        assert_eq!(SessionAck::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn task_dispatch_round_trip_preserves_identity() {
        let msg = sample_dispatch();
        let bytes = msg.encode_to_vec();
        let back = TaskDispatch::decode(bytes.as_slice()).unwrap();
        assert_eq!(back, msg);
        assert_eq!(back.execution_identity, framed([0xcdu8; 32]));
    }

    #[test]
    fn result_upload_round_trip_preserves_identity_and_steps() {
        let msg = sample_upload();
        let bytes = msg.encode_to_vec();
        let back = ResultUpload::decode(bytes.as_slice()).unwrap();
        assert_eq!(back, msg);
        assert_eq!(back.steps, 4096);
        assert_eq!(back.execution_identity, framed([0xabu8; 32]));
    }

    #[test]
    fn heartbeat_round_trip() {
        let msg = Heartbeat {
            worker_id: "w".to_string(),
            task_id: "t".to_string(),
            attempts: 7,
        };
        let bytes = msg.encode_to_vec();
        assert_eq!(Heartbeat::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn cancel_round_trip() {
        let msg = CancelTask {
            task_id: "t".to_string(),
            reason: "lease expired".to_string(),
        };
        let bytes = msg.encode_to_vec();
        assert_eq!(CancelTask::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn session_request_hello_oneof_round_trip() {
        let msg = SessionRequest {
            message: Some(session_request::Message::Hello(sample_hello())),
        };
        let bytes = msg.encode_to_vec();
        let back = SessionRequest::decode(bytes.as_slice()).unwrap();
        assert!(matches!(
            back.message,
            Some(session_request::Message::Hello(_))
        ));
        assert_eq!(back, msg);
    }

    #[test]
    fn session_response_assign_oneof_round_trip() {
        let msg = SessionResponse {
            message: Some(session_response::Message::Assign(sample_dispatch())),
        };
        let bytes = msg.encode_to_vec();
        let back = SessionResponse::decode(bytes.as_slice()).unwrap();
        assert!(matches!(
            back.message,
            Some(session_response::Message::Assign(_))
        ));
        assert_eq!(back, msg);
    }

    // Wire-layout pins: the proto source names these field numbers, and a
    // renumber without an approved format change would flip these bytes.

    #[test]
    fn worker_hello_field_numbers_stable() {
        let bytes = sample_hello().encode_to_vec();
        assert_eq!(
            bytes[0], 0x0A,
            "WorkerHello worker_id must be field 1/LEN => 0x0A"
        );
        // worker_id body, then version (2/LEN => 0x12), then
        // execution_identity (3/LEN => 0x1A).
        let worker_id_len = 8u64; // "worker-7"
        let pos = varint_len(0x0A) + varint_len(worker_id_len) + worker_id_len as usize;
        assert_eq!(decode_field_tag(&bytes, pos), 0x12, "version must be 2/LEN");
        let version_len = 5u64; // "0.1.0"
        let pos = pos + varint_len(0x12) + varint_len(version_len) + version_len as usize;
        assert_eq!(
            decode_field_tag(&bytes, pos),
            0x1A,
            "execution_identity must be 3/LEN"
        );
    }

    #[test]
    fn result_upload_field_numbers_stable() {
        let msg = sample_upload();
        let bytes = msg.encode_to_vec();
        // task_id = 1/LEN => 0x0A; journal_root_hex = 2/LEN => 0x12;
        // steps = 3/VARINT => 0x18; ok = 4/VARINT => 0x20; error is empty
        // and omitted; execution_identity = 6/LEN => 0x32.
        assert_eq!(bytes[0], 0x0A, "task_id must be 1/LEN");
        let pos = varint_len(0x0A) + varint_len(2) + 2;
        assert_eq!(decode_field_tag(&bytes, pos), 0x12, "root must be 2/LEN");
        let pos = pos + varint_len(0x12) + varint_len(64) + 64;
        assert_eq!(
            decode_field_tag(&bytes, pos),
            0x18,
            "steps must be 3/VARINT"
        );
        let pos = pos + varint_len(0x18) + varint_len(4096);
        assert_eq!(decode_field_tag(&bytes, pos), 0x20, "ok must be 4/VARINT");
        let pos = pos + varint_len(0x20) + 1;
        assert_eq!(
            decode_field_tag(&bytes, pos),
            0x32,
            "execution_identity must be 6/LEN"
        );
    }

    #[test]
    fn session_request_oneof_field_numbers_stable() {
        let msg = SessionRequest {
            message: Some(session_request::Message::Hello(sample_hello())),
        };
        let bytes = msg.encode_to_vec();
        // The oneof wrapper carries the variant: hello = field 1 => 0x0A.
        assert_eq!(
            bytes[0], 0x0A,
            "SessionRequest hello variant must be field 1/LEN => 0x0A"
        );
        // The payload is exactly the encoded hello; nothing else follows.
        let hello_len = decode_field_len(&bytes, 1) as usize;
        let pos = varint_len(0x0A) + varint_len(hello_len as u64);
        assert_eq!(pos + hello_len, bytes.len(), "hello must be the only field");
    }

    #[test]
    fn session_response_oneof_field_numbers_stable() {
        let msg = SessionResponse {
            message: Some(session_response::Message::Assign(sample_dispatch())),
        };
        let bytes = msg.encode_to_vec();
        // assign = field 2 => 0x12.
        assert_eq!(
            bytes[0], 0x12,
            "SessionResponse assign variant must be field 2/LEN => 0x12"
        );
        let dispatch_len = decode_field_len(&bytes, 1) as usize;
        let pos = varint_len(0x12) + varint_len(dispatch_len as u64) + dispatch_len;
        // No trailing fields after the dispatch.
        assert_eq!(pos, bytes.len(), "dispatch must be the only field");
    }

    // Unknown fields are skipped, so older readers tolerate newer writers.

    #[test]
    fn unknown_fields_are_skipped() {
        let mut bytes = sample_hello().encode_to_vec();
        append_unknown_len(&mut bytes, 99, b"unknown-bytes");
        append_unknown_varint(&mut bytes, 100, 12345);
        let back = WorkerHello::decode(bytes.as_slice()).unwrap();
        assert_eq!(back, sample_hello());
    }

    // Malformed input must produce a typed decode error, never a panic.

    #[test]
    fn truncated_input_returns_error() {
        let mut bytes = sample_hello().encode_to_vec();
        bytes.truncate(bytes.len() - 1);
        let err =
            WorkerHello::decode(bytes.as_slice()).expect_err("truncated input must not decode");
        assert!(err.to_string().contains("buffer underflow"), "got {err}");
    }

    #[test]
    fn length_prefix_at_u64_max_is_rejected_not_wrapped() {
        let bytes = len_tag(1, u64::MAX);
        let err = WorkerHello::decode(bytes.as_slice())
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
        let mut bytes = len_tag(1, 1 << 20);
        bytes.extend_from_slice(b"abcd");
        let err = WorkerHello::decode(bytes.as_slice())
            .expect_err("oversized length prefix must not decode");
        let msg = err.to_string();
        assert!(
            msg.contains("buffer underflow") || msg.contains("delimited length exceeded"),
            "got {msg}"
        );
    }

    #[test]
    fn varint_overflow_returns_error() {
        let bytes = vec![0x80u8; 11];
        let err =
            WorkerHello::decode(bytes.as_slice()).expect_err("overflowed varint must not decode");
        assert!(err.to_string().contains("invalid varint"), "got {err}");
    }

    #[test]
    fn invalid_wire_type_returns_error() {
        let mut bytes = Vec::new();
        encode_tag_varint(1, 3, &mut bytes);
        let err =
            WorkerHello::decode(bytes.as_slice()).expect_err("invalid wire type must not decode");
        assert!(err.to_string().contains("invalid wire type"), "got {err}");
    }

    #[test]
    fn invalid_utf8_returns_error() {
        let mut bytes = len_tag(1, 1);
        bytes.push(0xFF);
        let err = WorkerHello::decode(bytes.as_slice()).expect_err("invalid UTF-8 must not decode");
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
