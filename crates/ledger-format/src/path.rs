//! Canonical path identity for filesystem effects.
//!
//! Opaque bytes, not Unicode. `/` separates; empty components and `.`
//! vanish; `..` pops one component and fails past the virtual root;
//! NUL fails; other bytes pass through unchanged.

use alloc::vec::Vec;

use crate::limits::MAX_CANONICAL_PATH_BYTES;

/// Length of a canonical path digest (32-byte BLAKE3).
pub const PATH_HASH_LEN: usize = 32;

/// Domain prefix separating path hashes from entry and content hashes.
pub const PATH_DOMAIN: &[u8] = b"ldgr.fs.path.v2\0";

/// Canonical path failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    RootEscape,
    NulByte,
    /// Canonical bytes exceed [`MAX_CANONICAL_PATH_BYTES`].
    TooLong,
    /// `PathRef` hash does not match the canonical bytes.
    HashMismatch,
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RootEscape => f.write_str("path escaped virtual root via leading .."),
            Self::NulByte => f.write_str("path contains a NUL byte"),
            Self::TooLong => f.write_str("canonicalized path exceeds maximum byte length"),
            Self::HashMismatch => f.write_str("decoded path hash does not match canonical bytes"),
        }
    }
}

impl core::error::Error for PathError {}

/// Canonicalizes raw path bytes to an absolute virtual path.
///
/// The length limit applies after canonicalization.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, PathError> {
    if raw.contains(&0) {
        return Err(PathError::NulByte);
    }
    let mut out: Vec<&[u8]> = Vec::new();
    for component in raw.split(|b| *b == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            if out.pop().is_none() {
                return Err(PathError::RootEscape);
            }
            continue;
        }
        out.push(component);
    }
    let mut canonical =
        Vec::with_capacity(out.iter().map(|c| c.len()).sum::<usize>() + out.len() + 1);
    canonical.push(b'/');
    for (i, component) in out.iter().enumerate() {
        if i > 0 {
            canonical.push(b'/');
        }
        canonical.extend_from_slice(component);
    }
    if canonical.len() > MAX_CANONICAL_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    Ok(canonical)
}

/// Canonicalized path: content address of the canonical bytes.
///
/// The decoder recomputes and verifies the hash before trusting the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRef {
    pub path_hash: [u8; PATH_HASH_LEN],
    pub canonical_path: Vec<u8>,
}

impl PathRef {
    /// Computes the domain-separated content address of `canonical_path`.
    ///
    /// `canonical_path` must already be canonical. The caller supplies
    /// the hash to keep `ledger-format` free of the BLAKE3 dependency.
    pub fn new(path_hash: [u8; PATH_HASH_LEN], canonical_path: Vec<u8>) -> Self {
        Self {
            path_hash,
            canonical_path,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_path
    }
}

/// Encodes a `PathRef` as canonical CBOR `[hash, bytes]`.
pub fn encode_path_ref(out: &mut Vec<u8>, path_ref: &PathRef) {
    crate::cbor::array(out, 2);
    crate::cbor::bytes(out, &path_ref.path_hash);
    crate::cbor::bytes(out, &path_ref.canonical_path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn equivalent_lexical_paths_canonicalize_equal() {
        let a = canonicalize(b"/a/b/./c").expect("a canonicalizes");
        let b = canonicalize(b"a/b/c").expect("b canonicalizes");
        let c = canonicalize(b"/a//b/c/").expect("c canonicalizes");
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, b"/a/b/c");
    }

    #[test]
    fn dotdot_removes_a_component() {
        assert_eq!(canonicalize(b"/a/b/../c").expect("canonicalizes"), b"/a/c");
    }

    #[test]
    fn root_escape_is_rejected() {
        assert_eq!(canonicalize(b".."), Err(PathError::RootEscape));
        assert_eq!(canonicalize(b"/../a"), Err(PathError::RootEscape));
    }

    #[test]
    fn nul_is_rejected() {
        assert_eq!(canonicalize(b"/a\0b"), Err(PathError::NulByte));
    }

    #[test]
    fn non_ascii_bytes_are_preserved() {
        let raw = b"/data/\xFF\xFE/f\xC3\xA9";
        let canonical = canonicalize(raw).expect("canonicalizes");
        assert_eq!(canonical, b"/data/\xFF\xFE/f\xC3\xA9");
    }

    #[test]
    fn root_is_slash() {
        assert_eq!(canonicalize(b"/").expect("root canonicalizes"), b"/");
        assert_eq!(canonicalize(b"").expect("empty canonicalizes"), b"/");
    }

    #[test]
    fn oversized_canonical_path_is_rejected() {
        let long = vec![b'a'; MAX_CANONICAL_PATH_BYTES + 1];
        let raw: Vec<u8> = long;
        assert_eq!(canonicalize(&raw), Err(PathError::TooLong));
    }
}
