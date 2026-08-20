//! Mixed-topology Wasm test: multiple polyglot guests in one Store.
//!
//! Loads prebuilt polyglot guests (Go via TinyGo, Zig, C via clang,
//! Emscripten) as named instances in one [`WasmBackend`] and runs them.
//! Every present prebuilt guest is executed and must print its marker
//! deterministically; the two-guest topology check also asserts
//! hash-deterministic journals across two fresh runs with the same seed.
//! When prebuilt artifacts are absent the tests print a skip notice and
//! pass, so other CI jobs without the polyglot toolchains stay green.
//!
//! Prebuilt artifacts are optional drop-ins at `guests/prebuilt/*.wasm`. Build
//! them when toolchains are present (see `guests/README.md`):
//!   tinygo build -o guests/prebuilt/go.wasm -target wasi guests/go/main.go
//!   zig build-exe -target wasm32-freestanding -O ReleaseSmall -fno-entry --export=run -femit-bin=guests/prebuilt/zig.wasm guests/zig/main.zig
//!   clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--export=run -o guests/prebuilt/c.wasm guests/c/main.c
//!   emcc guests/emscripten/main.c -O3 -o guests/prebuilt/emscripten.wasm -sSTANDALONE_WASM -sEXPORTED_FUNCTIONS=_run --no-entry
#![cfg(feature = "backend-wasm")]

use std::path::Path;

use ledger_sim::{SeedTree, WasmBackend};

/// Prebuilt guest names and the marker strings their `run` export prints.
const CANDIDATES: [(&str, &str); 4] = [
    ("go", "go-guest-ok"),
    ("zig", "zig-guest-ok"),
    ("c", "c-guest-ok"),
    ("emscripten", "emcc-guest-ok"),
];

fn prebuilt_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../guests/prebuilt/{name}.wasm"))
}

fn guest_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|error| panic!("prebuilt guest missing at {}: {error}", path.display()))
}

fn run_two(
    seed: [u8; 32],
    a_name: &str,
    a_marker: &str,
    a_wasm: &[u8],
    b_name: &str,
    b_marker: &str,
    b_wasm: &[u8],
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let mut backend = WasmBackend::new(SeedTree::new(seed)).expect("wasm backend must build");
    backend
        .load_guest_multi(a_name, a_wasm)
        .unwrap_or_else(|e| panic!("{a_name} guest must load: {e:?}"));
    backend
        .load_guest_multi(b_name, b_wasm)
        .unwrap_or_else(|e| panic!("{b_name} guest must load: {e:?}"));

    let a_out = backend
        .run_export_on(a_name, "run")
        .unwrap_or_else(|e| panic!("{a_name} guest run must succeed: {e:?}"));
    let b_out = backend
        .run_export_on(b_name, "run")
        .unwrap_or_else(|e| panic!("{b_name} guest run must succeed: {e:?}"));

    let a_text = String::from_utf8_lossy(&a_out);
    assert!(
        a_text.contains(a_marker),
        "{a_name} guest must print marker {a_marker:?}; got {a_text:?}"
    );
    let b_text = String::from_utf8_lossy(&b_out);
    assert!(
        b_text.contains(b_marker),
        "{b_name} guest must print marker {b_marker:?}; got {b_text:?}"
    );

    let root = backend.journal_snapshot().root_hash();
    (a_out, b_out, root)
}

#[test]
fn mixed_topology_two_guests_hash_deterministic() {
    let mut available = Vec::new();
    for (name, marker) in CANDIDATES {
        let path = prebuilt_path(name);
        if path.exists() {
            let wasm = guest_bytes(&path);
            available.push((name, marker, wasm, path));
        }
    }

    if available.len() < 2 {
        eprintln!(
            "skip wasm_mixed_topology: need at least 2 prebuilt guests, found {}\n  go: {} exists={}\n  zig: {} exists={}\n  c: {} exists={}\n  emscripten: {} exists={}\n  Build them with:\n    tinygo build -o guests/prebuilt/go.wasm -target wasi guests/go/main.go\n    zig build-exe -target wasm32-freestanding -O ReleaseSmall -fno-entry --export=run -femit-bin=guests/prebuilt/zig.wasm guests/zig/main.zig\n    clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--export=run -o guests/prebuilt/c.wasm guests/c/main.c\n    emcc guests/emscripten/main.c -O3 -o guests/prebuilt/emscripten.wasm -sSTANDALONE_WASM -sEXPORTED_FUNCTIONS=_run --no-entry",
            available.len(),
            prebuilt_path("go").display(),
            prebuilt_path("go").exists(),
            prebuilt_path("zig").display(),
            prebuilt_path("zig").exists(),
            prebuilt_path("c").display(),
            prebuilt_path("c").exists(),
            prebuilt_path("emscripten").display(),
            prebuilt_path("emscripten").exists()
        );
        return;
    }

    // Prefer go+zig when both present, else first two available.
    let (a_name, a_marker, a_wasm, _) = &available[0];
    let (b_name, b_marker, b_wasm, _) = &available[1];
    // If go+zig both available, force that pair for spec compliance.
    let (a_name, a_marker, a_wasm, b_name, b_marker, b_wasm) =
        if available.iter().any(|(n, _, _, _)| *n == "go")
            && available.iter().any(|(n, _, _, _)| *n == "zig")
        {
            let go = available.iter().find(|(n, _, _, _)| *n == "go").unwrap();
            let zig = available.iter().find(|(n, _, _, _)| *n == "zig").unwrap();
            (go.0, go.1, go.2.as_slice(), zig.0, zig.1, zig.2.as_slice())
        } else {
            (
                *a_name,
                *a_marker,
                a_wasm.as_slice(),
                *b_name,
                *b_marker,
                b_wasm.as_slice(),
            )
        };

    let seed = [7u8; 32];
    let (a1, b1, root1) = run_two(seed, a_name, a_marker, a_wasm, b_name, b_marker, b_wasm);
    let (a2, b2, root2) = run_two(seed, a_name, a_marker, a_wasm, b_name, b_marker, b_wasm);

    assert_eq!(a1, a2, "{a_name} guest output must be deterministic");
    assert_eq!(b1, b2, "{b_name} guest output must be deterministic");
    assert_eq!(
        root1, root2,
        "mixed topology journal must be hash-deterministic across two runs (guests {a_name}+{b_name})"
    );
}

#[test]
fn mixed_topology_every_present_guest_runs() {
    // Semantic gate for every prebuilt artifact: each guest must load, run,
    // print its marker, and produce deterministic output and journal roots
    // across two fresh runs with the same seed. The two-guest topology test
    // prefers go+zig; this loop also executes the c and emscripten guests.
    for (name, marker) in CANDIDATES {
        let path = prebuilt_path(name);
        if !path.exists() {
            eprintln!(
                "skip guest {name}: no prebuilt artifact at {}",
                path.display()
            );
            continue;
        }
        let wasm = guest_bytes(&path);
        let seed = [11u8; 32];

        let mut backend = WasmBackend::new(SeedTree::new(seed)).expect("wasm backend must build");
        backend
            .load_guest_multi(name, &wasm)
            .unwrap_or_else(|e| panic!("{name} guest must load: {e:?}"));
        let out1 = backend
            .run_export_on(name, "run")
            .unwrap_or_else(|e| panic!("{name} guest run must succeed: {e:?}"));
        let root1 = backend.journal_snapshot().root_hash();

        let mut backend2 = WasmBackend::new(SeedTree::new(seed)).expect("second run must build");
        backend2
            .load_guest_multi(name, &wasm)
            .unwrap_or_else(|e| panic!("{name} guest must load on second run: {e:?}"));
        let out2 = backend2
            .run_export_on(name, "run")
            .unwrap_or_else(|e| panic!("{name} guest run must succeed on second run: {e:?}"));
        let root2 = backend2.journal_snapshot().root_hash();

        let text1 = String::from_utf8_lossy(&out1);
        assert!(
            text1.contains(marker),
            "{name} guest must print marker {marker:?}; got {text1:?}"
        );
        assert_eq!(out1, out2, "{name} guest output must be deterministic");
        assert_eq!(
            root1, root2,
            "{name} guest journal must be hash-deterministic across two runs"
        );
    }
}

#[test]
fn mixed_topology_single_guest_api_still_works() {
    // The prebuilt path is optional; when absent we fall back to the Rust
    // guest that is always present (wasm32-wasip1). This keeps the single-
    // instance API gate green without toolchains.
    let go_path = prebuilt_path("go");
    let zig_path = prebuilt_path("zig");

    let (wasm, marker): (Vec<u8>, &str) = if go_path.exists() {
        (guest_bytes(&go_path), "go-guest-ok")
    } else if zig_path.exists() {
        (guest_bytes(&zig_path), "zig-guest-ok")
    } else {
        // Fallback: use the Rust guest's deterministic stdout path via the
        // common helper. We cannot import `common::guest_wasm_bytes` without
        // duplicating that module, so read the same artifact path directly.
        let rust_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/wasm32-wasip1/debug/wasm_guest.wasm");
        if !rust_path.exists() {
            eprintln!(
                "skip mixed_topology_single_guest_api: no prebuilt and no Rust guest at {}",
                rust_path.display()
            );
            return;
        }
        let wasm = std::fs::read(&rust_path).unwrap();
        let mut backend = WasmBackend::from_wasm(SeedTree::new([9; 32]), &wasm)
            .expect("rust guest must load via from_wasm");
        let out = backend.run_export("run").expect("run must succeed");
        assert!(!out.is_empty(), "rust guest must produce stdout");
        let root1 = backend.journal_snapshot().root_hash();
        let mut backend2 =
            WasmBackend::from_wasm(SeedTree::new([9; 32]), &wasm).expect("second run must load");
        let out2 = backend2.run_export("run").expect("second run must succeed");
        assert_eq!(out, out2, "single-instance run must be deterministic");
        assert_eq!(
            root1,
            backend2.journal_snapshot().root_hash(),
            "single-instance journal must be deterministic"
        );
        return;
    };

    // If we reached here we loaded one prebuilt; verify the single-name
    // helper load_guest still works and run_export aliases "main".
    let mut backend = WasmBackend::new(SeedTree::new([9; 32])).unwrap();
    backend.load_guest(&wasm).expect("load_guest must succeed");
    let out = backend.run_export("run").expect("run_export must succeed");
    assert!(
        String::from_utf8_lossy(&out).contains(marker),
        "marker {marker} missing in {out:?}"
    );
    let root1 = backend.journal_snapshot().root_hash();

    let mut backend2 = WasmBackend::new(SeedTree::new([9; 32])).unwrap();
    backend2
        .load_guest(&wasm)
        .expect("second load_guest must succeed");
    let out2 = backend2
        .run_export("run")
        .expect("second run_export must succeed");
    assert_eq!(out, out2, "single-instance output must be deterministic");
    assert_eq!(
        root1,
        backend2.journal_snapshot().root_hash(),
        "single-instance journal must be deterministic"
    );
}

#[test]
fn mixed_topology_unknown_guest_is_no_guest() {
    let mut backend = WasmBackend::new(SeedTree::new([1; 32])).unwrap();
    let err = backend.run_export_on("does-not-exist", "run").unwrap_err();
    assert!(
        matches!(err, ledger_sim::WasmError::NoGuest),
        "unknown guest name must return NoGuest; got {err:?}"
    );
}
