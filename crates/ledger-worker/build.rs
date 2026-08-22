// ledger-lint:allow - build script may read env and fs by design
include!("src/build_codegen.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../ledger-format/proto/ledger/control/v1/control.proto");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/build_codegen.rs");
    if std::env::var("CARGO_FEATURE_GRPC").is_ok() {
        // Fail closed: a missing protoc, a broken proto, or an unwritable
        // out dir aborts the build. The default (non-grpc) build never runs
        // codegen and needs no protoc, which is the documented offline path.
        regenerate(Path::new(env!("CARGO_MANIFEST_DIR")), |paths| {
            let includes: Vec<&PathBuf> = paths.includes.iter().collect();
            tonic_prost_build::configure()
                .build_server(true)
                .build_client(true)
                .out_dir(&paths.out_dir)
                .compile_protos(&[&paths.proto], &includes)
                .map_err(Into::into)
        })?;
    }
    Ok(())
}
