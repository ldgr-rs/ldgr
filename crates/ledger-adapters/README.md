# ledger-adapters

OTel ingest adapters for the ldgr journal.

External traces become content-addressed journal entries: `ingest_otel*` maps OpenTelemetry spans onto journal entries, and the interchange envelope (`envelope.rs`) records the emitting tool and the entry mapping. No solver or scheduling logic lives here; only deterministic mapping and fidelity tracking.

Fidelity is structural: an ingest produces an `IngestedJournal` that carries `Fidelity` (`BitExact` or `LineageOnly`) explicitly. A lineage-only journal gets an `Epoch("lineage-only")` marker entry appended, and `is_certifiable()` returns `false`, so inferred lineage can never mint a certificate (the LDFI layer-A rule).

Modes:

- `ingest_otel_file` / `ingest_otel_file_with_config`: NDJSON file of OTel spans. The `std::fs` read is the host-daemon path (the one ambient I/O exception, analogous to `TokioBackend`), never simulation code.
- `ingest_otel`, `ingest_otel_dedup`, `ingest_otel_enveloped`, `ingest_otel_with_fidelity`: span-vector ingest with dedup and fidelity controls via `OtelIngestConfig`.

CLI entry point: `ledger ingest --input spans.ndjson --fidelity lineage-only`.
