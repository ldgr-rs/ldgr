#![deny(unsafe_code)]

//! Mini KV example: the same SUT runs under `tokio` and under `ldgr` sim.
//!
//! Porting guide: replace ambient APIs with `Handle` calls.
//! - `std::time::Instant::now` -> `handle.clock().now()`
//! - `rand::thread_rng`      -> `handle.rng(stream).next_u64()`
//! - `tokio::spawn`          -> `handle.spawn(|child| Box::pin(...))`
//! - `tokio::time::sleep`    -> `handle.sleep(d).await`
//! - `std::net`              -> `handle.net_send` / `handle.net_recv` or `handle.conn`
//!
//! Run without sim (tokio path):
//!   cargo run -p ldgr-rt --example mini_kv
//! Run with sim-link (direct link, workspace tests; deterministic journal):
//!   cargo run -p ldgr-rt --example mini_kv --features sim-link
//!   # Requires `LEDGER_ENGINE_BIN` or `ledger` on PATH only for the IPC
//!   # `sim` feature, where caller programs are refused (`run_named` reaches
//!   # server workloads such as "kv" instead).

use core::time::Duration;

use ldgr_rt::task_id_for;
use ldgr_rt::{Handle, RunConfig};

/// Simulated key-value node: stores one key and replicates it to a peer.
///
/// The logic is intentionally tiny so the deterministic properties are easy
/// to see: same seed -> same journal root, same RNG draws, same schedule.
async fn kv_node(mut handle: Handle, peer: u32) {
    // Deterministic RNG stream 0: same seed yields same value every run.
    let my_value = handle.rng_next_u64(0) % 1000;
    // Content-addressed task id for the write (CAM dedup demo).
    let input_hash = *blake3::hash(&my_value.to_le_bytes()).as_bytes();
    let write_id = task_id_for("kv_write", input_hash);
    println!(
        "[actor {}] write id {:?} value {}",
        handle.actor(),
        write_id,
        my_value
    );

    // Sleep on virtual time (deterministic under sim).
    handle.sleep(Duration::from_micros(5)).await;

    // Replicate via the facade net. `with_actor` shows multi-actor routing
    // outside sim without needing SimNet.
    let sent = handle.net_send(peer as usize, my_value);
    println!("[actor {}] sent to {peer}: {sent}", handle.actor());

    // Also demonstrate Conn for arbitrary pairs.
    let _conn = handle.conn(handle.actor(), peer);
}

async fn kv_replica(handle: Handle) {
    // This replica waits for the peer's value.
    let value = handle.net_recv().await;
    println!("[actor {}] received {value}", handle.actor());
    handle.sleep(Duration::from_micros(2)).await;
    println!("[actor {}] replica done", handle.actor());
    // Ack back so main can wait deterministically in both modes.
    let _ = handle.net_send(0, 999);
}

async fn mini_kv_main(handle: Handle) {
    // In sim the two nodes are separate tasks with distinct actors. Outside
    // sim they share the in-process SharedNet but use with_actor to route.
    // Spawn replica as actor 1, keep main as actor 0.
    let replica_handle = handle.with_actor(1);
    let _replica_id = handle.spawn(move |child| {
        // Child inherits the handle but we rebind to actor 1 for clarity.
        let child = child.with_actor(1);
        Box::pin(kv_replica(child))
    });

    // Main node remains actor 0 and talks to 1.
    let main_actor = handle.with_actor(0);
    kv_node(main_actor, 1).await;

    // Wait for replica ack (deterministic join in both modes).
    let ack = handle.net_recv().await;
    println!("[actor {}] got ack {ack}", handle.actor());
    handle.sleep(Duration::from_micros(10)).await;
    println!("mini_kv done (actor {})", handle.actor());
    let _ = replica_handle;
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = RunConfig::builder()
        .seed([42u8; 32])
        .max_steps(10_000)
        .build();
    let res = ldgr_rt::run(cfg, mini_kv_main)?;
    println!("run steps: {}", res.steps);
    #[cfg(any(feature = "sim", feature = "sim-link"))]
    println!("journal root: {:x?}", res.journal_root);
    Ok(())
}
