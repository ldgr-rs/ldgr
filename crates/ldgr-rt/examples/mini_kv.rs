#![deny(unsafe_code)]

//! Mini KV example: same SUT under `tokio` and `ldgr` sim.
//! Ambient `Instant`/`thread_rng`/`spawn`/`sleep`/`net` map to `Handle` calls.

use core::time::Duration;

use ldgr_rt::task_id_for;
use ldgr_rt::{Handle, RunConfig};
use ledger_format::{ActorId, EntryHash, StreamId};

/// Simulated key-value node: stores one key and replicates it to a peer.
async fn kv_node(mut handle: Handle, peer: ActorId) {
    let my_value = handle.rng_next_u64(StreamId(0)).unwrap_or(0) % 1000;
    let input_hash = EntryHash(*blake3::hash(&my_value.to_le_bytes()).as_bytes());
    let write_id = task_id_for("kv_write", input_hash);
    println!(
        "[actor {}] write id {:?} value {}",
        handle.actor().0,
        write_id,
        my_value
    );

    handle.sleep(Duration::from_micros(5)).await;

    let sent = handle.net_send(peer.0 as usize, my_value);
    println!("[actor {}] sent to {}: {sent}", handle.actor().0, peer.0);

    let _conn = handle.conn(handle.actor(), peer);
}

async fn kv_replica(handle: Handle) {
    let value = handle.net_recv().await;
    println!("[actor {}] received {value}", handle.actor().0);
    handle.sleep(Duration::from_micros(2)).await;
    println!("[actor {}] replica done", handle.actor().0);
    let _ = handle.net_send(0, 999);
}

async fn mini_kv_main(handle: Handle) {
    let replica_handle = handle.with_actor(ActorId(1));
    let _replica_id = handle.spawn(move |child| {
        let child = child.with_actor(ActorId(1));
        Box::pin(kv_replica(child))
    });

    let main_actor = handle.with_actor(ActorId(0));
    kv_node(main_actor, ActorId(1)).await;

    let ack = handle.net_recv().await;
    println!("[actor {}] got ack {ack}", handle.actor().0);
    handle.sleep(Duration::from_micros(10)).await;
    println!("mini_kv done (actor {})", handle.actor().0);
    let _ = replica_handle;
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = RunConfig::builder()
        .seed(EntryHash([42u8; 32]))
        .max_steps(10_000)
        .build();
    let res = ldgr_rt::run(cfg, mini_kv_main)?;
    println!("run steps: {}", res.steps);
    #[cfg(any(feature = "sim", feature = "sim-link"))]
    println!("journal root: {:x?}", res.journal_root);
    Ok(())
}
