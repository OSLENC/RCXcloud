use clap::{Parser, Subcommand};
use rcxcore::{
    kill::{generate_kill_blob, KillRequest},
    keystore::KeyStore,
    device::registry::DeviceRegistry,
};

use std::fs;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate {
        #[arg(long)]
        device_id: String,

        #[arg(long)]
        replay: u64,

        #[arg(long)]
        out: String,
    },
}

fn main() {
    let cli = Cli::parse();

    // Admin device must already be unlocked
    let keystore = KeyStore::new();
    let registry = DeviceRegistry::open().expect("registry");

    match cli.cmd {
        Command::Generate { device_id, replay, out } => {
            let id_bytes = hex::decode(device_id).expect("hex device id");
            let mut id = [0u8; 32];
            id.copy_from_slice(&id_bytes);

            let blob = generate_kill_blob(
                keystore.master_key(),
                &registry,
                KillRequest {
                    target_device_id: id,
                    replay,
                },
            );

            fs::write(out, blob.borrow()).expect("write kill blob");
        }
    }
}
