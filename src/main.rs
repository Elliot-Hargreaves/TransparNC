//! Main entry point for the TransparNC node.
//! This module provides a CLI for configuring and running a VPN node.

use boringtun::x25519::{PublicKey, StaticSecret};
use clap::{Parser, Subcommand};
use std::net::{Ipv4Addr, SocketAddr};
use transpar_nc::net::VpnEngine;
use transpar_nc::net::tun::{TunConfig, TunDevice};
use transpar_nc::net::wireguard::{KeyPair, WireGuardPeer};
use transpar_nc::net::nat::{RealStunClient, StunClient};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// The UDP port for physical communication.
    #[arg(long, default_value_t = 51820)]
    local_port: u16,

    /// The virtual IP for the TUN interface.
    #[arg(long, default_value = "10.0.0.1")]
    tun_ip: Ipv4Addr,

    /// The private key of the node. If not provided, a random one will be generated.
    #[arg(long)]
    private_key: Option<String>,

    /// The public key of the remote peer.
    #[arg(long)]
    peer_key: Option<String>,

    /// The physical IP:Port of the remote peer.
    #[arg(long)]
    peer_endpoint: Option<SocketAddr>,

    /// STUN server address for NAT discovery.
    #[arg(long)]
    stun_server: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates and prints a public key for setup.
    GenerateKeys,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::GenerateKeys) = cli.command {
        let keypair = KeyPair::generate();
        let private_hex = hex::encode(keypair.private.to_bytes());
        let public_hex = hex::encode(keypair.public.as_bytes());
        println!("Private Key: {}", private_hex);
        println!("Public Key: {}", public_hex);
        return Ok(());
    }

    // Configure TUN
    let tun_config = TunConfig {
        name: "utun%d".to_string(),
        address: cli.tun_ip,
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1420,
    };
    let tun_device = TunDevice::new(tun_config)?;

    // Configure STUN
    let stun_client: Option<Box<dyn StunClient>> = cli.stun_server
        .map(|s| Box::new(RealStunClient::new(s)) as Box<dyn StunClient>);

    // Configure VPN Engine
    let engine = VpnEngine::new(tun_device, cli.local_port, stun_client).await?;

    // Add peer if provided
    if let (Some(peer_key_str), Some(peer_endpoint)) = (cli.peer_key, cli.peer_endpoint) {
        let peer_key_bytes = hex::decode(peer_key_str)?;
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&peer_key_bytes);
        let peer_static_public = PublicKey::from(key_array);

        let private_key = if let Some(pk_str) = cli.private_key {
            let pk_bytes = hex::decode(pk_str)?;
            let mut pk_array = [0u8; 32];
            pk_array.copy_from_slice(&pk_bytes);
            StaticSecret::from(pk_array)
        } else {
            KeyPair::generate().private
        };

        let peer = WireGuardPeer::new(
            private_key,
            peer_static_public,
            None,
            None,
            0,
            Some(peer_endpoint),
        )?;
        engine.add_peer(peer).await;
    }

    println!("Starting VPN engine on port {}...", cli.local_port);
    engine.run().await?;

    Ok(())
}
