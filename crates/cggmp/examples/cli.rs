use clap::{Parser, Subcommand};
use curv::arithmetic::Converter;
use wamu_cggmp::{
    generate_parties_and_simulate_identity_rotation, generate_parties_and_simulate_key_refresh,
    generate_parties_and_simulate_share_addition,
    generate_parties_and_simulate_share_recovery_quorum,
    generate_parties_and_simulate_share_removal, generate_parties_and_simulate_signing,
    generate_parties_and_simulate_threshold_modification, simulate_keygen,
};

/// Wamu augmented CGGMP CLI.
#[derive(Debug, Parser)]
#[command(name = "wamu-cggmp")]
#[command(version, about = "Wamu augmented CGGMP CLI.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Commands for all sub-protocols.
// NOTE: Quorum size = threshold + 1
#[derive(Debug, Subcommand)]
enum Commands {
    /// Runs key generation protocol.
    Keygen {
        /// The threshold.
        #[arg(short, long)]
        threshold: u16,
        /// The number of parties.
        #[arg(short, long)]
        n_parties: u16,
    },
    /// Runs key refresh protocol.
    KeyRefresh {
        /// The threshold.
        #[arg(short, long)]
        threshold: u16,
        /// The number of parties.
        #[arg(short, long)]
        n_parties: u16,
    },
    /// Runs signing protocol.
    Sign {
        /// The threshold.
        #[arg(short, long)]
        threshold: u16,
        /// The total number of parties.
        #[arg(short, long)]
        n_parties: u16,
        /// The number of participants in the signing protocol.
        #[arg(short = 'q', long)]
        n_participants: u16,
    },
    /// Runs identity rotation protocol.
    IdentityRotation {
        /// The threshold.
        #[arg(short, long)]
        threshold: u16,
        /// The total number of parties.
        #[arg(short, long)]
        n_parties: u16,
    },
    /// Runs share addition protocol.
    ShareAddition {
        /// The initial threshold during key generation.
        #[arg(short, long)]
        threshold: u16,
        /// The initial number of parties during key generation.
        #[arg(short, long)]
        n_parties_init: u16,
        /// The new number of parties to add.
        #[arg(short = 'a', long)]
        n_parties_add: u16,
    },
    /// Runs share removal protocol.
    ShareRemoval {
        /// The initial threshold during key generation.
        #[arg(short, long)]
        threshold: u16,
        /// The initial number of parties during key generation.
        #[arg(short, long)]
        n_parties_init: u16,
        /// The new number of parties to remove.
        #[arg(short = 'r', long)]
        n_parties_remove: u16,
    },
    /// Runs threshold modification protocol.
    ThresholdModification {
        /// The initial threshold during key generation.
        #[arg(short, long)]
        threshold_init: u16,
        /// The number of parties.
        #[arg(short, long)]
        n_parties: u16,
        /// The new threshold after threshold modification.
        #[arg(short = 'u', long)]
        threshold_new: u16,
    },
    /// Runs share recovery protocol.
    ShareRecovery {
        /// The threshold.
        #[arg(short, long)]
        threshold: u16,
        /// The total number of parties.
        #[arg(short, long)]
        n_parties: u16,
    },
}

fn main() {
    let args = Cli::parse();

    let to_upper_hex = |bytes: &[u8]| -> String {
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join("")
    };

    match args.command {
        Commands::Keygen {
            threshold,
            n_parties,
        } => {
            println!(
                "Simulating key generation with threshold={}, quorum-size={}, number of parties={}",
                threshold,
                threshold + 1,
                n_parties,
            );
            let (keys, identity_providers) = simulate_keygen(threshold, n_parties);
            for (i, key) in keys.iter().enumerate() {
                let (signing_share, sub_share) = key.extra.as_ref().unwrap();
                println!();
                println!(
                    "Party #{}:\n\
                    signing-share: 0x{}\n\
                    sub-share: 0x{:X}\n\
                    identity: 0x{}",
                    i + 1,
                    to_upper_hex(&signing_share.to_be_bytes()),
                    sub_share.y(),
                    to_upper_hex(&identity_providers[i].export())
                );
            }
        }
        Commands::KeyRefresh {
            threshold,
            n_parties,
        } => {
            println!(
                "Simulating key refresh with threshold={}, quorum-size={}, number of parties={}",
                threshold,
                threshold + 1,
                n_parties,
            );
            let ((keys_init, identity_providers), (keys_new, _)) =
                generate_parties_and_simulate_key_refresh(
                    threshold, n_parties, threshold, n_parties,
                );
            for (i, key) in keys_init.iter().enumerate() {
                let (signing_share_init, sub_share_init) = key.extra.as_ref().unwrap();
                let (signing_share_final, sub_share_final) = keys_new[i].extra.as_ref().unwrap();
                println!();
                println!(
                    "Party #{}:\n\
                    initial signing-share: 0x{}\n\
                    initial sub-share: 0x{:X}\n\
                    final signing-share: 0x{}\n\
                    final sub-share: 0x{:X}\n\
                    identity: 0x{}",
                    i + 1,
                    to_upper_hex(&signing_share_init.to_be_bytes()),
                    sub_share_init.y(),
                    to_upper_hex(&signing_share_final.to_be_bytes()),
                    sub_share_final.y(),
                    to_upper_hex(&identity_providers[i].export())
                );
            }
        }
        Commands::Sign {
            threshold,
            n_parties,
            n_participants,
        } => {
            println!(
                "Simulating signing with threshold={}, quorum-size={}, number of parties={}, number of participants={}",
                threshold,
                threshold + 1,
                n_parties,
                n_participants,
            );
            let (keys, identity_providers, output) =
                generate_parties_and_simulate_signing(threshold, n_parties, n_participants);
            println!();
            let (r, s) = output[0]
                .base
                .as_ref()
                .map(|it| (it.r.clone(), it.sigma.clone()))
                .unwrap();
            println!(
                "Signature: (0x{}, 0x{})",
                to_upper_hex(&r.to_bytes()),
                to_upper_hex(&s.to_bytes())
            );
            println!(
                "Public key: 0x{}",
                to_upper_hex(&keys[0].base.public_key().to_bytes(false))
            );

            for (i, key) in keys.iter().enumerate() {
                let (signing_share, sub_share) = key.extra.as_ref().unwrap();
                println!();
                println!(
                    "Party #{}:\n\
                    signing-share: 0x{}\n\
                    sub-share: 0x{:X}\n\
                    identity: 0x{}",
                    i + 1,
                    to_upper_hex(&signing_share.to_be_bytes()),
                    sub_share.y(),
                    to_upper_hex(&identity_providers[i].export())
                );
            }
        }
        Commands::IdentityRotation {
            threshold,
            n_parties,
        } => {
            println!(
                "Simulating identity rotation with threshold={}, quorum-size={}, number of parties={}",
                threshold,
                threshold + 1,
                n_parties,
            );
            let rotating_party_idx = 2;
            let (keys, identity_providers, identity_provider_new) =
                generate_parties_and_simulate_identity_rotation(
                    threshold,
                    n_parties,
                    rotating_party_idx,
                );
            for (i, key) in keys.iter().enumerate() {
                let idx = i as u16 + 1;
                let (signing_share, sub_share) = key.extra.as_ref().unwrap();
                println!();
                println!(
                    "Party #{}:\n\
                    signing-share: 0x{}\n\
                    sub-share: 0x{:X}\n\
                    {}identity: 0x{}\
                    {}",
                    i + 1,
                    to_upper_hex(&signing_share.to_be_bytes()),
                    sub_share.y(),
                    if idx == rotating_party_idx {
                        "initial "
                    } else {
                        ""
                    },
                    to_upper_hex(&identity_providers[i].export()),
                    if idx == rotating_party_idx {
                        format!(
                            "\nfinal identity: {}",
                            to_upper_hex(&identity_provider_new.export())
                        )
                    } else {
                        "".to_string()
                    },
                );
            }
        }
        Commands::ShareAddition {
            threshold,
            n_parties_init,
            n_parties_add,
        } => {
            println!(
                "Simulating share addition with threshold={}, quorum-size={}, initial number of parties={}, number of parties to add={}",
                threshold,
                threshold + 1,
                n_parties_init,
                n_parties_add,
            );
            let ((keys_init, _), (keys_new, identity_providers)) =
                generate_parties_and_simulate_share_addition(
                    threshold,
                    n_parties_init,
                    n_parties_init + n_parties_add,
                    2,
                );
            for (i, key) in keys_new.iter().enumerate() {
                let key_init_option = keys_init.get(i);
                let share_option_init = key_init_option.and_then(|it| it.extra.as_ref());
                let signing_share_init_option =
                    share_option_init.map(|(signing_share, _)| signing_share);
                let sub_share_init_option = share_option_init.map(|(_, sub_share)| sub_share);
                let (signing_share_final, sub_share_final) = key.extra.as_ref().unwrap();
                println!();
                println!(
                    "Party #{}:\n\
                    initial signing-share: {}\n\
                    initial sub-share: {}\n\
                    final signing-share: 0x{}\n\
                    final sub-share: 0x{:X}\n\
                    identity: 0x{}",
                    i + 1,
                    match signing_share_init_option {
                        Some(signing_share_init) =>
                            format!("0x{}", to_upper_hex(&signing_share_init.to_be_bytes())),
                        None => "None".to_string(),
                    },
                    match sub_share_init_option {
                        Some(sub_share_init) => format!("0x{:X}", &sub_share_init.y()),
                        None => "None".to_string(),
                    },
                    to_upper_hex(&signing_share_final.to_be_bytes()),
                    sub_share_final.y(),
                    to_upper_hex(&identity_providers[i].export())
                );
            }
        }
        Commands::ShareRemoval {
            threshold,
            n_parties_init,
            n_parties_remove,
        } => {
            println!(
                "Simulating share removal with threshold={}, quorum-size={}, initial number of parties={}, number of parties to remove={}",
                threshold,
                threshold + 1,
                n_parties_init,
                n_parties_remove,
            );
            let ((keys_init, identity_providers), (keys_new, _)) =
                generate_parties_and_simulate_share_removal(
                    threshold,
                    n_parties_init,
                    n_parties_init - n_parties_remove,
                    2,
                );
            for (i, key_init) in keys_init.iter().enumerate() {
                let (signing_share_init, sub_share_init) = key_init.extra.as_ref().unwrap();
                let key_new_option = keys_new.get(i);
                let share_option_new = key_new_option.and_then(|it| it.extra.as_ref());
                let signing_share_new_option =
                    share_option_new.map(|(signing_share, _)| signing_share);
                let sub_share_new_option = share_option_new.map(|(_, sub_share)| sub_share);
                println!();
                println!(
                    "Party #{}:\n\
                    initial signing-share: 0x{}\n\
                    initial sub-share: 0x{:X}\n\
                    final signing-share: {}\n\
                    final sub-share: {}\n\
                    identity: 0x{}",
                    i + 1,
                    to_upper_hex(&signing_share_init.to_be_bytes()),
                    sub_share_init.y(),
                    match signing_share_new_option {
                        Some(signing_share_final) =>
                            format!("0x{}", to_upper_hex(&signing_share_final.to_be_bytes())),
                        None => "None".to_string(),
                    },
                    match sub_share_new_option {
                        Some(sub_share_final) => format!("0x{:X}", &sub_share_final.y()),
                        None => "None".to_string(),
                    },
                    to_upper_hex(&identity_providers[i].export())
                );
            }
        }
        Commands::ThresholdModification {
            threshold_init,
            n_parties,
            threshold_new,
        } => {
            println!(
                "Simulating threshold modification with initial threshold={}, initial quorum-size={}, final threshold={}, final quorum-size={}, number of parties={}",
                threshold_init,
                threshold_init + 1,
                threshold_new,
                threshold_new + 1,
                n_parties,
            );
            let (keys_init, keys_new, identity_providers) =
                generate_parties_and_simulate_threshold_modification(
                    threshold_init,
                    threshold_new,
                    n_parties,
                    2,
                );
            for (i, key) in keys_init.iter().enumerate() {
                let (signing_share_init, sub_share_init) = key.extra.as_ref().unwrap();
                let (signing_share_final, sub_share_final) = keys_new[i].extra.as_ref().unwrap();
                println!();
                println!(
                    "Party #{}:\n\
                    initial signing-share: 0x{}\n\
                    initial sub-share: 0x{:X}\n\
                    final signing-share: 0x{}\n\
                    final sub-share: 0x{:X}\n\
                    identity: 0x{}",
                    i + 1,
                    to_upper_hex(&signing_share_init.to_be_bytes()),
                    sub_share_init.y(),
                    to_upper_hex(&signing_share_final.to_be_bytes()),
                    sub_share_final.y(),
                    to_upper_hex(&identity_providers[i].export())
                );
            }
        }
        Commands::ShareRecovery {
            threshold,
            n_parties,
        } => {
            println!(
                "Simulating share recovery with quorum with threshold={}, quorum-size={}, number of parties={}",
                threshold,
                threshold + 1,
                n_parties,
            );
            let recovering_party_idx = 2;
            let (keys_init, keys_new, identity_providers) =
                generate_parties_and_simulate_share_recovery_quorum(
                    threshold,
                    n_parties,
                    recovering_party_idx,
                );
            for (i, key) in keys_init.iter().enumerate() {
                let idx = i as u16 + 1;
                let (signing_share_init, sub_share_init) = key.extra.as_ref().unwrap();
                let (signing_share_final, sub_share_final) = keys_new[i].extra.as_ref().unwrap();
                println!();
                println!(
                    "Party #{}:\n\
                    initial signing-share: {}\n\
                    initial sub-share: {}\n\
                    final signing-share: 0x{}\n\
                    final sub-share: 0x{:X}\n\
                    identity: 0x{}",
                    i + 1,
                    if idx == recovering_party_idx {
                        "None".to_string()
                    } else {
                        format!("0x{}", to_upper_hex(&signing_share_init.to_be_bytes()))
                    },
                    if idx == recovering_party_idx {
                        "None".to_string()
                    } else {
                        format!("0x{:X}", sub_share_init.y())
                    },
                    to_upper_hex(&signing_share_final.to_be_bytes()),
                    sub_share_final.y(),
                    to_upper_hex(&identity_providers[i].export())
                );
            }
        }
    }
}
