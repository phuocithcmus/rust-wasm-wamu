# Wamu

A collection of modular [Rust](https://www.rust-lang.org/) libraries for implementing the [Wamu protocol](https://wamu.tech/specification) for computation of [threshold signatures](https://en.wikipedia.org/wiki/Threshold_cryptosystem#Methodology) by multiple [decentralized identities](https://ethereum.org/en/decentralized-identity/#what-are-decentralized-identifiers).

## ⚠️ Security Warning

**All crates in this repository are pre-alpha software developed as PoCs (Proofs of Concept) of the [Wamu protocol](https://wamu.tech/specification).
They have NOT been independently audited and/or rigorously tested yet! 
They SHOULD NOT BE USED IN PRODUCTION!**

**NOTE:** 🚧 This project is still work in progress, check back over the next few weeks for regular updates.

## Architecture

This repository contains 2 main crates:

### 1. [Wamu Core (wamu-core)](/crates/core)

This crate implements the core sub-protocols (i.e. share splitting and reconstruction, identity authenticated request initiation and verification, identity challenge, quorum approved request initiation and verification and encrypted backup-based share recovery) as well as types, abstractions and utilities for augmentations (e.g. utilities for initializing and verifying identity rotation, quorum-based share recovery and other decentralized identity authenticated requests) as described by the [Wamu protocol](https://wamu.tech/specification).

### 2. [Wamu CGGMP (wamu-cggmp)](/crates/cggmp)

This crate implements [CGGMP20](https://eprint.iacr.org/2021/060.pdf) with augmentations as described by the [Wamu protocol](https://wamu.tech/specification).

It uses the [Wamu Core (wamu-core)](/crates/core) crate for [Wamu](https://wamu.tech/specification)'s core sub-protocols and augmentations, and [Webb tool's cggmp-threshold-ecdsa](https://github.com/webb-tools/cggmp-threshold-ecdsa) crate for the [CGGMP20](https://eprint.iacr.org/2021/060.pdf) implementation that it wraps and augments.

## Installation and Usage

Check the readme of each crate for installation and usage instructions and links to documentation.

- Wamu Core (wamu-core): [/crates/core](/crates/core)
- Wamu CGGMP (wamu-cggmp): [/crates/cggmp](/crates/cggmp)

## Documentation

- Wamu Core ([wamu-core](/crates/core)): [https://docs.rs/wamu-core/latest/wamu_core/](https://docs.rs/wamu-core/latest/wamu_core/)
- Wamu CGGMP ([wamu-cggmp](/crates/cggmp)): See [instructions in the crate's README](/crates/cggmp/README.md#documentation)

Or you can access documentation locally by running the following command from the project root

```shell
cargo doc --no-deps --open
```

To open crate specific docs, see instructions in the readme in each crate's directory.

## Testing

You can run unit tests for all the core functionality by running the following command from the project root

```shell
cargo test
```

**NOTE:** To run only tests for a single crate, add a `-p <crate_name>` argument to the above command e.g.
```shell
cargo test -p wamu-core
```

## Examples

See the [`/crates/cggmp/examples`](/crates/cggmp/examples) directory.

## License

| Crate                                   | License                                                                                            |
|-----------------------------------------|----------------------------------------------------------------------------------------------------|
| Wamu Core ([wamu-core](/crates/core))   | Licensed under either [MIT](/LICENSE-MIT) or [Apache-2.0](/LICENSE-APACHE) license at your option. |
| Wamu CGGMP ([wamu-cggmp](/crates/cggmp) | Licensed under [GPL-3.0](/LICENSE-GPL).                                                            |

## Contribution

| Crate                                    | Guidelines                                                                                                                                                                                                                           |
|------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Wamu Core ([wamu-core](/crates/core))    | Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions. |
| Wamu CGGMP ([wamu-cggmp](/crates/cggmp)) | Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the GPL-3.0 license, shall be licensed as above, without any additional terms or conditions.         |

## Acknowledgements

🌱 Funded by: the [Ethereum Foundation](https://esp.ethereum.foundation/).