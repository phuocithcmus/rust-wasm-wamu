# Wamu Core

A Rust implementation of the core [Wamu protocol](https://wamu.tech/specification) for computation of [threshold signatures](https://en.wikipedia.org/wiki/Threshold_cryptosystem#Methodology) by multiple [decentralized identities](https://ethereum.org/en/decentralized-identity/#what-are-decentralized-identifiers).

It implements the core sub-protocols (i.e. share splitting and reconstruction, identity authenticated request initiation and verification, identity challenge, quorum approved request initiation and verification and encrypted backup-based share recovery) as well as types, abstractions and utilities for augmentations (e.g. utilities for initializing and verifying identity rotation, quorum-based share recovery and other decentralized identity authenticated requests) as described by the [Wamu protocol](https://wamu.tech/specification).

## ⚠️ Security Warning

**This crate is pre-alpha software developed as a PoC (Proof of Concept) of the [Wamu protocol](https://wamu.tech/specification).
It has NOT been independently audited and/or rigorously tested yet!
It SHOULD NOT BE USED IN PRODUCTION!**

**NOTE:** 🚧 This project is still work in progress, check back over the next few weeks for regular updates.

## Installation

Run the following Cargo command in your project directory

```shell
cargo add wamu-core
```

## Documentation

[https://docs.rs/wamu-core/latest/wamu_core/](https://docs.rs/wamu-core/latest/wamu_core/)

Or you can access documentation locally by running the following command from the project root

```shell
cargo doc -p wamu-core --open
```

## Testing

You can run unit tests for all the core functionality by running the following command from the project root

```shell
cargo test -p wamu-core
```

## License

Licensed under either [MIT](https://github.com/wamutech/wamu-rs/tree/master/LICENSE-MIT) or [Apache-2.0](https://github.com/wamutech/wamu-rs/tree/master/LICENSE-APACHE) license at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
