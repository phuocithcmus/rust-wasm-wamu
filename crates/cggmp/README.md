# Wamu CGGMP

A Rust implementation of [CGGMP20](https://eprint.iacr.org/2021/060.pdf) with augmentations as described by the [Wamu protocol](https://wamu.tech/specification) for computation of [threshold signatures](https://en.wikipedia.org/wiki/Threshold_cryptosystem#Methodology) by multiple [decentralized identities](https://ethereum.org/en/decentralized-identity/#what-are-decentralized-identifiers).

It uses the [Wamu Core (wamu-core)](https://github.com/wamutech/wamu-rs/tree/master/crates/core) crate for [Wamu](https://wamu.tech/specification)'s core sub-protocols and augmentations, and [Webb tool's cggmp-threshold-ecdsa](https://github.com/webb-tools/cggmp-threshold-ecdsa) crate for the [CGGMP20](https://eprint.iacr.org/2021/060.pdf) implementation that it wraps and augments.

## ⚠️ Security Warning

**This crate is pre-alpha software developed as a PoC (Proof of Concept) of the [Wamu protocol](https://wamu.tech/specification).
It has NOT been independently audited and/or rigorously tested yet!
It SHOULD NOT BE USED IN PRODUCTION!**

**NOTE:** 🚧 This project is still work in progress, check back over the next few weeks for regular updates.

## Implementation

This crate is a PoC (Proof of Concept) implementation of the [Wamu protocol](https://wamu.tech/specification) and uses a [fork](https://github.com/davidsemakula/cggmp-threshold-ecdsa/tree/wamu) of [Webb tool's cggmp-threshold-ecdsa](https://github.com/webb-tools/cggmp-threshold-ecdsa) crate for the [CGGMP20](https://eprint.iacr.org/2021/060.pdf) implementation with the following modifications/additions:

- [Fixes for/completion of the CGGMP20 pre-signing protocol](https://github.com/davidsemakula/cggmp-threshold-ecdsa/commit/e7971848e6a1878dfa10cae984b5d09de757ef89).
- [Support for threshold modification during the key refresh protocol](https://github.com/davidsemakula/cggmp-threshold-ecdsa/commit/4cc57099e3a86886cf1b62cb1ef1fda2817d2343).
  - This also required [modifications/additions to the FS-DKR library](https://github.com/davidsemakula/fs-dkr/commit/4414f386ceb2a7d84f5d685a911e0708ecff2808) which `cggmp-threshold-ecdsa` uses on for key refresh implementation which are made in a [fork of FS-DKR](https://github.com/davidsemakula/fs-dkr/commits/wamu).
- Minor public interface changes to `pub` relevant fields required for augmentation.

### PoC implementation specific limitations, issues and deviations from CGGMP20 

- Due to reliance on `cggmp-threshold-ecdsa`, key generation is based on [GG20](https://eprint.iacr.org/2020/540.pdf) using [ZenGo's multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa) library, which is no longer maintained and contains some known and un-patched vulnerabilities (see https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report/ and https://www.verichains.io/tsshock/).
- Due to reliance on `cggmp-threshold-ecdsa` which uses [FS-DKR (which assumes an honest majority)](https://github.com/webb-tools/fs-dkr#our-model) for the key refresh implementation, key refresh and related protocols (i.e. share addition, share removal, threshold modification and share recovery with quorum) all operate in an honest majority setting (i.e. the threshold cannot be greater than half the number of parties).
- Due to reliance on `cggmp-threshold-ecdsa` (and [round-based-protocol](https://github.com/ZenGo-X/round-based-protocol)), state machine implementations use/require `u16` party identifiers instead of using decentralized verifying keys/addresses for the same purpose.
- Only 4-round $O(n^2)$ with identifiable abort version of CGGMP20 signing is implemented.

**NOTE**: There's an ongoing collaborative effort to resolve `cggmp-threshold-ecdsa`'s deviations from CGGMP20 (see https://github.com/webb-tools/cggmp-threshold-ecdsa/issues/37 for details and progress).

## Installation

Run the following Cargo command in your project directory

```shell
cargo add wamu-cggmp --git https://github.com/wamutech/wamu-rs.git
```

## Documentation

You can access documentation locally by running the following command from the project root

```shell
cargo doc --no-deps -p wamu-cggmp --open
```

## Testing

You can run unit tests for all the core functionality by running the following command from the project root

```shell
cargo test -p wamu-cggmp
```

## Examples

See the [`/crates/cggmp/examples`](/crates/cggmp/examples) directory.

## License

Licensed under [GPL-3.0](https://github.com/wamutech/wamu-rs/tree/master/LICENSE-GPL).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the GPL-3.0 license, shall be
licensed as above, without any additional terms or conditions.
