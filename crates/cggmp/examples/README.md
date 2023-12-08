# Wamu - CLI demo

## Compilation

```shell
cargo build --examples --features=dev --release
```

## Running simulations

Switch to the examples directory

```shell
cd target/release/examples
```

For CLI help text, run:

```shell
./cli -h
```

Prints
```console
Wamu augmented CGGMP CLI.

Usage: cli <COMMAND>

Commands:
  keygen                  Runs key generation protocol
  key-refresh             Runs key refresh protocol
  sign                    Runs signing protocol
  identity-rotation       Runs identity rotation protocol
  share-addition          Runs share addition protocol
  share-removal           Runs share removal protocol
  threshold-modification  Runs threshold modification protocol
  share-recovery          Runs share recovery protocol
  help                    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

For help text for a specific command, run:

```shell
./cli <COMMAND> -h
```

e.g for keygen, running

```shell
./cli keygen -h
```
Prints
```console
Runs key generation protocol

Usage: cli keygen --threshold <THRESHOLD> --n-parties <N_PARTIES>

Options:
  -t, --threshold <THRESHOLD>  The threshold
  -n, --n-parties <N_PARTIES>  The number of parties
  -h, --help                   Print help
```

Therefore, to run a keygen simulation with threshold=1 (i.e. quorum size=2) and number of parties=3, run:

```shell
./cli keygen -t 1 -n 3
```

Example output
```console
Simulating key generation with threshold=1, quorum-size=2, number of parties=3

Party #1:
signing-share: 0x96D6720846482ADC40054446D2AF4907463873D562389F01FCF728728AEFB475
sub-share: 0xF7E51072DF35EF6EC2BB47AFD8F03D032D844478CA7A7295DF6FB294D2B5657E
identity: 0x470746218402C6C2914049739B0687FF4586672F4393132D16CE9CB2AC60E4F5

Party #2:
signing-share: 0x0CB9F2728FF9A1D5A2401FE57C09232FE005E1F8D75AA0B4C40D71D916562A7B
sub-share: 0xB174ADF7E517DCFC9496F597ED3AAA6E35ACB303F3B95EBD4CD3BCCC732BEDAC
identity: 0xEDAF28D060CC12250B68D974E08060382DF07398BE90D4A5CE71E4CA197F1578

Party #3:
signing-share: 0xE0BE74294A843FC4FC8DE4B9F19ED4A7493D9033928CE505C454917274D56AAE
sub-share: 0x56A4426768F5B88BA11E46983EBB6001A6DDB957A2820FC084D9E0D97FACCF26
identity: 0xFB5DAD143216E3A8324CBE6AD4689A11264AB94077D288C95B0CADF21A8DD8E4
```
