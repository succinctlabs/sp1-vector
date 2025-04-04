# Reproducible Builds

## Overview

When deploying SP1 Vector in production, it's important to ensure that the program used when generating proofs is reproducible.

## Prerequisites

You first need to install the [cargo prove](https://docs.succinct.xyz/docs/getting-started/install) toolchain.

Ensure that you have the latest version of the toolchain by running:

```bash
sp1up
```

Confirm that you have the toolchain installed by running:

```bash
cargo prove --version
```

## Verify the SP1 Vector binary

To build the SP1 Vector binary, first ensure that Docker is running.

```bash
docker ps
```

Then build the binaries:

```bash
cd program

# Builds the SP1 Vector binary using the corresponding Docker tag and ELF name.
cargo prove build --docker --tag v4.1.3 --elf-name vector-elf
```

Now, verify the binaries by confirming the output of `vkey` matches the vkeys on the contract. The `vkey` program outputs the verification key
based on the ELF in `/elf`.

```bash
cargo run --bin vkey --release
```
