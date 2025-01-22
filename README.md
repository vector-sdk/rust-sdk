# A Rust SDK for building Keystone enclave applications

This project aims to provide a Rust programming language SDK for building
[Keystone](https://keystone-enclave.org/) enclave and host applications for
the RISC-V architecture.

The SDK is designed to be compatible with the
[Keystone Eyrie Modular Runtime](https://github.com/keystone-enclave/keystone)
(available in subdirectory <kbd>runtime</kbd>).

**NOTE**: This work is experimental and on a very early stage. The security of
          the API or its implementation has not been properly verified yet.
          Therefore, **Do not use in production!**

# Prequisites

## Bulding Keystone

The Rust SDK can be used with Keystone enclave. Use either custom
version or upstream Keystone. The custom version contains few patches
that have not yet been merged to the upstream (e.g., support for the
StarFive VisionFive2 development board). The code has been tested with
QEMU and StarFive VisionFive2 development board.

### Custom Keystone repository

Download or clone custom [Keystone](https://github.com/vector-sdk/vector-keystone).
Build for QEMU:

    make

Alternatively build for StarFive VisionFive2 development board:

    scripts/build_visionfive2.sh

### Upstream Keystone repository

Download or clone and build [Keystone](https://github.com/keystone-enclave/keystone)
for QEMU environment using instructions given in
[Keystone documentation](http://docs.keystone-enclave.org).

## Install RISC-V toolchains

If you are using Ubuntu make sure that you have basic support for
development environment by installing the following essiential packages:

    sudo apt install build-essential
    sudo apt install crossbuild-essential-riscv64

Install also toolchain files:

    sudo apt install gcc-riscv64-linux-gnu g++-riscv64-linux-gnu libc6-dev-riscv64-cross
    sudo apt install gcc-riscv64-unknown-elf

## Install Rust

This project uses an experimental Rust feature (per-package-target)
that is only available in Rust's nightly build. Use
[rustup](https://www.rust-lang.org/tools/install) to install the Rust
environment and add required RISC-V targets.

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	rustup default nightly
    rustup target add riscv64gc-unknown-none-elf
    rustup target add riscv64gc-unknown-linux-gnu

# Build SDK crates

Using cargo:

    cargo build --release
Using make:

    make

# Test

Test with Rust SDK [demo application](https://github.com/vector-sdk/rust-sdk-demo)!

# Cleanup

Using cargo:

    cargo clean
Using make:

    make clean

# More information

An old conference paper is describing the first version:

Julku, J. and Kylänpää, M. (2023). **Towards a Rust SDK for Keystone
Enclave Application Development**. In *Proceedings of the 9th
International Conference on Information Systems Security and Privacy -
ICISSP*; ISBN 978-989-758-624-8; ISSN 2184-4356, SciTePress, pages
29-37. DOI:
[10.5220/0011611900003405](https://doi.org/10.5220/0011611900003405)

# Acknowledgment

This work is partly supported by the European Union’s Horizon Europe
research and innovation programme in the scope of the the
[CONFIDENTIAL6G](https://confidential6g.eu/) project under Grant
Agreement 101096435.
