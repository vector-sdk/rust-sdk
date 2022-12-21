# A Rust SDK for building Keystone enclave applications

This project aims to provide a Rust programming language SDK for building
[Keystone](https://keystone-enclave.org/) enclave and host applications for the
RISC-V architecture.

The SDK is designed to be compatible with the
[Keystone Eyrie Modular Runtime](https://github.com/keystone-enclave/keystone-runtime).

**NOTE**: This work is experimental and on a very early stage. The security of
          the API or its implementation has not been properly verified yet.
          Therefore, **Do not use in production!**

# Prequisites

### Bulding Keystone

Download and build [Keystone](https://github.com/keystone-enclave/keystone) for QEMU
environment using [instructions](http://docs.keystone-enclave.org/en/latest/Getting-Started/Install-Dependencies.html)
given in [Keystone documentation](http://docs.keystone-enclave.org).

**NOTE:** The code in this repository has only been tested using QEMU!

### Install Rust

This project uses experimental Rust features currently only available in Rust's
nightly build.

Use [rustup](https://www.rust-lang.org/tools/install) to install the Rust
environment and add required RISC-V targets:

      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
      rustup default nightly
      rustup target add riscv64gc-unknown-none-elf
      rustup target add riscv64gc-unknown-linux-gnu

# Build SDK crates

      cargo build --release

# Test

Test with Rust SDK [demo application](https://github.com/vector-sdk/rust-sdk-demo)!