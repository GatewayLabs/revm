# REVM Gateway

**Rust Ethereum Virtual Machine**

![](./assets/logo/revm-banner.png)

Revm is an EVM written in Rust that is focused on **speed** and **simplicity**.
It has a fast and flexible implementation with a simple interface and embedded Host.

Here is a list of guiding principles that Revm follows.

- **EVM compatibility and stability** - this goes without saying but it is nice to put it here. In the blockchain industry, stability is the most desired attribute of any system.
- **Speed** - is one of the most important things and most decisions are made to complement this.
- **Simplicity** - simplification of internals so that it can be easily understood and extended, and interface that can be easily used or integrated into other projects.
- **interfacing** - `[no_std]` so that it can be used as wasm lib and integrate with JavaScript and cpp binding if needed.

## Project

Structure:

- crates
  - revm -> main EVM library.
  - revm-primitives -> Primitive data types.
  - revm-interpreter -> Execution loop with instructions
  - revm-precompile -> EVM precompiles
- bins:
  - revme: cli binary, used for running state test jsons

This project tends to use the newest rust version, so if you're encountering a build error try running `rustup update` first.

## Running the project

### Dependencies

- [Gateway Circuit SDK](https://github.com/GatewayLabs/circuit-sdk)  
  In in the same work directory as you cloned this repository, you have to clone the `Gateway Circuit SDK`.

```shell
git clone git@github.com:GatewayLabs/circuit-sdk.git
```

### Building the project

```shell
cargo build --release
```

### Running an example

```shell
cargo run -p add-example (for instance)
```

```shell
cargo run
```

## Important considerations

This is a very volatile project, and it is under heavy development. Expect constant changes in the code and the documentation.
