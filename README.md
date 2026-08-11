# Binary Ninja Intel 8086 plugin

The Intel 8086 plugin provides a 16-bit x86 architecture for Binary Ninja.
This repository is a fork of the project originally started by [whitequark](https://github.com/whitequark).

## Choosing an architecture

Unlike Binary Ninja's general-purpose `x86_16` architecture, this plugin models the original 8086 specifically: its exact opcode set and CPU quirks, 20-bit real-mode segmented addressing and wraparound, and DOS `.COM` loading. It is more faithful for true 8086 binaries, but intentionally less capable for 80186+ code and detailed 8087 analysis; use `x86_16` when the target uses later extensions or its CPU generation is uncertain.

## Features

This plugin decodes and lifts all original 8086 instructions. However, 80186 (and more recent) instructions such as `enter` and `leave` are not recognized. Non-well-formed instructions (including unrecognized opcodes and invalid addressing modes) are displayed as `unrecognized` and rejected during lifting.

The `pascal` and `cdecl` calling conventions are provided.

![](screenshot.png)

## License

[0-clause BSD](LICENSE-0BSD.txt)
